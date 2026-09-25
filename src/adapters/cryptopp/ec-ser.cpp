// EC-ser x Crypto++ adapter implementation.
// See ec-ser.hpp for the full precise findings against the pinned commit.

#include "ec-ser.hpp"

#include <cstring>
#include <stdexcept>

#include "asn.h"
#include "cryptlib.h"
#include "eccrypto.h"
#include "hex.h"
#include "integer.h"
#include "oids.h"
#include "osrng.h"
#include "queue.h"

using namespace CryptoPP;

namespace paper4 {
namespace {

// --- P-256 domain constants -- same values verified this session against
// NIST SP 800-186/SEC 2 and computationally cross-checked against real
// OpenSSL-generated keys (see src/contract/p256.ts's header for the exact
// verification performed). Reproduced here as CryptoPP::Integer literals. ---

Integer P256_P() { return Integer("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"); }
Integer P256_A() { return P256_P() - Integer(3L); }
Integer P256_B() { return Integer("0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"); }
Integer P256_GX() { return Integer("0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"); }
Integer P256_GY() { return Integer("0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"); }
Integer P256_N() { return Integer("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"); }

// --- Our own P-256 point arithmetic -- mirrors src/contract/p256.ts.
// Deliberately NOT CryptoPP::ECP/DL_GroupParameters_EC's own VerifyPoint/
// ValidateElement/Multiply (see this file's header comment). ---

Integer Mod(const Integer& x, const Integer& m) {
  Integer r = x % m;
  return r.IsNegative() ? r + m : r;
}

Integer ModInverse(const Integer& a, const Integer& m) { return a.InverseMod(m); }

bool IsOnCurve(const EcPoint& p) {
  if (p.isInfinity) return false;
  const Integer p256p = P256_P();
  if (p.x.IsNegative() || p.x >= p256p || p.y.IsNegative() || p.y >= p256p) return false;
  Integer lhs = Mod(p.y * p.y, p256p);
  Integer rhs = Mod(Mod(p.x * p.x, p256p) * p.x + P256_A() * p.x + P256_B(), p256p);
  return lhs == rhs;
}

EcPoint PointAdd(const EcPoint& p1, const EcPoint& p2);
EcPoint PointDouble(const EcPoint& p1);

EcPoint PointAdd(const EcPoint& p1, const EcPoint& p2) {
  if (p1.isInfinity) return p2;
  if (p2.isInfinity) return p1;
  const Integer p256p = P256_P();
  if (p1.x == p2.x) {
    if (Mod(p1.y + p2.y, p256p) == Integer::Zero()) return EcPoint{true, Integer::Zero(), Integer::Zero()};
    return PointDouble(p1);
  }
  Integer lambda = Mod((p2.y - p1.y) * ModInverse(Mod(p2.x - p1.x, p256p), p256p), p256p);
  Integer x3 = Mod(lambda * lambda - p1.x - p2.x, p256p);
  Integer y3 = Mod(lambda * (p1.x - x3) - p1.y, p256p);
  return EcPoint{false, x3, y3};
}

EcPoint PointDouble(const EcPoint& p1) {
  if (p1.isInfinity) return p1;
  const Integer p256p = P256_P();
  if (p1.y == Integer::Zero()) return EcPoint{true, Integer::Zero(), Integer::Zero()};
  Integer lambda = Mod((Integer(3L) * p1.x * p1.x + P256_A()) * ModInverse(Mod(Integer(2L) * p1.y, p256p), p256p), p256p);
  Integer x3 = Mod(lambda * lambda - Integer(2L) * p1.x, p256p);
  Integer y3 = Mod(lambda * (p1.x - x3) - p1.y, p256p);
  return EcPoint{false, x3, y3};
}

EcPoint ScalarMultiply(const Integer& d, const EcPoint& point) {
  if (point.isInfinity || d == Integer::Zero()) return EcPoint{true, Integer::Zero(), Integer::Zero()};
  EcPoint result{true, Integer::Zero(), Integer::Zero()};
  EcPoint addend = point;
  Integer k = d;
  while (k > Integer::Zero()) {
    if (k.IsOdd()) result = PointAdd(result, addend);
    addend = PointDouble(addend);
    k >>= 1;
  }
  return result;
}

EcPoint ScalarMultiplyG(const Integer& d) {
  return ScalarMultiply(d, EcPoint{false, P256_GX(), P256_GY()});
}

bool IsPair(const Integer& d, const EcPoint& q) {
  EcPoint computed = ScalarMultiplyG(d);
  if (computed.isInfinity || q.isInfinity) return false;
  return computed.x == q.x && computed.y == q.y;
}

bool IsValidScalar(const Integer& d) { return d >= Integer(1L) && d < P256_N(); }

// --- Our own minimal DER TLV walker, extended with EXPLICIT context tags ---

struct Tlv {
  int tag;
  std::vector<uint8_t> content;
  size_t nextOffset;
};

Tlv DecodeTlv(const std::vector<uint8_t>& buf, size_t offset) {
  if (offset >= buf.size()) throw std::runtime_error("unexpected end of buffer reading tag");
  int tag = buf[offset];
  if ((tag & 0x1f) == 0x1f) throw std::runtime_error("multi-byte tags are not supported by this profile");
  size_t pos = offset + 1;
  if (pos >= buf.size()) throw std::runtime_error("unexpected end of buffer reading length");
  uint8_t first = buf[pos];
  pos += 1;
  size_t len;
  if (first == 0x80) {
    throw std::runtime_error("indefinite length (BER, not DER)");
  } else if (first < 0x80) {
    len = first;
  } else {
    size_t numLenBytes = first & 0x7f;
    if (numLenBytes == 0 || numLenBytes > 4) throw std::runtime_error("unsupported long-form length");
    if (pos + numLenBytes > buf.size()) throw std::runtime_error("unexpected end of buffer reading long-form length");
    len = 0;
    for (size_t i = 0; i < numLenBytes; i++) len = (len << 8) | buf[pos + i];
    pos += numLenBytes;
    if (len < 0x80) throw std::runtime_error("non-minimal long-form length (BER, not DER)");
  }
  if (pos + len > buf.size()) throw std::runtime_error("declared length exceeds remaining buffer");
  Tlv out;
  out.tag = tag;
  out.content.assign(buf.begin() + static_cast<long>(pos), buf.begin() + static_cast<long>(pos + len));
  out.nextOffset = pos + len;
  return out;
}

std::vector<Tlv> DecodeSequenceChildren(const Tlv& tlv, int exactCount = -1) {
  if (tlv.tag != 0x30) throw std::runtime_error("expected SEQUENCE");
  std::vector<Tlv> children;
  size_t offset = 0;
  while (offset < tlv.content.size()) {
    Tlv child = DecodeTlv(tlv.content, offset);
    offset = child.nextOffset;
    children.push_back(child);
  }
  if (exactCount >= 0 && static_cast<int>(children.size()) != exactCount) throw std::runtime_error("unexpected SEQUENCE element count");
  return children;
}

Integer DecodeIntegerTlv(const Tlv& tlv) {
  if (tlv.tag != 0x02) throw std::runtime_error("expected INTEGER");
  const auto& c = tlv.content;
  if (c.empty()) throw std::runtime_error("empty INTEGER content");
  if (c[0] & 0x80) throw std::runtime_error("negative INTEGER not supported by this profile");
  return Integer(c.data(), c.size(), Integer::UNSIGNED, BIG_ENDIAN_ORDER);
}

std::vector<uint8_t> DecodeOctetStringTlv(const Tlv& tlv) {
  if (tlv.tag != 0x04) throw std::runtime_error("expected OCTET STRING");
  return tlv.content;
}

std::vector<uint8_t> DecodeBitStringWholeBytes(const Tlv& tlv) {
  if (tlv.tag != 0x03) throw std::runtime_error("expected BIT STRING");
  if (tlv.content.empty()) throw std::runtime_error("empty BIT STRING content");
  if (tlv.content[0] != 0x00) throw std::runtime_error("BIT STRING has non-zero unused bits");
  return std::vector<uint8_t>(tlv.content.begin() + 1, tlv.content.end());
}

const uint8_t kEcPublicKeyOid[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
const uint8_t kSecp256r1Oid[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

bool IsOidTlv(const Tlv& tlv, const uint8_t* expected, size_t len) {
  return tlv.tag == 0x06 && tlv.content.size() == len && std::memcmp(tlv.content.data(), expected, len) == 0;
}

bool IsExplicitTag(const Tlv& tlv, int tagNumber) { return tlv.tag == (0xa0 + tagNumber); }

std::vector<uint8_t> EncodeLength(size_t len) {
  if (len < 0x80) return {static_cast<uint8_t>(len)};
  std::vector<uint8_t> bytes;
  size_t n = len;
  while (n > 0) {
    bytes.insert(bytes.begin(), static_cast<uint8_t>(n & 0xff));
    n >>= 8;
  }
  std::vector<uint8_t> out;
  out.push_back(static_cast<uint8_t>(0x80 | bytes.size()));
  out.insert(out.end(), bytes.begin(), bytes.end());
  return out;
}

std::vector<uint8_t> EncodeTlv(int tag, const std::vector<uint8_t>& content) {
  std::vector<uint8_t> out;
  out.push_back(static_cast<uint8_t>(tag));
  auto lenBytes = EncodeLength(content.size());
  out.insert(out.end(), lenBytes.begin(), lenBytes.end());
  out.insert(out.end(), content.begin(), content.end());
  return out;
}

std::vector<uint8_t> EncodeIntegerFixedNonneg(const Integer& value) {
  size_t len = value.MinEncodedSize(Integer::SIGNED);
  std::vector<uint8_t> content(len);
  value.Encode(content.data(), len, Integer::SIGNED);
  return EncodeTlv(0x02, content);
}

std::vector<uint8_t> EncodeSequence(const std::vector<std::vector<uint8_t>>& children) {
  std::vector<uint8_t> content;
  for (const auto& c : children) content.insert(content.end(), c.begin(), c.end());
  return EncodeTlv(0x30, content);
}

std::vector<uint8_t> EncodeOctetString(const std::vector<uint8_t>& content) { return EncodeTlv(0x04, content); }

std::vector<uint8_t> EncodeBitStringWholeBytes(const std::vector<uint8_t>& content) {
  std::vector<uint8_t> wrapped;
  wrapped.push_back(0x00);
  wrapped.insert(wrapped.end(), content.begin(), content.end());
  return EncodeTlv(0x03, wrapped);
}

std::vector<uint8_t> EncodeExplicit(int tagNumber, const std::vector<uint8_t>& innerTlvBytes) {
  return EncodeTlv(0xa0 + tagNumber, innerTlvBytes);
}

std::vector<uint8_t> EncodeEcPublicKeyOid() { return EncodeTlv(0x06, std::vector<uint8_t>(kEcPublicKeyOid, kEcPublicKeyOid + sizeof(kEcPublicKeyOid))); }
std::vector<uint8_t> EncodeSecp256r1Oid() { return EncodeTlv(0x06, std::vector<uint8_t>(kSecp256r1Oid, kSecp256r1Oid + sizeof(kSecp256r1Oid))); }
std::vector<uint8_t> EncodeAlgorithmIdentifier() { return EncodeSequence({EncodeEcPublicKeyOid(), EncodeSecp256r1Oid()}); }

std::vector<uint8_t> BigIntToFixed32(const Integer& value) {
  std::vector<uint8_t> out(32, 0);
  size_t len = value.MinEncodedSize(Integer::UNSIGNED);
  if (len > 32) throw std::runtime_error("scalar does not fit in 32 bytes");
  std::vector<uint8_t> tmp(len);
  value.Encode(tmp.data(), len, Integer::UNSIGNED);
  std::copy(tmp.begin(), tmp.end(), out.begin() + static_cast<long>(32 - len));
  return out;
}

std::vector<uint8_t> EncodeUncompressedPoint(const EcPoint& p) {
  std::vector<uint8_t> out;
  out.push_back(0x04);
  auto xb = BigIntToFixed32(p.x);
  auto yb = BigIntToFixed32(p.y);
  out.insert(out.end(), xb.begin(), xb.end());
  out.insert(out.end(), yb.begin(), yb.end());
  return out;
}

EcPoint DecodeUncompressedPoint(const std::vector<uint8_t>& bytes) {
  if (bytes.size() != 65) throw std::runtime_error("uncompressed point must be exactly 65 bytes");
  if (bytes[0] != 0x04) throw std::runtime_error("expected uncompressed point form (0x04)");
  Integer x(bytes.data() + 1, 32, Integer::UNSIGNED, BIG_ENDIAN_ORDER);
  Integer y(bytes.data() + 33, 32, Integer::UNSIGNED, BIG_ENDIAN_ORDER);
  return EcPoint{false, x, y};
}

struct ParsedContainer {
  std::string containerRole;
  Tlv algIdTlv;
  Tlv innerTlv;
};

ParsedContainer ParseContainerStructural(const std::vector<uint8_t>& artifact) {
  Tlv outer;
  try {
    outer = DecodeTlv(artifact, 0);
  } catch (const std::exception& e) {
    throw EcSerError{"ec-ser.validation.syntax", "malformed_artifact", std::string("DER parse failed: ") + e.what()};
  }
  if (outer.nextOffset != artifact.size()) {
    throw EcSerError{"ec-ser.validation.syntax", "malformed_artifact", "trailing bytes after the top-level DER object"};
  }
  std::vector<Tlv> children;
  try {
    children = DecodeSequenceChildren(outer);
  } catch (const std::exception& e) {
    throw EcSerError{"ec-ser.validation.syntax", "malformed_artifact", std::string("outer SEQUENCE parse failed: ") + e.what()};
  }

  if (children.size() == 2 && children[1].tag == 0x03) {
    return {"public", children[0], children[1]};
  }
  if (children.size() == 3 && children[0].tag == 0x02 && children[2].tag == 0x04) {
    Integer version;
    try {
      version = DecodeIntegerTlv(children[0]);
    } catch (...) {
      throw EcSerError{"ec-ser.validation.syntax", "malformed_artifact", "PrivateKeyInfo version field is not a valid INTEGER"};
    }
    if (version != Integer::Zero()) throw EcSerError{"ec-ser.validation.syntax", "malformed_artifact", "PrivateKeyInfo version != 0"};
    return {"private", children[1], children[2]};
  }
  throw EcSerError{"ec-ser.validation.syntax", "malformed_artifact", "valid DER instantiating neither SPKI nor PrivateKeyInfo"};
}

}  // namespace

EcSerImportResult ImportEcSerCryptoPP(const std::vector<uint8_t>& artifact, const std::string& requestedRole) {
  ParsedContainer container = ParseContainerStructural(artifact);

  if (container.containerRole != requestedRole) {
    throw EcSerError{"ec-ser.key.role", "invalid_parameter",
                      "artifact instantiates a " + container.containerRole + " container but role=" + requestedRole + " was requested"};
  }

  std::vector<Tlv> algChildren;
  try {
    algChildren = DecodeSequenceChildren(container.algIdTlv, 2);
  } catch (...) {
    throw EcSerError{requestedRole == "public" ? "ec-ser.public.asn1" : "ec-ser.private.asn1", "invalid_parameter",
                      "AlgorithmIdentifier is not a well-formed two-OID SEQUENCE"};
  }
  bool algOk = IsOidTlv(algChildren[0], kEcPublicKeyOid, sizeof(kEcPublicKeyOid));
  bool curveOk = IsOidTlv(algChildren[1], kSecp256r1Oid, sizeof(kSecp256r1Oid));
  if (!algOk) {
    throw EcSerError{requestedRole == "public" ? "ec-ser.public.asn1" : "ec-ser.private.asn1", "invalid_parameter",
                      "AlgorithmIdentifier.algorithm != id-ecPublicKey"};
  }
  if (!curveOk) {
    throw EcSerError{"ec-ser.curve", "invalid_parameter", "curve OID != secp256r1"};
  }

  if (requestedRole == "public") {
    EcPoint point;
    try {
      auto pointBytes = DecodeBitStringWholeBytes(container.innerTlv);
      point = DecodeUncompressedPoint(pointBytes);
    } catch (const std::exception& e) {
      throw EcSerError{"ec-ser.public.point", "invalid_parameter", std::string("point decode failed: ") + e.what()};
    }
    if (!IsOnCurve(point)) {
      throw EcSerError{"ec-ser.curveMembership", "invalid_membership", "Q is not a point on secp256r1"};
    }
    EcKeyMaterial m;
    m.role = "public";
    m.q = point;
    return EcSerImportResult{m, false};
  }

  if (container.innerTlv.tag != 0x04) throw EcSerError{"ec-ser.private.asn1", "malformed_artifact", "PrivateKeyInfo.privateKey is not an OCTET STRING"};
  std::vector<Tlv> innerChildren;
  try {
    Tlv innerSeq = DecodeTlv(container.innerTlv.content, 0);
    innerChildren = DecodeSequenceChildren(innerSeq);
  } catch (const std::exception& e) {
    throw EcSerError{"ec-ser.private.asn1", "malformed_artifact", std::string("ECPrivateKey inner structure malformed: ") + e.what()};
  }
  if (innerChildren.size() < 2) throw EcSerError{"ec-ser.private.asn1", "malformed_artifact", "ECPrivateKey requires at least version and privateKey fields"};

  Integer version;
  std::vector<uint8_t> dBytes;
  try {
    version = DecodeIntegerTlv(innerChildren[0]);
    dBytes = DecodeOctetStringTlv(innerChildren[1]);
  } catch (const std::exception& e) {
    throw EcSerError{"ec-ser.private.asn1", "malformed_artifact", std::string("ECPrivateKey version/privateKey malformed: ") + e.what()};
  }
  if (version != Integer(1L)) throw EcSerError{"ec-ser.private.asn1", "malformed_artifact", "ECPrivateKey.version != 1"};
  if (dBytes.size() != 32) throw EcSerError{"ec-ser.private.asn1", "malformed_artifact", "privateKey OCTET STRING is not 32 bytes"};
  Integer d(dBytes.data(), dBytes.size(), Integer::UNSIGNED, BIG_ENDIAN_ORDER);

  bool sawParamsZero = false;
  bool paramsMatch = true;
  bool sawPub = false;
  std::vector<uint8_t> pointBytes;

  for (size_t i = 2; i < innerChildren.size(); i++) {
    const Tlv& child = innerChildren[i];
    if (IsExplicitTag(child, 0)) {
      sawParamsZero = true;
      try {
        Tlv inner = DecodeTlv(child.content, 0);
        paramsMatch = IsOidTlv(inner, kSecp256r1Oid, sizeof(kSecp256r1Oid));
      } catch (...) {
        paramsMatch = false;
      }
    } else if (IsExplicitTag(child, 1)) {
      try {
        Tlv bitStringTlv = DecodeTlv(child.content, 0);
        pointBytes = DecodeBitStringWholeBytes(bitStringTlv);
        sawPub = true;
      } catch (...) {
        sawPub = false;
      }
    }
  }

  if (sawParamsZero && !paramsMatch) {
    throw EcSerError{"ec-ser.private.asn1", "invalid_parameter", "ECPrivateKey.parameters[0] present but != secp256r1"};
  }
  if (!sawPub) {
    throw EcSerError{"ec-ser.private.asn1", "invalid_parameter", "ECPrivateKey.publicKey[1] is absent -- excluded from D_import^common entirely (D-059)"};
  }

  EcPoint point;
  try {
    point = DecodeUncompressedPoint(pointBytes);
  } catch (const std::exception& e) {
    throw EcSerError{"ec-ser.public.point", "invalid_parameter", std::string("embedded publicKey[1] point decode failed: ") + e.what()};
  }

  if (!IsValidScalar(d)) throw EcSerError{"ec-ser.private.scalar", "invalid_key", "private scalar fails V_scalar (1<=d<n)"};
  if (!IsOnCurve(point)) throw EcSerError{"ec-ser.curveMembership", "invalid_membership", "embedded publicKey[1] is not a point on secp256r1"};
  if (!IsPair(d, point)) throw EcSerError{"ec-ser.pairConsistency", "invalid_key", "Q != dG -- never normalized"};

  EcKeyMaterial m;
  m.role = "private";
  m.d = d;
  m.q = point;
  return EcSerImportResult{m, !sawParamsZero};
}

std::vector<uint8_t> ExportEcSerCryptoPP(const EcKeyMaterial& material) {
  if (material.role == "public") {
    auto point = EncodeUncompressedPoint(material.q);
    return EncodeSequence({EncodeAlgorithmIdentifier(), EncodeBitStringWholeBytes(point)});
  }
  auto dBytes = BigIntToFixed32(material.d);
  auto paramsExplicit = EncodeExplicit(0, EncodeSecp256r1Oid());
  auto pubExplicit = EncodeExplicit(1, EncodeBitStringWholeBytes(EncodeUncompressedPoint(material.q)));
  auto inner = EncodeSequence({EncodeIntegerFixedNonneg(Integer(1L)), EncodeOctetString(dBytes), paramsExplicit, pubExplicit});
  return EncodeSequence({EncodeIntegerFixedNonneg(Integer::Zero()), EncodeAlgorithmIdentifier(), EncodeOctetString(inner)});
}

std::vector<uint8_t> NativeCryptoPPSpkiExport(const EcKeyMaterial& material) {
  DL_GroupParameters_EC<ECP> params(ASN1::secp256r1());
  ECP::Point q(material.q.x, material.q.y);
  DL_PublicKey_EC<ECP> pub;
  pub.Initialize(params, q);
  std::string out;
  pub.Save(StringSink(out).Ref());
  return std::vector<uint8_t>(out.begin(), out.end());
}

std::vector<uint8_t> NativeCryptoPPPkcs8Export(const EcKeyMaterial& material) {
  DL_GroupParameters_EC<ECP> params(ASN1::secp256r1());
  DL_PrivateKey_EC<ECP> priv;
  priv.Initialize(params, material.d);
  std::string out;
  priv.Save(StringSink(out).Ref());
  return std::vector<uint8_t>(out.begin(), out.end());
}

EcKeyMaterial NativeCryptoPPImport(const std::vector<uint8_t>& artifact, const std::string& role) {
  StringStore store(artifact.data(), artifact.size());
  EcKeyMaterial m;
  m.role = role;
  if (role == "public") {
    DL_PublicKey_EC<ECP> pub;
    pub.Load(store);
    const ECP::Point& q = pub.GetPublicElement();
    m.q = EcPoint{false, q.x, q.y};
  } else {
    DL_PrivateKey_EC<ECP> priv;
    priv.Load(store);
    m.d = priv.GetPrivateExponent();
    // Confirmed (this file's header comment): Crypto++'s own PKCS8 private
    // decode parses publicKey[1] then DISCARDS it -- it is never retained
    // as private-key material, so there is no native accessor for it
    // here. m.q is left default/unset; callers needing Q from a native
    // import must derive it themselves (e.g. via our own ScalarMultiplyG
    // equivalent), exactly mirroring what this adapter's own Accept_C
    // does NOT do (Accept_C requires publicKey[1] present and checks it,
    // it never derives Q).
  }
  return m;
}

EcKeyMaterial GenerateEcSerKeyMaterial() {
  AutoSeededRandomPool rng;
  DL_GroupParameters_EC<ECP> params(ASN1::secp256r1());
  DL_PrivateKey_EC<ECP> priv;
  priv.Initialize(rng, params);  // CryptoPP's own scalar generation -- a legitimate fixture-generation utility, not part of Accept_C's own math
  Integer d = priv.GetPrivateExponent();

  // Q derived via OUR OWN scalar multiplication, not CryptoPP's own point
  // multiplication -- keeps the independence principle intact even for
  // fixture construction.
  EcPoint q = ScalarMultiplyG(d);

  EcKeyMaterial m;
  m.role = "private";
  m.d = d;
  m.q = q;
  return m;
}

}  // namespace paper4
