// RSA-ser x Crypto++ adapter implementation.
//
// CONFIRMED DIVERGENCE, itemized (this session's explicit requirement):
// RSA::PrivateKey::Validate() is NOT a substitute for V_domain^RSA,2 ^
// V_rel^RSA,2 (Design Freeze v0.6, D-054). Verified directly against the
// pinned commit's rsa.cpp (InvertibleRSAFunction::Validate):
//   MISSING (Validate() does NOT check these, at any level):
//     - p != q (distinctness -- never compared, at any level)
//     - p, q primality -- only at level>=2, and even then via a
//       probabilistic VerifyPrime() call requiring an RNG parameter our
//       Accept_C has no business taking
//     - gcd(e, lambda(n)) = 1 -- never checked at ANY level
//   USES THE WRONG RELATION FORM: Validate()'s level>=1 check is
//     `m_dp == m_d % (m_p-1)` -- the common SHORTHAND -- not RFC 8017's own
//     defining relation `e*dP === 1 (mod p-1)`. Design Freeze v0.6 already
//     flagged this exact shorthand-vs-defining-relation distinction as
//     consequential (sec:rsa-ser-admission); Validate() uses the shorthand.
//   EXTRA (Validate() checks something V_domain/V_rel do not require):
//     - dP, dQ required ODD explicitly -- not a literal RFC 8017 domain
//       constraint.
//   ALSO: Validate() with no `level` argument runs ONLY the level-0 checks
//     -- the n=pq and CRT relational checks require the CALLER to
//     remember to pass level>=1 explicitly, a footgun this adapter does
//     not rely on at all.
// CONCLUSION: this adapter NEVER calls Validate() for admission. C_math is
// reimplemented independently below, using CryptoPP::IsPrime/Gcd/LCM only
// as bignum-arithmetic PRIMITIVES, not as the contractual authority.
//
// MULTI-PRIME, confirmed precisely: InvertibleRSAFunction::BERDecodePrivateKey
// decodes `version` via BERDecodeUnsigned<word32>(..., INTEGER, 0, 0) --
// the trailing 0,0 are exact min/max bounds, so Crypto++'s OWN native
// BERDecode() THROWS for any version != 0 -- NATIVE REJECTION AT PARSE
// TIME for multi-prime artifacts, a different mechanism from Bouncy
// Castle's later-confirmed "parse but discard" -- but our own adapter
// classifies this via its OWN structural walker regardless (never via
// catching Crypto++'s native BERDecodeErr).

#include "rsa-ser.hpp"

#include <chrono>
#include <cctype>
#include <cstring>
#include <sstream>
#include <stdexcept>

#include "asn.h"
#include "cryptlib.h"
#include "hex.h"
#include "integer.h"
#include "nbtheory.h"
#include "osrng.h"
#include "queue.h"
#include "rsa.h"

using namespace CryptoPP;

namespace paper4 {
namespace {

// Our own minimal DER TLV walker -- mirrors src/contract/der.ts exactly.
// NOT CryptoPP::BERSequenceDecoder: that would mean Crypto++'s own ASN.1
// machinery decides structural admission before Accept_C gets a say.

struct Tlv {
  uint8_t tag;
  std::vector<uint8_t> content;
  size_t nextOffset;
};

Tlv DecodeTlv(const std::vector<uint8_t>& buf, size_t offset) {
  if (offset >= buf.size()) throw std::runtime_error("unexpected end of buffer reading tag");
  uint8_t tag = buf[offset];
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
    if (numLenBytes > 1 && buf[pos - numLenBytes] == 0x00) throw std::runtime_error("non-minimal long-form length (leading zero)");
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
  if (exactCount >= 0 && static_cast<int>(children.size()) != exactCount) {
    throw std::runtime_error("unexpected SEQUENCE element count");
  }
  return children;
}

Integer DecodeIntegerTlv(const Tlv& tlv) {
  if (tlv.tag != 0x02) throw std::runtime_error("expected INTEGER");
  const auto& c = tlv.content;
  if (c.empty()) throw std::runtime_error("empty INTEGER content");
  if (c.size() > 1 && c[0] == 0x00 && (c[1] & 0x80) == 0) throw std::runtime_error("non-minimal INTEGER encoding");
  if (c[0] & 0x80) throw std::runtime_error("negative INTEGER not supported by this profile");
  return Integer(c.data(), c.size(), Integer::UNSIGNED, BIG_ENDIAN_ORDER);
}

const uint8_t kRsaEncryptionOidContent[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};

bool IsRsaEncryptionOidTlv(const Tlv& tlv) {
  return tlv.tag == 0x06 && tlv.content.size() == sizeof(kRsaEncryptionOidContent) &&
         std::memcmp(tlv.content.data(), kRsaEncryptionOidContent, sizeof(kRsaEncryptionOidContent)) == 0;
}

bool IsNullTlv(const Tlv& tlv) { return tlv.tag == 0x05 && tlv.content.empty(); }

std::vector<uint8_t> DecodeBitStringWholeBytes(const Tlv& tlv) {
  if (tlv.tag != 0x03) throw std::runtime_error("expected BIT STRING");
  if (tlv.content.empty()) throw std::runtime_error("empty BIT STRING content");
  if (tlv.content[0] != 0x00) throw std::runtime_error("BIT STRING has non-zero unused bits");
  return std::vector<uint8_t>(tlv.content.begin() + 1, tlv.content.end());
}

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

std::vector<uint8_t> EncodeTlv(uint8_t tag, const std::vector<uint8_t>& content) {
  std::vector<uint8_t> out;
  out.push_back(tag);
  auto lenBytes = EncodeLength(content.size());
  out.insert(out.end(), lenBytes.begin(), lenBytes.end());
  out.insert(out.end(), content.begin(), content.end());
  return out;
}

std::vector<uint8_t> EncodeInteger(const Integer& value) {
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

std::vector<uint8_t> EncodeBitStringWholeBytes(const std::vector<uint8_t>& content) {
  std::vector<uint8_t> wrapped;
  wrapped.push_back(0x00);
  wrapped.insert(wrapped.end(), content.begin(), content.end());
  return EncodeTlv(0x03, wrapped);
}

std::vector<uint8_t> EncodeOctetString(const std::vector<uint8_t>& content) { return EncodeTlv(0x04, content); }
std::vector<uint8_t> EncodeNull() { return EncodeTlv(0x05, {}); }
std::vector<uint8_t> EncodeRsaEncryptionOid() {
  return EncodeTlv(0x06, std::vector<uint8_t>(kRsaEncryptionOidContent, kRsaEncryptionOidContent + sizeof(kRsaEncryptionOidContent)));
}
std::vector<uint8_t> EncodeAlgorithmIdentifier() { return EncodeSequence({EncodeRsaEncryptionOid(), EncodeNull()}); }

bool CheckPublicValidity(const Integer& n, const Integer& e) {
  return n >= Integer(15L) && n.IsOdd() && e >= Integer(3L) && e <= n - Integer(1L) && e.IsOdd();
}

bool CheckPrivateDomain(const RsaKeyMaterial& m) {
  return m.p != m.q && IsPrime(m.p) && IsPrime(m.q) && m.p.IsOdd() && m.q.IsOdd() && m.e >= Integer(3L) &&
         m.e <= m.n - Integer(1L) && m.d > Integer(0L) && m.d < m.n && m.dP > Integer(0L) && m.dP < m.p &&
         m.dQ > Integer(0L) && m.dQ < m.q && m.qInv > Integer(0L) && m.qInv < m.p;
}

bool CheckPrivateRelations(const RsaKeyMaterial& m) {
  const Integer lambdaN = LCM(m.p - Integer(1L), m.q - Integer(1L));
  auto modOk = [](const Integer& a, const Integer& b, const Integer& mod) { return (a * b) % mod == Integer(1L) % mod; };
  return m.n == m.p * m.q && Integer::Gcd(m.e, lambdaN) == Integer(1L) && modOk(m.e, m.d, lambdaN) &&
         modOk(m.e, m.dP, m.p - Integer(1L)) && modOk(m.e, m.dQ, m.q - Integer(1L)) && modOk(m.q, m.qInv, m.p);
}

}  // namespace

RsaKeyMaterial ImportRsaSerCryptoPP(const std::vector<uint8_t>& artifact, const std::string& requestedRole) {
  Tlv outer;
  try {
    outer = DecodeTlv(artifact, 0);
  } catch (const std::exception& e) {
    throw RsaSerError{"rsa-ser.der-syntax", "malformed_artifact", std::string("DER parse failed: ") + e.what()};
  }
  if (outer.nextOffset != artifact.size()) {
    throw RsaSerError{"rsa-ser.exact-consumption", "malformed_artifact", "trailing bytes after the top-level DER object"};
  }

  std::vector<Tlv> children;
  try {
    children = DecodeSequenceChildren(outer);
  } catch (const std::exception& e) {
    throw RsaSerError{"rsa-ser.der-syntax", "malformed_artifact", std::string("outer SEQUENCE parse failed: ") + e.what()};
  }

  std::string containerRole;
  Tlv algIdTlv, innerTlv;
  if (children.size() == 2 && children[1].tag == 0x03) {
    containerRole = "public";
    algIdTlv = children[0];
    innerTlv = children[1];
  } else if (children.size() == 3 && children[0].tag == 0x02 && children[2].tag == 0x04) {
    Integer version;
    try {
      version = DecodeIntegerTlv(children[0]);
    } catch (...) {
      throw RsaSerError{"rsa-ser.container", "malformed_artifact", "PrivateKeyInfo version field is not a valid INTEGER"};
    }
    if (version != Integer(0L)) {
      throw RsaSerError{"rsa-ser.container", "malformed_artifact", "PrivateKeyInfo version != 0 (multi-prime is outside the portable profile, D-053)"};
    }
    containerRole = "private";
    algIdTlv = children[1];
    innerTlv = children[2];
  } else {
    throw RsaSerError{"rsa-ser.container", "malformed_artifact", "valid DER instantiating neither SPKI nor PrivateKeyInfo"};
  }

  if (containerRole != requestedRole) {
    throw RsaSerError{"rsa-ser.role-container", "invalid_parameter",
                       "artifact instantiates a " + containerRole + " container but role=" + requestedRole + " was requested"};
  }

  std::vector<Tlv> algChildren;
  try {
    algChildren = DecodeSequenceChildren(algIdTlv);
  } catch (...) {
    throw RsaSerError{"rsa-ser.algorithm-id", "invalid_parameter", "AlgorithmIdentifier is not a well-formed SEQUENCE"};
  }
  if (algChildren.empty() || algChildren.size() > 2) {
    throw RsaSerError{"rsa-ser.algorithm-params", "invalid_parameter", "AlgorithmIdentifier has an unexpected number of elements"};
  }
  if (!IsRsaEncryptionOidTlv(algChildren[0])) {
    throw RsaSerError{"rsa-ser.algorithm-id", "invalid_parameter", "AlgorithmIdentifier.algorithm != rsaEncryption (D-053)"};
  }
  bool paramsOk = algChildren.size() == 1 || IsNullTlv(algChildren[1]);
  if (!paramsOk) {
    throw RsaSerError{"rsa-ser.algorithm-params", "invalid_parameter", "AlgorithmIdentifier.parameters is neither absent nor explicit NULL (D-053)"};
  }

  RsaKeyMaterial m;
  m.role = requestedRole;

  if (requestedRole == "public") {
    std::vector<uint8_t> innerBytes;
    try {
      innerBytes = DecodeBitStringWholeBytes(innerTlv);
    } catch (const std::exception& e) {
      throw RsaSerError{"rsa-ser.container", "malformed_artifact", std::string("RSAPublicKey BIT STRING malformed: ") + e.what()};
    }
    std::vector<Tlv> innerChildren;
    try {
      Tlv innerSeq = DecodeTlv(innerBytes, 0);
      innerChildren = DecodeSequenceChildren(innerSeq, 2);
      m.n = DecodeIntegerTlv(innerChildren[0]);
      m.e = DecodeIntegerTlv(innerChildren[1]);
    } catch (const std::exception& e) {
      throw RsaSerError{"rsa-ser.container", "malformed_artifact", std::string("RSAPublicKey inner structure malformed: ") + e.what()};
    }
    if (!CheckPublicValidity(m.n, m.e)) {
      throw RsaSerError{"rsa-ser.public-validity", "invalid_key", "public key fails C_math^public (n>=15, n odd, 3<=e<=n-1, e odd)"};
    }
    return m;
  }

  if (innerTlv.tag != 0x04) {
    throw RsaSerError{"rsa-ser.container", "malformed_artifact", "PrivateKeyInfo.privateKey is not an OCTET STRING"};
  }
  std::vector<Tlv> innerChildren;
  try {
    Tlv innerSeq = DecodeTlv(innerTlv.content, 0);
    innerChildren = DecodeSequenceChildren(innerSeq);
  } catch (const std::exception& e) {
    throw RsaSerError{"rsa-ser.container", "malformed_artifact", std::string("RSAPrivateKey inner structure malformed: ") + e.what()};
  }
  if (innerChildren.size() != 9) {
    throw RsaSerError{"rsa-ser.container", "malformed_artifact", "RSAPrivateKey is not two-prime (9 fields) -- multi-prime is outside the portable profile (D-053)"};
  }
  try {
    Integer version = DecodeIntegerTlv(innerChildren[0]);
    if (version != Integer(0L)) {
      throw RsaSerError{"rsa-ser.container", "malformed_artifact", "RSAPrivateKey version != 0"};
    }
    m.n = DecodeIntegerTlv(innerChildren[1]);
    m.e = DecodeIntegerTlv(innerChildren[2]);
    m.d = DecodeIntegerTlv(innerChildren[3]);
    m.p = DecodeIntegerTlv(innerChildren[4]);
    m.q = DecodeIntegerTlv(innerChildren[5]);
    m.dP = DecodeIntegerTlv(innerChildren[6]);
    m.dQ = DecodeIntegerTlv(innerChildren[7]);
    m.qInv = DecodeIntegerTlv(innerChildren[8]);
  } catch (const RsaSerError&) {
    throw;
  } catch (const std::exception& e) {
    throw RsaSerError{"rsa-ser.container", "malformed_artifact", std::string("RSAPrivateKey field malformed: ") + e.what()};
  }

  if (!CheckPrivateDomain(m)) {
    throw RsaSerError{"rsa-ser.private-domain", "invalid_key", "private key fails V_domain^RSA,2 (D-054)"};
  }
  if (!CheckPrivateRelations(m)) {
    throw RsaSerError{"rsa-ser.private-relations", "invalid_key", "private key fails V_rel^RSA,2 (D-054)"};
  }
  return m;
}

std::vector<uint8_t> ExportRsaSerCryptoPP(const RsaKeyMaterial& material) {
  if (material.role == "public") {
    auto inner = EncodeSequence({EncodeInteger(material.n), EncodeInteger(material.e)});
    return EncodeSequence({EncodeAlgorithmIdentifier(), EncodeBitStringWholeBytes(inner)});
  }
  auto inner = EncodeSequence({
      EncodeInteger(Integer(0L)),
      EncodeInteger(material.n),
      EncodeInteger(material.e),
      EncodeInteger(material.d),
      EncodeInteger(material.p),
      EncodeInteger(material.q),
      EncodeInteger(material.dP),
      EncodeInteger(material.dQ),
      EncodeInteger(material.qInv),
  });
  return EncodeSequence({EncodeInteger(Integer(0L)), EncodeAlgorithmIdentifier(), EncodeOctetString(inner)});
}

std::vector<uint8_t> NativeCryptoPPSpkiExport(const RsaKeyMaterial& material) {
  RSA::PublicKey pub;
  pub.Initialize(material.n, material.e);
  std::string out;
  pub.Save(StringSink(out).Ref());
  return std::vector<uint8_t>(out.begin(), out.end());
}

std::vector<uint8_t> NativeCryptoPPPkcs8Export(const RsaKeyMaterial& material) {
  RSA::PrivateKey priv;
  priv.Initialize(material.n, material.e, material.d, material.p, material.q, material.dP, material.dQ, material.qInv);
  std::string out;
  priv.Save(StringSink(out).Ref());
  return std::vector<uint8_t>(out.begin(), out.end());
}

bool NativeCryptoPPImportSucceeds(const std::vector<uint8_t>& artifact, const std::string& role) {
  try {
    StringStore store(artifact.data(), artifact.size());
    if (role == "public") {
      RSA::PublicKey pub;
      pub.Load(store);
    } else {
      RSA::PrivateKey priv;
      priv.Load(store);
    }
    return true;
  } catch (...) {
    return false;
  }
}

RsaKeyMaterial NativeCryptoPPImport(const std::vector<uint8_t>& artifact, const std::string& role) {
  // Genuinely native: RSA::PublicKey/PrivateKey::Load() (X509PublicKey/
  // PKCS8PrivateKey's own BERDecode machinery, traced in asn.cpp) does the
  // ENTIRE parse. This function's only job afterward is to read the
  // material back out via the class's own named accessors -- no byte of
  // this project's own DER walker or Accept_C is touched anywhere in this
  // call. Used exclusively by the native-only interop matrix.
  StringStore store(artifact.data(), artifact.size());
  RsaKeyMaterial m;
  m.role = role;
  if (role == "public") {
    RSA::PublicKey pub;
    pub.Load(store);
    m.n = pub.GetModulus();
    m.e = pub.GetPublicExponent();
  } else {
    RSA::PrivateKey priv;
    priv.Load(store);
    m.n = priv.GetModulus();
    m.e = priv.GetPublicExponent();
    m.d = priv.GetPrivateExponent();
    m.p = priv.GetPrime1();
    m.q = priv.GetPrime2();
    m.dP = priv.GetModPrime1PrivateExponent();
    m.dQ = priv.GetModPrime2PrivateExponent();
    m.qInv = priv.GetMultiplicativeInverseOfPrime2ModPrime1();
  }
  return m;
}

RsaKeyMaterial GenerateRsaSerKeyMaterial(int modulusBits) {
  AutoSeededRandomPool rng;
  RSA::PrivateKey priv;
  priv.GenerateRandomWithKeySize(rng, modulusBits);

  RsaKeyMaterial m;
  m.role = "private";
  m.n = priv.GetModulus();
  m.e = priv.GetPublicExponent();
  m.d = priv.GetPrivateExponent();
  m.p = priv.GetPrime1();
  m.q = priv.GetPrime2();
  m.dP = priv.GetModPrime1PrivateExponent();
  m.dQ = priv.GetModPrime2PrivateExponent();
  m.qInv = priv.GetMultiplicativeInverseOfPrime2ModPrime1();
  return m;
}

}  // namespace paper4
