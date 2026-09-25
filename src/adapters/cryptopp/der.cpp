#include "der.hpp"

#include <sstream>

using CryptoPP::Integer;

namespace paper4 {
namespace der {

const std::vector<uint8_t> RSA_ENCRYPTION_OID_CONTENT = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};

namespace {

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

}  // namespace

std::vector<uint8_t> EncodeTlv(uint8_t tag, const std::vector<uint8_t>& content) {
  std::vector<uint8_t> lenBytes = EncodeLength(content.size());
  std::vector<uint8_t> out;
  out.reserve(1 + lenBytes.size() + content.size());
  out.push_back(tag);
  out.insert(out.end(), lenBytes.begin(), lenBytes.end());
  out.insert(out.end(), content.begin(), content.end());
  return out;
}

DecodedTlv DecodeTlv(const std::vector<uint8_t>& buf, size_t offset) {
  if (offset >= buf.size()) throw DerError("unexpected end of buffer reading tag");
  uint8_t tag = buf[offset];
  if ((tag & 0x1f) == 0x1f) throw DerError("multi-byte tags are not supported by this profile");
  size_t pos = offset + 1;
  if (pos >= buf.size()) throw DerError("unexpected end of buffer reading length");
  uint8_t first = buf[pos];
  pos += 1;
  size_t len;
  if (first == 0x80) {
    throw DerError("indefinite length (BER, not DER)");
  } else if (first < 0x80) {
    len = first;
  } else {
    size_t numLenBytes = first & 0x7f;
    if (numLenBytes == 0 || numLenBytes > 4) throw DerError("unsupported long-form length");
    if (pos + numLenBytes > buf.size()) throw DerError("unexpected end of buffer reading long-form length");
    len = 0;
    for (size_t i = 0; i < numLenBytes; i++) {
      len = (len << 8) | buf[pos + i];
    }
    size_t lenStart = pos;
    pos += numLenBytes;
    if (len < 0x80) throw DerError("non-minimal long-form length (BER, not DER)");
    if (numLenBytes > 1 && buf[lenStart] == 0x00) throw DerError("non-minimal long-form length (leading zero)");
  }
  if (pos + len > buf.size()) throw DerError("declared length exceeds remaining buffer");
  std::vector<uint8_t> content(buf.begin() + static_cast<long>(pos), buf.begin() + static_cast<long>(pos + len));
  return DecodedTlv{tag, content, pos + len};
}

std::vector<uint8_t> EncodeInteger(const Integer& value) {
  if (value.IsNegative()) throw DerError("negative INTEGER not supported by this profile");
  if (value.IsZero()) return EncodeTlv(TAG_INTEGER, {0x00});
  size_t byteCount = static_cast<size_t>(value.MinEncodedSize(Integer::UNSIGNED));
  std::vector<uint8_t> bytes(byteCount);
  value.Encode(bytes.data(), byteCount, Integer::UNSIGNED);
  if (bytes[0] & 0x80) {
    std::vector<uint8_t> padded;
    padded.push_back(0x00);
    padded.insert(padded.end(), bytes.begin(), bytes.end());
    bytes = padded;
  }
  return EncodeTlv(TAG_INTEGER, bytes);
}

Integer DecodeInteger(const DecodedTlv& tlv) {
  if (tlv.tag != TAG_INTEGER) throw DerError("expected INTEGER, got a different tag");
  const auto& c = tlv.content;
  if (c.empty()) throw DerError("empty INTEGER content");
  if (c.size() > 1) {
    uint8_t b0 = c[0];
    uint8_t b1 = c[1];
    if (b0 == 0x00 && (b1 & 0x80) == 0) throw DerError("non-minimal INTEGER encoding (unnecessary leading 0x00)");
  }
  if (c[0] & 0x80) throw DerError("negative INTEGER not supported by this profile");
  return Integer(c.data(), c.size(), Integer::UNSIGNED);
}

std::vector<uint8_t> EncodeBitStringWholeBytes(const std::vector<uint8_t>& content) {
  std::vector<uint8_t> out;
  out.reserve(content.size() + 1);
  out.push_back(0x00);
  out.insert(out.end(), content.begin(), content.end());
  return EncodeTlv(TAG_BIT_STRING, out);
}

std::vector<uint8_t> DecodeBitStringWholeBytes(const DecodedTlv& tlv) {
  if (tlv.tag != TAG_BIT_STRING) throw DerError("expected BIT STRING, got a different tag");
  if (tlv.content.empty()) throw DerError("empty BIT STRING content (missing unused-bits octet)");
  if (tlv.content[0] != 0x00) throw DerError("BIT STRING has non-zero unused bits; not a whole-byte DER object");
  return std::vector<uint8_t>(tlv.content.begin() + 1, tlv.content.end());
}

std::vector<uint8_t> EncodeOctetString(const std::vector<uint8_t>& content) {
  return EncodeTlv(TAG_OCTET_STRING, content);
}

std::vector<uint8_t> DecodeOctetString(const DecodedTlv& tlv) {
  if (tlv.tag != TAG_OCTET_STRING) throw DerError("expected OCTET STRING, got a different tag");
  return tlv.content;
}

std::vector<uint8_t> EncodeNull() { return EncodeTlv(TAG_NULL, {}); }

bool IsNullTlv(const DecodedTlv& tlv) { return tlv.tag == TAG_NULL && tlv.content.empty(); }

std::vector<uint8_t> EncodeRsaEncryptionOid() { return EncodeTlv(TAG_OID, RSA_ENCRYPTION_OID_CONTENT); }

bool IsRsaEncryptionOidTlv(const DecodedTlv& tlv) {
  return tlv.tag == TAG_OID && tlv.content == RSA_ENCRYPTION_OID_CONTENT;
}

std::vector<uint8_t> EncodeSequence(const std::vector<std::vector<uint8_t>>& children) {
  size_t totalLen = 0;
  for (const auto& c : children) totalLen += c.size();
  std::vector<uint8_t> content;
  content.reserve(totalLen);
  for (const auto& c : children) content.insert(content.end(), c.begin(), c.end());
  return EncodeTlv(TAG_SEQUENCE, content);
}

std::vector<DecodedTlv> DecodeSequenceChildren(const DecodedTlv& tlv, int exactCount) {
  if (tlv.tag != TAG_SEQUENCE) throw DerError("expected SEQUENCE, got a different tag");
  std::vector<DecodedTlv> children;
  size_t offset = 0;
  while (offset < tlv.content.size()) {
    DecodedTlv child = DecodeTlv(tlv.content, offset);
    offset = child.nextOffset;
    children.push_back(child);
  }
  if (exactCount >= 0 && static_cast<int>(children.size()) != exactCount) {
    std::ostringstream oss;
    oss << "expected exactly " << exactCount << " SEQUENCE elements, got " << children.size();
    throw DerError(oss.str());
  }
  return children;
}

}  // namespace der
}  // namespace paper4
