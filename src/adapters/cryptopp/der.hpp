// Minimal DER primitives for RSA-ser, C++ port of src/contract/der.ts.
// NOT a general ASN.1/BER library -- deliberately scoped to exactly what
// the frozen portable profile requires. Independently reimplemented from
// the TypeScript version (not shared code), and DELIBERATELY NOT built on
// top of Crypto++'s own BERDecode/DEREncode machinery -- this is the
// adapter's OWN parser, so Accept_C is never delegated to Crypto++'s
// native decode path (this session's explicit requirement, mirroring the
// discipline already applied to the WebCrypto adapter).
#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "integer.h"

namespace paper4 {
namespace der {

constexpr uint8_t TAG_INTEGER = 0x02;
constexpr uint8_t TAG_BIT_STRING = 0x03;
constexpr uint8_t TAG_OCTET_STRING = 0x04;
constexpr uint8_t TAG_NULL = 0x05;
constexpr uint8_t TAG_OID = 0x06;
constexpr uint8_t TAG_SEQUENCE = 0x30;

extern const std::vector<uint8_t> RSA_ENCRYPTION_OID_CONTENT;

class DerError : public std::runtime_error {
 public:
  explicit DerError(const std::string& msg) : std::runtime_error(msg) {}
};

struct DecodedTlv {
  uint8_t tag;
  std::vector<uint8_t> content;
  size_t nextOffset;
};

std::vector<uint8_t> EncodeTlv(uint8_t tag, const std::vector<uint8_t>& content);
DecodedTlv DecodeTlv(const std::vector<uint8_t>& buf, size_t offset);

std::vector<uint8_t> EncodeInteger(const CryptoPP::Integer& value);
CryptoPP::Integer DecodeInteger(const DecodedTlv& tlv);

std::vector<uint8_t> EncodeBitStringWholeBytes(const std::vector<uint8_t>& content);
std::vector<uint8_t> DecodeBitStringWholeBytes(const DecodedTlv& tlv);

std::vector<uint8_t> EncodeOctetString(const std::vector<uint8_t>& content);
std::vector<uint8_t> DecodeOctetString(const DecodedTlv& tlv);

std::vector<uint8_t> EncodeNull();
bool IsNullTlv(const DecodedTlv& tlv);

std::vector<uint8_t> EncodeRsaEncryptionOid();
bool IsRsaEncryptionOidTlv(const DecodedTlv& tlv);

std::vector<uint8_t> EncodeSequence(const std::vector<std::vector<uint8_t>>& children);

std::vector<DecodedTlv> DecodeSequenceChildren(const DecodedTlv& tlv, int exactCount = -1);

}  // namespace der
}  // namespace paper4
