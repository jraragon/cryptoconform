// M1 vertical slice: HKDF x Crypto++, no mutations.
// See Experimental_Evidence_Base v0.2, sec:m1-slice; mirrors
// scripts/run-hkdf-webcrypto.ts and scripts/RunHkdfBouncyCastle.java (same
// KAT, same D-068 boundary checks, same evidence-record shape) so all three
// backends' results are directly comparable. Extended to full coverage
// parity (L=8160/L=8161/salt-triple-equivalence) when closing the HKDF
// cross-provider baseline -- previously this runner only had KAT + L=0.
//
// Build (pinned): weidai11/cryptopp, commit
// 782425901d36fe0944b16aae37801b8ec2fa9000 (master, NOT the CRYPTOPP_8_9_0
// tag -- see Experimental_Evidence_Base v0.2, sec:environment for why).
// Build-verified in this environment, e.g.:
//   g++ -std=c++17 -I<cryptopp_include> scripts/run-hkdf-cryptopp.cpp \
//       src/adapters/cryptopp/hkdf.cpp -L<cryptopp_lib> -lcryptopp \
//       -o run-hkdf-cryptopp

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../src/adapters/cryptopp/hkdf.hpp"

namespace {

std::vector<uint8_t> fromHex(const std::string& hex) {
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}

bool contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

}  // namespace

int main() {
  using namespace paper4;

  std::printf("=== M1 vertical slice: HKDF x Crypto++ ===\n\n");

  // --- 1. RFC 5869 Appendix A.1, Test Case 1 (same vector as the WebCrypto slice) ---
  std::printf("--- RFC 5869 Test Case 1 (KAT) ---\n");
  const std::string expectedOkmHex =
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5b"
      "f34007208d5b887185865";

  HkdfRequest kat;
  kat.ikm = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  kat.salt = fromHex("000102030405060708090a0b0c");
  kat.saltPresent = true;
  kat.info = fromHex("f0f1f2f3f4f5f6f7f8f9");
  kat.length = 42;

  const std::string katRecord = HkdfCryptoPP(kat);
  std::printf("%s\n\n", katRecord.c_str());

  if (!contains(katRecord, "\"kind\":\"accept\"")) {
    std::fprintf(stderr, "FAILED: expected acceptance.\n");
    return 1;
  }
  if (!contains(katRecord, expectedOkmHex)) {
    std::fprintf(stderr, "KAT MISMATCH: expected OKM %s not found in record.\n",
                 expectedOkmHex.c_str());
    return 1;
  }
  std::printf(
      "PASS: Crypto++ realization matches RFC 5869 Test Case 1 exactly.\n\n");

  // --- 2. D-068 boundary sanity check ---
  std::printf("--- D-068 boundary sanity check (L=0) ---\n");
  HkdfRequest zeroLength = kat;
  zeroLength.length = 0;
  const std::string zeroRecord = HkdfCryptoPP(zeroLength);
  std::printf("%s\n\n", zeroRecord.c_str());

  if (!contains(zeroRecord, "\"kind\":\"reject\"") ||
      !contains(zeroRecord, "\"errorClass\":\"invalid_parameter\"")) {
    std::fprintf(stderr, "FAILED: expected L=0 to be rejected as invalid_parameter.\n");
    return 1;
  }
  std::printf("PASS: D-068 lower bound enforced by the SDK adapter.\n\n");

  // --- 3. D-068 boundary: L=8160 (exact upper bound, must accept) ---
  std::printf("--- D-068 boundary check (L=8160, exact upper bound) ---\n");
  HkdfRequest maxLength = kat;
  maxLength.length = 8160;
  const std::string maxRecord = HkdfCryptoPP(maxLength);
  std::printf("outcome.kind=%s, record length=%zu chars\n\n",
              contains(maxRecord, "\"kind\":\"accept\"") ? "accept" : "reject",
              maxRecord.size());

  if (!contains(maxRecord, "\"kind\":\"accept\"")) {
    std::fprintf(stderr, "FAILED: expected L=8160 (exact upper bound) to be accepted.\n");
    return 1;
  }
  std::printf("PASS: L=8160 (exact D-068 upper bound) accepted.\n\n");

  // --- 4. D-068 boundary: L=8161 (one past upper bound, must reject) ---
  std::printf("--- D-068 boundary check (L=8161, one past upper bound) ---\n");
  HkdfRequest overMaxLength = kat;
  overMaxLength.length = 8161;
  const std::string overMaxRecord = HkdfCryptoPP(overMaxLength);
  std::printf("%s\n\n", overMaxRecord.c_str());

  if (!contains(overMaxRecord, "\"kind\":\"reject\"") ||
      !contains(overMaxRecord, "\"errorClass\":\"invalid_parameter\"")) {
    std::fprintf(stderr, "FAILED: expected L=8161 to be rejected as invalid_parameter.\n");
    return 1;
  }
  std::printf("PASS: D-068 upper bound enforced by the SDK adapter (L=8161 rejected).\n\n");

  // --- 5. Absent salt vs. explicit empty salt vs. explicit HashLen-zero-byte
  //         salt: contractual triple-equivalence check, same three cases as
  //         the WebCrypto and Bouncy Castle runners, for coverage parity. ---
  std::printf("--- absent-salt vs empty-salt vs explicit-zero-salt equivalence ---\n");
  HkdfRequest absentSalt;
  absentSalt.ikm = kat.ikm;
  absentSalt.saltPresent = false;
  absentSalt.info = kat.info;
  absentSalt.length = 42;

  HkdfRequest emptySalt = absentSalt;
  emptySalt.saltPresent = true;
  emptySalt.salt = {};  // explicit zero-length, distinct from saltPresent=false

  HkdfRequest explicitZeroSalt = absentSalt;
  explicitZeroSalt.saltPresent = true;
  explicitZeroSalt.salt = std::vector<uint8_t>(32, 0);  // HashLen = 32 for SHA-256

  const std::string absentRecord = HkdfCryptoPP(absentSalt);
  const std::string emptyRecord = HkdfCryptoPP(emptySalt);
  const std::string explicitZeroRecord = HkdfCryptoPP(explicitZeroSalt);

  std::printf("absent salt:         %s\n", absentRecord.c_str());
  std::printf("empty salt:          %s\n", emptyRecord.c_str());
  std::printf("explicit zero salt:  %s\n\n", explicitZeroRecord.c_str());

  if (!contains(absentRecord, "\"kind\":\"accept\"") ||
      !contains(emptyRecord, "\"kind\":\"accept\"") ||
      !contains(explicitZeroRecord, "\"kind\":\"accept\"")) {
    std::fprintf(stderr, "FAILED: expected all three salt representations to be accepted.\n");
    return 1;
  }

  auto extractOkm = [](const std::string& record) -> std::string {
    const std::string key = "\"okmHex\":\"";
    size_t start = record.find(key);
    if (start == std::string::npos) return "";
    start += key.size();
    size_t end = record.find('"', start);
    return record.substr(start, end - start);
  };

  const std::string absentOkm = extractOkm(absentRecord);
  const std::string emptyOkm = extractOkm(emptyRecord);
  const std::string explicitZeroOkm = extractOkm(explicitZeroRecord);

  if (absentOkm.empty() || absentOkm != emptyOkm || emptyOkm != explicitZeroOkm) {
    std::fprintf(stderr,
                 "FAILED: absent/empty/explicit-zero-byte salt OKMs are not all identical "
                 "(absent=%s empty=%s explicitZero=%s).\n",
                 absentOkm.c_str(), emptyOkm.c_str(), explicitZeroOkm.c_str());
    return 1;
  }
  std::printf(
      "PASS: absent salt, empty salt, and explicit HashLen-zero-byte salt all "
      "yield an identical OKM for this backend.\n\n");

  std::printf(
      "=== M1 slice complete for HKDF x Crypto++: ALL CHECKS PASSED ===\n");
  return 0;
}
