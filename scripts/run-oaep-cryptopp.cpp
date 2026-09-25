// M1 vertical slice: RSA-OAEP x Crypto++, no mutations.
// Mirrors tests/oaep/webcrypto.test.ts's checklist exactly, plus a
// Crypto++-specific check: RNG injection is used normally (Crypto++'s OAEP
// requires an explicit RandomNumberGenerator&) but never exposed as a
// portable "seed" field -- this session's explicit requirement, protecting
// oaep.randomness directly.
//
// Build (pinned): weidai11/cryptopp, commit
// 782425901d36fe0944b16aae37801b8ec2fa9000 (Experimental_Evidence_Base
// sec:environment), e.g.:
//   g++ -std=c++17 -I<cryptopp_include> scripts/run-oaep-cryptopp.cpp \
//       src/adapters/cryptopp/oaep.cpp -L<cryptopp_lib> -lcryptopp \
//       -o run-oaep-cryptopp

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../src/adapters/cryptopp/oaep.hpp"
#include "osrng.h"
#include "rsa.h"

namespace {

bool contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

std::string extractField(const std::string& record, const std::string& key) {
  const std::string marker = "\"" + key + "\":\"";
  size_t start = record.find(marker);
  if (start == std::string::npos) return "";
  start += marker.size();
  size_t end = record.find('"', start);
  return record.substr(start, end - start);
}

int failures = 0;

void check(bool condition, const std::string& failMessage) {
  if (!condition) {
    std::fprintf(stderr, "FAILED: %s\n", failMessage.c_str());
    failures++;
  }
}

std::vector<uint8_t> textBytes(const std::string& s) {
  return std::vector<uint8_t>(s.begin(), s.end());
}

}  // namespace

int main() {
  using namespace paper4;
  using namespace CryptoPP;

  std::printf("=== M1 vertical slice: RSA-OAEP x Crypto++ ===\n\n");

  std::printf("--- key generation (RSA-3072, shared fixture) ---\n");
  const OaepKeyMaterial privMaterial = GenerateOaepKeyMaterial();
  OaepKeyMaterial pubMaterial = privMaterial;
  pubMaterial.declaredRole = "public";
  const OaepKeyMaterial otherPrivMaterial = GenerateOaepKeyMaterial();  // unrelated key, for the cross-key test
  check(privMaterial.modulusBits == OAEP_MODULUS_BITS, "generated key is not 3072 bits.");
  std::printf("PASS: RSA-3072 key pair generated.\n\n");

  // --- 1. Encrypt -> decrypt round trip ---
  std::printf("--- encrypt -> decrypt round trip ---\n");
  const std::vector<uint8_t> message = textBytes("the quick brown fox jumps over the lazy dog");
  {
    OaepEncryptRequest encReq;
    encReq.key = pubMaterial;
    encReq.plaintext = message;
    encReq.labelPresent = false;
    const std::string encRecord = OaepEncryptCryptoPP(encReq);
    check(contains(encRecord, "\"kind\":\"accept\""), "expected round-trip encrypt to succeed.");

    OaepDecryptRequest decReq;
    decReq.key = privMaterial;
    decReq.ciphertext = std::vector<uint8_t>();
    const std::string ctHex = extractField(encRecord, "ciphertextHex");
    for (size_t i = 0; i + 1 < ctHex.size(); i += 2) {
      decReq.ciphertext.push_back(static_cast<uint8_t>(std::stoi(ctHex.substr(i, 2), nullptr, 16)));
    }
    decReq.labelPresent = false;
    const std::string decRecord = OaepDecryptCryptoPP(decReq);
    check(contains(decRecord, "\"kind\":\"accept\""), "expected round-trip decrypt to succeed.");
    check(extractField(decRecord, "plaintextHex") ==
              [&] {
                std::string h;
                for (uint8_t b : message) {
                  char buf[3];
                  std::snprintf(buf, sizeof(buf), "%02x", b);
                  h += buf;
                }
                return h;
              }(),
          "round-trip plaintext does not match the original.");
  }
  if (failures == 0) std::printf("PASS: encrypt -> decrypt recovers the exact plaintext.\n\n");

  // --- 2. Message-length boundary ---
  std::printf("--- message-length boundary (318 accept / 319 reject) ---\n");
  {
    OaepEncryptRequest req318;
    req318.key = pubMaterial;
    req318.plaintext = std::vector<uint8_t>(OAEP_MAX_MESSAGE_LEN_BYTES, 0);
    req318.labelPresent = false;
    check(contains(OaepEncryptCryptoPP(req318), "\"kind\":\"accept\""), "expected mLen=318 to be accepted.");

    OaepEncryptRequest req319;
    req319.key = pubMaterial;
    req319.plaintext = std::vector<uint8_t>(OAEP_MAX_MESSAGE_LEN_BYTES + 1, 0);
    req319.labelPresent = false;
    const std::string rec319 = OaepEncryptCryptoPP(req319);
    check(contains(rec319, "\"errorClass\":\"invalid_parameter\"") && contains(rec319, "\"oaep.message\""),
          "expected mLen=319 to be rejected as invalid_parameter (oaep.message).");
  }
  if (failures == 0) std::printf("PASS: message-length boundary enforced correctly.\n\n");

  // --- 3. Ciphertext output is exactly 384 bytes ---
  std::printf("--- ciphertext output length (384 bytes) ---\n");
  {
    OaepEncryptRequest req;
    req.key = pubMaterial;
    req.plaintext = message;
    req.labelPresent = false;
    const std::string record = OaepEncryptCryptoPP(req);
    check(extractField(record, "ciphertextHex").size() == OAEP_K_BYTES * 2, "ciphertext is not exactly 384 bytes.");
  }
  if (failures == 0) std::printf("PASS: ciphertext output is exactly 384 bytes.\n\n");

  // --- 4. Label absent === label empty; non-empty rejected ---
  std::printf("--- label absent/empty equivalence, non-empty rejection ---\n");
  {
    OaepEncryptRequest absentReq;
    absentReq.key = pubMaterial;
    absentReq.plaintext = message;
    absentReq.labelPresent = false;
    OaepEncryptRequest emptyReq;
    emptyReq.key = pubMaterial;
    emptyReq.plaintext = message;
    emptyReq.labelPresent = true;
    emptyReq.label = {};
    check(contains(OaepEncryptCryptoPP(absentReq), "\"kind\":\"accept\""), "expected absent label to be accepted.");
    check(contains(OaepEncryptCryptoPP(emptyReq), "\"kind\":\"accept\""), "expected empty label to be accepted.");

    OaepEncryptRequest nonEmptyReq;
    nonEmptyReq.key = pubMaterial;
    nonEmptyReq.plaintext = message;
    nonEmptyReq.labelPresent = true;
    nonEmptyReq.label = {0x01, 0x02};
    const std::string rec = OaepEncryptCryptoPP(nonEmptyReq);
    check(contains(rec, "\"errorClass\":\"invalid_parameter\"") && contains(rec, "\"oaep.label\""),
          "expected non-empty label to be rejected as invalid_parameter (oaep.label).");
  }
  if (failures == 0) std::printf("PASS: label absent/empty equivalence and non-empty rejection both correct.\n\n");

  // --- 5. Key role -> invalid_key ---
  std::printf("--- key role mismatch -> invalid_key ---\n");
  {
    OaepEncryptRequest badEncReq;
    badEncReq.key = privMaterial;  // wrong role for encrypt
    badEncReq.plaintext = message;
    badEncReq.labelPresent = false;
    const std::string rec1 = OaepEncryptCryptoPP(badEncReq);
    check(contains(rec1, "\"errorClass\":\"invalid_key\"") && contains(rec1, "\"oaep.key\""),
          "expected encrypt with a private-declared key to be rejected as invalid_key.");

    OaepDecryptRequest badDecReq;
    badDecReq.key = pubMaterial;  // wrong role for decrypt
    badDecReq.ciphertext = std::vector<uint8_t>(OAEP_K_BYTES, 0);
    badDecReq.labelPresent = false;
    const std::string rec2 = OaepDecryptCryptoPP(badDecReq);
    check(contains(rec2, "\"errorClass\":\"invalid_key\"") && contains(rec2, "\"oaep.key\""),
          "expected decrypt with a public-declared key to be rejected as invalid_key.");
  }
  if (failures == 0) std::printf("PASS: key-role mismatch rejected in both directions.\n\n");

  // --- 6. modulus out of profile -> invalid_parameter ---
  std::printf("--- non-3072-bit modulus -> invalid_parameter ---\n");
  {
    AutoSeededRandomPool rng;
    RSA::PrivateKey smallPrivKey;
    smallPrivKey.GenerateRandomWithKeySize(rng, 2048);

    OaepKeyMaterial smallPub;
    smallPub.declaredRole = "public";
    smallPub.modulus = smallPrivKey.GetModulus();
    smallPub.publicExponent = smallPrivKey.GetPublicExponent();
    smallPub.modulusBits = smallPrivKey.GetModulus().BitCount();

    OaepEncryptRequest req;
    req.key = smallPub;
    req.plaintext = message;
    req.labelPresent = false;
    const std::string rec = OaepEncryptCryptoPP(req);
    check(contains(rec, "\"errorClass\":\"invalid_parameter\"") && contains(rec, "\"oaep.modulus\""),
          "expected a 2048-bit key to be rejected as invalid_parameter (oaep.modulus).");
  }
  if (failures == 0) std::printf("PASS: non-3072-bit modulus rejected as invalid_parameter.\n\n");

  // --- 7. Corrupted / truncated / lengthened / unrelated-key ciphertext -> decryption_error ---
  std::printf("--- corrupted/truncated/lengthened/unrelated-key ciphertext -> decryption_error ---\n");
  {
    OaepEncryptRequest encReq;
    encReq.key = pubMaterial;
    encReq.plaintext = message;
    encReq.labelPresent = false;
    const std::string encRecord = OaepEncryptCryptoPP(encReq);
    const std::string ctHex = extractField(encRecord, "ciphertextHex");
    std::vector<uint8_t> ciphertext;
    for (size_t i = 0; i + 1 < ctHex.size(); i += 2) {
      ciphertext.push_back(static_cast<uint8_t>(std::stoi(ctHex.substr(i, 2), nullptr, 16)));
    }

    // corrupted (single flipped byte)
    std::vector<uint8_t> corrupted = ciphertext;
    corrupted[0] ^= 0xff;
    OaepDecryptRequest req1;
    req1.key = privMaterial;
    req1.ciphertext = corrupted;
    req1.labelPresent = false;
    const std::string rec1 = OaepDecryptCryptoPP(req1);
    check(contains(rec1, "\"errorClass\":\"decryption_error\""), "corrupted ciphertext did not yield decryption_error.");

    // truncated
    OaepDecryptRequest req2;
    req2.key = privMaterial;
    req2.ciphertext = std::vector<uint8_t>(ciphertext.begin(), ciphertext.begin() + 10);
    req2.labelPresent = false;
    const std::string rec2 = OaepDecryptCryptoPP(req2);
    check(contains(rec2, "\"errorClass\":\"decryption_error\""), "truncated ciphertext did not yield decryption_error.");
    check(!contains(rec2, "\"errorClass\":\"invalid_parameter\""),
          "CRITICAL: truncated ciphertext must NOT be invalid_parameter (v0.6 D-034).");

    // lengthened
    std::vector<uint8_t> lengthened = ciphertext;
    lengthened.insert(lengthened.end(), 10, 0);
    OaepDecryptRequest req3;
    req3.key = privMaterial;
    req3.ciphertext = lengthened;
    req3.labelPresent = false;
    const std::string rec3 = OaepDecryptCryptoPP(req3);
    check(contains(rec3, "\"errorClass\":\"decryption_error\""), "lengthened ciphertext did not yield decryption_error.");
    check(!contains(rec3, "\"errorClass\":\"invalid_parameter\""),
          "CRITICAL: lengthened ciphertext must NOT be invalid_parameter (v0.6 D-034).");

    // unrelated key
    OaepDecryptRequest req4;
    req4.key = otherPrivMaterial;
    req4.ciphertext = ciphertext;
    req4.labelPresent = false;
    const std::string rec4 = OaepDecryptCryptoPP(req4);
    check(contains(rec4, "\"errorClass\":\"decryption_error\""), "unrelated-key decrypt did not yield decryption_error.");
  }
  if (failures == 0) {
    std::printf(
        "PASS: corrupted/truncated/lengthened/unrelated-key ciphertext all yield decryption_error -- "
        "Crypto++'s two-tier native error surface (thrown InvalidArgument for length mismatch vs. "
        "DecodingResult.isValidCoding=false for decode failure) is fully hidden.\n\n");
  }

  // --- 8. Non-determinism control ---
  std::printf("--- CONTROL: two encryptions of identical (K,M) differ, both still decrypt to M ---\n");
  {
    OaepEncryptRequest req;
    req.key = pubMaterial;
    req.plaintext = message;
    req.labelPresent = false;
    const std::string r1 = OaepEncryptCryptoPP(req);
    const std::string r2 = OaepEncryptCryptoPP(req);
    const std::string ct1 = extractField(r1, "ciphertextHex");
    const std::string ct2 = extractField(r2, "ciphertextHex");
    check(ct1 != ct2, "CONTROL FAILED: two encryptions of identical (K,M) produced the SAME ciphertext -- "
                       "this would undermine the R_byte=N/A argument for OAEP, not confirm it.");
  }
  if (failures == 0) {
    std::printf(
        "PASS (control, not a conformance obligation): ciphertexts differ, confirming R_byte=N/A for OAEP (D-033) "
        "empirically, not just by design intent.\n\n");
  }

  // --- 9. oaep.randomness non-exposure check ---
  std::printf("--- oaep.randomness non-exposure check ---\n");
  {
    OaepEncryptRequest req;
    req.key = pubMaterial;
    req.plaintext = message;
    req.labelPresent = false;
    const std::string record = OaepEncryptCryptoPP(req);
    // This adapter DOES use AutoSeededRandomPool internally (Crypto++'s
    // OAEP requires an explicit RandomNumberGenerator&) -- but that
    // capability must never surface as a portable contractual field. This
    // check confirms the evidence record contains no seed/rng-shaped key
    // and that oaep.randomness never appears as PER-REQUEST ACCEPT EVIDENCE
    // implying portable randomness control (matching the WebCrypto adapter's
    // identical omission). oaep.randomness remains a legitimate frozen
    // ClauseID (v0.6) -- it is the clause OAEP-RANDOMNESS-INTERFACE-LEAK
    // (Gamma_0^OAEP) will exercise in M2, likely as an API-surface/manifest
    // property rather than a per-request runtime outcome, per v0.6's own
    // methodological note. This check is narrower than "the clause must
    // never appear anywhere" -- it only confirms this M1 baseline's accept
    // outcomes don't fabricate false portable-capability evidence.
    check(!contains(record, "\"seed"), "EvidenceRecord input unexpectedly exposes a seed field.");
    check(!contains(record, "\"rng"), "EvidenceRecord input unexpectedly exposes an rng field.");
    check(!contains(record, "randomness\":true") && !contains(record, "\"randomness\":\""),
          "EvidenceRecord unexpectedly exposes a randomness-control field.");
    check(!contains(record, "\"oaep.randomness\""),
          "oaep.randomness must not appear in this M1 baseline's accept-outcome clauseIds as if it were "
          "positive portable-capability evidence -- RNG injection is used internally but is not a portable "
          "capability (D-033).");
  }
  if (failures == 0) {
    std::printf(
        "PASS: RNG injection used internally, never exposed as per-request portable accept evidence -- "
        "protects the D-033 boundary directly, not just by omission.\n\n");
  }

  std::printf("=== M1 slice complete for RSA-OAEP x Crypto++: %s ===\n",
              failures == 0 ? "ALL CHECKS PASSED" : (std::to_string(failures) + " CHECK(S) FAILED").c_str());
  return failures == 0 ? 0 : 1;
}
