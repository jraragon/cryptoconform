// M1 vertical slice: RSA-PSS x Crypto++, no mutations.
// Mirrors tests/pss/webcrypto.test.ts's checklist, plus this session's four
// explicit Crypto++ vigilance points:
//   1. declaredRole decoupling (same pattern as OAEP) -- invalid_key testable
//      despite RSASS<PSS,H>::Signer/Verifier's compile-time role enforcement.
//   2. saltLength=32 confirmed empirically from a real produced signature
//      by reversing RSAVP1 + EMSA-PSS MGF1 unmasking, rather than inferred
//      from documentation or an inaccessible SaltLen() accessor.
//   3. Accept_C admission strictly separated from cryptographic verification:
//      everything violating C_pre^PSS -> {unsupported, invalid_key,
//      invalid_parameter}; everything past that (corrupted/truncated/
//      lengthened/wrong-key) -> verified(false), no invented error class.
//   4. A dedicated D-046 regression guard: fails loudly if anyone ever adds
//      a pre-validation |signature|!=384 -> invalid_parameter.
//
// Build (pinned): weidai11/cryptopp, commit
// 782425901d36fe0944b16aae37801b8ec2fa9000 (Experimental Evidence Base
// sec:environment), e.g.:
//   g++ -std=c++17 -I<cryptopp_include> scripts/run-pss-cryptopp.cpp \
//       src/adapters/cryptopp/pss.cpp -L<cryptopp_lib> -lcryptopp \
//       -o run-pss-cryptopp

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../src/adapters/cryptopp/pss.hpp"
#include "osrng.h"
#include "rsa.h"

namespace {

std::vector<uint8_t> textBytes(const std::string& s) {
  return std::vector<uint8_t>(s.begin(), s.end());
}

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

}  // namespace

int main() {
  using namespace paper4;
  using namespace CryptoPP;

  std::printf("=== M1 vertical slice: RSA-PSS x Crypto++ ===\n\n");

  std::printf("--- key generation (RSA-3072, shared fixture) ---\n");
  const PssKeyMaterial privMaterial = GeneratePssKeyMaterial();
  PssKeyMaterial pubMaterial = privMaterial;
  pubMaterial.declaredRole = "public";
  const PssKeyMaterial otherPrivMaterial = GeneratePssKeyMaterial();  // unrelated key
  PssKeyMaterial otherPubMaterial = otherPrivMaterial;
  otherPubMaterial.declaredRole = "public";
  check(privMaterial.modulusBits == PSS_MODULUS_BITS, "generated key is not 3072 bits.");
  std::printf("PASS: RSA-3072 key pair generated.\n\n");

  const std::vector<uint8_t> message = textBytes("the quick brown fox jumps over the lazy dog");

  // --- 0. saltLength=32 empirical confirmation (vigilance point #2) ---
  // Requires a REAL signature, so this runs after keygen and one sign call,
  // ahead of the round-trip test below (which reuses this same signature).
  std::printf("--- saltLength=32 empirical confirmation (reversing RSAVP1+MGF1 on a real signature, not citing docs) ---\n");
  PssSignRequest saltProbeReq;
  saltProbeReq.key = privMaterial;
  saltProbeReq.message = message;
  const std::string saltProbeRecord = PssSignCryptoPP(saltProbeReq);
  check(contains(saltProbeRecord, "\"kind\":\"accept\""), "expected the salt-length probe sign to succeed.");
  const std::vector<uint8_t> saltProbeSignature = fromHex(extractField(saltProbeRecord, "signatureHex"));
  try {
    const size_t saltLen = PssSaltLenBytes(pubMaterial, saltProbeSignature);
    check(saltLen == PSS_SALT_LEN_BYTES,
          "empirically recovered salt length does not equal 32 -- the standard PSS type's actual embedded salt no "
          "longer matches the portable profile.");
    if (failures == 0) {
      std::printf("PASS: manually reversed RSAVP1+EMSA-PSS unmasking recovers a %zu-byte salt from a REAL signature -- "
                   "empirical measurement, not a config citation.\n\n",
                   saltLen);
    }
  } catch (const std::exception& e) {
    check(false, std::string("PssSaltLenBytes threw: ") + e.what());
  }

  // --- 1. Sign -> verify round trip ---
  std::printf("--- sign -> verify round trip ---\n");
  PssSignRequest signReq;
  signReq.key = privMaterial;
  signReq.message = message;
  const std::string signRecord = PssSignCryptoPP(signReq);
  check(contains(signRecord, "\"kind\":\"accept\""), "expected sign to succeed.");
  const std::vector<uint8_t> signature = fromHex(extractField(signRecord, "signatureHex"));
  check(signature.size() == PSS_K_BYTES, "signature is not exactly 384 bytes.");

  PssVerifyRequest verifyReq;
  verifyReq.key = pubMaterial;
  verifyReq.message = message;
  verifyReq.signature = signature;
  const std::string verifyRecord = PssVerifyCryptoPP(verifyReq);
  check(contains(verifyRecord, "\"kind\":\"verified\"") && contains(verifyRecord, "\"valid\":true"),
        "expected round-trip verify to be valid.");
  if (failures == 0) std::printf("PASS: sign -> verify round trip yields a valid signature.\n\n");

  // --- 2. Corrupted / truncated / lengthened / wrong-key -> verified(false), NEVER reject ---
  std::printf("--- corrupted/truncated/lengthened/wrong-key signature -> verified(false), never reject ---\n");
  {
    std::vector<uint8_t> corrupted = signature;
    corrupted[0] ^= 0xff;
    PssVerifyRequest r1;
    r1.key = pubMaterial;
    r1.message = message;
    r1.signature = corrupted;
    const std::string rec1 = PssVerifyCryptoPP(r1);
    check(contains(rec1, "\"kind\":\"verified\"") && contains(rec1, "\"valid\":false"),
          "corrupted signature did not yield verified(false).");
    check(!contains(rec1, "\"kind\":\"reject\""), "CRITICAL: corrupted signature must never yield reject.");

    PssVerifyRequest r2;
    r2.key = pubMaterial;
    r2.message = message;
    r2.signature = std::vector<uint8_t>(signature.begin(), signature.begin() + 10);  // truncated
    const std::string rec2 = PssVerifyCryptoPP(r2);
    check(contains(rec2, "\"kind\":\"verified\"") && contains(rec2, "\"valid\":false"),
          "truncated signature did not yield verified(false).");
    check(!contains(rec2, "\"kind\":\"reject\""),
          "CRITICAL (D-046): truncated signature must never yield reject/invalid_parameter.");

    std::vector<uint8_t> lengthened = signature;
    lengthened.insert(lengthened.end(), 10, 0);
    PssVerifyRequest r3;
    r3.key = pubMaterial;
    r3.message = message;
    r3.signature = lengthened;
    const std::string rec3 = PssVerifyCryptoPP(r3);
    check(contains(rec3, "\"kind\":\"verified\"") && contains(rec3, "\"valid\":false"),
          "lengthened signature did not yield verified(false).");
    check(!contains(rec3, "\"kind\":\"reject\""),
          "CRITICAL (D-046): lengthened signature must never yield reject/invalid_parameter.");

    PssVerifyRequest r4;
    r4.key = otherPubMaterial;  // unrelated key
    r4.message = message;
    r4.signature = signature;
    const std::string rec4 = PssVerifyCryptoPP(r4);
    check(contains(rec4, "\"kind\":\"verified\"") && contains(rec4, "\"valid\":false"),
          "wrong-key verification did not yield verified(false).");
  }
  if (failures == 0) {
    std::printf(
        "PASS: corrupted/truncated/lengthened/wrong-key signatures all yield verified(false), never reject.\n\n");
  }

  // --- 3. Key role -> invalid_key ---
  std::printf("--- key role mismatch -> invalid_key ---\n");
  {
    PssSignRequest badSignReq;
    badSignReq.key = pubMaterial;  // wrong role for sign
    badSignReq.message = message;
    const std::string rec1 = PssSignCryptoPP(badSignReq);
    check(contains(rec1, "\"errorClass\":\"invalid_key\"") && contains(rec1, "\"pss.key\""),
          "expected sign with a public-declared key to be rejected as invalid_key.");

    PssVerifyRequest badVerifyReq;
    badVerifyReq.key = privMaterial;  // wrong role for verify
    badVerifyReq.message = message;
    badVerifyReq.signature = signature;
    const std::string rec2 = PssVerifyCryptoPP(badVerifyReq);
    check(contains(rec2, "\"errorClass\":\"invalid_key\"") && contains(rec2, "\"pss.key\""),
          "expected verify with a private-declared key to be rejected as invalid_key.");
  }
  if (failures == 0) std::printf("PASS: key-role mismatch rejected in both directions.\n\n");

  // --- 4. modulus out of profile -> invalid_parameter ---
  std::printf("--- non-3072-bit modulus -> invalid_parameter ---\n");
  {
    AutoSeededRandomPool rng;
    RSA::PrivateKey smallPrivKey;
    smallPrivKey.GenerateRandomWithKeySize(rng, 2048);

    PssKeyMaterial smallPriv;
    smallPriv.declaredRole = "private";
    smallPriv.modulus = smallPrivKey.GetModulus();
    smallPriv.publicExponent = smallPrivKey.GetPublicExponent();
    smallPriv.privateExponent = smallPrivKey.GetPrivateExponent();
    smallPriv.modulusBits = smallPrivKey.GetModulus().BitCount();

    PssSignRequest req;
    req.key = smallPriv;
    req.message = message;
    const std::string rec = PssSignCryptoPP(req);
    check(contains(rec, "\"errorClass\":\"invalid_parameter\"") && contains(rec, "\"pss.modulus\""),
          "expected a 2048-bit key to be rejected as invalid_parameter (pss.modulus).");
  }
  if (failures == 0) std::printf("PASS: non-3072-bit modulus rejected as invalid_parameter.\n\n");

  // --- 5. Non-determinism control ---
  std::printf("--- CONTROL: two signatures of identical (K,M) differ, both still verify true ---\n");
  {
    PssSignRequest req;
    req.key = privMaterial;
    req.message = message;
    const std::string r1 = PssSignCryptoPP(req);
    const std::string r2 = PssSignCryptoPP(req);
    const std::string sig1Hex = extractField(r1, "signatureHex");
    const std::string sig2Hex = extractField(r2, "signatureHex");
    check(sig1Hex != sig2Hex, "CONTROL FAILED: two signatures of identical (K,M) produced the SAME bytes.");

    PssVerifyRequest v1;
    v1.key = pubMaterial;
    v1.message = message;
    v1.signature = fromHex(sig1Hex);
    PssVerifyRequest v2;
    v2.key = pubMaterial;
    v2.message = message;
    v2.signature = fromHex(sig2Hex);
    check(contains(PssVerifyCryptoPP(v1), "\"valid\":true"), "signature 1 did not verify true.");
    check(contains(PssVerifyCryptoPP(v2), "\"valid\":true"), "signature 2 did not verify true.");
  }
  if (failures == 0) {
    std::printf(
        "PASS (control, not a conformance obligation): signatures differ (random salt), both still verify true -- "
        "material evidence for R_byte=N/A on PSS.\n\n");
  }

  // --- 6. D-046 regression guard: dedicated, explicit ---
  std::printf("--- D-046 REGRESSION GUARD: |signature|!=384 must NEVER become invalid_parameter ---\n");
  {
    PssVerifyRequest shortReq;
    shortReq.key = pubMaterial;
    shortReq.message = message;
    shortReq.signature = std::vector<uint8_t>(10, 0);
    const std::string shortRec = PssVerifyCryptoPP(shortReq);
    check(contains(shortRec, "\"kind\":\"verified\""), "D-046 VIOLATION: a 10-byte signature was not routed to Verify's own result domain.");
    check(!contains(shortRec, "\"errorClass\":\"invalid_parameter\""),
          "D-046 VIOLATION: a wrong-length signature was classified as invalid_parameter -- "
          "this contradicts RFC 8017 Sec.8.1.2 Step 1 directly.");

    PssVerifyRequest emptyReq;
    emptyReq.key = pubMaterial;
    emptyReq.message = message;
    emptyReq.signature = {};
    const std::string emptyRec = PssVerifyCryptoPP(emptyReq);
    check(contains(emptyRec, "\"kind\":\"verified\""), "D-046 VIOLATION: an empty signature was not routed to Verify's own result domain.");
    check(!contains(emptyRec, "\"errorClass\":\"invalid_parameter\""),
          "D-046 VIOLATION: an empty signature was classified as invalid_parameter.");
  }
  if (failures == 0) {
    std::printf("PASS: D-046 respected -- wrong-length signatures never intercepted as invalid_parameter.\n\n");
  }

  std::printf("=== M1 slice complete for RSA-PSS x Crypto++: %s ===\n",
              failures == 0 ? "ALL CHECKS PASSED" : (std::to_string(failures) + " CHECK(S) FAILED").c_str());
  return failures == 0 ? 0 : 1;
}
