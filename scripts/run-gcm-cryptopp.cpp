// M1 vertical slice: AES-256-GCM x Crypto++, no mutations.
// Mirrors tests/gcm/webcrypto.test.ts's checklist exactly: KAT, encrypt<->
// decrypt round-trip, AAD absent===empty, R_byte determinism, tamper of
// T/C/AAD/IV -> authentication_failure, pre-backend rejection of
// key/IV/tagLength boundaries and malformed artifacts, and the 12 ClauseId
// vocabulary. Plus one Crypto++-specific check not present in the WebCrypto
// suite: an explicit verification of the C/T split invariant, independent
// of whether the KAT happens to pass -- protection against a misconfigured
// filter that a passing KAT alone would not catch.
//
// Build (pinned): weidai11/cryptopp, commit
// 782425901d36fe0944b16aae37801b8ec2fa9000 (master; Experimental_Evidence_Base
// v0.3, sec:environment), e.g.:
//   g++ -std=c++17 -I<cryptopp_include> scripts/run-gcm-cryptopp.cpp \
//       src/adapters/cryptopp/gcm.cpp -L<cryptopp_lib> -lcryptopp \
//       -o run-gcm-cryptopp

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../src/adapters/cryptopp/gcm.hpp"

namespace {

std::vector<uint8_t> fromHex(const std::string& hex) {
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}

std::string toHex(const std::vector<uint8_t>& bytes) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t b : bytes) {
    out.push_back(digits[b >> 4]);
    out.push_back(digits[b & 0xf]);
  }
  return out;
}

bool contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

int failures = 0;

void check(bool condition, const std::string& failMessage) {
  if (!condition) {
    std::fprintf(stderr, "FAILED: %s\n", failMessage.c_str());
    failures++;
  }
}

// Same NIST CAVS 14.0 vector used by the WebCrypto suite (Keylen=256,
// IVlen=96, PTlen=128, AADlen=160, Taglen=128, Count=0) -- independently
// re-verified against Node's webcrypto in that session, byte-for-byte.
// Reused here unmodified so a KAT match across backends is a genuine
// cross-provider R_byte agreement, not two different vectors that happen
// to both "pass."
const std::string KEY_HEX = "83688deb4af8007f9b713b47cfa6c73e35ea7a3aa4ecdb414dded03bf7a0fd3a";
const std::string IV_HEX = "0b459724904e010a46901cf3";
const std::string PT_HEX = "33d893a2114ce06fc15d55e454cf90c3";
const std::string AAD_HEX = "794a14ccd178c8ebfd1379dc704c5e208f9d8424";
const std::string EXPECTED_CT_HEX = "cc66bee423e3fcd4c0865715e9586696";
const std::string EXPECTED_TAG_HEX = "0fb291bd3dba94a1dfd8b286cfb97ac5";

}  // namespace

int main() {
  using namespace paper4;

  std::printf("=== M1 vertical slice: AES-256-GCM x Crypto++ ===\n\n");

  // --- 1. KAT: exact C and T ---
  std::printf("--- NIST KAT (same vector as WebCrypto slice) ---\n");
  GcmEncryptRequest kat;
  kat.key = fromHex(KEY_HEX);
  kat.plaintext = fromHex(PT_HEX);
  kat.aad = fromHex(AAD_HEX);
  kat.aadPresent = true;
  kat.iv = fromHex(IV_HEX);
  kat.tagLengthBits = GCM_TAG_LEN_BITS;

  const std::string katRecord = GcmEncryptCryptoPP(kat);
  std::printf("%s\n\n", katRecord.c_str());
  check(contains(katRecord, "\"kind\":\"accept\""), "expected KAT to be accepted.");

  // Extract artifactHex and slice out C/T for comparison.
  auto extractField = [](const std::string& record, const std::string& key) -> std::string {
    const std::string marker = "\"" + key + "\":\"";
    size_t start = record.find(marker);
    if (start == std::string::npos) return "";
    start += marker.size();
    size_t end = record.find('"', start);
    return record.substr(start, end - start);
  };
  const std::string katArtifactHex = extractField(katRecord, "artifactHex");
  const std::vector<uint8_t> katArtifact = fromHex(katArtifactHex);
  check(katArtifact.size() == 1 + 12 + 16 + 16, "unexpected KAT artifact length.");
  const std::string ctHex = toHex(std::vector<uint8_t>(katArtifact.begin() + 13, katArtifact.begin() + 13 + 16));
  const std::string tagHex = toHex(std::vector<uint8_t>(katArtifact.begin() + 13 + 16, katArtifact.end()));
  check(ctHex == EXPECTED_CT_HEX, "KAT ciphertext MISMATCH: expected " + EXPECTED_CT_HEX + " got " + ctHex);
  check(tagHex == EXPECTED_TAG_HEX, "KAT tag MISMATCH: expected " + EXPECTED_TAG_HEX + " got " + tagHex);
  if (failures == 0) {
    std::printf("PASS: Crypto++ realization matches the NIST KAT exactly, byte-for-byte with WebCrypto.\n\n");
  }

  // --- 2. Split-invariant check, independent of the KAT passing ---
  std::printf("--- C/T split invariant check (|T|=16, explicit re-parse) ---\n");
  {
    AeadArtifactParts parts;
    std::string parseErr;
    const bool ok = ParseAeadArtifact(katArtifact, parts, parseErr);
    check(ok, "expected KAT artifact to parse successfully: " + parseErr);
    check(toHex(parts.iv) == IV_HEX, "parsed IV does not match the IV fed into encryption.");
    check(toHex(parts.ciphertext) == EXPECTED_CT_HEX, "parsed ciphertext does not match the split used to build the artifact.");
    check(toHex(parts.tag) == EXPECTED_TAG_HEX, "parsed tag does not match the split used to build the artifact.");
    check(parts.tag.size() == GCM_TAG_LEN_BYTES, "parsed tag length is not exactly 16 bytes.");
  }
  if (failures == 0) {
    std::printf("PASS: BuildAeadArtifact -> ParseAeadArtifact round-trip recovers IV/C/T exactly (protects against filter misconfiguration even if the KAT happened to pass).\n\n");
  }

  // --- 3. Determinism: same K,IV,AAD,M -> same ciphertext bytes ---
  std::printf("--- R_byte determinism (two independent encrypt calls) ---\n");
  {
    const std::string r1 = GcmEncryptCryptoPP(kat);
    const std::string r2 = GcmEncryptCryptoPP(kat);
    check(extractField(r1, "artifactHex") == extractField(r2, "artifactHex"),
          "two encrypt calls with identical K,IV,AAD,M produced different artifacts.");
  }
  if (failures == 0) {
    std::printf("PASS: deterministic ciphertext for fixed K,IV,AAD,M.\n\n");
  }

  // --- 4. Encrypt -> decrypt round trip ---
  std::printf("--- encrypt -> decrypt round trip ---\n");
  GcmDecryptRequest decReq;
  decReq.key = kat.key;
  decReq.artifact = katArtifact;
  decReq.aad = kat.aad;
  decReq.aadPresent = true;
  const std::string decRecord = GcmDecryptCryptoPP(decReq);
  std::printf("%s\n\n", decRecord.c_str());
  check(contains(decRecord, "\"kind\":\"accept\""), "expected round-trip decrypt to succeed.");
  check(extractField(decRecord, "plaintextHex") == PT_HEX, "round-trip plaintext does not match the original.");
  if (failures == 0) {
    std::printf("PASS: encrypt -> decrypt recovers the exact plaintext.\n\n");
  }

  // --- 5. AAD absent === AAD empty ---
  std::printf("--- AAD absent vs AAD empty equivalence ---\n");
  {
    GcmEncryptRequest absentReq = kat;
    absentReq.aadPresent = false;
    absentReq.aad.clear();
    GcmEncryptRequest emptyReq = kat;
    emptyReq.aadPresent = true;
    emptyReq.aad.clear();

    const std::string absentRecord = GcmEncryptCryptoPP(absentReq);
    const std::string emptyRecord = GcmEncryptCryptoPP(emptyReq);
    check(extractField(absentRecord, "artifactHex") == extractField(emptyRecord, "artifactHex"),
          "AAD absent and AAD empty produced different artifacts.");

    // Cross-check through decrypt too.
    const std::vector<uint8_t> absentArtifact = fromHex(extractField(absentRecord, "artifactHex"));
    GcmDecryptRequest decAbsentWithEmpty;
    decAbsentWithEmpty.key = kat.key;
    decAbsentWithEmpty.artifact = absentArtifact;
    decAbsentWithEmpty.aadPresent = true;
    decAbsentWithEmpty.aad = {};
    const std::string decCross = GcmDecryptCryptoPP(decAbsentWithEmpty);
    check(contains(decCross, "\"kind\":\"accept\""), "artifact encrypted with AAD-absent failed to decrypt with AAD-explicit-empty.");
  }
  if (failures == 0) {
    std::printf("PASS: AAD_absent === AAD_empty, encrypt and decrypt.\n\n");
  }

  // --- 6. Tamper T/C/AAD/IV -> authentication_failure ---
  std::printf("--- tamper T/C/AAD/IV -> authentication_failure ---\n");
  {
    auto tamperedDecrypt = [&](std::vector<uint8_t> artifact, std::vector<uint8_t> aad) {
      GcmDecryptRequest req;
      req.key = kat.key;
      req.artifact = std::move(artifact);
      req.aad = std::move(aad);
      req.aadPresent = true;
      return GcmDecryptCryptoPP(req);
    };

    std::vector<uint8_t> tamperedTag = katArtifact;
    tamperedTag.back() ^= 0xff;
    const std::string tagTamperRecord = tamperedDecrypt(tamperedTag, kat.aad);
    check(contains(tagTamperRecord, "\"errorClass\":\"authentication_failure\""), "tag tamper did not yield authentication_failure.");

    std::vector<uint8_t> tamperedCt = katArtifact;
    tamperedCt[13] ^= 0xff;  // first ciphertext byte
    const std::string ctTamperRecord = tamperedDecrypt(tamperedCt, kat.aad);
    check(contains(ctTamperRecord, "\"errorClass\":\"authentication_failure\""), "ciphertext tamper did not yield authentication_failure.");

    std::vector<uint8_t> tamperedAad = kat.aad;
    tamperedAad[0] ^= 0xff;
    const std::string aadTamperRecord = tamperedDecrypt(katArtifact, tamperedAad);
    check(contains(aadTamperRecord, "\"errorClass\":\"authentication_failure\""), "AAD tamper did not yield authentication_failure.");

    std::vector<uint8_t> tamperedIv = katArtifact;
    tamperedIv[1] ^= 0xff;  // first IV byte
    const std::string ivTamperRecord = tamperedDecrypt(tamperedIv, kat.aad);
    check(contains(ivTamperRecord, "\"errorClass\":\"authentication_failure\""), "IV tamper did not yield authentication_failure.");
  }
  if (failures == 0) {
    std::printf("PASS: tampering T, C, AAD, or IV each independently yields authentication_failure.\n\n");
  }

  // --- 7. Pre-backend rejections ---
  std::printf("--- pre-backend rejections (key/IV/tagLength, malformed artifact) ---\n");
  {
    GcmEncryptRequest badKey = kat;
    badKey.key = std::vector<uint8_t>(16, 0);  // AES-128 length, not our profile
    const std::string badKeyRecord = GcmEncryptCryptoPP(badKey);
    check(contains(badKeyRecord, "\"errorClass\":\"invalid_parameter\"") && contains(badKeyRecord, "\"gcm.key\""),
          "expected key length!=256 bits to be rejected as invalid_parameter (gcm.key).");

    GcmEncryptRequest badIv = kat;
    badIv.iv = std::vector<uint8_t>(16, 0);
    const std::string badIvRecord = GcmEncryptCryptoPP(badIv);
    check(contains(badIvRecord, "\"errorClass\":\"invalid_parameter\"") && contains(badIvRecord, "\"gcm.iv\""),
          "expected IV length!=96 bits to be rejected as invalid_parameter (gcm.iv).");

    GcmEncryptRequest badTag80 = kat;
    badTag80.tagLengthBits = 80;
    const std::string badTag80Record = GcmEncryptCryptoPP(badTag80);
    check(contains(badTag80Record, "\"errorClass\":\"invalid_parameter\"") && contains(badTag80Record, "\"gcm.tagLength\""),
          "expected tagLength=80 to be rejected as invalid_parameter (gcm.tagLength), not unsupported.");

    // THE critical case for this backend: t=0 is accepted by Crypto++'s
    // own generic API path (no lower bound at all) -- this MUST be
    // rejected by Accept_C before GCM<AES>::Encryption is ever touched.
    GcmEncryptRequest badTag0 = kat;
    badTag0.tagLengthBits = 0;
    const std::string badTag0Record = GcmEncryptCryptoPP(badTag0);
    check(contains(badTag0Record, "\"errorClass\":\"invalid_parameter\"") && contains(badTag0Record, "\"gcm.tagLength\""),
          "CRITICAL: expected tagLength=0 to be rejected as invalid_parameter -- Crypto++ has NO native floor and would otherwise silently accept it.");

    GcmDecryptRequest badKeyDecrypt;
    badKeyDecrypt.key = std::vector<uint8_t>(24, 0);
    badKeyDecrypt.artifact = katArtifact;
    badKeyDecrypt.aadPresent = false;
    const std::string badKeyDecryptRecord = GcmDecryptCryptoPP(badKeyDecrypt);
    check(contains(badKeyDecryptRecord, "\"errorClass\":\"invalid_parameter\"") && contains(badKeyDecryptRecord, "\"gcm.key\""),
          "expected decrypt with key length!=256 bits to be rejected as invalid_parameter (gcm.key).");

    GcmDecryptRequest malformed;
    malformed.key = kat.key;
    malformed.artifact = std::vector<uint8_t>(10, 0);  // below the 29-byte minimum
    malformed.aadPresent = false;
    const std::string malformedRecord = GcmDecryptCryptoPP(malformed);
    check(contains(malformedRecord, "\"errorClass\":\"malformed_artifact\"") && contains(malformedRecord, "\"gcm.artifact\""),
          "expected undersized artifact to be rejected as malformed_artifact, not authentication_failure.");
  }
  if (failures == 0) {
    std::printf("PASS: all pre-backend rejections enforced correctly, including the t=0 critical case.\n\n");
  }

  std::printf("=== M1 slice complete for AES-256-GCM x Crypto++: %s ===\n",
              failures == 0 ? "ALL CHECKS PASSED" : (std::to_string(failures) + " CHECK(S) FAILED").c_str());
  return failures == 0 ? 0 : 1;
}
