#include "oaep.hpp"

#include <chrono>
#include <cctype>
#include <iomanip>
#include <sstream>

#include "cryptlib.h"
#include "hex.h"
#include "integer.h"
#include "oaep.h"
#include "osrng.h"
#include "rsa.h"
#include "sha.h"

using namespace CryptoPP;

namespace paper4 {
namespace {

std::string toHex(const std::vector<uint8_t>& bytes) {
  std::string out;
  HexEncoder encoder(new StringSink(out));
  if (!bytes.empty()) {
    encoder.Put(bytes.data(), bytes.size());
  }
  encoder.MessageEnd();
  for (auto& c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

std::string nowIso() {
  using namespace std::chrono;
  const auto now = system_clock::now();
  const auto t = system_clock::to_time_t(now);
  const auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
  std::ostringstream ss;
  ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%S") << '.' << std::setw(3) << std::setfill('0') << ms.count()
     << 'Z';
  return ss.str();
}

std::string jsonStringArray(const std::vector<std::string>& xs) {
  std::ostringstream ss;
  ss << "[";
  for (size_t i = 0; i < xs.size(); ++i) {
    if (i) ss << ",";
    ss << "\"" << xs[i] << "\"";
  }
  ss << "]";
  return ss.str();
}

std::string realizationId() {
  // Same CRYPTOPP_VERSION provenance-limitation pattern already recorded
  // for HKDF/GCM. hash/MGF1 are NOT runtime parameters here --
  // RSAES<OAEP<SHA256>> is a COMPILE-TIME template instantiation, so
  // oaep.hash/oaep.mgfCoupling are satisfied by construction, not a
  // runtime check (unlike WebCrypto, where they are read from live
  // CryptoKey material).
  std::ostringstream ss;
  ss << "cryptopp:" << CRYPTOPP_VERSION
     << " RSAES<OAEP<SHA256>>::Encryptor/Decryptor (compile-time hash/MGF1"
        " template instantiation, not a runtime parameter; see sec:environment"
        " for exact pinned build)";
  return ss.str();
}

std::string buildEncryptRecord(const std::string& inputJson, const std::vector<std::string>& clauseIds,
                                const std::string& outcomeJson) {
  std::ostringstream out;
  out << "{"
      << "\"operation\":\"RSA-OAEP\","
      << "\"direction\":\"encrypt\","
      << "\"backend\":{\"name\":\"cryptopp\",\"realization\":\"" << realizationId() << "\"},"
      << "\"clauseIds\":" << jsonStringArray(clauseIds) << ","
      << "\"mutationId\":null,"
      << "\"input\":" << inputJson << ","
      << "\"outcome\":" << outcomeJson << ","
      << "\"timestampIso\":\"" << nowIso() << "\""
      << "}";
  return out.str();
}

std::string buildDecryptRecord(const std::string& inputJson, const std::vector<std::string>& clauseIds,
                                const std::string& outcomeJson) {
  std::ostringstream out;
  out << "{"
      << "\"operation\":\"RSA-OAEP\","
      << "\"direction\":\"decrypt\","
      << "\"backend\":{\"name\":\"cryptopp\",\"realization\":\"" << realizationId() << "\"},"
      << "\"clauseIds\":" << jsonStringArray(clauseIds) << ","
      << "\"mutationId\":null,"
      << "\"input\":" << inputJson << ","
      << "\"outcome\":" << outcomeJson << ","
      << "\"timestampIso\":\"" << nowIso() << "\""
      << "}";
  return out.str();
}

std::string rejectOutcomeJson(const std::string& errorClass, const std::string& detail) {
  std::ostringstream ss;
  ss << "{\"kind\":\"reject\",\"errorClass\":\"" << errorClass << "\",\"detail\":\"" << detail << "\"}";
  return ss.str();
}

// Note: NO "seed"/"rng"/"randomness" field appears anywhere in these input
// builders, by design -- see oaep.hpp's invariant 1. The AutoSeededRandomPool
// used internally by Encrypt()/Decrypt() below is never surfaced to the
// caller or to the evidence record.
std::string buildEncryptInputJson(const OaepEncryptRequest& req, int modulusBits) {
  return "{"
         "\"keyRole\":\"" +
         req.key.declaredRole +
         "\","
         "\"modulusBits\":" +
         std::to_string(modulusBits) +
         ","
         "\"plaintextHex\":\"" +
         toHex(req.plaintext) +
         "\","
         "\"labelHex\":" +
         (req.labelPresent ? ("\"" + toHex(req.label) + "\"") : "null") +
         ","
         "\"hash\":\"" +
         req.hash +
         "\","
         "\"mgfHash\":\"" +
         req.mgfHash +
         "\"}";
}

std::string buildDecryptInputJson(const OaepDecryptRequest& req, int modulusBits) {
  return "{"
         "\"keyRole\":\"" +
         req.key.declaredRole +
         "\","
         "\"modulusBits\":" +
         std::to_string(modulusBits) +
         ","
         "\"ciphertextHex\":\"" +
         toHex(req.ciphertext) +
         "\","
         "\"labelHex\":" +
         (req.labelPresent ? ("\"" + toHex(req.label) + "\"") : "null") +
         ","
         "\"hash\":\"" +
         req.hash +
         "\","
         "\"mgfHash\":\"" +
         req.mgfHash +
         "\"}";
}

}  // namespace

OaepKeyMaterial GenerateOaepKeyMaterial() {
  AutoSeededRandomPool rng;
  RSA::PrivateKey privateKey;
  privateKey.GenerateRandomWithKeySize(rng, OAEP_MODULUS_BITS);

  OaepKeyMaterial material;
  material.declaredRole = "private";
  material.modulus = privateKey.GetModulus();
  material.publicExponent = privateKey.GetPublicExponent();
  material.privateExponent = privateKey.GetPrivateExponent();
  material.modulusBits = privateKey.GetModulus().BitCount();
  return material;
}

std::string OaepEncryptCryptoPP(const OaepEncryptRequest& req) {
  const int modulusBits = req.key.modulusBits > 0 ? req.key.modulusBits : req.key.modulus.BitCount();
  const std::string inputJson = buildEncryptInputJson(req, modulusBits);

  // Accept_C, step 2: key contract -- checked BEFORE any typed CryptoPP
  // key object is constructed. This is the ONLY place a Crypto++-backed
  // request can be rejected for role mismatch, since Crypto++ itself
  // cannot represent the misuse at all (see oaep.hpp header comment).
  if (req.key.declaredRole != "public") {
    std::string detail = "encrypt requires a public key; got role=\"" + req.key.declaredRole + "\"";
    return buildEncryptRecord(inputJson, {"oaep.key"}, rejectOutcomeJson("invalid_key", detail));
  }

  // Accept_C, step 3: portable parameter/input contract.
  if (modulusBits != OAEP_MODULUS_BITS) {
    std::string detail = "modulus " + std::to_string(modulusBits) + " bits, portable profile requires exactly " +
                          std::to_string(OAEP_MODULUS_BITS);
    return buildEncryptRecord(inputJson, {"oaep.modulus"}, rejectOutcomeJson("invalid_parameter", detail));
  }
  if (req.hash != "SHA-256") {
    std::string detail = "hash \"" + req.hash + "\", portable profile requires exactly \"SHA-256\"";
    return buildEncryptRecord(inputJson, {"oaep.hash"}, rejectOutcomeJson("invalid_parameter", detail));
  }
  if (req.mgfHash != req.hash) {
    std::string detail = "mgfHash \"" + req.mgfHash + "\" != hash \"" + req.hash +
                         "\"; portable profile requires H_OAEP=H_MGF1 (D-028)";
    return buildEncryptRecord(inputJson, {"oaep.mgfCoupling"}, rejectOutcomeJson("invalid_parameter", detail));
  }
  if (req.labelPresent && !req.label.empty()) {
    std::string detail = "label present with " + std::to_string(req.label.size()) +
                          " byte(s); portable profile requires L=empty (D-030)";
    return buildEncryptRecord(inputJson, {"oaep.label"}, rejectOutcomeJson("invalid_parameter", detail));
  }
  if (req.plaintext.size() > OAEP_MAX_MESSAGE_LEN_BYTES) {
    std::string detail = "mLen=" + std::to_string(req.plaintext.size()) + " exceeds portable bound 0<=mLen<=" +
                          std::to_string(OAEP_MAX_MESSAGE_LEN_BYTES) + " (D-032)";
    return buildEncryptRecord(inputJson, {"oaep.message"}, rejectOutcomeJson("invalid_parameter", detail));
  }

  // Only NOW is a typed CryptoPP::RSA::PublicKey constructed and used.
  RSA::PublicKey publicKey;
  publicKey.Initialize(req.key.modulus, req.key.publicExponent);

  RSAES<OAEP<SHA256>>::Encryptor encryptor(publicKey);
  AutoSeededRandomPool rng;  // used normally for the OAEP seed; NEVER exposed to the caller or evidence record (invariant 1)

  std::vector<uint8_t> ciphertext(encryptor.CiphertextLength(req.plaintext.size()));
  encryptor.Encrypt(rng, req.plaintext.empty() ? nullptr : req.plaintext.data(), req.plaintext.size(),
                     ciphertext.data());

  std::ostringstream outcome;
  outcome << "{\"kind\":\"accept\",\"ciphertextHex\":\"" << toHex(ciphertext) << "\"}";
  return buildEncryptRecord(
      inputJson,
      {"oaep.key", "oaep.modulus", "oaep.message", "oaep.ciphertext", "oaep.ciphertextLength", "oaep.hash",
       "oaep.mgfCoupling", "oaep.label"},
      outcome.str());
}

std::string OaepDecryptCryptoPP(const OaepDecryptRequest& req) {
  const int modulusBits = req.key.modulusBits > 0 ? req.key.modulusBits : req.key.modulus.BitCount();
  const std::string inputJson = buildDecryptInputJson(req, modulusBits);

  // Step 2.
  if (req.key.declaredRole != "private") {
    std::string detail = "decrypt requires a private key; got role=\"" + req.key.declaredRole + "\"";
    return buildDecryptRecord(inputJson, {"oaep.key"}, rejectOutcomeJson("invalid_key", detail));
  }

  // Step 3 (ciphertext length DELIBERATELY excluded -- v0.6 D-034; see oaep.hpp).
  if (modulusBits != OAEP_MODULUS_BITS) {
    std::string detail = "modulus " + std::to_string(modulusBits) + " bits, portable profile requires exactly " +
                          std::to_string(OAEP_MODULUS_BITS);
    return buildDecryptRecord(inputJson, {"oaep.modulus"}, rejectOutcomeJson("invalid_parameter", detail));
  }
  if (req.hash != "SHA-256") {
    std::string detail = "hash \"" + req.hash + "\", portable profile requires exactly \"SHA-256\"";
    return buildDecryptRecord(inputJson, {"oaep.hash"}, rejectOutcomeJson("invalid_parameter", detail));
  }
  if (req.mgfHash != req.hash) {
    std::string detail = "mgfHash \"" + req.mgfHash + "\" != hash \"" + req.hash +
                         "\"; portable profile requires H_OAEP=H_MGF1 (D-028)";
    return buildDecryptRecord(inputJson, {"oaep.mgfCoupling"}, rejectOutcomeJson("invalid_parameter", detail));
  }
  if (req.labelPresent && !req.label.empty()) {
    std::string detail = "label present with " + std::to_string(req.label.size()) +
                          " byte(s); portable profile requires L=empty (D-030)";
    return buildDecryptRecord(inputJson, {"oaep.label"}, rejectOutcomeJson("invalid_parameter", detail));
  }

  // Step 4: the actual RSAES-OAEP-DECRYPT call. Crypto++ exposes TWO
  // different native failure mechanisms here (v0.6, sec:oaep, Crypto++
  // inventory) -- both must collapse to the SAME decryption_error outcome:
  //   (a) ciphertext length != FixedCiphertextLength() -> THROWS
  //       InvalidArgument, structurally, before any RSA/OAEP processing;
  //   (b) internal OAEP-decode failure (bad lHash, padding, RSA
  //       representative out of range) -> returns DecodingResult with
  //       isValidCoding=false, no exception at all.
  // Handling only one of these would leak exactly the granularity v0.6
  // requires this adapter to hide.
  RSA::PrivateKey privateKey;
  privateKey.Initialize(req.key.modulus, req.key.publicExponent, req.key.privateExponent);
  RSAES<OAEP<SHA256>>::Decryptor decryptor(privateKey);
  AutoSeededRandomPool rng;

  std::vector<uint8_t> plaintext(OAEP_MAX_MESSAGE_LEN_BYTES);
  DecodingResult result;
  try {
    result = decryptor.Decrypt(rng, req.ciphertext.empty() ? nullptr : req.ciphertext.data(), req.ciphertext.size(),
                                plaintext.data());
  } catch (const CryptoPP::Exception&) {
    // Mechanism (a): ciphertext-length mismatch (or any other native
    // exception). Deliberately NOT inspecting the caught exception's type
    // or message -- normalized unconditionally to decryption_error, same
    // discipline as the WebCrypto adapter's blanket, uninspected catch.
    return buildDecryptRecord(
        inputJson, {"oaep.error"},
        rejectOutcomeJson("decryption_error",
                           "RSAES-OAEP-DECRYPT failed (ciphertext length, lHash, padding, or "
                           "RSA-representative-range cause -- collapsed per RFC 8017 Sec.7.1.2 "
                           "anti-oracle requirement, D-027)"));
  }

  if (!result.isValidCoding) {
    // Mechanism (b): internal OAEP-decode failure, no exception thrown --
    // the SAME decryption_error outcome as mechanism (a) above. This is
    // the check that specifically prevents Crypto++'s two-tier error
    // surface from leaking through this adapter.
    return buildDecryptRecord(
        inputJson, {"oaep.error"},
        rejectOutcomeJson("decryption_error",
                           "RSAES-OAEP-DECRYPT failed (ciphertext length, lHash, padding, or "
                           "RSA-representative-range cause -- collapsed per RFC 8017 Sec.7.1.2 "
                           "anti-oracle requirement, D-027)"));
  }

  plaintext.resize(result.messageLength);
  std::ostringstream outcome;
  outcome << "{\"kind\":\"accept\",\"plaintextHex\":\"" << toHex(plaintext) << "\"}";
  return buildDecryptRecord(inputJson, {"oaep.key", "oaep.modulus", "oaep.hash", "oaep.mgfCoupling", "oaep.label"},
                             outcome.str());
}

}  // namespace paper4
