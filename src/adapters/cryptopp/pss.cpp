#include "pss.hpp"

#include <chrono>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#include "cryptlib.h"
#include "hex.h"
#include "integer.h"
#include "osrng.h"
#include "pssr.h"
#include "pubkey.h"
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
  std::ostringstream ss;
  ss << "cryptopp:" << CRYPTOPP_VERSION
     << " RSASS<PSS,SHA256>::Signer/Verifier (compile-time hash/MGF1 template"
        " instantiation; saltLength empirically confirmed from produced signatures via"
        " RSAVP1 + EMSA-PSS MGF1 unmasking, not a runtime SaltLen() call -- see"
        " sec:environment for exact pinned build)";
  return ss.str();
}

std::string buildSignRecord(const std::string& inputJson, const std::vector<std::string>& clauseIds,
                             const std::string& outcomeJson) {
  std::ostringstream out;
  out << "{"
      << "\"operation\":\"RSA-PSS\","
      << "\"direction\":\"sign\","
      << "\"backend\":{\"name\":\"cryptopp\",\"realization\":\"" << realizationId() << "\"},"
      << "\"clauseIds\":" << jsonStringArray(clauseIds) << ","
      << "\"mutationId\":null,"
      << "\"input\":" << inputJson << ","
      << "\"outcome\":" << outcomeJson << ","
      << "\"timestampIso\":\"" << nowIso() << "\""
      << "}";
  return out.str();
}

std::string buildVerifyRecord(const std::string& inputJson, const std::vector<std::string>& clauseIds,
                               const std::string& outcomeJson) {
  std::ostringstream out;
  out << "{"
      << "\"operation\":\"RSA-PSS\","
      << "\"direction\":\"verify\","
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

std::string buildSignInputJson(const PssSignRequest& req) {
  return "{"
         "\"keyRole\":\"" +
         req.key.declaredRole +
         "\","
         "\"modulusBits\":" +
         std::to_string(req.key.modulusBits) +
         ","
         "\"messageHex\":\"" +
         toHex(req.message) +
         "\","
         "\"hash\":\"" + req.hash + "\","
         "\"mgfHash\":\"" + req.mgfHash + "\","
         "\"saltLengthBytes\":" +
         std::to_string(req.saltLengthBytes) + "}";
}

std::string buildVerifyInputJson(const PssVerifyRequest& req) {
  return "{"
         "\"keyRole\":\"" +
         req.key.declaredRole +
         "\","
         "\"modulusBits\":" +
         std::to_string(req.key.modulusBits) +
         ","
         "\"messageHex\":\"" +
         toHex(req.message) +
         "\","
         "\"signatureHex\":\"" +
         toHex(req.signature) +
         "\","
         "\"hash\":\"" + req.hash + "\","
         "\"mgfHash\":\"" + req.mgfHash + "\","
         "\"saltLengthBytes\":" +
         std::to_string(req.saltLengthBytes) + "}";
}

}  // namespace

PssKeyMaterial GeneratePssKeyMaterial() {
  AutoSeededRandomPool rng;
  RSA::PrivateKey privateKey;
  privateKey.GenerateRandomWithKeySize(rng, PSS_MODULUS_BITS);

  PssKeyMaterial material;
  material.declaredRole = "private";
  material.modulus = privateKey.GetModulus();
  material.publicExponent = privateKey.GetPublicExponent();
  material.privateExponent = privateKey.GetPrivateExponent();
  material.modulusBits = privateKey.GetModulus().BitCount();
  return material;
}

size_t PssSaltLenBytes(const PssKeyMaterial& publicKey, const std::vector<uint8_t>& signature) {
  // Manually reverses RSAVP1 (RFC 8017 Sec.5.2.2) and EMSA-PSS-VERIFY's
  // MGF1 unmasking step (Sec.9.1.2) on a REAL Crypto++-produced signature,
  // to recover the actual embedded salt length -- see pss.hpp's header
  // comment for why this replaced a direct (inaccessible) SaltLen() call.

  // Step 1: RSAVP1. s = OS2IP(signature); m = s^e mod n; EM = I2OSP(m, emLen).
  Integer s;
  s.Decode(signature.data(), signature.size());
  RSA::PublicKey pub;
  pub.Initialize(publicKey.modulus, publicKey.publicExponent);
  const Integer m = pub.ApplyFunction(s);

  const size_t modBits = static_cast<size_t>(publicKey.modulus.BitCount());
  const size_t emBits = modBits - 1;
  const size_t emLen = (emBits + 7) / 8;

  std::vector<uint8_t> em(emLen);
  m.Encode(em.data(), emLen);

  if (em.empty() || em.back() != 0xbc) {
    throw std::runtime_error("PssSaltLenBytes: trailer byte 0xbc not found -- not well-formed EMSA-PSS output");
  }

  // Step 2: split EM into maskedDB || H || 0xbc.
  const size_t hLen = PSS_HASH_LEN_BYTES;
  if (emLen < hLen + 1) {
    throw std::runtime_error("PssSaltLenBytes: emLen too short to contain H + trailer");
  }
  const size_t dbLen = emLen - hLen - 1;
  std::vector<uint8_t> maskedDB(em.begin(), em.begin() + static_cast<long>(dbLen));
  std::vector<uint8_t> H(em.begin() + static_cast<long>(dbLen), em.begin() + static_cast<long>(dbLen + hLen));

  // Step 3: dbMask = MGF1(H, dbLen); DB = maskedDB XOR dbMask.
  // GenerateAndMask's `mask=true` XORs the generated mask INTO the buffer
  // already holding maskedDB, yielding DB directly, in place.
  SHA256 hashFn;
  P1363_MGF1 mgf;
  std::vector<uint8_t> db = maskedDB;
  mgf.GenerateAndMask(hashFn, db.data(), db.size(), H.data(), H.size(), true);

  // Step 4: clear the leftmost 8*emLen-emBits bits of the leftmost octet of DB.
  const size_t extraBits = 8 * emLen - emBits;
  if (extraBits > 0 && !db.empty()) {
    db[0] = static_cast<uint8_t>(db[0] & (0xFFu >> extraBits));
  }

  // Step 5: DB = PS(zero octets) || 0x01 || salt. Find the 0x01 separator.
  size_t sepIndex = 0;
  bool found = false;
  for (size_t i = 0; i < db.size(); ++i) {
    if (db[i] == 0x01) {
      sepIndex = i;
      found = true;
      break;
    }
    if (db[i] != 0x00) {
      throw std::runtime_error("PssSaltLenBytes: non-zero byte before 0x01 separator in DB -- malformed padding");
    }
  }
  if (!found) {
    throw std::runtime_error("PssSaltLenBytes: 0x01 separator not found in DB");
  }

  // Everything after the separator is the salt.
  return db.size() - sepIndex - 1;
}

std::string PssSignCryptoPP(const PssSignRequest& req) {
  const std::string inputJson = buildSignInputJson(req);

  // Accept_C, step 2: key contract -- checked BEFORE any typed CryptoPP key
  // object is constructed (same discipline as the OAEP adapter).
  if (req.key.declaredRole != "private") {
    std::string detail = "sign requires a private key; got role=\"" + req.key.declaredRole + "\"";
    return buildSignRecord(inputJson, {"pss.key"}, rejectOutcomeJson("invalid_key", detail));
  }

  // Accept_C, step 3: portable parameter/input contract.
  if (req.key.modulusBits != PSS_MODULUS_BITS) {
    std::string detail = "modulus " + std::to_string(req.key.modulusBits) + " bits, portable profile requires exactly " +
                          std::to_string(PSS_MODULUS_BITS);
    return buildSignRecord(inputJson, {"pss.modulus"}, rejectOutcomeJson("invalid_parameter", detail));
  }
  if (req.hash != "SHA-256") {
    std::string detail = "hash \"" + req.hash + "\", portable profile requires exactly \"SHA-256\"";
    return buildSignRecord(inputJson, {"pss.hash"}, rejectOutcomeJson("invalid_parameter", detail));
  }
  if (req.mgfHash != req.hash) {
    std::string detail = "mgfHash \"" + req.mgfHash + "\" != hash \"" + req.hash +
                         "\"; portable profile requires H_PSS=H_MGF1 (D-040)";
    return buildSignRecord(inputJson, {"pss.mgfCoupling"}, rejectOutcomeJson("invalid_parameter", detail));
  }
  if (req.saltLengthBytes != PSS_SALT_LEN_BYTES) {
    std::string detail = "saltLength=" + std::to_string(req.saltLengthBytes) +
                         " bytes, portable profile requires exactly " +
                         std::to_string(PSS_SALT_LEN_BYTES) + " (=hLen, D-041)";
    return buildSignRecord(inputJson, {"pss.saltLength"}, rejectOutcomeJson("invalid_parameter", detail));
  }
  // Crypto++ realizes the frozen SHA-256 / coupled-MGF1 / sLen=32
  // profile internally. Accept_C validates that the portable request
  // descriptor agrees with that realization before execution.
  // pss.message has no portable length boundary.

  RSA::PrivateKey privateKey;
  privateKey.Initialize(req.key.modulus, req.key.publicExponent, req.key.privateExponent);
  RSASS<PSS, SHA256>::Signer signer(privateKey);
  AutoSeededRandomPool rng;  // required by Crypto++'s own API for the random salt; never exposed to caller or evidence record

  std::vector<uint8_t> signature(signer.MaxSignatureLength());
  const size_t sigLen = signer.SignMessage(rng, req.message.empty() ? nullptr : req.message.data(), req.message.size(),
                                            signature.data());
  signature.resize(sigLen);

  std::ostringstream outcome;
  outcome << "{\"kind\":\"accept\",\"signatureHex\":\"" << toHex(signature) << "\"}";
  return buildSignRecord(
      inputJson,
      {"pss.key", "pss.modulus", "pss.message", "pss.hash", "pss.mgfCoupling", "pss.saltLength", "pss.signature",
       "pss.signatureLength"},
      outcome.str());
}

std::string PssVerifyCryptoPP(const PssVerifyRequest& req) {
  const std::string inputJson = buildVerifyInputJson(req);

  // Step 2.
  if (req.key.declaredRole != "public") {
    std::string detail = "verify requires a public key; got role=\"" + req.key.declaredRole + "\"";
    return buildVerifyRecord(inputJson, {"pss.key"}, rejectOutcomeJson("invalid_key", detail));
  }

  // Step 3 (signature length DELIBERATELY excluded -- Design Freeze v0.6 D-046).
  if (req.key.modulusBits != PSS_MODULUS_BITS) {
    std::string detail = "modulus " + std::to_string(req.key.modulusBits) + " bits, portable profile requires exactly " +
                          std::to_string(PSS_MODULUS_BITS);
    return buildVerifyRecord(inputJson, {"pss.modulus"}, rejectOutcomeJson("invalid_parameter", detail));
  }

  if (req.hash != "SHA-256") {
    std::string detail = "hash \"" + req.hash + "\", portable profile requires exactly \"SHA-256\"";
    return buildVerifyRecord(inputJson, {"pss.hash"}, rejectOutcomeJson("invalid_parameter", detail));
  }
  if (req.mgfHash != req.hash) {
    std::string detail = "mgfHash \"" + req.mgfHash + "\" != hash \"" + req.hash +
                         "\"; portable profile requires H_PSS=H_MGF1 (D-040)";
    return buildVerifyRecord(inputJson, {"pss.mgfCoupling"}, rejectOutcomeJson("invalid_parameter", detail));
  }
  if (req.saltLengthBytes != PSS_SALT_LEN_BYTES) {
    std::string detail = "saltLength=" + std::to_string(req.saltLengthBytes) +
                         " bytes, portable profile requires exactly " +
                         std::to_string(PSS_SALT_LEN_BYTES) + " (=hLen, D-041)";
    return buildVerifyRecord(inputJson, {"pss.saltLength"}, rejectOutcomeJson("invalid_parameter", detail));
  }

  // Step 4: the actual verification call. Two distinct causal layers exist
  // here (Design Freeze v0.6, sec:pss "Two causal layers, not one"):
  // pre-C_pre^PSS configuration realizability (KeyTooShort()-style, never
  // actually reachable under the fixed 3072/SHA-256/sLen=32 profile since
  // 384>=66 with wide margin) vs. genuine cryptographic verification.
  // CRITICAL DISTINCTION FROM OAEP: unlike OAEP's decrypt, where a native
  // exception past Accept_C became the SDK error decryption_error, HERE a
  // native exception past Accept_C becomes a `false` VERIFY RESULT, not any
  // SDK error -- E_PSS^SDK has no such class at all (D-047: only
  // {unsupported, invalid_key, invalid_parameter}). Design Freeze v0.6
  // explicitly leaves Crypto++'s exact native behavior for a wrong-length
  // signature unconfirmed (VerifyMessage() vs. an internal exception), but
  // the CONTRACT does not depend on which: either way, this adapter
  // collapses it to valid=false.
  RSA::PublicKey publicKey;
  publicKey.Initialize(req.key.modulus, req.key.publicExponent);
  RSASS<PSS, SHA256>::Verifier verifier(publicKey);

  bool valid;
  try {
    valid = verifier.VerifyMessage(req.message.empty() ? nullptr : req.message.data(), req.message.size(),
                                    req.signature.empty() ? nullptr : req.signature.data(), req.signature.size());
  } catch (const CryptoPP::Exception&) {
    // Deliberately NOT inspecting the caught exception's type or message.
    // Whatever native cause fired (signature length, malformed encoding,
    // out-of-range representative), it becomes a `false` verification
    // result -- NOT normalized to any SDK error, per the distinction above.
    valid = false;
  }

  std::ostringstream outcome;
  outcome << "{\"kind\":\"verified\",\"valid\":" << (valid ? "true" : "false") << "}";
  return buildVerifyRecord(inputJson, {"pss.key", "pss.modulus", "pss.hash", "pss.mgfCoupling", "pss.saltLength", "pss.verification"},
                            outcome.str());
}

}  // namespace paper4
