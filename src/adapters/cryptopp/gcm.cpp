#include "gcm.hpp"

#include <chrono>
#include <cctype>
#include <iomanip>
#include <sstream>

#include "aes.h"
#include "cryptlib.h"
#include "filters.h"
#include "gcm.h"
#include "hex.h"

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
  // CRYPTOPP_VERSION provenance limitation applies identically here as it
  // did for HKDF (Experimental_Evidence_Base v0.3, sec:provenance-findings)
  // -- this string is a runtime cross-check, not the authoritative pin.
  std::ostringstream ss;
  ss << "cryptopp:" << CRYPTOPP_VERSION
     << " GCM<AES> via AuthenticatedEncryptionFilter/AuthenticatedDecryptionFilter"
        " (explicit DEFAULT_CHANNEL macChannel, explicit MAC_AT_END; see sec:environment"
        " for exact pinned build)";
  return ss.str();
}

std::string buildEncryptRecord(const std::string& realization, const std::string& inputJson,
                                const std::vector<std::string>& clauseIds, const std::string& outcomeJson) {
  std::ostringstream out;
  out << "{"
      << "\"operation\":\"AES-256-GCM\","
      << "\"direction\":\"encrypt\","
      << "\"backend\":{\"name\":\"cryptopp\",\"realization\":\"" << realization << "\"},"
      << "\"clauseIds\":" << jsonStringArray(clauseIds) << ","
      << "\"mutationId\":null,"
      << "\"input\":" << inputJson << ","
      << "\"outcome\":" << outcomeJson << ","
      << "\"timestampIso\":\"" << nowIso() << "\""
      << "}";
  return out.str();
}

std::string buildDecryptRecord(const std::string& realization, const std::string& inputJson,
                                const std::vector<std::string>& clauseIds, const std::string& outcomeJson) {
  std::ostringstream out;
  out << "{"
      << "\"operation\":\"AES-256-GCM\","
      << "\"direction\":\"decrypt\","
      << "\"backend\":{\"name\":\"cryptopp\",\"realization\":\"" << realization << "\"},"
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

}  // namespace

std::vector<uint8_t> BuildAeadArtifact(const std::vector<uint8_t>& iv, const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& tag) {
  std::vector<uint8_t> out;
  out.reserve(1 + iv.size() + ciphertext.size() + tag.size());
  out.push_back(GCM_ARTIFACT_VERSION);
  out.insert(out.end(), iv.begin(), iv.end());
  out.insert(out.end(), ciphertext.begin(), ciphertext.end());
  out.insert(out.end(), tag.begin(), tag.end());
  return out;
}

bool ParseAeadArtifact(const std::vector<uint8_t>& artifact, AeadArtifactParts& out, std::string& errorDetail) {
  if (artifact.size() < GCM_MIN_ARTIFACT_LEN_BYTES) {
    std::ostringstream d;
    d << "artifact length " << artifact.size() << " below minimum " << GCM_MIN_ARTIFACT_LEN_BYTES
      << " bytes (version(1) + IV(12) + tag(16), empty ciphertext)";
    errorDetail = d.str();
    return false;
  }
  const uint8_t version = artifact[0];
  if (version != GCM_ARTIFACT_VERSION) {
    std::ostringstream d;
    d << "unsupported artifact version " << static_cast<int>(version) << ", expected "
      << static_cast<int>(GCM_ARTIFACT_VERSION);
    errorDetail = d.str();
    return false;
  }
  out.version = version;
  out.iv.assign(artifact.begin() + 1, artifact.begin() + 1 + static_cast<long>(GCM_IV_LEN_BYTES));
  out.tag.assign(artifact.end() - static_cast<long>(GCM_TAG_LEN_BYTES), artifact.end());
  out.ciphertext.assign(artifact.begin() + 1 + static_cast<long>(GCM_IV_LEN_BYTES),
                         artifact.end() - static_cast<long>(GCM_TAG_LEN_BYTES));
  return true;
}

std::string GcmEncryptCryptoPP(const GcmEncryptRequest& req) {
  const std::string realization = realizationId();

  std::ostringstream inputJson;
  inputJson << "{"
            << "\"keyHex\":\"" << toHex(req.key) << "\","
            << "\"plaintextHex\":\"" << toHex(req.plaintext) << "\","
            << "\"aadHex\":" << (req.aadPresent ? ("\"" + toHex(req.aad) + "\"") : "null") << ","
            << "\"ivHex\":\"" << toHex(req.iv) << "\","
            << "\"tagLengthBits\":" << req.tagLengthBits << "}";

  // Accept_C, steps 1+3 -- independently reimplemented from
  // src/contract/gcm.ts's validateGcmEncryptRequest, same clause-by-clause
  // order. Step 3 (gcm.plaintext/gcm.aad type checks) is trivially
  // satisfied here: std::vector<uint8_t> is always a well-formed byte
  // sequence at the C++ type level, so only steps that can genuinely fail
  // are checked.
  if (req.key.size() != GCM_KEY_LEN_BYTES) {
    std::ostringstream d;
    d << "key length " << req.key.size() << " bytes, portable profile requires exactly " << GCM_KEY_LEN_BYTES
      << " (256 bits)";
    return buildEncryptRecord(realization, inputJson.str(), {"gcm.key"},
                               rejectOutcomeJson("invalid_parameter", d.str()));
  }
  if (req.iv.size() != GCM_IV_LEN_BYTES) {
    std::ostringstream d;
    d << "IV length " << req.iv.size() << " bytes, portable profile requires exactly " << GCM_IV_LEN_BYTES
      << " (96 bits)";
    return buildEncryptRecord(realization, inputJson.str(), {"gcm.iv"},
                               rejectOutcomeJson("invalid_parameter", d.str()));
  }
  if (req.tagLengthBits != GCM_TAG_LEN_BITS) {
    // THE single most adapter-critical check in this operation (see
    // gcm.hpp's header comment, invariant 3): Crypto++'s generic API path
    // enforces no lower bound on tag length at all. Without this check,
    // t=0 would reach GCM<AES>::Encryption below and produce ciphertext
    // with no real authentication whatsoever.
    std::ostringstream d;
    d << "tagLength=" << req.tagLengthBits << " bits outside portable profile; must be exactly " << GCM_TAG_LEN_BITS
      << " bits (v0.6 sec:aesgcm)";
    return buildEncryptRecord(realization, inputJson.str(), {"gcm.tagLength"},
                               rejectOutcomeJson("invalid_parameter", d.str()));
  }

  // Invariant 1 (tagLength unit conversion): contractual tagLengthBits is
  // BITS; already validated == GCM_TAG_LEN_BITS == 128, so this is always
  // exactly GCM_TAG_LEN_BYTES == 16. Centralized here, used at exactly one
  // call site below -- not scattered.
  const int truncatedDigestSizeBytes = static_cast<int>(GCM_TAG_LEN_BYTES);

  GCM<AES>::Encryption enc;
  enc.SetKeyWithIV(req.key.data(), req.key.size(), req.iv.data(), req.iv.size());

  std::string cipherAndTag;
  // Invariant 2 (explicit MAC_AT_END-equivalent): AuthenticatedEncryptionFilter
  // has NO separate MAC-position flag; passing DEFAULT_CHANNEL explicitly as
  // macChannel (rather than omitting the argument) is the deliberate,
  // documented choice that makes the tag land in the SAME output sink as the
  // ciphertext, giving C||T -- not reliance on an unexamined default.
  AuthenticatedEncryptionFilter aef(enc, new StringSink(cipherAndTag), false /* putAAD */, truncatedDigestSizeBytes,
                                     DEFAULT_CHANNEL);

  // AAD_absent (req.aadPresent==false) never writes to AAD_CHANNEL at all --
  // v0.6's own source-confirmed architecture (ChannelPut2 only forwards to
  // GHASH when the caller explicitly writes to AAD_CHANNEL) is what makes
  // this equivalent to AAD_empty; this adapter relies on that confirmed
  // architecture, not an untested assumption.
  if (req.aadPresent) {
    if (!req.aad.empty()) {
      aef.ChannelPut(AAD_CHANNEL, req.aad.data(), req.aad.size());
    }
    aef.ChannelMessageEnd(AAD_CHANNEL);
  }
  if (!req.plaintext.empty()) {
    aef.ChannelPut(DEFAULT_CHANNEL, req.plaintext.data(), req.plaintext.size());
  }
  aef.ChannelMessageEnd(DEFAULT_CHANNEL);

  // Split invariant, checked explicitly here (not merely assumed from a
  // passing KAT, per the specific risk flagged for this adapter): |T|=16,
  // C=output[0:|output|-16], T=output[|output|-16:].
  const std::vector<uint8_t> cipherAndTagBytes(cipherAndTag.begin(), cipherAndTag.end());
  const std::vector<uint8_t> ciphertext(cipherAndTagBytes.begin(),
                                         cipherAndTagBytes.end() - static_cast<long>(GCM_TAG_LEN_BYTES));
  const std::vector<uint8_t> tag(cipherAndTagBytes.end() - static_cast<long>(GCM_TAG_LEN_BYTES),
                                  cipherAndTagBytes.end());

  const std::vector<uint8_t> artifact = BuildAeadArtifact(req.iv, ciphertext, tag);

  std::ostringstream outcome;
  outcome << "{\"kind\":\"accept\",\"artifactHex\":\"" << toHex(artifact) << "\"}";
  return buildEncryptRecord(
      realization, inputJson.str(),
      {"gcm.key", "gcm.plaintext", "gcm.aad", "gcm.iv", "gcm.tagLength", "gcm.ciphertext", "gcm.artifact"},
      outcome.str());
}

std::string GcmDecryptCryptoPP(const GcmDecryptRequest& req) {
  const std::string realization = realizationId();

  std::ostringstream inputJson;
  inputJson << "{"
            << "\"keyHex\":\"" << toHex(req.key) << "\","
            << "\"artifactHex\":\"" << toHex(req.artifact) << "\","
            << "\"aadHex\":" << (req.aadPresent ? ("\"" + toHex(req.aad) + "\"") : "null") << "}";

  // Step 1: gcm.key.
  if (req.key.size() != GCM_KEY_LEN_BYTES) {
    std::ostringstream d;
    d << "key length " << req.key.size() << " bytes, portable profile requires exactly " << GCM_KEY_LEN_BYTES
      << " (256 bits)";
    return buildDecryptRecord(realization, inputJson.str(), {"gcm.key"},
                               rejectOutcomeJson("invalid_parameter", d.str()));
  }

  // Step 2: gcm.artifact (structural), interleaved BEFORE step 3, exactly
  // as the frozen classification order requires (v0.6 sec:aesgcm) and
  // exactly as the WebCrypto adapter does (validateGcmDecryptKey ->
  // parseAeadArtifact -> validateGcmDecryptAad).
  AeadArtifactParts parts;
  std::string artifactErrorDetail;
  if (!ParseAeadArtifact(req.artifact, parts, artifactErrorDetail)) {
    return buildDecryptRecord(realization, inputJson.str(), {"gcm.artifact"},
                               rejectOutcomeJson("malformed_artifact", artifactErrorDetail));
  }

  // Step 3: gcm.aad -- trivially satisfied at the C++ type level (see this
  // function's header comment); kept as an explicit step only for
  // structural parity with the classification order, not because it can
  // fail here the way TypeScript's runtime guard can.

  // Step 4: the decrypt/authentication call itself.
  const int truncatedDigestSizeBytes = static_cast<int>(GCM_TAG_LEN_BYTES);
  GCM<AES>::Decryption dec;
  dec.SetKeyWithIV(req.key.data(), req.key.size(), parts.iv.data(), parts.iv.size());

  std::string recovered;
  try {
    // Invariant 2's decrypt-side counterpart: MAC_AT_END is passed
    // EXPLICITLY (spelled out, not via the DEFAULT_FLAGS constant which
    // happens to already include it) so the choice is self-documenting at
    // the call site, per this session's requirement.
    AuthenticatedDecryptionFilter adf(
        dec, new StringSink(recovered),
        AuthenticatedDecryptionFilter::MAC_AT_END | AuthenticatedDecryptionFilter::THROW_EXCEPTION,
        truncatedDigestSizeBytes);

    if (req.aadPresent) {
      if (!req.aad.empty()) {
        adf.ChannelPut(AAD_CHANNEL, req.aad.data(), req.aad.size());
      }
      adf.ChannelMessageEnd(AAD_CHANNEL);
    }

    std::vector<uint8_t> cipherAndTag;
    cipherAndTag.reserve(parts.ciphertext.size() + parts.tag.size());
    cipherAndTag.insert(cipherAndTag.end(), parts.ciphertext.begin(), parts.ciphertext.end());
    cipherAndTag.insert(cipherAndTag.end(), parts.tag.begin(), parts.tag.end());

    if (!cipherAndTag.empty()) {
      adf.ChannelPut(DEFAULT_CHANNEL, cipherAndTag.data(), cipherAndTag.size());
    }
    adf.ChannelMessageEnd(DEFAULT_CHANNEL);  // throws CryptoPP::Exception (HashVerificationFailed) on tag mismatch
  } catch (const CryptoPP::Exception&) {
    // Deliberately NOT inspecting the caught exception's type or message --
    // any failure reaching here, after steps 1-3 already passed, is
    // normalized to authentication_failure. No taxonomy is built from the
    // exception text, per this session's explicit rule (same discipline as
    // the WebCrypto adapter's blanket, uninspected catch).
    return buildDecryptRecord(
        realization, inputJson.str(), {"gcm.authentication"},
        rejectOutcomeJson("authentication_failure",
                           "GCM authentication failed (tag verification rejected the ciphertext/tag/AAD/IV combination)"));
  }

  const std::vector<uint8_t> recoveredBytes(recovered.begin(), recovered.end());
  std::ostringstream outcome;
  outcome << "{\"kind\":\"accept\",\"plaintextHex\":\"" << toHex(recoveredBytes) << "\"}";
  return buildDecryptRecord(realization, inputJson.str(), {"gcm.key", "gcm.aad", "gcm.artifact", "gcm.authentication"},
                             outcome.str());
}

}  // namespace paper4
