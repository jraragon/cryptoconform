#include "hkdf.hpp"

#include <chrono>
#include <cctype>
#include <iomanip>
#include <sstream>

#include "cryptlib.h"
#include "filters.h"
#include "hex.h"
#include "hkdf.h"
#include "sha.h"

using namespace CryptoPP;

namespace paper4 {
namespace {

constexpr size_t HASH_LEN = 32;      // HKDF-SHA-256
constexpr size_t MIN_L = 1;          // D-068
constexpr size_t MAX_L = 255 * HASH_LEN;  // 8160, D-068

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
  ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%S") << '.'
     << std::setw(3) << std::setfill('0') << ms.count() << 'Z';
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
  // CRYPTOPP_VERSION is a compile-time integer macro (e.g. 890 = 8.9.0).
  // The exact pinned tag/commit is recorded in Experimental_Evidence_Base
  // v0.1, sec:environment -- this string is a runtime cross-check, not the
  // authoritative pin.
  std::ostringstream ss;
  ss << "cryptopp:" << CRYPTOPP_VERSION
     << " HKDF<SHA256>::DeriveKey (raw-pointer overload; see sec:environment "
        "for exact pinned build)";
  return ss.str();
}

}  // namespace

std::string HkdfCryptoPP(const HkdfRequest& req) {
  const std::string realization = realizationId();

  std::ostringstream inputJson;
  inputJson << "{"
            << "\"ikmHex\":\"" << toHex(req.ikm) << "\","
            << "\"saltHex\":"
            << (req.saltPresent ? ("\"" + toHex(req.salt) + "\"") : "null")
            << ","
            << "\"infoHex\":\"" << toHex(req.info) << "\","
            << "\"length\":" << req.length << "}";

  // Accept_C(request) -- SDK-level admission, enforced by the adapter
  // itself. HKDF<SHA256>::DeriveKey performs no portable-profile bound
  // checking of its own; the D-054/D-060 pattern (no backend guarantees
  // the contract natively) applies here exactly as it did for RSA-ser/EC-ser.
  if (!(req.length >= MIN_L && req.length <= MAX_L)) {
    std::ostringstream detail;
    detail << "L=" << req.length << " outside portable-profile bound "
           << MIN_L << "<=L<=" << MAX_L << " (D-068)";

    std::ostringstream out;
    out << "{"
        << "\"operation\":\"HKDF-SHA-256\","
        << "\"backend\":{\"name\":\"cryptopp\",\"realization\":\""
        << realization << "\"},"
        << "\"clauseIds\":" << jsonStringArray({"hkdf.length"}) << ","
        << "\"mutationId\":null,"
        << "\"input\":" << inputJson.str() << ","
        << "\"outcome\":{\"kind\":\"reject\",\"errorClass\":\"invalid_"
           "parameter\",\"detail\":\""
        << detail.str() << "\"},"
        << "\"timestampIso\":\"" << nowIso() << "\""
        << "}";
    return out.str();
  }

  // RFC 5869: absent salt = HashLen zero octets. Applied explicitly here,
  // NOT delegated to HKDF<SHA256>::DeriveKey's own null-salt handling --
  // the official docs flag null-vs-zero-length salt as behaviorally
  // significant ("HKDF is unusual in that a non-NULL salt with length 0
  // is different than a NULL salt"), and this adapter does not rely on an
  // unconfirmed default for a contractual property (mirrors the WebCrypto
  // adapter's explicit `req.salt ?? new Uint8Array(0)` handling).
  const std::vector<uint8_t> effectiveSalt =
      req.saltPresent ? req.salt : std::vector<uint8_t>(HASH_LEN, 0);

  std::vector<uint8_t> derived(req.length);
  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(derived.data(), derived.size(),
                 req.ikm.empty() ? nullptr : req.ikm.data(), req.ikm.size(),
                 effectiveSalt.empty() ? nullptr : effectiveSalt.data(),
                 effectiveSalt.size(),
                 req.info.empty() ? nullptr : req.info.data(),
                 req.info.size());

  std::ostringstream out;
  out << "{"
      << "\"operation\":\"HKDF-SHA-256\","
      << "\"backend\":{\"name\":\"cryptopp\",\"realization\":\""
      << realization << "\"},"
      << "\"clauseIds\":"
      << jsonStringArray({"hkdf.ikm", "hkdf.salt", "hkdf.info", "hkdf.hash",
                           "hkdf.length", "hkdf.output"})
      << ","
      << "\"mutationId\":null,"
      << "\"input\":" << inputJson.str() << ","
      << "\"outcome\":{\"kind\":\"accept\",\"okmHex\":\"" << toHex(derived)
      << "\"},"
      << "\"timestampIso\":\"" << nowIso() << "\""
      << "}";
  return out.str();
}

}  // namespace paper4
