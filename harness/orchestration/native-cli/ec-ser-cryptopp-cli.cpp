// M2.5.2/M2.5.3.5 -- generic, parametric CLI around the real
// ExportEcSerCryptoPP / ImportEcSerCryptoPP adapters
// (src/adapters/cryptopp/ec-ser.hpp, M1, unmodified).
//
// Usage:
//   ec-ser-cryptopp-cli roundtrip <role> <xHex> <yHex> <dHex-or-empty>
//   ec-ser-cryptopp-cli export <role> <xHex> <yHex> <dHex-or-empty>
//   ec-ser-cryptopp-cli import <role> <artifactHex>
//
// 'import' echoes back the recovered x/y/d as hex (never re-deriving
// V_scalar/V_curve/V_pair itself) so the TypeScript caller can
// independently verify them using M1's own real p256.ts arithmetic --
// the SAME arithmetic module already used throughout M2.4.6/M2.5.2,
// never a second implementation.

#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <stdexcept>
#include <string>
#include <vector>

#include "integer.h"
#include "filters.h"
#include "../../../src/adapters/cryptopp/ec-ser.hpp"

namespace {
CryptoPP::Integer integerFromHex(const std::string& hex) {
  if (hex.empty()) return CryptoPP::Integer::Zero();
  return CryptoPP::Integer((hex + "h").c_str());
}
std::vector<uint8_t> bytesFromHex(const std::string& hex) {
  if (hex.size() % 2 != 0) throw std::invalid_argument("odd-length hex string");
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    for (int k = 0; k < 2; k++) {
      char c = hex[i + k];
      if (!std::isxdigit(static_cast<unsigned char>(c))) throw std::invalid_argument("non-hex character in artifact hex");
    }
    out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}
std::string hexFromBytes(const std::vector<uint8_t>& bytes) {
  std::string hex;
  static const char* digits = "0123456789abcdef";
  for (uint8_t b : bytes) { hex += digits[b >> 4]; hex += digits[b & 0xf]; }
  return hex;
}
std::string hexFromInteger(const CryptoPP::Integer& n) {
  if (n.IsZero()) return "";
  std::string s;
  CryptoPP::StringSink sink(s);
  n.Encode(sink, n.MinEncodedSize());
  std::vector<uint8_t> bytes(s.begin(), s.end());
  return hexFromBytes(bytes);
}
std::string jsonEscape(const std::string& s) {
  std::string out;
  for (char c : s) { if (c == '"' || c == '\\') out += '\\'; out += c; }
  return out;
}
}  // namespace

int main(int argc, char** argv) {
  std::string mode = argc >= 2 ? argv[1] : "";

  if (mode == "export") {
    if (argc != 6) { std::fprintf(stderr, "usage: %s export <role> <xHex> <yHex> <dHex-or-empty>\n", argv[0]); return 2; }
    paper4::EcKeyMaterial material;
    material.role = argv[2];
    material.q.isInfinity = false;
    material.q.x = integerFromHex(argv[3]);
    material.q.y = integerFromHex(argv[4]);
    material.d = integerFromHex(argv[5]);
    try {
      std::vector<uint8_t> artifact = paper4::ExportEcSerCryptoPP(material);
      std::printf("{\"exportOk\":true,\"artifactHex\":\"%s\"}\n", hexFromBytes(artifact).c_str());
    } catch (const std::exception& ex) {
      std::printf("{\"exportOk\":false,\"exportError\":\"%s\"}\n", jsonEscape(ex.what()).c_str());
    }
    return 0;
  }

  if (mode == "import") {
    if (argc != 4) { std::fprintf(stderr, "usage: %s import <role> <artifactHex>\n", argv[0]); return 2; }
    std::string role = argv[2];
    try {
      std::vector<uint8_t> artifact = bytesFromHex(argv[3]); // the OTHER backend's own literal artifact bytes, never re-encoded here
      paper4::EcSerImportResult result = paper4::ImportEcSerCryptoPP(artifact, role);
      std::printf(
        "{\"importOk\":true,\"normalized\":%s,\"recoveredXHex\":\"%s\",\"recoveredYHex\":\"%s\",\"recoveredDHex\":\"%s\"}\n",
        result.normalized ? "true" : "false",
        hexFromInteger(result.material.q.x).c_str(), hexFromInteger(result.material.q.y).c_str(),
        role == "private" ? hexFromInteger(result.material.d).c_str() : "");
    } catch (const paper4::EcSerError& err) {
      std::printf("{\"importOk\":false,\"errorClass\":\"%s\",\"detail\":\"%s\"}\n", jsonEscape(err.errorClass).c_str(), jsonEscape(err.detail).c_str());
    } catch (const std::exception& ex) {
      // Malformed argv (e.g. a truncated/empty artifactHex) is reported
      // structurally, never left to abort the process via an uncaught
      // exception -- a harness/environment failure must never masquerade
      // as either a silent crash or a false scientific result.
      std::printf("{\"importOk\":false,\"errorClass\":\"malformed_artifact\",\"detail\":\"%s\"}\n", jsonEscape(ex.what()).c_str());
    }
    return 0;
  }

  if (mode != "roundtrip" || argc != 6) {
    std::fprintf(stderr, "usage: %s roundtrip|export|import ...\n", argv[0]);
    return 2;
  }
  paper4::EcKeyMaterial material;
  material.role = argv[2];
  material.q.isInfinity = false;
  material.q.x = integerFromHex(argv[3]);
  material.q.y = integerFromHex(argv[4]);
  material.d = integerFromHex(argv[5]);

  std::vector<uint8_t> artifact;
  try {
    artifact = paper4::ExportEcSerCryptoPP(material);
  } catch (const std::exception& ex) {
    std::printf("{\"exportOk\":false,\"exportError\":\"%s\"}\n", jsonEscape(ex.what()).c_str());
    return 0;
  }

  try {
    paper4::EcSerImportResult result = paper4::ImportEcSerCryptoPP(artifact, material.role);
    // V_scalar/V_curve/V_pair are already enforced INSIDE ImportEcSerCryptoPP's
    // own Accept_C -- reaching this line without a thrown EcSerError IS the
    // positive confirmation. We additionally echo the recovered point back
    // for the caller's own independent cross-check against the material it
    // supplied, using no separate arithmetic of our own here.
    bool qMatches = result.material.q.x == material.q.x && result.material.q.y == material.q.y;
    bool dMatches = material.role != "private" || result.material.d == material.d;
    std::printf(
      "{\"exportOk\":true,\"artifactHex\":\"%s\",\"importOk\":true,\"normalized\":%s,\"materialPreserved\":%s}\n",
      hexFromBytes(artifact).c_str(), result.normalized ? "true" : "false", (qMatches && dMatches) ? "true" : "false");
  } catch (const paper4::EcSerError& err) {
    std::printf(
      "{\"exportOk\":true,\"artifactHex\":\"%s\",\"importOk\":false,\"errorClass\":\"%s\",\"detail\":\"%s\"}\n",
      hexFromBytes(artifact).c_str(), jsonEscape(err.errorClass).c_str(), jsonEscape(err.detail).c_str());
  }
  return 0;
}
