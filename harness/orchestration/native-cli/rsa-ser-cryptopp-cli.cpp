// M2.5.2/M2.5.3.4 -- generic, parametric CLI around the real
// ExportRsaSerCryptoPP / ImportRsaSerCryptoPP adapters
// (src/adapters/cryptopp/rsa-ser.hpp, M1, unmodified). Unlike
// HKDF/GCM/OAEP/PSS's adapters, these return raw bytes/material directly,
// not a JSON EvidenceRecord -- this CLI builds its own JSON wrapper.
//
// Usage:
//   rsa-ser-cryptopp-cli roundtrip <role> <nHex> <eHex> <dHex-or-empty> <pHex-or-empty> <qHex-or-empty> <dPHex-or-empty> <dQHex-or-empty> <qInvHex-or-empty>
//   rsa-ser-cryptopp-cli export <role> <nHex> <eHex> <dHex-or-empty> <pHex-or-empty> <qHex-or-empty> <dPHex-or-empty> <dQHex-or-empty> <qInvHex-or-empty>
//   rsa-ser-cryptopp-cli import <role> <artifactHex> <expectedNHex> <expectedEHex> <expectedDHex-or-empty> <expectedPHex-or-empty> <expectedQHex-or-empty>
//
// 'import' is the M2.5.3.4 addition: takes an artifact PRODUCED BY ANOTHER
// BACKEND verbatim (never re-encoded here) and imports it through this
// backend's own real ImportRsaSerCryptoPP, checking the recovered material
// against the expected values supplied by the caller (which already knows
// what it exported elsewhere).

#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <stdexcept>
#include <string>
#include <vector>

#include "integer.h"
#include "../../../src/adapters/cryptopp/rsa-ser.hpp"

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
std::string jsonEscape(const std::string& s) {
  std::string out;
  for (char c : s) { if (c == '"' || c == '\\') out += '\\'; out += c; }
  return out;
}
}  // namespace

int main(int argc, char** argv) {
  std::string mode = argc >= 2 ? argv[1] : "";

  if (mode == "export") {
    if (argc != 11) { std::fprintf(stderr, "usage: %s export <role> <nHex> <eHex> <dHex-or-empty> <pHex-or-empty> <qHex-or-empty> <dPHex-or-empty> <dQHex-or-empty> <qInvHex-or-empty>\n", argv[0]); return 2; }
    paper4::RsaKeyMaterial material;
    material.role = argv[2];
    material.n = integerFromHex(argv[3]);
    material.e = integerFromHex(argv[4]);
    material.d = integerFromHex(argv[5]);
    material.p = integerFromHex(argv[6]);
    material.q = integerFromHex(argv[7]);
    material.dP = integerFromHex(argv[8]);
    material.dQ = integerFromHex(argv[9]);
    material.qInv = integerFromHex(argv[10]);
    try {
      std::vector<uint8_t> artifact = paper4::ExportRsaSerCryptoPP(material);
      std::printf("{\"exportOk\":true,\"artifactHex\":\"%s\"}\n", hexFromBytes(artifact).c_str());
    } catch (const std::exception& ex) {
      std::printf("{\"exportOk\":false,\"exportError\":\"%s\"}\n", jsonEscape(ex.what()).c_str());
    }
    return 0;
  }

  if (mode == "import") {
    if (argc != 9) { std::fprintf(stderr, "usage: %s import <role> <artifactHex> <expectedNHex> <expectedEHex> <expectedDHex-or-empty> <expectedPHex-or-empty> <expectedQHex-or-empty>\n", argv[0]); return 2; }
    std::string role = argv[2];
    try {
      std::vector<uint8_t> artifact = bytesFromHex(argv[3]); // the OTHER backend's own literal artifact bytes, never re-encoded here
      CryptoPP::Integer expectedN = integerFromHex(argv[4]);
      CryptoPP::Integer expectedE = integerFromHex(argv[5]);
      CryptoPP::Integer expectedD = integerFromHex(argv[6]);
      CryptoPP::Integer expectedP = integerFromHex(argv[7]);
      CryptoPP::Integer expectedQ = integerFromHex(argv[8]);
      paper4::RsaKeyMaterial recovered = paper4::ImportRsaSerCryptoPP(artifact, role);
      bool preserved = recovered.n == expectedN && recovered.e == expectedE &&
        (role != "private" || (recovered.d == expectedD && recovered.p == expectedP && recovered.q == expectedQ));
      std::printf("{\"importOk\":true,\"materialPreserved\":%s}\n", preserved ? "true" : "false");
    } catch (const paper4::RsaSerError& err) {
      std::printf("{\"importOk\":false,\"errorClass\":\"%s\",\"detail\":\"%s\"}\n", jsonEscape(err.errorClass).c_str(), jsonEscape(err.detail).c_str());
    } catch (const std::exception& ex) {
      // Malformed argv reported structurally, never left to abort the
      // process via an uncaught exception.
      std::printf("{\"importOk\":false,\"errorClass\":\"malformed_artifact\",\"detail\":\"%s\"}\n", jsonEscape(ex.what()).c_str());
    }
    return 0;
  }

  if (mode != "roundtrip" || argc != 11) {
    std::fprintf(stderr, "usage: %s roundtrip|export|import ...\n", argv[0]);
    return 2;
  }
  paper4::RsaKeyMaterial material;
  material.role = argv[2];
  material.n = integerFromHex(argv[3]);
  material.e = integerFromHex(argv[4]);
  material.d = integerFromHex(argv[5]);
  material.p = integerFromHex(argv[6]);
  material.q = integerFromHex(argv[7]);
  material.dP = integerFromHex(argv[8]);
  material.dQ = integerFromHex(argv[9]);
  material.qInv = integerFromHex(argv[10]);

  std::vector<uint8_t> artifact;
  try {
    artifact = paper4::ExportRsaSerCryptoPP(material);
  } catch (const std::exception& ex) {
    std::printf("{\"exportOk\":false,\"exportError\":\"%s\"}\n", jsonEscape(ex.what()).c_str());
    return 0;
  }

  try {
    paper4::RsaKeyMaterial recovered = paper4::ImportRsaSerCryptoPP(artifact, material.role);
    bool preserved = recovered.n == material.n && recovered.e == material.e &&
      (material.role != "private" || (recovered.d == material.d && recovered.p == material.p && recovered.q == material.q));
    std::printf(
      "{\"exportOk\":true,\"artifactHex\":\"%s\",\"importOk\":true,\"materialPreserved\":%s}\n",
      hexFromBytes(artifact).c_str(), preserved ? "true" : "false");
  } catch (const paper4::RsaSerError& err) {
    std::printf(
      "{\"exportOk\":true,\"artifactHex\":\"%s\",\"importOk\":false,\"errorClass\":\"%s\",\"detail\":\"%s\"}\n",
      hexFromBytes(artifact).c_str(), jsonEscape(err.errorClass).c_str(), jsonEscape(err.detail).c_str());
  }
  return 0;
}
