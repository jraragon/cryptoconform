// M2.5.2 -- generic, parametric CLI around the real OaepEncryptCryptoPP /
// OaepDecryptCryptoPP adapters (src/adapters/cryptopp/oaep.hpp, M1,
// unmodified). Same discipline as hkdf-cryptopp-cli.cpp/gcm-cryptopp-cli.cpp.
//
// Usage:
//   oaep-cryptopp-cli encrypt <declaredRole> <modulusHex> <pubExpHex> <privExpHex-or-empty> <modulusBits> <plaintextHex> <labelHex-or-empty> <labelPresent:0|1> <hash> <mgfHash>
//   oaep-cryptopp-cli decrypt <declaredRole> <modulusHex> <pubExpHex> <privExpHex-or-empty> <modulusBits> <ciphertextHex> <labelHex-or-empty> <labelPresent:0|1> <hash> <mgfHash>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "integer.h"
#include "../../../src/adapters/cryptopp/oaep.hpp"

namespace {
std::vector<uint8_t> fromHex(const std::string& hex) {
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}

CryptoPP::Integer integerFromHex(const std::string& hex) {
  if (hex.empty()) return CryptoPP::Integer::Zero();
  return CryptoPP::Integer((hex + "h").c_str());  // Crypto++'s own "<hex>h" literal suffix convention
}
}  // namespace

int main(int argc, char** argv) {
  if (argc != 12) {
    std::fprintf(stderr,
      "usage: %s encrypt|decrypt <declaredRole> <modulusHex> <pubExpHex> <privExpHex-or-empty> "
      "<modulusBits> <plaintext-or-ciphertextHex> <labelHex-or-empty> <labelPresent:0|1> <hash> <mgfHash>\n", argv[0]);
    return 2;
  }
  std::string mode = argv[1];

  paper4::OaepKeyMaterial key;
  key.declaredRole = argv[2];
  key.modulus = integerFromHex(argv[3]);
  key.publicExponent = integerFromHex(argv[4]);
  key.privateExponent = integerFromHex(argv[5]);
  key.modulusBits = std::atoi(argv[6]);

  bool labelPresent = std::string(argv[9]) == "1";
  std::vector<uint8_t> label = labelPresent ? fromHex(argv[8]) : std::vector<uint8_t>{};

  if (mode == "encrypt") {
    paper4::OaepEncryptRequest req;
    req.key = key;
    req.plaintext = fromHex(argv[7]);
    req.label = label;
    req.labelPresent = labelPresent;
    req.hash = argv[10];
    req.mgfHash = argv[11];
    std::printf("%s\n", paper4::OaepEncryptCryptoPP(req).c_str());
    return 0;
  }
  if (mode == "decrypt") {
    paper4::OaepDecryptRequest req;
    req.key = key;
    req.ciphertext = fromHex(argv[7]);
    req.label = label;
    req.labelPresent = labelPresent;
    req.hash = argv[10];
    req.mgfHash = argv[11];
    std::printf("%s\n", paper4::OaepDecryptCryptoPP(req).c_str());
    return 0;
  }
  std::fprintf(stderr, "unknown mode: %s\n", mode.c_str());
  return 2;
}
