// M2.5.2 -- generic, parametric CLI around the real PssSignCryptoPP /
// PssVerifyCryptoPP adapters (src/adapters/cryptopp/pss.hpp, M1,
// unmodified). Same discipline as oaep-cryptopp-cli.cpp.
//
// Usage:
//   pss-cryptopp-cli sign <declaredRole> <modulusHex> <pubExpHex> <privExpHex-or-empty> <modulusBits> <messageHex>
//   pss-cryptopp-cli verify <declaredRole> <modulusHex> <pubExpHex> <privExpHex-or-empty> <modulusBits> <messageHex> <signatureHex>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "integer.h"
#include "../../../src/adapters/cryptopp/pss.hpp"

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
  return CryptoPP::Integer((hex + "h").c_str());
}
}  // namespace

int main(int argc, char** argv) {
  if (argc < 7) {
    std::fprintf(stderr, "usage: %s sign|verify <declaredRole> <modulusHex> <pubExpHex> <privExpHex-or-empty> <modulusBits> <messageHex> [signatureHex]\n", argv[0]);
    return 2;
  }
  std::string mode = argv[1];

  paper4::PssKeyMaterial key;
  key.declaredRole = argv[2];
  key.modulus = integerFromHex(argv[3]);
  key.publicExponent = integerFromHex(argv[4]);
  key.privateExponent = integerFromHex(argv[5]);
  key.modulusBits = std::atoi(argv[6]);

  if (mode == "sign") {
    if (argc != 11) { std::fprintf(stderr, "sign requires <messageHex> <hash> <mgfHash> <saltLengthBytes>\n"); return 2; }
    paper4::PssSignRequest req;
    req.key = key;
    req.message = fromHex(argv[7]);
    req.hash = argv[8];
    req.mgfHash = argv[9];
    req.saltLengthBytes = static_cast<size_t>(std::stoul(argv[10]));
    std::printf("%s\n", paper4::PssSignCryptoPP(req).c_str());
    return 0;
  }
  if (mode == "verify") {
    if (argc != 12) { std::fprintf(stderr, "verify requires <messageHex> <signatureHex> <hash> <mgfHash> <saltLengthBytes>\n"); return 2; }
    paper4::PssVerifyRequest req;
    req.key = key;
    req.message = fromHex(argv[7]);
    req.signature = fromHex(argv[8]);
    req.hash = argv[9];
    req.mgfHash = argv[10];
    req.saltLengthBytes = static_cast<size_t>(std::stoul(argv[11]));
    std::printf("%s\n", paper4::PssVerifyCryptoPP(req).c_str());
    return 0;
  }
  std::fprintf(stderr, "unknown mode: %s\n", mode.c_str());
  return 2;
}
