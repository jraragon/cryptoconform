// M2.5.2 -- generic, parametric CLI around the real GcmEncryptCryptoPP /
// GcmDecryptCryptoPP adapters (src/adapters/cryptopp/gcm.hpp, M1,
// unmodified). Same discipline as hkdf-cryptopp-cli.cpp.
//
// Usage:
//   gcm-cryptopp-cli encrypt <keyHex> <plaintextHex> <aadHex-or-empty> <aadPresent:0|1> <ivHex> <tagLengthBits>
//   gcm-cryptopp-cli decrypt <keyHex> <artifactHex> <aadHex-or-empty> <aadPresent:0|1>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../../../src/adapters/cryptopp/gcm.hpp"

namespace {
std::vector<uint8_t> fromHex(const std::string& hex) {
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: %s encrypt|decrypt ...\n", argv[0]);
    return 2;
  }
  std::string mode = argv[1];

  if (mode == "encrypt") {
    if (argc != 8) {
      std::fprintf(stderr, "usage: %s encrypt <keyHex> <plaintextHex> <aadHex-or-empty> <aadPresent:0|1> <ivHex> <tagLengthBits>\n", argv[0]);
      return 2;
    }
    paper4::GcmEncryptRequest req;
    req.key = fromHex(argv[2]);
    req.plaintext = fromHex(argv[3]);
    req.aadPresent = std::string(argv[5]) == "1";
    req.aad = req.aadPresent ? fromHex(argv[4]) : std::vector<uint8_t>{};
    req.iv = fromHex(argv[6]);
    req.tagLengthBits = static_cast<size_t>(std::atoi(argv[7]));
    std::printf("%s\n", paper4::GcmEncryptCryptoPP(req).c_str());
    return 0;
  }

  if (mode == "decrypt") {
    if (argc != 6) {
      std::fprintf(stderr, "usage: %s decrypt <keyHex> <artifactHex> <aadHex-or-empty> <aadPresent:0|1>\n", argv[0]);
      return 2;
    }
    paper4::GcmDecryptRequest req;
    req.key = fromHex(argv[2]);
    req.artifact = fromHex(argv[3]);
    req.aadPresent = std::string(argv[5]) == "1";
    req.aad = req.aadPresent ? fromHex(argv[4]) : std::vector<uint8_t>{};
    std::printf("%s\n", paper4::GcmDecryptCryptoPP(req).c_str());
    return 0;
  }

  std::fprintf(stderr, "unknown mode: %s\n", mode.c_str());
  return 2;
}
