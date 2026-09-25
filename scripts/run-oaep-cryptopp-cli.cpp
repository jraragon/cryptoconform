// CLI wrapper around OaepEncryptCryptoPP/OaepDecryptCryptoPP for the 3x3
// interoperability orchestrator (scripts/run-oaep-interop-3x3.ts) to shell
// out to. Does not alter adapter logic in any way.
//
// Usage:
//   run-oaep-cryptopp-cli genkey
//     -> prints "modulusHex publicExponentHex privateExponentHex" (one line)
//   run-oaep-cryptopp-cli encrypt <modulusHex> <pubExpHex> <ptHex>
//     -> prints ciphertextHex on accept (exit 0), or "REJECT" (exit 1)
//   run-oaep-cryptopp-cli decrypt <modulusHex> <pubExpHex> <privExpHex> <ctHex>
//     -> prints plaintextHex on accept (exit 0), or "REJECT" (exit 1)

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../src/adapters/cryptopp/oaep.hpp"
#include "integer.h"
#include "hex.h"
#include "osrng.h"
#include "rsa.h"

using namespace CryptoPP;

namespace {

std::vector<uint8_t> fromHex(const std::string& hex) {
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}

std::string integerToHex(const Integer& n) {
  std::string out;
  HexEncoder encoder(new StringSink(out));
  n.Encode(encoder, n.MinEncodedSize());
  encoder.MessageEnd();
  for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

Integer hexToInteger(const std::string& hex) {
  return Integer((std::string("0x") + hex).c_str());
}

std::string extractField(const std::string& record, const std::string& key) {
  const std::string marker = "\"" + key + "\":\"";
  size_t start = record.find(marker);
  if (start == std::string::npos) return "";
  start += marker.size();
  size_t end = record.find('"', start);
  return record.substr(start, end - start);
}

bool contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

}  // namespace

int main(int argc, char** argv) {
  using namespace paper4;

  if (argc < 2) {
    std::fprintf(stderr, "usage: %s genkey|encrypt|decrypt ...\n", argv[0]);
    return 2;
  }
  const std::string mode = argv[1];

  if (mode == "genkey") {
    const OaepKeyMaterial material = GenerateOaepKeyMaterial();
    std::printf("%s %s %s\n", integerToHex(material.modulus).c_str(), integerToHex(material.publicExponent).c_str(),
                integerToHex(material.privateExponent).c_str());
    return 0;
  }

  if (mode == "encrypt") {
    if (argc != 5) {
      std::fprintf(stderr, "usage: %s encrypt <modulusHex> <pubExpHex> <ptHex>\n", argv[0]);
      return 2;
    }
    OaepEncryptRequest req;
    req.key.declaredRole = "public";
    req.key.modulus = hexToInteger(argv[2]);
    req.key.publicExponent = hexToInteger(argv[3]);
    req.key.modulusBits = req.key.modulus.BitCount();
    req.plaintext = fromHex(argv[4]);
    req.labelPresent = false;

    const std::string record = OaepEncryptCryptoPP(req);
    if (contains(record, "\"kind\":\"accept\"")) {
      std::printf("%s\n", extractField(record, "ciphertextHex").c_str());
      return 0;
    }
    std::printf("REJECT\n");
    return 1;
  }

  if (mode == "decrypt") {
    if (argc != 6) {
      std::fprintf(stderr, "usage: %s decrypt <modulusHex> <pubExpHex> <privExpHex> <ctHex>\n", argv[0]);
      return 2;
    }
    OaepDecryptRequest req;
    req.key.declaredRole = "private";
    req.key.modulus = hexToInteger(argv[2]);
    req.key.publicExponent = hexToInteger(argv[3]);
    req.key.privateExponent = hexToInteger(argv[4]);
    req.key.modulusBits = req.key.modulus.BitCount();
    req.ciphertext = fromHex(argv[5]);
    req.labelPresent = false;

    const std::string record = OaepDecryptCryptoPP(req);
    if (contains(record, "\"kind\":\"accept\"")) {
      std::printf("%s\n", extractField(record, "plaintextHex").c_str());
      return 0;
    }
    std::printf("REJECT\n");
    return 1;
  }

  std::fprintf(stderr, "unknown mode: %s\n", mode.c_str());
  return 2;
}
