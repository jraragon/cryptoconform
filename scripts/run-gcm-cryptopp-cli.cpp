// CLI wrapper around GcmEncryptCryptoPP/GcmDecryptCryptoPP for the 3x3
// interoperability orchestrator (scripts/run-gcm-interop-3x3.ts) to shell
// out to. Does not alter adapter logic in any way -- purely argv parsing
// and stdout formatting around the existing, already-tested functions.
//
// Usage:
//   run-gcm-cryptopp-cli encrypt <keyHex> <ivHex> <aadHexOrABSENT> <ptHex> <tagLengthBits>
//   run-gcm-cryptopp-cli decrypt <keyHex> <artifactHex> <aadHexOrABSENT>
// Prints artifactHex/plaintextHex on accept (exit 0), or "REJECT" (exit 1).

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../src/adapters/cryptopp/gcm.hpp"

namespace {

std::vector<uint8_t> fromHex(const std::string& hex) {
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
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
    std::fprintf(stderr, "usage: %s encrypt|decrypt ...\n", argv[0]);
    return 2;
  }
  const std::string mode = argv[1];

  if (mode == "encrypt") {
    if (argc != 7) {
      std::fprintf(stderr, "usage: %s encrypt <keyHex> <ivHex> <aadHexOrABSENT> <ptHex> <tagLengthBits>\n", argv[0]);
      return 2;
    }
    GcmEncryptRequest req;
    req.key = fromHex(argv[2]);
    req.iv = fromHex(argv[3]);
    const std::string aadArg = argv[4];
    if (aadArg == "ABSENT") {
      req.aadPresent = false;
    } else {
      req.aadPresent = true;
      req.aad = fromHex(aadArg);
    }
    req.plaintext = fromHex(argv[5]);
    req.tagLengthBits = static_cast<size_t>(std::stoul(argv[6]));

    const std::string record = GcmEncryptCryptoPP(req);
    if (contains(record, "\"kind\":\"accept\"")) {
      std::printf("%s\n", extractField(record, "artifactHex").c_str());
      return 0;
    }
    std::printf("REJECT\n");
    return 1;
  }

  if (mode == "decrypt") {
    if (argc != 5) {
      std::fprintf(stderr, "usage: %s decrypt <keyHex> <artifactHex> <aadHexOrABSENT>\n", argv[0]);
      return 2;
    }
    GcmDecryptRequest req;
    req.key = fromHex(argv[2]);
    req.artifact = fromHex(argv[3]);
    const std::string aadArg = argv[4];
    if (aadArg == "ABSENT") {
      req.aadPresent = false;
    } else {
      req.aadPresent = true;
      req.aad = fromHex(aadArg);
    }

    const std::string record = GcmDecryptCryptoPP(req);
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
