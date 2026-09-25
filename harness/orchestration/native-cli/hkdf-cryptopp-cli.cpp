// M2.5.2 -- generic, parametric CLI around the real HkdfCryptoPP adapter
// (src/adapters/cryptopp/hkdf.hpp, M1, unmodified). Distinct from M1's own
// scripts/run-hkdf-cryptopp.cpp, which runs FIXED regression cases; this
// CLI accepts an arbitrary request via argv so the M2 orchestrator can
// drive Crypto++ with the same generic ExecutionAdapter pattern already
// used for Chromium/Node. Lives under harness/ (M2), never scripts/ (M1),
// to keep the M1 boundary unambiguous.
//
// Usage: hkdf-cryptopp-cli <ikmHex> <saltHex-or-empty> <saltPresent:0|1> <infoHex> <length>
// Prints the real HkdfCryptoPP() JSON EvidenceRecord to stdout, unmodified.

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../../../src/adapters/cryptopp/hkdf.hpp"

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
  if (argc != 6) {
    std::fprintf(stderr, "usage: %s <ikmHex> <saltHex-or-empty> <saltPresent:0|1> <infoHex> <length>\n", argv[0]);
    return 2;
  }
  paper4::HkdfRequest req;
  req.ikm = fromHex(argv[1]);
  req.saltPresent = std::string(argv[3]) == "1";
  req.salt = req.saltPresent ? fromHex(argv[2]) : std::vector<uint8_t>{};
  req.info = fromHex(argv[4]);
  req.length = static_cast<size_t>(std::atoi(argv[5]));

  std::printf("%s\n", paper4::HkdfCryptoPP(req).c_str());
  return 0;
}
