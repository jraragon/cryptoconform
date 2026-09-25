// CLI wrapper around the EC-ser Crypto++ adapter for the cross-provider
// interop orchestrator to shell out to. Mirrors run-rsa-ser-cryptopp-cli.cpp's
// two-level design (SDK/contract verbs vs native-* verbs).
//
// Usage:
//   genkey -> "dHex xHex yHex" (one line)
//   export-spki <xHex> <yHex> -> SPKI DER hex (SDK/contract canonical writer)
//   export-pkcs8 <dHex> <xHex> <yHex> -> PKCS8 DER hex (SDK/contract canonical writer)
//   import-public <artifactHex> -> "xHex yHex" or "REJECT <errorClass> <clauseId>"
//   import-private <artifactHex> -> "dHex xHex yHex normalized(0|1)" or "REJECT ..."
//   native-export-spki <xHex> <yHex> -> SPKI DER hex (genuine Crypto++ native writer)
//   native-export-pkcs8 <dHex> <xHex> <yHex> -> PKCS8 DER hex (genuine native writer)
//   native-import-public <artifactHex> -> "xHex yHex" or "REJECT native <msg>"
//   native-import-private <artifactHex> -> "dHex" or "REJECT native <msg>" (Q never recovered natively, confirmed parse-then-discard)

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../src/adapters/cryptopp/ec-ser.hpp"
#include "hex.h"
#include "integer.h"

using namespace CryptoPP;

namespace {

std::vector<uint8_t> fromHex(const std::string& hex) {
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
  return out;
}

std::string toHex(const std::vector<uint8_t>& bytes) {
  std::string out;
  HexEncoder encoder(new StringSink(out));
  if (!bytes.empty()) encoder.Put(bytes.data(), bytes.size());
  encoder.MessageEnd();
  for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
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

Integer hexToInteger(const std::string& hex) { return Integer((std::string("0x") + hex).c_str()); }

}  // namespace

int main(int argc, char** argv) {
  using namespace paper4;

  if (argc < 2) {
    std::fprintf(stderr, "usage: %s <verb> ...\n", argv[0]);
    return 2;
  }
  const std::string mode = argv[1];

  if (mode == "genkey") {
    const EcKeyMaterial m = GenerateEcSerKeyMaterial();
    std::printf("%s %s %s\n", integerToHex(m.d).c_str(), integerToHex(m.q.x).c_str(), integerToHex(m.q.y).c_str());
    return 0;
  }

  if (mode == "export-spki") {
    if (argc != 4) { std::fprintf(stderr, "usage: export-spki <xHex> <yHex>\n"); return 2; }
    EcKeyMaterial m;
    m.role = "public";
    m.q.x = hexToInteger(argv[2]);
    m.q.y = hexToInteger(argv[3]);
    std::printf("%s\n", toHex(ExportEcSerCryptoPP(m)).c_str());
    return 0;
  }

  if (mode == "export-pkcs8") {
    if (argc != 5) { std::fprintf(stderr, "usage: export-pkcs8 <dHex> <xHex> <yHex>\n"); return 2; }
    EcKeyMaterial m;
    m.role = "private";
    m.d = hexToInteger(argv[2]);
    m.q.x = hexToInteger(argv[3]);
    m.q.y = hexToInteger(argv[4]);
    std::printf("%s\n", toHex(ExportEcSerCryptoPP(m)).c_str());
    return 0;
  }

  if (mode == "import-public") {
    if (argc != 3) { std::fprintf(stderr, "usage: import-public <artifactHex>\n"); return 2; }
    try {
      auto result = ImportEcSerCryptoPP(fromHex(argv[2]), "public");
      std::printf("%s %s\n", integerToHex(result.material.q.x).c_str(), integerToHex(result.material.q.y).c_str());
      return 0;
    } catch (const EcSerError& err) {
      std::printf("REJECT %s %s\n", err.errorClass.c_str(), err.clauseId.c_str());
      return 1;
    }
  }

  if (mode == "import-private") {
    if (argc != 3) { std::fprintf(stderr, "usage: import-private <artifactHex>\n"); return 2; }
    try {
      auto result = ImportEcSerCryptoPP(fromHex(argv[2]), "private");
      std::printf("%s %s %s %d\n", integerToHex(result.material.d).c_str(), integerToHex(result.material.q.x).c_str(),
                  integerToHex(result.material.q.y).c_str(), result.normalized ? 1 : 0);
      return 0;
    } catch (const EcSerError& err) {
      std::printf("REJECT %s %s\n", err.errorClass.c_str(), err.clauseId.c_str());
      return 1;
    }
  }

  if (mode == "native-export-spki") {
    if (argc != 4) { std::fprintf(stderr, "usage: native-export-spki <xHex> <yHex>\n"); return 2; }
    EcKeyMaterial m;
    m.role = "public";
    m.q.x = hexToInteger(argv[2]);
    m.q.y = hexToInteger(argv[3]);
    std::printf("%s\n", toHex(NativeCryptoPPSpkiExport(m)).c_str());
    return 0;
  }

  if (mode == "native-export-pkcs8") {
    if (argc != 5) { std::fprintf(stderr, "usage: native-export-pkcs8 <dHex> <xHex> <yHex>\n"); return 2; }
    EcKeyMaterial m;
    m.role = "private";
    m.d = hexToInteger(argv[2]);
    m.q.x = hexToInteger(argv[3]);
    m.q.y = hexToInteger(argv[4]);
    std::printf("%s\n", toHex(NativeCryptoPPPkcs8Export(m)).c_str());
    return 0;
  }

  if (mode == "native-import-public") {
    if (argc != 3) { std::fprintf(stderr, "usage: native-import-public <artifactHex>\n"); return 2; }
    try {
      EcKeyMaterial m = NativeCryptoPPImport(fromHex(argv[2]), "public");
      std::printf("%s %s\n", integerToHex(m.q.x).c_str(), integerToHex(m.q.y).c_str());
      return 0;
    } catch (const std::exception& ex) {
      std::printf("REJECT native %s\n", ex.what());
      return 1;
    }
  }

  if (mode == "native-import-private") {
    if (argc != 3) { std::fprintf(stderr, "usage: native-import-private <artifactHex>\n"); return 2; }
    try {
      EcKeyMaterial m = NativeCryptoPPImport(fromHex(argv[2]), "private");
      std::printf("%s\n", integerToHex(m.d).c_str());
      return 0;
    } catch (const std::exception& ex) {
      std::printf("REJECT native %s\n", ex.what());
      return 1;
    }
  }

  std::fprintf(stderr, "unknown mode: %s\n", mode.c_str());
  return 2;
}
