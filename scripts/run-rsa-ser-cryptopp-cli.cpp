// CLI wrapper around the RSA-ser Crypto++ adapter for the cross-provider
// interop orchestrator (scripts/run-rsa-ser-interop.ts) to shell out to.
// Does not alter adapter logic in any way.
//
// Usage:
//   run-rsa-ser-cryptopp-cli genkey
//     -> prints "nHex eHex dHex pHex qHex dPHex dQHex qInvHex" (one line)
//   run-rsa-ser-cryptopp-cli export-spki <nHex> <eHex>
//     -> prints SPKI DER as hex
//   run-rsa-ser-cryptopp-cli export-pkcs8 <nHex> <eHex> <dHex> <pHex> <qHex> <dPHex> <dQHex> <qInvHex>
//     -> prints PKCS8 DER as hex
//   run-rsa-ser-cryptopp-cli import-public <artifactHex>
//     -> prints "nHex eHex" on accept (exit 0), or "REJECT <errorClass> <clauseId>" (exit 1)
//   run-rsa-ser-cryptopp-cli import-private <artifactHex>
//     -> prints "nHex eHex dHex pHex qHex dPHex dQHex qInvHex" on accept (exit 0), or "REJECT ..." (exit 1)

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../src/adapters/cryptopp/rsa-ser.hpp"
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

Integer hexToInteger(const std::string& hex) {
  return Integer((std::string("0x") + hex).c_str());
}

}  // namespace

int main(int argc, char** argv) {
  using namespace paper4;

  if (argc < 2) {
    std::fprintf(stderr, "usage: %s genkey|export-spki|export-pkcs8|import-public|import-private ...\n", argv[0]);
    return 2;
  }
  const std::string mode = argv[1];

  if (mode == "genkey") {
    const RsaKeyMaterial m = GenerateRsaSerKeyMaterial(3072);
    std::printf("%s %s %s %s %s %s %s %s\n", integerToHex(m.n).c_str(), integerToHex(m.e).c_str(),
                integerToHex(m.d).c_str(), integerToHex(m.p).c_str(), integerToHex(m.q).c_str(),
                integerToHex(m.dP).c_str(), integerToHex(m.dQ).c_str(), integerToHex(m.qInv).c_str());
    return 0;
  }

  if (mode == "export-spki") {
    if (argc != 4) { std::fprintf(stderr, "usage: export-spki <nHex> <eHex>\n"); return 2; }
    RsaKeyMaterial m;
    m.role = "public";
    m.n = hexToInteger(argv[2]);
    m.e = hexToInteger(argv[3]);
    std::printf("%s\n", toHex(ExportRsaSerCryptoPP(m)).c_str());
    return 0;
  }

  if (mode == "export-pkcs8") {
    if (argc != 10) { std::fprintf(stderr, "usage: export-pkcs8 <n> <e> <d> <p> <q> <dP> <dQ> <qInv>\n"); return 2; }
    RsaKeyMaterial m;
    m.role = "private";
    m.n = hexToInteger(argv[2]);
    m.e = hexToInteger(argv[3]);
    m.d = hexToInteger(argv[4]);
    m.p = hexToInteger(argv[5]);
    m.q = hexToInteger(argv[6]);
    m.dP = hexToInteger(argv[7]);
    m.dQ = hexToInteger(argv[8]);
    m.qInv = hexToInteger(argv[9]);
    std::printf("%s\n", toHex(ExportRsaSerCryptoPP(m)).c_str());
    return 0;
  }

  if (mode == "import-public") {
    if (argc != 3) { std::fprintf(stderr, "usage: import-public <artifactHex>\n"); return 2; }
    try {
      RsaKeyMaterial m = ImportRsaSerCryptoPP(fromHex(argv[2]), "public");
      std::printf("%s %s\n", integerToHex(m.n).c_str(), integerToHex(m.e).c_str());
      return 0;
    } catch (const RsaSerError& err) {
      std::printf("REJECT %s %s\n", err.errorClass.c_str(), err.clauseId.c_str());
      return 1;
    }
  }

  if (mode == "import-private") {
    if (argc != 3) { std::fprintf(stderr, "usage: import-private <artifactHex>\n"); return 2; }
    try {
      RsaKeyMaterial m = ImportRsaSerCryptoPP(fromHex(argv[2]), "private");
      std::printf("%s %s %s %s %s %s %s %s\n", integerToHex(m.n).c_str(), integerToHex(m.e).c_str(),
                  integerToHex(m.d).c_str(), integerToHex(m.p).c_str(), integerToHex(m.q).c_str(),
                  integerToHex(m.dP).c_str(), integerToHex(m.dQ).c_str(), integerToHex(m.qInv).c_str());
      return 0;
    } catch (const RsaSerError& err) {
      std::printf("REJECT %s %s\n", err.errorClass.c_str(), err.clauseId.c_str());
      return 1;
    }
  }

  // --- Genuinely native-only verbs (this session's explicit correction) --
  // NEVER call ExportRsaSerCryptoPP/ImportRsaSerCryptoPP (the SDK's own
  // contract-level codec/Accept_C) -- only NativeCryptoPPSpkiExport/
  // PkcsExport/NativeCryptoPPImport, which use RSA::PublicKey/PrivateKey +
  // Save()/Load() exclusively.

  if (mode == "native-export-spki") {
    if (argc != 4) { std::fprintf(stderr, "usage: native-export-spki <nHex> <eHex>\n"); return 2; }
    RsaKeyMaterial m;
    m.role = "public";
    m.n = hexToInteger(argv[2]);
    m.e = hexToInteger(argv[3]);
    std::printf("%s\n", toHex(NativeCryptoPPSpkiExport(m)).c_str());
    return 0;
  }

  if (mode == "native-export-pkcs8") {
    if (argc != 10) { std::fprintf(stderr, "usage: native-export-pkcs8 <n> <e> <d> <p> <q> <dP> <dQ> <qInv>\n"); return 2; }
    RsaKeyMaterial m;
    m.role = "private";
    m.n = hexToInteger(argv[2]);
    m.e = hexToInteger(argv[3]);
    m.d = hexToInteger(argv[4]);
    m.p = hexToInteger(argv[5]);
    m.q = hexToInteger(argv[6]);
    m.dP = hexToInteger(argv[7]);
    m.dQ = hexToInteger(argv[8]);
    m.qInv = hexToInteger(argv[9]);
    std::printf("%s\n", toHex(NativeCryptoPPPkcs8Export(m)).c_str());
    return 0;
  }

  if (mode == "native-import-public") {
    if (argc != 3) { std::fprintf(stderr, "usage: native-import-public <artifactHex>\n"); return 2; }
    try {
      RsaKeyMaterial m = NativeCryptoPPImport(fromHex(argv[2]), "public");
      std::printf("%s %s\n", integerToHex(m.n).c_str(), integerToHex(m.e).c_str());
      return 0;
    } catch (const std::exception& ex) {
      std::printf("REJECT native %s\n", ex.what());
      return 1;
    }
  }

  if (mode == "native-import-private") {
    if (argc != 3) { std::fprintf(stderr, "usage: native-import-private <artifactHex>\n"); return 2; }
    try {
      RsaKeyMaterial m = NativeCryptoPPImport(fromHex(argv[2]), "private");
      std::printf("%s %s %s %s %s %s %s %s\n", integerToHex(m.n).c_str(), integerToHex(m.e).c_str(),
                  integerToHex(m.d).c_str(), integerToHex(m.p).c_str(), integerToHex(m.q).c_str(),
                  integerToHex(m.dP).c_str(), integerToHex(m.dQ).c_str(), integerToHex(m.qInv).c_str());
      return 0;
    } catch (const std::exception& ex) {
      std::printf("REJECT native %s\n", ex.what());
      return 1;
    }
  }

  std::fprintf(stderr, "unknown mode: %s\n", mode.c_str());
  return 2;
}
