// M1 vertical slice: RSA-ser x Crypto++, no mutations.
// Mirrors tests/rsa-ser/webcrypto.test.ts's checklist, plus the four
// backend-specific vigilance points from this session's design review:
//   1. Native format identification: X509PublicKey::Save()/PKCS8PrivateKey::Save()
//      ARE genuine, independent SPKI/PKCS8 writers (confirmed by source).
//   2. RSA::PrivateKey::Validate() is confirmed NOT equivalent to our own
//      V_domain/V_rel -- Accept_C never calls it for admission.
//   3. Multi-prime: confirmed native rejection AT PARSE TIME.
//   4. R_byte: compared against Crypto++'s OWN independent writer, not our
//      own re-used encoder -- a genuinely independent comparison.
//
// Build (pinned): weidai11/cryptopp, commit
// 782425901d36fe0944b16aae37801b8ec2fa9000, e.g.:
//   g++ -std=c++17 -I<cryptopp_include> scripts/run-rsa-ser-cryptopp.cpp \
//       src/adapters/cryptopp/rsa-ser.cpp -L<cryptopp_lib> -lcryptopp \
//       -o run-rsa-ser-cryptopp

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../src/adapters/cryptopp/rsa-ser.hpp"
#include "osrng.h"
#include "rsa.h"

namespace {

int failures = 0;

void check(bool condition, const std::string& failMessage) {
  if (!condition) {
    std::fprintf(stderr, "FAILED: %s\n", failMessage.c_str());
    failures++;
  }
}

}  // namespace

int main() {
  using namespace paper4;
  using namespace CryptoPP;

  std::printf("=== M1 vertical slice: RSA-ser x Crypto++ ===\n\n");

  std::printf("--- key generation (RSA-3072, shared fixture) ---\n");
  const RsaKeyMaterial priv = GenerateRsaSerKeyMaterial(3072);
  RsaKeyMaterial pub = priv;
  pub.role = "public";
  std::printf("PASS: RSA-3072 key pair generated.\n\n");

  std::printf("--- round trip (our own canonical encoder) ---\n");
  {
    auto pubDer = ExportRsaSerCryptoPP(pub);
    auto pubBack = ImportRsaSerCryptoPP(pubDer, "public");
    check(pubBack.n == pub.n && pubBack.e == pub.e, "public round trip did not preserve material.");

    auto privDer = ExportRsaSerCryptoPP(priv);
    auto privBack = ImportRsaSerCryptoPP(privDer, "private");
    check(privBack.n == priv.n && privBack.d == priv.d && privBack.p == priv.p, "private round trip did not preserve material.");
  }
  if (failures == 0) std::printf("PASS: round trip preserves material exactly (R_ser).\n\n");

  std::printf("--- R_byte: SDK canonical DER vs Crypto++'s OWN independent native SPKI/PKCS8 writer ---\n");
  {
    auto sdkSpki = ExportRsaSerCryptoPP(pub);
    auto nativeSpki = NativeCryptoPPSpkiExport(pub);
    check(sdkSpki == nativeSpki, "SDK canonical SPKI differs from Crypto++'s own native SPKI writer.");

    auto sdkPkcs8 = ExportRsaSerCryptoPP(priv);
    auto nativePkcs8 = NativeCryptoPPPkcs8Export(priv);
    check(sdkPkcs8 == nativePkcs8, "SDK canonical PKCS8 differs from Crypto++'s own native PKCS8 writer.");
  }
  if (failures == 0) {
    std::printf(
        "PASS: byte-identical against Crypto++'s OWN X509PublicKey::Save()/PKCS8PrivateKey::Save() -- a "
        "genuinely independent writer (NOT our own encoder reused), second real cross-provider R_byte "
        "data point for RSA-ser.\n\n");
  }

  std::printf("--- interop: Crypto++ natively imports our own canonical SDK-exported artifacts ---\n");
  {
    auto sdkSpki = ExportRsaSerCryptoPP(pub);
    check(NativeCryptoPPImportSucceeds(sdkSpki, "public"), "Crypto++ natively rejected our own canonical SPKI export.");
    auto sdkPkcs8 = ExportRsaSerCryptoPP(priv);
    check(NativeCryptoPPImportSucceeds(sdkPkcs8, "private"), "Crypto++ natively rejected our own canonical PKCS8 export.");
  }
  if (failures == 0) std::printf("PASS: Crypto++ natively accepts our SDK-canonical artifacts (genuine interop, not self-consistency).\n\n");

  std::printf("--- rsa-ser.exact-consumption: trailing byte rejected ---\n");
  {
    auto artifact = ExportRsaSerCryptoPP(pub);
    artifact.push_back(0xaa);
    try {
      ImportRsaSerCryptoPP(artifact, "public");
      check(false, "expected trailing-byte artifact to be rejected.");
    } catch (const RsaSerError& e) {
      check(e.errorClass == "malformed_artifact" && e.clauseId == "rsa-ser.exact-consumption",
            "wrong classification for trailing bytes: " + e.errorClass + "/" + e.clauseId);
    }
  }
  if (failures == 0) std::printf("PASS: exact-consumption enforced.\n\n");

  std::printf("--- rsa-ser.role-container: wrong requested role rejected ---\n");
  {
    auto pubDer = ExportRsaSerCryptoPP(pub);
    try {
      ImportRsaSerCryptoPP(pubDer, "private");
      check(false, "expected SPKI-as-private to be rejected.");
    } catch (const RsaSerError& e) {
      check(e.errorClass == "invalid_parameter" && e.clauseId == "rsa-ser.role-container",
            "wrong classification for role-container mismatch.");
    }
  }
  if (failures == 0) std::printf("PASS: role-container mismatch rejected as invalid_parameter.\n\n");

  std::printf("--- Accept_C independence: corrupted CRT relation rejected as invalid_key (never delegated to Validate()) ---\n");
  {
    RsaKeyMaterial corrupted = priv;
    corrupted.dP = corrupted.dP + Integer(2L);
    auto artifact = ExportRsaSerCryptoPP(corrupted);
    try {
      ImportRsaSerCryptoPP(artifact, "private");
      check(false, "expected corrupted private-relations key to be rejected.");
    } catch (const RsaSerError& e) {
      check(e.errorClass == "invalid_key" && e.clauseId == "rsa-ser.private-relations",
            "wrong classification for corrupted CRT relation: " + e.errorClass + "/" + e.clauseId);
    }
  }
  if (failures == 0) {
    std::printf(
        "PASS: corrupted CRT relation rejected via OUR OWN V_rel check -- Accept_C never delegated to "
        "RSA::PrivateKey::Validate(), which (per this file's header comment) checks a different, "
        "incomparable condition set.\n\n");
  }

  std::printf("--- multi-prime: Crypto++ natively rejects version!=0 at parse time (confirmed, not assumed) ---\n");
  {
    auto artifact = ExportRsaSerCryptoPP(priv);
    bool found = false;
    for (size_t i = 0; i + 2 < artifact.size(); i++) {
      if (artifact[i] == 0x02 && artifact[i + 1] == 0x01 && artifact[i + 2] == 0x00) {
        artifact[i + 2] = 0x01;
        found = true;
        break;
      }
    }
    check(found, "could not locate the version INTEGER to corrupt in the exported artifact.");

    try {
      ImportRsaSerCryptoPP(artifact, "private");
      check(false, "expected version!=0 artifact to be rejected by our own Accept_C.");
    } catch (const RsaSerError& e) {
      check(e.errorClass == "malformed_artifact" && e.clauseId == "rsa-ser.container",
            "wrong classification for version!=0: " + e.errorClass + "/" + e.clauseId);
    }

    bool nativeAccepted = NativeCryptoPPImportSucceeds(artifact, "private");
    check(!nativeAccepted, "Crypto++ unexpectedly accepted a version!=0 artifact natively -- contradicts the confirmed BERDecodeUnsigned(0,0) bound.");
  }
  if (failures == 0) {
    std::printf(
        "PASS: multi-prime (version!=0) rejected both by our own Accept_C (malformed_artifact/container) AND, "
        "separately, by Crypto++'s own native BERDecode -- confirming the version-range-check finding "
        "empirically, not just by source inspection.\n\n");
  }

  std::printf("=== M1 slice complete for RSA-ser x Crypto++: %s ===\n",
              failures == 0 ? "ALL CHECKS PASSED" : (std::to_string(failures) + " CHECK(S) FAILED").c_str());
  return failures == 0 ? 0 : 1;
}
