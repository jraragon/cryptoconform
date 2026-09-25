// M1 vertical slice: HKDF x Bouncy Castle, no mutations.
// See Experimental_Evidence_Base v0.1, sec:m1-slice; mirrors
// scripts/run-hkdf-webcrypto.ts and scripts/run-hkdf-cryptopp.cpp exactly
// (same KAT, same D-068 boundary checks, same evidence-record shape), plus
// the additional checks agreed for the first HKDF cross-provider baseline:
// L=8160 (accept, exact upper bound) and L=8161 (reject, one past it), and
// an explicit absent-vs-empty-salt equivalence check.
//
// Build (pinned): org.bouncycastle:bcprov-jdk18on:1.77 (Maven Central),
// jar SHA-256 recorded in Experimental_Evidence_Base v0.1, sec:environment.
//   javac -cp bcprov-jdk18on-1.77.jar -d out \
//       src/adapters/bouncycastle/HkdfBouncyCastle.java \
//       scripts/RunHkdfBouncyCastle.java
//   java -cp out:bcprov-jdk18on-1.77.jar paper4.scripts.RunHkdfBouncyCastle

package paper4.scripts;

import paper4.adapters.bouncycastle.HkdfBouncyCastle;
import paper4.adapters.bouncycastle.HkdfBouncyCastle.HkdfRequest;

public final class RunHkdfBouncyCastle {

  private static byte[] fromHex(String hex) {
    int len = hex.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
    }
    return out;
  }

  private static boolean contains(String haystack, String needle) {
    return haystack.contains(needle);
  }

  private static int failures = 0;

  private static void check(boolean condition, String failMessage) {
    if (!condition) {
      System.err.println("FAILED: " + failMessage);
      failures++;
    }
  }

  public static void main(String[] args) {
    System.out.println("=== M1 vertical slice: HKDF x Bouncy Castle ===\n");

    // --- 1. RFC 5869 Appendix A.1, Test Case 1 (same vector as WebCrypto/Crypto++) ---
    System.out.println("--- RFC 5869 Test Case 1 (KAT) ---");
    final String expectedOkmHex =
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5b"
        + "f34007208d5b887185865";

    byte[] ikm = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    byte[] salt = fromHex("000102030405060708090a0b0c");
    byte[] info = fromHex("f0f1f2f3f4f5f6f7f8f9");

    HkdfRequest kat = new HkdfRequest(ikm, salt, true, info, 42);
    String katRecord = HkdfBouncyCastle.hkdfBouncyCastle(kat);
    System.out.println(katRecord + "\n");

    check(contains(katRecord, "\"kind\":\"accept\""), "expected acceptance for KAT.");
    check(contains(katRecord, expectedOkmHex), "KAT MISMATCH: expected OKM " + expectedOkmHex + " not found.");
    if (failures == 0) {
      System.out.println("PASS: Bouncy Castle realization matches RFC 5869 Test Case 1 exactly.\n");
    }

    // --- 2. D-068 boundary: L=0 (below MIN_L, must reject) ---
    System.out.println("--- D-068 boundary check (L=0) ---");
    HkdfRequest zeroLength = new HkdfRequest(ikm, salt, true, info, 0);
    String zeroRecord = HkdfBouncyCastle.hkdfBouncyCastle(zeroLength);
    System.out.println(zeroRecord + "\n");
    check(contains(zeroRecord, "\"kind\":\"reject\"") && contains(zeroRecord, "\"errorClass\":\"invalid_parameter\""),
        "expected L=0 to be rejected as invalid_parameter.");
    if (contains(zeroRecord, "\"kind\":\"reject\"")) {
      System.out.println("PASS: D-068 lower bound enforced by the SDK adapter.\n");
    }

    // --- 3. D-068 boundary: L=8160 (exact upper bound MAX_L, must accept) ---
    System.out.println("--- D-068 boundary check (L=8160, exact upper bound) ---");
    HkdfRequest maxLength = new HkdfRequest(ikm, salt, true, info, 8160);
    String maxRecord = HkdfBouncyCastle.hkdfBouncyCastle(maxLength);
    // Don't print the full 8160-byte OKM inline; print only outcome.kind + length for readability.
    System.out.println("outcome.kind=" + (contains(maxRecord, "\"kind\":\"accept\"") ? "accept" : "reject")
        + ", record length=" + maxRecord.length() + " chars\n");
    check(contains(maxRecord, "\"kind\":\"accept\""), "expected L=8160 (exact upper bound) to be accepted.");
    if (contains(maxRecord, "\"kind\":\"accept\"")) {
      System.out.println("PASS: L=8160 (exact D-068 upper bound) accepted.\n");
    }

    // --- 4. D-068 boundary: L=8161 (one past upper bound, must reject) ---
    System.out.println("--- D-068 boundary check (L=8161, one past upper bound) ---");
    HkdfRequest overMaxLength = new HkdfRequest(ikm, salt, true, info, 8161);
    String overMaxRecord = HkdfBouncyCastle.hkdfBouncyCastle(overMaxLength);
    System.out.println(overMaxRecord + "\n");
    check(contains(overMaxRecord, "\"kind\":\"reject\"") && contains(overMaxRecord, "\"errorClass\":\"invalid_parameter\""),
        "expected L=8161 to be rejected as invalid_parameter.");
    if (contains(overMaxRecord, "\"kind\":\"reject\"")) {
      System.out.println("PASS: D-068 upper bound enforced by the SDK adapter (L=8161 rejected).\n");
    }

    // --- 5. Absent salt vs. explicit empty salt: contractual distinctness check ---
    // v0.6 / hkdf.ts: absent salt (saltPresent=false) is DISTINCT from an
    // explicitly supplied zero-length salt (saltPresent=true, salt=byte[0]),
    // even though RFC 5869 defines both as producing the same HashLen
    // zero-octet HMAC key in the end. This checks the two request shapes
    // both reach 'accept' and, per RFC 5869 semantics, must yield the SAME
    // OKM as each other (and the same as an explicit HashLen-zero-byte salt),
    // confirming the contractual "absent == HashLen zero octets" mapping
    // holds for this backend's realization -- exactly the property already
    // source-verified in HkdfBouncyCastle's header comment, now checked
    // end-to-end through the adapter rather than by source inspection alone.
    System.out.println("--- absent-salt vs empty-salt vs explicit-zero-salt equivalence ---");
    HkdfRequest absentSalt = new HkdfRequest(ikm, null, false, info, 42);
    HkdfRequest emptySalt = new HkdfRequest(ikm, new byte[0], true, info, 42);
    HkdfRequest explicitZeroSalt = new HkdfRequest(ikm, new byte[32], true, info, 42);

    String absentRecord = HkdfBouncyCastle.hkdfBouncyCastle(absentSalt);
    String emptyRecord = HkdfBouncyCastle.hkdfBouncyCastle(emptySalt);
    String explicitZeroRecord = HkdfBouncyCastle.hkdfBouncyCastle(explicitZeroSalt);

    System.out.println("absent salt:        " + absentRecord);
    System.out.println("empty salt:          " + emptyRecord);
    System.out.println("explicit zero salt:  " + explicitZeroRecord + "\n");

    boolean absentOk = contains(absentRecord, "\"kind\":\"accept\"") && contains(absentRecord, expectedOkmHex) == false; // different info-derived OKM than KAT (different salt), just check acceptance shape below
    check(contains(absentRecord, "\"kind\":\"accept\""), "expected absent-salt request to be accepted.");
    check(contains(emptyRecord, "\"kind\":\"accept\""), "expected empty-salt request to be accepted.");
    check(contains(explicitZeroRecord, "\"kind\":\"accept\""), "expected explicit-zero-salt request to be accepted.");

    // Extract okmHex substrings to compare the three OKMs to each other.
    String absentOkm = absentRecord.replaceAll(".*\"okmHex\":\"([0-9a-f]+)\".*", "$1");
    String emptyOkm = emptyRecord.replaceAll(".*\"okmHex\":\"([0-9a-f]+)\".*", "$1");
    String explicitZeroOkm = explicitZeroRecord.replaceAll(".*\"okmHex\":\"([0-9a-f]+)\".*", "$1");

    check(absentOkm.equals(explicitZeroOkm),
        "absent-salt OKM differs from explicit-HashLen-zero-byte-salt OKM (breaks RFC 5869 absent==zero-octets equivalence).");
    check(!absentOkm.equals(emptyOkm) || emptyOkm.equals(explicitZeroOkm),
        "sanity check on empty-vs-zero-byte salt comparison malformed.");
    // RFC 5869 distinguishes a NULL salt from a zero-LENGTH-but-present salt
    // for HMAC purposes only insofar as HMAC's own key-padding makes an
    // empty key and a HashLen-zero-byte key behave identically under
    // HMAC-SHA-256 (both hash down to the same effective key) -- so all
    // three are expected to coincide here. This is exactly the point flagged
    // as behaviorally significant in the Crypto++ adapter's comment; this
    // check confirms it holds (not just is asserted) for Bouncy Castle too.
    check(emptyOkm.equals(explicitZeroOkm),
        "empty-salt OKM differs from explicit-HashLen-zero-byte-salt OKM under HMAC-SHA-256 (unexpected -- would be a genuine adapter/backend divergence, not a deviation from v0.6).");

    if (absentOkm.equals(emptyOkm) && emptyOkm.equals(explicitZeroOkm)) {
      System.out.println("PASS: absent salt, empty salt, and explicit HashLen-zero-byte salt all yield an identical OKM for this backend.\n");
    }

    System.out.println("=== M1 slice complete for HKDF x Bouncy Castle: "
        + (failures == 0 ? "ALL CHECKS PASSED" : (failures + " CHECK(S) FAILED")) + " ===");

    if (failures > 0) {
      System.exit(1);
    }
  }
}
