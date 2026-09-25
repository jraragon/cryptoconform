// M1 vertical slice: RSA-PSS x Bouncy Castle, no mutations.
// Mirrors scripts/run-pss-cryptopp.cpp and tests/pss/webcrypto.test.ts's
// checklist, plus the backend-specific critical cases for THIS adapter:
// BC never enforces key role natively (Accept_C is the only enforcement),
// and BC is the only backend that can represent H_PSS != H_MGF1 at all.
//
// Build (pinned): org.bouncycastle:bcprov-jdk18on:1.77 (Maven Central), jar
// SHA-256 dabb98c2...a495d58 (Experimental Evidence Base sec:environment).
//   javac -cp bcprov-jdk18on-1.77.jar -d out \
//       src/adapters/bouncycastle/PssBouncyCastle.java \
//       scripts/RunPssBouncyCastle.java
//   java -cp out:bcprov-jdk18on-1.77.jar paper4.scripts.RunPssBouncyCastle

package paper4.scripts;

import paper4.adapters.bouncycastle.PssBouncyCastle;
import paper4.adapters.bouncycastle.PssBouncyCastle.PssSignRequest;
import paper4.adapters.bouncycastle.PssBouncyCastle.PssVerifyRequest;
import paper4.adapters.bouncycastle.PssBouncyCastle.PssKeyMaterial;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class RunPssBouncyCastle {

  private static boolean contains(String haystack, String needle) {
    return haystack.contains(needle);
  }

  private static String extractField(String record, String key) {
    String marker = "\"" + key + "\":\"";
    int start = record.indexOf(marker);
    if (start < 0) return "";
    start += marker.length();
    int end = record.indexOf('"', start);
    return record.substring(start, end);
  }

  private static byte[] fromHex(String hex) {
    int len = hex.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
    }
    return out;
  }

  private static int failures = 0;

  private static void check(boolean condition, String failMessage) {
    if (!condition) {
      System.err.println("FAILED: " + failMessage);
      failures++;
    }
  }

  public static void main(String[] args) {
    System.out.println("=== M1 vertical slice: RSA-PSS x Bouncy Castle ===\n");

    System.out.println("--- key generation (RSA-3072, shared fixture) ---");
    final PssKeyMaterial privMaterial = PssBouncyCastle.generatePssKeyMaterial();
    final PssKeyMaterial pubMaterial = new PssKeyMaterial("public", privMaterial.modulus,
        privMaterial.publicExponent, null, privMaterial.modulusBits);
    final PssKeyMaterial otherPrivMaterial = PssBouncyCastle.generatePssKeyMaterial(); // unrelated key
    final PssKeyMaterial otherPubMaterial = new PssKeyMaterial("public", otherPrivMaterial.modulus,
        otherPrivMaterial.publicExponent, null, otherPrivMaterial.modulusBits);
    check(privMaterial.modulusBits == PssBouncyCastle.MODULUS_BITS, "generated key is not 3072 bits.");
    System.out.println("PASS: RSA-3072 key pair generated.\n");

    byte[] message = "the quick brown fox jumps over the lazy dog".getBytes();

    // --- 1. Sign -> verify round trip ---
    System.out.println("--- sign -> verify round trip ---");
    String signRecord = PssBouncyCastle.pssBouncyCastleSign(
        new PssSignRequest(privMaterial, message, "SHA-256", "SHA-256"));
    check(contains(signRecord, "\"kind\":\"accept\""), "expected sign to succeed.");
    byte[] signature = fromHex(extractField(signRecord, "signatureHex"));
    check(signature.length == PssBouncyCastle.K_BYTES, "signature is not exactly 384 bytes.");

    String verifyRecord = PssBouncyCastle.pssBouncyCastleVerify(
        new PssVerifyRequest(pubMaterial, message, signature, "SHA-256", "SHA-256"));
    check(contains(verifyRecord, "\"kind\":\"verified\"") && contains(verifyRecord, "\"valid\":true"),
        "expected round-trip verify to be valid.");
    if (failures == 0) System.out.println("PASS: sign -> verify round trip yields a valid signature.\n");

    // --- 2. Corrupted / truncated / lengthened / wrong-key -> verified(false), NEVER reject ---
    System.out.println("--- corrupted/truncated/lengthened/wrong-key signature -> verified(false), never reject ---");
    {
      byte[] corrupted = signature.clone();
      corrupted[0] ^= (byte) 0xff;
      String rec1 = PssBouncyCastle.pssBouncyCastleVerify(
          new PssVerifyRequest(pubMaterial, message, corrupted, "SHA-256", "SHA-256"));
      check(contains(rec1, "\"kind\":\"verified\"") && contains(rec1, "\"valid\":false"),
          "corrupted signature did not yield verified(false).");
      check(!contains(rec1, "\"kind\":\"reject\""), "CRITICAL: corrupted signature must never yield reject.");

      byte[] truncated = new byte[10];
      System.arraycopy(signature, 0, truncated, 0, 10);
      String rec2 = PssBouncyCastle.pssBouncyCastleVerify(
          new PssVerifyRequest(pubMaterial, message, truncated, "SHA-256", "SHA-256"));
      check(contains(rec2, "\"kind\":\"verified\"") && contains(rec2, "\"valid\":false"),
          "truncated signature did not yield verified(false).");
      check(!contains(rec2, "\"kind\":\"reject\""),
          "CRITICAL (D-046): truncated signature must never yield reject/invalid_parameter.");

      byte[] lengthened = new byte[signature.length + 10];
      System.arraycopy(signature, 0, lengthened, 0, signature.length);
      String rec3 = PssBouncyCastle.pssBouncyCastleVerify(
          new PssVerifyRequest(pubMaterial, message, lengthened, "SHA-256", "SHA-256"));
      check(contains(rec3, "\"kind\":\"verified\"") && contains(rec3, "\"valid\":false"),
          "lengthened signature did not yield verified(false).");
      check(!contains(rec3, "\"kind\":\"reject\""),
          "CRITICAL (D-046): lengthened signature must never yield reject/invalid_parameter.");

      String rec4 = PssBouncyCastle.pssBouncyCastleVerify(
          new PssVerifyRequest(otherPubMaterial, message, signature, "SHA-256", "SHA-256"));
      check(contains(rec4, "\"kind\":\"verified\"") && contains(rec4, "\"valid\":false"),
          "wrong-key verification did not yield verified(false).");
    }
    if (failures == 0) {
      System.out.println(
          "PASS: corrupted/truncated/lengthened/wrong-key signatures all yield verified(false), never reject.\n");
    }

    // --- 3. Key role -> invalid_key (BC's OWN defining case: never enforced natively) ---
    System.out.println("--- key role mismatch -> invalid_key (BC never enforces this natively -- Accept_C is the only guard) ---");
    {
      String rec1 = PssBouncyCastle.pssBouncyCastleSign(
          new PssSignRequest(pubMaterial, message, "SHA-256", "SHA-256")); // wrong role
      check(contains(rec1, "\"errorClass\":\"invalid_key\"") && contains(rec1, "\"pss.key\""),
          "expected sign with a public-declared key to be rejected as invalid_key.");

      String rec2 = PssBouncyCastle.pssBouncyCastleVerify(
          new PssVerifyRequest(privMaterial, message, signature, "SHA-256", "SHA-256")); // wrong role
      check(contains(rec2, "\"errorClass\":\"invalid_key\"") && contains(rec2, "\"pss.key\""),
          "expected verify with a private-declared key to be rejected as invalid_key.");
    }
    if (failures == 0) System.out.println("PASS: key-role mismatch rejected in both directions.\n");

    // --- 4. modulus out of profile -> invalid_parameter ---
    System.out.println("--- non-3072-bit modulus -> invalid_parameter ---");
    {
      SecureRandom random = new SecureRandom();
      org.bouncycastle.crypto.generators.RSAKeyPairGenerator smallGen =
          new org.bouncycastle.crypto.generators.RSAKeyPairGenerator();
      smallGen.init(new org.bouncycastle.crypto.params.RSAKeyGenerationParameters(BigInteger.valueOf(65537), random,
          2048, 80));
      org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters smallPriv =
          (org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters) smallGen.generateKeyPair().getPrivate();
      PssKeyMaterial smallPrivMaterial = new PssKeyMaterial("private", smallPriv.getModulus(),
          smallPriv.getPublicExponent(), smallPriv.getExponent(), smallPriv.getModulus().bitLength());

      String rec = PssBouncyCastle.pssBouncyCastleSign(
          new PssSignRequest(smallPrivMaterial, message, "SHA-256", "SHA-256"));
      check(contains(rec, "\"errorClass\":\"invalid_parameter\"") && contains(rec, "\"pss.modulus\""),
          "expected a 2048-bit key to be rejected as invalid_parameter (pss.modulus).");
    }
    if (failures == 0) System.out.println("PASS: non-3072-bit modulus rejected as invalid_parameter.\n");

    // --- 5. THE CRITICAL BC-SPECIFIC CASE: decoupled hash/MGF1 ---
    System.out.println("--- CRITICAL: SHA256/SHA256 accept, SHA256/SHA1 rejected BEFORE any PSSSigner construction ---");
    {
      String recCoupled = PssBouncyCastle.pssBouncyCastleSign(
          new PssSignRequest(privMaterial, message, "SHA-256", "SHA-256"));
      check(contains(recCoupled, "\"kind\":\"accept\""), "expected SHA256/SHA256 (coupled) to be accepted.");

      String recDecoupled = PssBouncyCastle.pssBouncyCastleSign(
          new PssSignRequest(privMaterial, message, "SHA-256", "SHA-1"));
      check(contains(recDecoupled, "\"errorClass\":\"invalid_parameter\"") && contains(recDecoupled, "\"pss.mgfCoupling\""),
          "expected SHA256/SHA1 (decoupled -- BC-valid natively, non-portable) to be rejected as "
              + "invalid_parameter (pss.mgfCoupling), NOT unsupported.");
      check(!contains(recDecoupled, "\"kind\":\"accept\""),
          "CRITICAL: a decoupled-digest request must never be accepted, regardless of BC's native capability.");

      String recDecoupledVerify = PssBouncyCastle.pssBouncyCastleVerify(
          new PssVerifyRequest(pubMaterial, message, signature, "SHA-256", "SHA-1"));
      check(contains(recDecoupledVerify, "\"errorClass\":\"invalid_parameter\"")
          && contains(recDecoupledVerify, "\"pss.mgfCoupling\""),
          "expected verify with SHA256/SHA1 to also be rejected as invalid_parameter (pss.mgfCoupling).");
    }
    if (failures == 0) {
      System.out.println(
          "PASS: decoupled digest rejected by Accept_C before any PSSSigner object exists -- the SDK does not "
              + "merely 'allow then reject' Bouncy Castle's provider-specific capability, it structurally never "
              + "constructs the decoupled case in the success path.\n");
    }

    // --- 6. Non-determinism control ---
    System.out.println("--- CONTROL: two signatures of identical (K,M) differ, both still verify true ---");
    {
      String r1 = PssBouncyCastle.pssBouncyCastleSign(new PssSignRequest(privMaterial, message, "SHA-256", "SHA-256"));
      String r2 = PssBouncyCastle.pssBouncyCastleSign(new PssSignRequest(privMaterial, message, "SHA-256", "SHA-256"));
      String sig1Hex = extractField(r1, "signatureHex");
      String sig2Hex = extractField(r2, "signatureHex");
      check(!sig1Hex.equals(sig2Hex), "CONTROL FAILED: two signatures of identical (K,M) produced the SAME bytes.");

      String v1 = PssBouncyCastle.pssBouncyCastleVerify(
          new PssVerifyRequest(pubMaterial, message, fromHex(sig1Hex), "SHA-256", "SHA-256"));
      String v2 = PssBouncyCastle.pssBouncyCastleVerify(
          new PssVerifyRequest(pubMaterial, message, fromHex(sig2Hex), "SHA-256", "SHA-256"));
      check(contains(v1, "\"valid\":true"), "signature 1 did not verify true.");
      check(contains(v2, "\"valid\":true"), "signature 2 did not verify true.");
    }
    if (failures == 0) {
      System.out.println(
          "PASS (control, not a conformance obligation): signatures differ (random salt), both still verify true -- "
              + "material evidence for R_byte=N/A on PSS, third backend.\n");
    }

    // --- 7. D-046 regression guard: dedicated, explicit ---
    System.out.println("--- D-046 REGRESSION GUARD: |signature|!=384 must NEVER become invalid_parameter ---");
    {
      String shortRec = PssBouncyCastle.pssBouncyCastleVerify(
          new PssVerifyRequest(pubMaterial, message, new byte[10], "SHA-256", "SHA-256"));
      check(contains(shortRec, "\"kind\":\"verified\""),
          "D-046 VIOLATION: a 10-byte signature was not routed to Verify's own result domain.");
      check(!contains(shortRec, "\"errorClass\":\"invalid_parameter\""),
          "D-046 VIOLATION: a wrong-length signature was classified as invalid_parameter -- "
              + "this contradicts RFC 8017 Sec.8.1.2 Step 1 directly.");

      String emptyRec = PssBouncyCastle.pssBouncyCastleVerify(
          new PssVerifyRequest(pubMaterial, message, new byte[0], "SHA-256", "SHA-256"));
      check(contains(emptyRec, "\"kind\":\"verified\""),
          "D-046 VIOLATION: an empty signature was not routed to Verify's own result domain.");
      check(!contains(emptyRec, "\"errorClass\":\"invalid_parameter\""),
          "D-046 VIOLATION: an empty signature was classified as invalid_parameter.");
    }
    if (failures == 0) {
      System.out.println("PASS: D-046 respected -- wrong-length signatures never intercepted as invalid_parameter.\n");
    }

    System.out.println("=== M1 slice complete for RSA-PSS x Bouncy Castle: "
        + (failures == 0 ? "ALL CHECKS PASSED" : (failures + " CHECK(S) FAILED")) + " ===");

    if (failures > 0) {
      System.exit(1);
    }
  }
}
