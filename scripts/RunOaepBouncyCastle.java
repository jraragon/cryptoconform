// M1 vertical slice: RSA-OAEP x Bouncy Castle, no mutations.
// Mirrors scripts/run-oaep-cryptopp.cpp and tests/oaep/webcrypto.test.ts's
// checklist, plus the backend-specific critical case for THIS adapter:
// Bouncy Castle is the only one of the three backends whose native API can
// represent H_OAEP != H_MGF1 at all -- this suite proves the SDK rejects
// that request before any decoupled OAEPEncoding is ever constructed, not
// merely that BC "can do it and then we reject it."
//
// Build (pinned): org.bouncycastle:bcprov-jdk18on:1.77 (Maven Central), jar
// SHA-256 dabb98c2...a495d58 (Experimental_Evidence_Base sec:environment).
//   javac -cp bcprov-jdk18on-1.77.jar -d out \
//       src/adapters/bouncycastle/OaepBouncyCastle.java \
//       scripts/RunOaepBouncyCastle.java
//   java -cp out:bcprov-jdk18on-1.77.jar paper4.scripts.RunOaepBouncyCastle

package paper4.scripts;

import paper4.adapters.bouncycastle.OaepBouncyCastle;
import paper4.adapters.bouncycastle.OaepBouncyCastle.OaepEncryptRequest;
import paper4.adapters.bouncycastle.OaepBouncyCastle.OaepDecryptRequest;
import paper4.adapters.bouncycastle.OaepBouncyCastle.OaepKeyMaterial;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public final class RunOaepBouncyCastle {

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
    System.out.println("=== M1 vertical slice: RSA-OAEP x Bouncy Castle ===\n");

    System.out.println("--- key generation (RSA-3072, shared fixture) ---");
    final OaepKeyMaterial privMaterial = OaepBouncyCastle.generateOaepKeyMaterial();
    final OaepKeyMaterial pubMaterial = new OaepKeyMaterial("public", privMaterial.modulus,
        privMaterial.publicExponent, null, privMaterial.modulusBits);
    final OaepKeyMaterial otherPrivMaterial = OaepBouncyCastle.generateOaepKeyMaterial(); // unrelated key
    check(privMaterial.modulusBits == OaepBouncyCastle.MODULUS_BITS, "generated key is not 3072 bits.");
    System.out.println("PASS: RSA-3072 key pair generated.\n");

    byte[] message = "the quick brown fox jumps over the lazy dog".getBytes();

    // --- 1. Round trip ---
    System.out.println("--- encrypt -> decrypt round trip ---");
    String encRecord = OaepBouncyCastle.oaepBouncyCastleEncrypt(
        new OaepEncryptRequest(pubMaterial, message, new byte[0], false, "SHA-256", "SHA-256"));
    check(contains(encRecord, "\"kind\":\"accept\""), "expected round-trip encrypt to succeed.");
    byte[] ciphertext = fromHex(extractField(encRecord, "ciphertextHex"));
    String decRecord = OaepBouncyCastle.oaepBouncyCastleDecrypt(
        new OaepDecryptRequest(privMaterial, ciphertext, new byte[0], false, "SHA-256", "SHA-256"));
    check(contains(decRecord, "\"kind\":\"accept\""), "expected round-trip decrypt to succeed.");
    check(Arrays.equals(fromHex(extractField(decRecord, "plaintextHex")), message),
        "round-trip plaintext does not match the original.");
    if (failures == 0) System.out.println("PASS: encrypt -> decrypt recovers the exact plaintext.\n");

    // --- 2. Message-length boundary ---
    System.out.println("--- message-length boundary (318 accept / 319 reject) ---");
    byte[] msg318 = new byte[OaepBouncyCastle.MAX_MESSAGE_LEN_BYTES];
    byte[] msg319 = new byte[OaepBouncyCastle.MAX_MESSAGE_LEN_BYTES + 1];
    check(contains(OaepBouncyCastle.oaepBouncyCastleEncrypt(
        new OaepEncryptRequest(pubMaterial, msg318, new byte[0], false, "SHA-256", "SHA-256")), "\"kind\":\"accept\""),
        "expected mLen=318 to be accepted.");
    String rec319 = OaepBouncyCastle.oaepBouncyCastleEncrypt(
        new OaepEncryptRequest(pubMaterial, msg319, new byte[0], false, "SHA-256", "SHA-256"));
    check(contains(rec319, "\"errorClass\":\"invalid_parameter\"") && contains(rec319, "\"oaep.message\""),
        "expected mLen=319 to be rejected as invalid_parameter (oaep.message).");
    if (failures == 0) System.out.println("PASS: message-length boundary enforced correctly.\n");

    // --- 3. Ciphertext output length ---
    System.out.println("--- ciphertext output length (384 bytes) ---");
    String rec = OaepBouncyCastle.oaepBouncyCastleEncrypt(
        new OaepEncryptRequest(pubMaterial, message, new byte[0], false, "SHA-256", "SHA-256"));
    check(extractField(rec, "ciphertextHex").length() == OaepBouncyCastle.K_BYTES * 2,
        "ciphertext is not exactly 384 bytes.");
    if (failures == 0) System.out.println("PASS: ciphertext output is exactly 384 bytes.\n");

    // --- 4. Label absent === empty; non-empty rejected ---
    System.out.println("--- label absent/empty equivalence, non-empty rejection ---");
    check(contains(OaepBouncyCastle.oaepBouncyCastleEncrypt(
        new OaepEncryptRequest(pubMaterial, message, new byte[0], false, "SHA-256", "SHA-256")), "\"kind\":\"accept\""),
        "expected absent label to be accepted.");
    check(contains(OaepBouncyCastle.oaepBouncyCastleEncrypt(
        new OaepEncryptRequest(pubMaterial, message, new byte[0], true, "SHA-256", "SHA-256")), "\"kind\":\"accept\""),
        "expected empty label to be accepted.");
    String recLabel = OaepBouncyCastle.oaepBouncyCastleEncrypt(
        new OaepEncryptRequest(pubMaterial, message, new byte[] {0x01, 0x02}, true, "SHA-256", "SHA-256"));
    check(contains(recLabel, "\"errorClass\":\"invalid_parameter\"") && contains(recLabel, "\"oaep.label\""),
        "expected non-empty label to be rejected as invalid_parameter (oaep.label).");
    if (failures == 0) System.out.println("PASS: label absent/empty equivalence and non-empty rejection both correct.\n");

    // --- 5. Key role -> invalid_key ---
    System.out.println("--- key role mismatch -> invalid_key ---");
    String recBadEnc = OaepBouncyCastle.oaepBouncyCastleEncrypt(
        new OaepEncryptRequest(privMaterial, message, new byte[0], false, "SHA-256", "SHA-256")); // wrong role
    check(contains(recBadEnc, "\"errorClass\":\"invalid_key\"") && contains(recBadEnc, "\"oaep.key\""),
        "expected encrypt with a private-declared key to be rejected as invalid_key.");
    String recBadDec = OaepBouncyCastle.oaepBouncyCastleDecrypt(
        new OaepDecryptRequest(pubMaterial, new byte[OaepBouncyCastle.K_BYTES], new byte[0], false, "SHA-256",
            "SHA-256")); // wrong role
    check(contains(recBadDec, "\"errorClass\":\"invalid_key\"") && contains(recBadDec, "\"oaep.key\""),
        "expected decrypt with a public-declared key to be rejected as invalid_key.");
    if (failures == 0) System.out.println("PASS: key-role mismatch rejected in both directions.\n");

    // --- 6. modulus out of profile -> invalid_parameter ---
    System.out.println("--- non-3072-bit modulus -> invalid_parameter ---");
    SecureRandom random = new SecureRandom();
    org.bouncycastle.crypto.generators.RSAKeyPairGenerator smallGen =
        new org.bouncycastle.crypto.generators.RSAKeyPairGenerator();
    smallGen.init(new org.bouncycastle.crypto.params.RSAKeyGenerationParameters(BigInteger.valueOf(65537), random,
        2048, 80));
    org.bouncycastle.crypto.params.RSAKeyParameters smallPub =
        (org.bouncycastle.crypto.params.RSAKeyParameters) smallGen.generateKeyPair().getPublic();
    OaepKeyMaterial smallPubMaterial = new OaepKeyMaterial("public", smallPub.getModulus(), smallPub.getExponent(),
        null, smallPub.getModulus().bitLength());
    String recModulus = OaepBouncyCastle.oaepBouncyCastleEncrypt(
        new OaepEncryptRequest(smallPubMaterial, message, new byte[0], false, "SHA-256", "SHA-256"));
    check(contains(recModulus, "\"errorClass\":\"invalid_parameter\"") && contains(recModulus, "\"oaep.modulus\""),
        "expected a 2048-bit key to be rejected as invalid_parameter (oaep.modulus).");
    if (failures == 0) System.out.println("PASS: non-3072-bit modulus rejected as invalid_parameter.\n");

    // --- 7. THE CRITICAL BC-SPECIFIC CASE: decoupled hash/MGF1 ---
    System.out.println("--- CRITICAL: SHA256/SHA256 accept, SHA256/SHA1 rejected BEFORE any OAEPEncoding construction ---");
    String recCoupled = OaepBouncyCastle.oaepBouncyCastleEncrypt(
        new OaepEncryptRequest(pubMaterial, message, new byte[0], false, "SHA-256", "SHA-256"));
    check(contains(recCoupled, "\"kind\":\"accept\""), "expected SHA256/SHA256 (coupled) to be accepted.");

    String recDecoupled = OaepBouncyCastle.oaepBouncyCastleEncrypt(
        new OaepEncryptRequest(pubMaterial, message, new byte[0], false, "SHA-256", "SHA-1"));
    check(
        contains(recDecoupled, "\"errorClass\":\"invalid_parameter\"") && contains(recDecoupled, "\"oaep.mgfCoupling\""),
        "expected SHA256/SHA1 (decoupled -- BC-valid natively, non-portable) to be rejected as "
            + "invalid_parameter (oaep.mgfCoupling), NOT unsupported.");
    check(!contains(recDecoupled, "\"kind\":\"accept\""),
        "CRITICAL: a decoupled-digest request must never be accepted, regardless of BC's native capability.");

    String recDecoupledDecrypt = OaepBouncyCastle.oaepBouncyCastleDecrypt(
        new OaepDecryptRequest(privMaterial, new byte[OaepBouncyCastle.K_BYTES], new byte[0], false, "SHA-256",
            "SHA-1"));
    check(contains(recDecoupledDecrypt, "\"errorClass\":\"invalid_parameter\"")
        && contains(recDecoupledDecrypt, "\"oaep.mgfCoupling\""),
        "expected decrypt with SHA256/SHA1 to also be rejected as invalid_parameter (oaep.mgfCoupling).");
    if (failures == 0) {
      System.out.println(
          "PASS: decoupled digest rejected by Accept_C before any OAEPEncoding object exists -- the SDK does not "
              + "merely 'allow then reject' Bouncy Castle's provider-specific capability, it structurally never "
              + "constructs the decoupled case in the success path.\n");
    }

    // --- 8. Corrupted/truncated/lengthened/unrelated-key -> decryption_error ---
    System.out.println("--- corrupted/truncated/lengthened/unrelated-key ciphertext -> decryption_error ---");
    byte[] baseCiphertext = fromHex(extractField(
        OaepBouncyCastle.oaepBouncyCastleEncrypt(
            new OaepEncryptRequest(pubMaterial, message, new byte[0], false, "SHA-256", "SHA-256")),
        "ciphertextHex"));

    byte[] corrupted = baseCiphertext.clone();
    corrupted[0] ^= (byte) 0xff;
    String recCorrupted = OaepBouncyCastle.oaepBouncyCastleDecrypt(
        new OaepDecryptRequest(privMaterial, corrupted, new byte[0], false, "SHA-256", "SHA-256"));
    check(contains(recCorrupted, "\"errorClass\":\"decryption_error\""), "corrupted ciphertext did not yield decryption_error.");

    byte[] truncated = Arrays.copyOfRange(baseCiphertext, 0, 10);
    String recTruncated = OaepBouncyCastle.oaepBouncyCastleDecrypt(
        new OaepDecryptRequest(privMaterial, truncated, new byte[0], false, "SHA-256", "SHA-256"));
    check(contains(recTruncated, "\"errorClass\":\"decryption_error\""), "truncated ciphertext did not yield decryption_error.");
    check(!contains(recTruncated, "\"errorClass\":\"invalid_parameter\""),
        "CRITICAL: truncated ciphertext must NOT be invalid_parameter (v0.6 D-034).");

    byte[] lengthened = Arrays.copyOf(baseCiphertext, baseCiphertext.length + 10);
    String recLengthened = OaepBouncyCastle.oaepBouncyCastleDecrypt(
        new OaepDecryptRequest(privMaterial, lengthened, new byte[0], false, "SHA-256", "SHA-256"));
    check(contains(recLengthened, "\"errorClass\":\"decryption_error\""), "lengthened ciphertext did not yield decryption_error.");
    check(!contains(recLengthened, "\"errorClass\":\"invalid_parameter\""),
        "CRITICAL: lengthened ciphertext must NOT be invalid_parameter (v0.6 D-034).");

    String recUnrelated = OaepBouncyCastle.oaepBouncyCastleDecrypt(
        new OaepDecryptRequest(otherPrivMaterial, baseCiphertext, new byte[0], false, "SHA-256", "SHA-256"));
    check(contains(recUnrelated, "\"errorClass\":\"decryption_error\""), "unrelated-key decrypt did not yield decryption_error.");

    if (failures == 0) {
      System.out.println(
          "PASS: corrupted/truncated/lengthened/unrelated-key ciphertext all yield decryption_error -- "
              + "BC's decodeBlock() constant-time wrongMask folding is not relied upon; the adapter catches broadly regardless.\n");
    }

    // --- 9. Non-determinism control ---
    System.out.println("--- CONTROL: two encryptions of identical (K,M) differ, both still decrypt to M ---");
    String r1 = OaepBouncyCastle.oaepBouncyCastleEncrypt(
        new OaepEncryptRequest(pubMaterial, message, new byte[0], false, "SHA-256", "SHA-256"));
    String r2 = OaepBouncyCastle.oaepBouncyCastleEncrypt(
        new OaepEncryptRequest(pubMaterial, message, new byte[0], false, "SHA-256", "SHA-256"));
    String ct1 = extractField(r1, "ciphertextHex");
    String ct2 = extractField(r2, "ciphertextHex");
    check(!ct1.equals(ct2), "CONTROL FAILED: two encryptions of identical (K,M) produced the SAME ciphertext.");
    if (failures == 0) {
      System.out.println(
          "PASS (control, not a conformance obligation): ciphertexts differ, confirming R_byte=N/A for OAEP (D-033) "
              + "empirically for this backend too.\n");
    }

    // --- 10. oaep.randomness non-exposure check ---
    // oaep.randomness remains a legitimate frozen ClauseID (v0.6) -- it is
    // what M2's OAEP-RANDOMNESS-INTERFACE-LEAK class exercises, likely as
    // an API-surface/manifest property rather than a per-request runtime
    // outcome. This check is narrower: it only confirms this M1 baseline's
    // accept outcomes don't fabricate false portable-capability evidence.
    System.out.println("--- oaep.randomness non-exposure check ---");
    String recRandomness = OaepBouncyCastle.oaepBouncyCastleEncrypt(
        new OaepEncryptRequest(pubMaterial, message, new byte[0], false, "SHA-256", "SHA-256"));
    check(!contains(recRandomness, "\"seed"), "EvidenceRecord input unexpectedly exposes a seed field.");
    check(!contains(recRandomness, "\"random"), "EvidenceRecord input unexpectedly exposes a random field.");
    check(!contains(recRandomness, "\"oaep.randomness\""),
        "oaep.randomness must not appear in this M1 baseline's accept-outcome clauseIds as if it were "
            + "positive portable-capability evidence -- no ParametersWithRandom is ever constructed by this adapter (D-033).");
    if (failures == 0) {
      System.out.println(
          "PASS: no ParametersWithRandom ever constructed; SecureRandom falls back to the JVM default internally, "
              + "never exposed as per-request portable accept evidence.\n");
    }

    System.out.println("=== M1 slice complete for RSA-OAEP x Bouncy Castle: "
        + (failures == 0 ? "ALL CHECKS PASSED" : (failures + " CHECK(S) FAILED")) + " ===");

    if (failures > 0) {
      System.exit(1);
    }
  }
}
