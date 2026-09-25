package paper4.adapters.bouncycastle;

// RSA-OAEP x Bouncy Castle adapter.
//
// Mirrors src/contract/oaep.ts, src/adapters/webcrypto/oaep.ts, and
// src/adapters/cryptopp/oaep.{hpp,cpp}: same Accept_C checks (v0.6,
// sec:oaep-error-model), same ClauseId set, same EvidenceRecord JSON shape
// -- independently reimplemented in Java.
//
// THE critical invariant for this backend: Bouncy Castle's OAEPEncoding is the ONLY one of the three
// backends whose native API can represent H_OAEP != H_MGF1 at all
// (OAEPEncoding(cipher, hash, mgf1Hash, encodingParams), a 4-argument
// constructor accepting two independent Digest objects -- v0.6, sec:oaep,
// Bouncy Castle inventory). This adapter must demonstrate the SDK does not
// let that provider-specific capability leak into the portable contract,
// and -- more than that -- must never even CONSTRUCT a decoupled
// OAEPEncoding instance for a request that would exercise it:
//   - Accept_C rejects hash != mgfHash as invalid_parameter BEFORE any
//     OAEPEncoding object is built at all (checked alongside key role and
//     the other portable-parameter checks, all before the native cipher
//     engine is touched).
//   - The success-path code below calls ONLY the 2-argument constructor
//     OAEPEncoding(cipher, hash) -- which is structurally coupled by
//     construction (the 3-arg/4-arg convenience overload internally passes
//     the SAME hash object as both hash and mgf1Hash: "this(cipher, hash,
//     hash, encodingParams)", confirmed against the bc-java source). This
//     adapter never calls the 4-arg constructor with two DIFFERENT Digest
//     instances anywhere in this file -- not merely "rejects then allows
//     it later," genuinely cannot construct the decoupled case at all.
//
// RNG: OAEPEncoding.init() without a ParametersWithRandom wrapper falls
// back to CryptoServicesRegistrar.getSecureRandom() internally (confirmed
// against bc-java source) -- a real, unpredictable seed. This adapter never
// wraps the key parameters in ParametersWithRandom, so no seed is ever
// caller-controlled or exposed, matching invariant 1 already established
// for the Crypto++ adapter (v0.6, D-033).

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.List;

public final class OaepBouncyCastle {

  public static final int MODULUS_BITS = 3072;
  public static final int K_BYTES = MODULUS_BITS / 8; // 384
  public static final int HASH_LEN_BYTES = 32; // SHA-256
  public static final int MAX_MESSAGE_LEN_BYTES = K_BYTES - 2 * HASH_LEN_BYTES - 2; // 318
  public static final String OAEP_HASH = "SHA-256";

  private OaepBouncyCastle() {}

  public static final class OaepKeyMaterial {
    public final String declaredRole; // "public" | "private" -- caller's claim, checked by Accept_C
    public final BigInteger modulus;
    public final BigInteger publicExponent;
    public final BigInteger privateExponent; // meaningful only when declaredRole == "private"
    public final int modulusBits;

    public OaepKeyMaterial(String declaredRole, BigInteger modulus, BigInteger publicExponent,
        BigInteger privateExponent, int modulusBits) {
      this.declaredRole = declaredRole;
      this.modulus = modulus;
      this.publicExponent = publicExponent;
      this.privateExponent = privateExponent;
      this.modulusBits = modulusBits;
    }
  }

  public static final class OaepEncryptRequest {
    public final OaepKeyMaterial key;
    public final byte[] plaintext;
    public final byte[] label;
    public final boolean labelPresent;
    public final String hash; // requested OAEP digest -- caller-declared, checked by Accept_C
    public final String mgfHash; // requested MGF1 digest -- caller-declared, checked by Accept_C

    public OaepEncryptRequest(OaepKeyMaterial key, byte[] plaintext, byte[] label, boolean labelPresent, String hash,
        String mgfHash) {
      this.key = key;
      this.plaintext = plaintext;
      this.label = label;
      this.labelPresent = labelPresent;
      this.hash = hash;
      this.mgfHash = mgfHash;
    }
  }

  public static final class OaepDecryptRequest {
    public final OaepKeyMaterial key;
    public final byte[] ciphertext; // NOT length-checked by Accept_C -- v0.6 D-034
    public final byte[] label;
    public final boolean labelPresent;
    public final String hash;
    public final String mgfHash;

    public OaepDecryptRequest(OaepKeyMaterial key, byte[] ciphertext, byte[] label, boolean labelPresent, String hash,
        String mgfHash) {
      this.key = key;
      this.ciphertext = ciphertext;
      this.label = label;
      this.labelPresent = labelPresent;
      this.hash = hash;
      this.mgfHash = mgfHash;
    }
  }

  public static OaepKeyMaterial generateOaepKeyMaterial() {
    SecureRandom random = new SecureRandom();
    RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
    gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), random, MODULUS_BITS, 80));
    AsymmetricCipherKeyPair pair = gen.generateKeyPair();
    RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters) pair.getPrivate();
    return new OaepKeyMaterial("private", priv.getModulus(), priv.getPublicExponent(), priv.getExponent(),
        priv.getModulus().bitLength());
  }

  private static String toHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  private static String nowIso() {
    return DateTimeFormatter.ISO_INSTANT.format(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS));
  }

  private static String jsonStringArray(List<String> xs) {
    StringBuilder sb = new StringBuilder("[");
    for (int i = 0; i < xs.size(); i++) {
      if (i > 0) sb.append(",");
      sb.append('"').append(xs.get(i)).append('"');
    }
    sb.append("]");
    return sb.toString();
  }

  private static String realizationId() {
    return "bouncycastle:bcprov-jdk18on:1.77 OAEPEncoding(RSAEngine,SHA256Digest) (lightweight API, "
        + "always constructed via the inherently-coupled 2-arg constructor -- see sec:environment for exact pinned jar + SHA-256)";
  }

  private static String buildEncryptInputJson(OaepEncryptRequest req) {
    return "{"
        + "\"keyRole\":\"" + req.key.declaredRole + "\","
        + "\"modulusBits\":" + req.key.modulusBits + ","
        + "\"plaintextHex\":\"" + toHex(req.plaintext) + "\","
        + "\"labelHex\":" + (req.labelPresent ? ("\"" + toHex(req.label) + "\"") : "null") + ","
        + "\"hash\":\"" + req.hash + "\","
        + "\"mgfHash\":\"" + req.mgfHash + "\"}";
  }

  private static String buildDecryptInputJson(OaepDecryptRequest req) {
    return "{"
        + "\"keyRole\":\"" + req.key.declaredRole + "\","
        + "\"modulusBits\":" + req.key.modulusBits + ","
        + "\"ciphertextHex\":\"" + toHex(req.ciphertext) + "\","
        + "\"labelHex\":" + (req.labelPresent ? ("\"" + toHex(req.label) + "\"") : "null") + ","
        + "\"hash\":\"" + req.hash + "\","
        + "\"mgfHash\":\"" + req.mgfHash + "\"}";
  }

  private static String encryptRecord(String inputJson, List<String> clauseIds, String outcomeJson) {
    return "{"
        + "\"operation\":\"RSA-OAEP\","
        + "\"direction\":\"encrypt\","
        + "\"backend\":{\"name\":\"bouncycastle\",\"realization\":\"" + realizationId() + "\"},"
        + "\"clauseIds\":" + jsonStringArray(clauseIds) + ","
        + "\"mutationId\":null,"
        + "\"input\":" + inputJson + ","
        + "\"outcome\":" + outcomeJson + ","
        + "\"timestampIso\":\"" + nowIso() + "\""
        + "}";
  }

  private static String decryptRecord(String inputJson, List<String> clauseIds, String outcomeJson) {
    return "{"
        + "\"operation\":\"RSA-OAEP\","
        + "\"direction\":\"decrypt\","
        + "\"backend\":{\"name\":\"bouncycastle\",\"realization\":\"" + realizationId() + "\"},"
        + "\"clauseIds\":" + jsonStringArray(clauseIds) + ","
        + "\"mutationId\":null,"
        + "\"input\":" + inputJson + ","
        + "\"outcome\":" + outcomeJson + ","
        + "\"timestampIso\":\"" + nowIso() + "\""
        + "}";
  }

  private static String rejectOutcome(String errorClass, String detail) {
    return "{\"kind\":\"reject\",\"errorClass\":\"" + errorClass + "\",\"detail\":\"" + detail + "\"}";
  }

  /**
   * I_p = API_p . Adapter_p for (RSA-OAEP encrypt, Bouncy Castle). Accept_C
   * steps 2+3, ALL evaluated before any OAEPEncoding/RSAEngine object is
   * constructed -- in particular, oaep.mgfCoupling is checked here, so a
   * decoupled request never reaches the point where BC's 4-arg constructor
   * could even be considered.
   */
  public static String oaepBouncyCastleEncrypt(OaepEncryptRequest req) {
    final String inputJson = buildEncryptInputJson(req);

    // Step 2: key contract.
    if (!"public".equals(req.key.declaredRole)) {
      String detail = "encrypt requires a public key; got role=\"" + req.key.declaredRole + "\"";
      return encryptRecord(inputJson, List.of("oaep.key"), rejectOutcome("invalid_key", detail));
    }

    // Step 3: portable parameter/input contract.
    if (req.key.modulusBits != MODULUS_BITS) {
      String detail = "modulus " + req.key.modulusBits + " bits, portable profile requires exactly " + MODULUS_BITS;
      return encryptRecord(inputJson, List.of("oaep.modulus"), rejectOutcome("invalid_parameter", detail));
    }
    if (!OAEP_HASH.equals(req.hash)) {
      String detail = "hash \"" + req.hash + "\", portable profile requires exactly \"" + OAEP_HASH + "\"";
      return encryptRecord(inputJson, List.of("oaep.hash"), rejectOutcome("invalid_parameter", detail));
    }
    if (!req.hash.equals(req.mgfHash)) {
      // THE critical check for this backend: rejected HERE, before any
      // OAEPEncoding object exists -- Bouncy Castle is the only backend
      // that could otherwise realize this natively (SHA256/SHA1).
      String detail =
          "mgfHash \"" + req.mgfHash + "\" != hash \"" + req.hash + "\"; portable profile requires H_OAEP=H_MGF1 (D-028)";
      return encryptRecord(inputJson, List.of("oaep.mgfCoupling"), rejectOutcome("invalid_parameter", detail));
    }
    if (req.labelPresent && req.label.length > 0) {
      String detail = "label present with " + req.label.length + " byte(s); portable profile requires L=empty (D-030)";
      return encryptRecord(inputJson, List.of("oaep.label"), rejectOutcome("invalid_parameter", detail));
    }
    if (req.plaintext.length > MAX_MESSAGE_LEN_BYTES) {
      String detail =
          "mLen=" + req.plaintext.length + " exceeds portable bound 0<=mLen<=" + MAX_MESSAGE_LEN_BYTES + " (D-032)";
      return encryptRecord(inputJson, List.of("oaep.message"), rejectOutcome("invalid_parameter", detail));
    }

    // Only now is any BC cipher object constructed -- via the 2-arg
    // constructor ONLY, which is inherently coupled (see file header).
    RSAKeyParameters publicKey = new RSAKeyParameters(false, req.key.modulus, req.key.publicExponent);
    OAEPEncoding cipher = new OAEPEncoding(new RSAEngine(), new SHA256Digest());
    cipher.init(true, publicKey); // no ParametersWithRandom -- falls back to CryptoServicesRegistrar.getSecureRandom()

    byte[] ciphertext;
    try {
      ciphertext = cipher.processBlock(req.plaintext, 0, req.plaintext.length);
    } catch (InvalidCipherTextException e) {
      // Not expected on encrypt with contractually-valid inputs -- an
      // unexpected native failure is a genuine finding, not silently normalized.
      throw new RuntimeException("Unexpected InvalidCipherTextException during OAEP encrypt", e);
    }

    return encryptRecord(inputJson,
        List.of("oaep.key", "oaep.modulus", "oaep.message", "oaep.ciphertext", "oaep.ciphertextLength", "oaep.hash",
            "oaep.mgfCoupling", "oaep.label"),
        "{\"kind\":\"accept\",\"ciphertextHex\":\"" + toHex(ciphertext) + "\"}");
  }

  /**
   * I_p = API_p . Adapter_p for (RSA-OAEP decrypt, Bouncy Castle). Same
   * frozen classification order as the other two adapters. Ciphertext
   * length is DELIBERATELY not checked (v0.6 D-034).
   */
  public static String oaepBouncyCastleDecrypt(OaepDecryptRequest req) {
    final String inputJson = buildDecryptInputJson(req);

    // Step 2.
    if (!"private".equals(req.key.declaredRole)) {
      String detail = "decrypt requires a private key; got role=\"" + req.key.declaredRole + "\"";
      return decryptRecord(inputJson, List.of("oaep.key"), rejectOutcome("invalid_key", detail));
    }

    // Step 3 (ciphertext length excluded).
    if (req.key.modulusBits != MODULUS_BITS) {
      String detail = "modulus " + req.key.modulusBits + " bits, portable profile requires exactly " + MODULUS_BITS;
      return decryptRecord(inputJson, List.of("oaep.modulus"), rejectOutcome("invalid_parameter", detail));
    }
    if (!OAEP_HASH.equals(req.hash)) {
      String detail = "hash \"" + req.hash + "\", portable profile requires exactly \"" + OAEP_HASH + "\"";
      return decryptRecord(inputJson, List.of("oaep.hash"), rejectOutcome("invalid_parameter", detail));
    }
    if (!req.hash.equals(req.mgfHash)) {
      String detail =
          "mgfHash \"" + req.mgfHash + "\" != hash \"" + req.hash + "\"; portable profile requires H_OAEP=H_MGF1 (D-028)";
      return decryptRecord(inputJson, List.of("oaep.mgfCoupling"), rejectOutcome("invalid_parameter", detail));
    }
    if (req.labelPresent && req.label.length > 0) {
      String detail = "label present with " + req.label.length + " byte(s); portable profile requires L=empty (D-030)";
      return decryptRecord(inputJson, List.of("oaep.label"), rejectOutcome("invalid_parameter", detail));
    }

    // Step 4: the actual RSAES-OAEP-DECRYPT call. Bouncy Castle's
    // decodeBlock() folds ciphertext-length divergence into the same
    // constant-time wrongMask flow used for internal decode validation
    // (v0.6, source-confirmed) -- closer to RFC 8017's anti-oracle spirit
    // than Crypto++'s two-tier surface, but this adapter does not rely on
    // that architecture; it catches broadly regardless.
    RSAKeyParameters privateKey = new RSAKeyParameters(true, req.key.modulus, req.key.privateExponent);
    OAEPEncoding cipher = new OAEPEncoding(new RSAEngine(), new SHA256Digest());
    cipher.init(false, privateKey);

    byte[] plaintext;
    try {
      plaintext = cipher.processBlock(req.ciphertext, 0, req.ciphertext.length);
    } catch (Exception e) {
      // Deliberately NOT inspecting e's type or message -- any failure
      // reaching here, after steps 2-3 already passed, is normalized to
      // decryption_error. Catches InvalidCipherTextException (checked) and
      // any RuntimeException (e.g. DataLengthException from a grossly
      // malformed input) uniformly, same discipline as WebCrypto/Crypto++.
      return decryptRecord(inputJson, List.of("oaep.error"),
          rejectOutcome("decryption_error",
              "RSAES-OAEP-DECRYPT failed (ciphertext length, lHash, padding, or RSA-representative-range "
                  + "cause -- collapsed per RFC 8017 Sec.7.1.2 anti-oracle requirement, D-027)"));
    }

    return decryptRecord(inputJson, List.of("oaep.key", "oaep.modulus", "oaep.hash", "oaep.mgfCoupling", "oaep.label"),
        "{\"kind\":\"accept\",\"plaintextHex\":\"" + toHex(plaintext) + "\"}");
  }
}
