package paper4.adapters.bouncycastle;

// RSA-PSS x Bouncy Castle adapter.
//
// Mirrors src/contract/pss.ts, src/adapters/webcrypto/pss.ts, and
// src/adapters/cryptopp/pss.{hpp,cpp}: same Accept_C checks (Design Freeze
// v0.6, sec:pss-error-model), same ClauseId set, same EvidenceRecord JSON
// shape -- independently reimplemented in Java.
//
// TWO critical invariants for this backend specifically (Design Freeze
// v0.6's PSS backend inventory):
//   1. PSSSigner.init() NEVER checks isPrivate() against forSigning --
//      confirmed source-literal ("matches OAEP's RSAEngine pattern exactly").
//      Unlike WebCrypto (InvalidAccessError) and Crypto++ (compile-time),
//      Bouncy Castle enforces key role NOT AT ALL natively. Accept_C's
//      declaredRole check is therefore not merely redundant defense-in-depth
//      here -- it is the ONLY thing standing between a role-swapped request
//      and BC silently proceeding.
//   2. PSSSigner CAN decouple H_PSS and H_MGF1 (a 4-arg constructor variant
//      accepting two independent Digest objects -- the same decoupling
//      pattern OAEPEncoding already demonstrated, "not a coincidence
//      specific to OAEP"). Accept_C rejects hash != mgfHash BEFORE any
//      PSSSigner object is constructed, and -- stronger than rejection
//      alone -- this adapter's success path calls ONLY the 3-argument
//      constructor PSSSigner(cipher, digest, sLen), which has no separate
//      mgfDigest parameter at all and is therefore structurally coupled by
//      construction, exactly like the OAEP adapter's 2-arg OAEPEncoding
//      choice. The decoupled 4-arg constructor never appears anywhere in
//      this file's success path.
//
// Narrow catch discipline: the catch
// around verifySignature() below is scoped to RuntimeException -- the class
// of exception a malformed-but-admitted verification input could plausibly
// raise from BC's own verify path -- NOT a blanket catch(Throwable), which
// would also silently swallow genuinely unexpected environment/bug-class
// failures (OutOfMemoryError, StackOverflowError, an actual adapter bug).
// Design Freeze v0.6 additionally notes BC's verifySignature() already
// internally absorbs most causes into a boolean return
// ("cipher.processBlock() wrapped in try{...}catch(Exception e){return
// false;}, and every subsequent EMSA-PSS-VERIFY internal check... uniformly
// returns false") -- so this adapter-level catch is a defensive backstop
// for the unconfirmed edge (malformed-input unchecked-exception behavior),
// not the primary normalization mechanism the way it is for Crypto++.

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.List;

public final class PssBouncyCastle {

  public static final int MODULUS_BITS = 3072;
  public static final int K_BYTES = MODULUS_BITS / 8; // 384
  public static final int HASH_LEN_BYTES = 32; // SHA-256
  public static final int SALT_LEN_BYTES = HASH_LEN_BYTES; // 32
  public static final String PSS_HASH = "SHA-256";

  private PssBouncyCastle() {}

  public static final class PssKeyMaterial {
    public final String declaredRole; // "public" | "private" -- caller's claim, checked by Accept_C
    public final BigInteger modulus;
    public final BigInteger publicExponent;
    public final BigInteger privateExponent; // meaningful only when declaredRole == "private"
    public final int modulusBits;

    public PssKeyMaterial(String declaredRole, BigInteger modulus, BigInteger publicExponent,
        BigInteger privateExponent, int modulusBits) {
      this.declaredRole = declaredRole;
      this.modulus = modulus;
      this.publicExponent = publicExponent;
      this.privateExponent = privateExponent;
      this.modulusBits = modulusBits;
    }
  }

  public static final class PssSignRequest {
    public final PssKeyMaterial key;
    public final byte[] message;
    public final String hash;
    public final String mgfHash;
    public final int saltLengthBytes;

    public PssSignRequest(PssKeyMaterial key, byte[] message, String hash, String mgfHash, int saltLengthBytes) {
      this.key = key;
      this.message = message;
      this.hash = hash;
      this.mgfHash = mgfHash;
      this.saltLengthBytes = saltLengthBytes;
    }
  }

  public static final class PssVerifyRequest {
    public final PssKeyMaterial key;
    public final byte[] message;
    public final byte[] signature; // NOT length-checked by Accept_C -- Design Freeze v0.6 D-046
    public final String hash;
    public final String mgfHash;
    public final int saltLengthBytes;

    public PssVerifyRequest(PssKeyMaterial key, byte[] message, byte[] signature, String hash, String mgfHash, int saltLengthBytes) {
      this.key = key;
      this.message = message;
      this.signature = signature;
      this.hash = hash;
      this.mgfHash = mgfHash;
      this.saltLengthBytes = saltLengthBytes;
    }
  }

  public static PssKeyMaterial generatePssKeyMaterial() {
    SecureRandom random = new SecureRandom();
    RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
    gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), random, MODULUS_BITS, 80));
    AsymmetricCipherKeyPair pair = gen.generateKeyPair();
    RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters) pair.getPrivate();
    return new PssKeyMaterial("private", priv.getModulus(), priv.getPublicExponent(), priv.getExponent(),
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
    return "bouncycastle:bcprov-jdk18on:1.77 PSSSigner(RSAEngine,SHA256Digest,sLen=32) (lightweight API, "
        + "always constructed via the coupled 3-arg constructor -- see sec:environment for exact pinned jar + SHA-256)";
  }

  private static String buildSignInputJson(PssSignRequest req) {
    return "{"
        + "\"keyRole\":\"" + req.key.declaredRole + "\","
        + "\"modulusBits\":" + req.key.modulusBits + ","
        + "\"messageHex\":\"" + toHex(req.message) + "\","
        + "\"hash\":\"" + req.hash + "\","
        + "\"mgfHash\":\"" + req.mgfHash + "\","
        + "\"saltLengthBytes\":" + req.saltLengthBytes + "}";
  }

  private static String buildVerifyInputJson(PssVerifyRequest req) {
    return "{"
        + "\"keyRole\":\"" + req.key.declaredRole + "\","
        + "\"modulusBits\":" + req.key.modulusBits + ","
        + "\"messageHex\":\"" + toHex(req.message) + "\","
        + "\"signatureHex\":\"" + toHex(req.signature) + "\","
        + "\"hash\":\"" + req.hash + "\","
        + "\"mgfHash\":\"" + req.mgfHash + "\","
        + "\"saltLengthBytes\":" + req.saltLengthBytes + "}";
  }

  private static String signRecord(String inputJson, List<String> clauseIds, String outcomeJson) {
    return "{"
        + "\"operation\":\"RSA-PSS\","
        + "\"direction\":\"sign\","
        + "\"backend\":{\"name\":\"bouncycastle\",\"realization\":\"" + realizationId() + "\"},"
        + "\"clauseIds\":" + jsonStringArray(clauseIds) + ","
        + "\"mutationId\":null,"
        + "\"input\":" + inputJson + ","
        + "\"outcome\":" + outcomeJson + ","
        + "\"timestampIso\":\"" + nowIso() + "\""
        + "}";
  }

  private static String verifyRecord(String inputJson, List<String> clauseIds, String outcomeJson) {
    return "{"
        + "\"operation\":\"RSA-PSS\","
        + "\"direction\":\"verify\","
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
   * I_p = API_p . Adapter_p for (RSA-PSS sign, Bouncy Castle). Accept_C
   * (key role, modulus, hash, mgfCoupling) runs entirely BEFORE PSSSigner
   * is ever constructed -- most importantly, key role, since PSSSigner.init()
   * itself performs no such check at all.
   */
  public static String pssBouncyCastleSign(PssSignRequest req) {
    final String inputJson = buildSignInputJson(req);

    if (!"private".equals(req.key.declaredRole)) {
      String detail = "sign requires a private key; got role=\"" + req.key.declaredRole + "\"";
      return signRecord(inputJson, List.of("pss.key"), rejectOutcome("invalid_key", detail));
    }
    if (req.key.modulusBits != MODULUS_BITS) {
      String detail = "modulus " + req.key.modulusBits + " bits, portable profile requires exactly " + MODULUS_BITS;
      return signRecord(inputJson, List.of("pss.modulus"), rejectOutcome("invalid_parameter", detail));
    }
    if (!PSS_HASH.equals(req.hash)) {
      String detail = "hash \"" + req.hash + "\", portable profile requires exactly \"" + PSS_HASH + "\"";
      return signRecord(inputJson, List.of("pss.hash"), rejectOutcome("invalid_parameter", detail));
    }
    if (!req.hash.equals(req.mgfHash)) {
      // THE critical check for this backend: rejected HERE, before any
      // PSSSigner object exists -- Bouncy Castle is the only backend that
      // could otherwise realize this natively (SHA256/SHA1).
      String detail =
          "mgfHash \"" + req.mgfHash + "\" != hash \"" + req.hash + "\"; portable profile requires H_PSS=H_MGF1 (D-040)";
      return signRecord(inputJson, List.of("pss.mgfCoupling"), rejectOutcome("invalid_parameter", detail));
    }
    if (req.saltLengthBytes != SALT_LEN_BYTES) {
      String detail = "saltLength=" + req.saltLengthBytes
          + " bytes, portable profile requires exactly " + SALT_LEN_BYTES + " (=hLen, D-041)";
      return signRecord(inputJson, List.of("pss.saltLength"), rejectOutcome("invalid_parameter", detail));
    }

    // pss.message: no portable length boundary exists (unlike OAEP) --
    // byte[] is always a well-formed byte sequence at the Java type level.

    // Only now is any BC signer object constructed -- via the 3-arg
    // constructor ONLY (cipher, digest, sLen), which has no separate
    // mgfDigest parameter and is therefore structurally coupled (see file
    // header). saltLength=32 is passed EXPLICITLY, not left to any default.
    RSAKeyParameters privateKey = new RSAKeyParameters(true, req.key.modulus, req.key.privateExponent);
    PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA256Digest(), SALT_LEN_BYTES);
    signer.init(true, privateKey);
    signer.update(req.message, 0, req.message.length);

    byte[] signature;
    try {
      signature = signer.generateSignature();
    } catch (CryptoException e) {
      // Not expected on sign with contractually-valid inputs (the
      // KeyTooShort()-equivalent realizability guard is unreachable under
      // the fixed 3072/SHA-256/sLen=32 profile, 384>=66 with wide margin)
      // -- an unexpected native failure here is a genuine finding, not
      // silently normalized.
      throw new RuntimeException("Unexpected CryptoException during PSS sign", e);
    }

    return signRecord(inputJson,
        List.of("pss.key", "pss.modulus", "pss.message", "pss.hash", "pss.mgfCoupling", "pss.saltLength",
            "pss.signature", "pss.signatureLength"),
        "{\"kind\":\"accept\",\"signatureHex\":\"" + toHex(signature) + "\"}");
  }

  /**
   * I_p = API_p . Adapter_p for (RSA-PSS verify, Bouncy Castle). Accept_C
   * covers key role, modulus, hash, mgfCoupling -- deliberately NOT
   * signature length (D-046). Once Accept_C passes, verifySignature()'s own
   * result IS the outcome; a caught RuntimeException (narrowly scoped, see
   * file header) is normalized to valid=false, NEVER to any SDK error --
   * E_PSS^SDK has no decryption_error-equivalent class at all.
   */
  public static String pssBouncyCastleVerify(PssVerifyRequest req) {
    final String inputJson = buildVerifyInputJson(req);

    if (!"public".equals(req.key.declaredRole)) {
      String detail = "verify requires a public key; got role=\"" + req.key.declaredRole + "\"";
      return verifyRecord(inputJson, List.of("pss.key"), rejectOutcome("invalid_key", detail));
    }
    if (req.key.modulusBits != MODULUS_BITS) {
      String detail = "modulus " + req.key.modulusBits + " bits, portable profile requires exactly " + MODULUS_BITS;
      return verifyRecord(inputJson, List.of("pss.modulus"), rejectOutcome("invalid_parameter", detail));
    }
    if (!PSS_HASH.equals(req.hash)) {
      String detail = "hash \"" + req.hash + "\", portable profile requires exactly \"" + PSS_HASH + "\"";
      return verifyRecord(inputJson, List.of("pss.hash"), rejectOutcome("invalid_parameter", detail));
    }
    if (!req.hash.equals(req.mgfHash)) {
      String detail =
          "mgfHash \"" + req.mgfHash + "\" != hash \"" + req.hash + "\"; portable profile requires H_PSS=H_MGF1 (D-040)";
      return verifyRecord(inputJson, List.of("pss.mgfCoupling"), rejectOutcome("invalid_parameter", detail));
    }

    if (req.saltLengthBytes != SALT_LEN_BYTES) {
      String detail = "saltLength=" + req.saltLengthBytes
          + " bytes, portable profile requires exactly " + SALT_LEN_BYTES + " (=hLen, D-041)";
      return verifyRecord(inputJson, List.of("pss.saltLength"), rejectOutcome("invalid_parameter", detail));
    }

    RSAKeyParameters publicKey = new RSAKeyParameters(false, req.key.modulus, req.key.publicExponent);
    PSSSigner verifier = new PSSSigner(new RSAEngine(), new SHA256Digest(), SALT_LEN_BYTES);
    verifier.init(false, publicKey);
    verifier.update(req.message, 0, req.message.length);

    boolean valid;
    try {
      valid = verifier.verifySignature(req.signature);
    } catch (RuntimeException e) {
      // Narrowly scoped (RuntimeException, not Throwable) -- see file
      // header for why. This is a defensive backstop: Design Freeze v0.6
      // confirms BC's own verifySignature() already internally collapses
      // most causes to a boolean return without throwing.
      valid = false;
    }

    return verifyRecord(inputJson, List.of("pss.key", "pss.modulus", "pss.hash", "pss.mgfCoupling", "pss.saltLength", "pss.verification"),
        "{\"kind\":\"verified\",\"valid\":" + (valid ? "true" : "false") + "}");
  }
}
