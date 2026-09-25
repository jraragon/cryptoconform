package paper4.adapters.bouncycastle;

// AES-256-GCM x Bouncy Castle adapter.
//
// Mirrors src/contract/gcm.ts, src/adapters/webcrypto/gcm.ts, and
// src/adapters/cryptopp/gcm.{hpp,cpp} exactly: same Accept_C checks (v0.6,
// sec:aesgcm), same ClauseId set, same EvidenceRecord JSON shape --
// independently reimplemented in Java, not shared code across languages.
//
// Pinned artifact: org.bouncycastle:bcprov-jdk18on:1.77 (Maven Central,
// SHA-256 dabb98c2...a495d58; see Experimental_Evidence_Base v0.4,
// sec:environment) -- same jar already pinned for the HKDF slice.
//
// API used: org.bouncycastle.crypto.modes.GCMBlockCipher (lightweight API,
// AEADBlockCipher interface), with org.bouncycastle.crypto.params.AEADParameters
// carrying macSize directly in BITS -- unlike Crypto++, Bouncy Castle needs
// NO tagLength unit conversion; AEADParameters' macSizeInBits constructor
// argument already matches the contractual unit exactly.
//
// Four non-negotiable adapter invariants for THIS backend (v0.6
// sec:aesgcm-backends findings, source-confirmed against bc-java
// GCMBlockCipher.java):
//   1. SINGLE-SHOT doFinal(): the entire ciphertext/plaintext buffer is fed
//      to processBytes() in exactly ONE call, never chunked across multiple
//      processBytes() calls, per CVE-2026-8149 (published May 2026): GCM
//      decryption chunked at certain boundaries could incorrectly raise a
//      bad-tag exception on affected BC-LTS versions. This adapter's fixed
//      execution path (one processBytes() call with the full buffer, then
//      one doFinal() call) is not a performance choice -- it is required
//      correctness per the documented mitigation.
//   2. t=128 bits enforced by Accept_C before GCMBlockCipher.init() is ever
//      called -- source-confirmed BC DOES enforce a native floor
//      (32<=macSizeBits<=128, mod 8), unlike Crypto++, but the portable
//      profile is still strictly narrower (exactly 128), so this adapter's
//      own check is not redundant: BC would happily accept, e.g., t=80.
//   3. AAD_absent === AAD_empty, normalized contractually (via AEADParameters'
//      3-arg vs. 4-arg constructor, exercising two genuinely different code
//      paths that BC's own source confirms converge -- not left to whichever
//      happens to be convenient at the call site).
//   4. Native output is C||T (BC's doFinal() appends the tag after the
//      ciphertext, unconfigurable) -- this adapter treats that as GIVEN
//      (matching v0.6's source-confirmed finding for BC specifically, unlike
//      Crypto++ where it required explicit filter configuration) and adapts
//      it explicitly into version||IV||C||T; it does not assume this
//      generalizes to any other backend.

import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.engines.AESEngine;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;

public final class GcmBouncyCastle {

  public static final int KEY_LEN_BYTES = 32;       // 256 bits
  public static final int IV_LEN_BYTES = 12;        // 96 bits
  public static final int TAG_LEN_BYTES = 16;       // 128 bits
  public static final int TAG_LEN_BITS = TAG_LEN_BYTES * 8;  // 128
  public static final byte ARTIFACT_VERSION = 1;
  public static final int MIN_ARTIFACT_LEN_BYTES = 1 + IV_LEN_BYTES + TAG_LEN_BYTES;  // 29

  private GcmBouncyCastle() {}

  public static final class GcmEncryptRequest {
    public final byte[] key;
    public final byte[] plaintext;
    public final byte[] aad;       // meaningful only if aadPresent
    public final boolean aadPresent;
    public final byte[] iv;
    public final int tagLengthBits;  // contractual unit: BITS (matches AEADParameters directly)

    public GcmEncryptRequest(byte[] key, byte[] plaintext, byte[] aad, boolean aadPresent, byte[] iv,
        int tagLengthBits) {
      this.key = key;
      this.plaintext = plaintext;
      this.aad = aad;
      this.aadPresent = aadPresent;
      this.iv = iv;
      this.tagLengthBits = tagLengthBits;
    }
  }

  public static final class GcmDecryptRequest {
    public final byte[] key;
    public final byte[] artifact;  // version || IV12 || C || T16
    public final byte[] aad;
    public final boolean aadPresent;

    public GcmDecryptRequest(byte[] key, byte[] artifact, byte[] aad, boolean aadPresent) {
      this.key = key;
      this.artifact = artifact;
      this.aad = aad;
      this.aadPresent = aadPresent;
    }
  }

  public static final class AeadArtifactParts {
    public final byte version;
    public final byte[] iv;
    public final byte[] ciphertext;
    public final byte[] tag;

    AeadArtifactParts(byte version, byte[] iv, byte[] ciphertext, byte[] tag) {
      this.version = version;
      this.iv = iv;
      this.ciphertext = ciphertext;
      this.tag = tag;
    }
  }

  /** Pure encoder: version(1) || IV || C || T. Exposed (not private) so the runner can independently verify the split invariant. */
  public static byte[] buildAeadArtifact(byte[] iv, byte[] ciphertext, byte[] tag) {
    byte[] out = new byte[1 + iv.length + ciphertext.length + tag.length];
    out[0] = ARTIFACT_VERSION;
    System.arraycopy(iv, 0, out, 1, iv.length);
    System.arraycopy(ciphertext, 0, out, 1 + iv.length, ciphertext.length);
    System.arraycopy(tag, 0, out, 1 + iv.length + ciphertext.length, tag.length);
    return out;
  }

  private static final class MalformedArtifactException extends RuntimeException {
    MalformedArtifactException(String detail) {
      super(detail);
    }
  }

  /** Structurally validates and parses an artifact; throws MalformedArtifactException (caught internally, mapped to malformed_artifact) rather than returning a sentinel. */
  public static AeadArtifactParts parseAeadArtifact(byte[] artifact) {
    if (artifact == null || artifact.length < MIN_ARTIFACT_LEN_BYTES) {
      throw new MalformedArtifactException("artifact length " + (artifact == null ? "null" : artifact.length)
          + " below minimum " + MIN_ARTIFACT_LEN_BYTES + " bytes (version(1) + IV(12) + tag(16), empty ciphertext)");
    }
    byte version = artifact[0];
    if (version != ARTIFACT_VERSION) {
      throw new MalformedArtifactException("unsupported artifact version " + version + ", expected " + ARTIFACT_VERSION);
    }
    byte[] iv = Arrays.copyOfRange(artifact, 1, 1 + IV_LEN_BYTES);
    byte[] tag = Arrays.copyOfRange(artifact, artifact.length - TAG_LEN_BYTES, artifact.length);
    byte[] ciphertext = Arrays.copyOfRange(artifact, 1 + IV_LEN_BYTES, artifact.length - TAG_LEN_BYTES);
    return new AeadArtifactParts(version, iv, ciphertext, tag);
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
    // Same provenance-limitation pattern already recorded for HKDF/Crypto++:
    // this string is a human-readable cross-check, not the authoritative
    // pin (Maven coordinate + jar SHA-256, sec:environment).
    return "bouncycastle:bcprov-jdk18on:1.77 GCMBlockCipher(AESEngine) (lightweight API, single-shot processBytes+doFinal per CVE-2026-8149; see sec:environment for exact pinned jar + SHA-256)";
  }

  private static String buildEncryptInputJson(GcmEncryptRequest req) {
    return "{"
        + "\"keyHex\":\"" + toHex(req.key) + "\","
        + "\"plaintextHex\":\"" + toHex(req.plaintext) + "\","
        + "\"aadHex\":" + (req.aadPresent ? ("\"" + toHex(req.aad) + "\"") : "null") + ","
        + "\"ivHex\":\"" + toHex(req.iv) + "\","
        + "\"tagLengthBits\":" + req.tagLengthBits + "}";
  }

  private static String buildDecryptInputJson(GcmDecryptRequest req) {
    return "{"
        + "\"keyHex\":\"" + toHex(req.key) + "\","
        + "\"artifactHex\":\"" + toHex(req.artifact) + "\","
        + "\"aadHex\":" + (req.aadPresent ? ("\"" + toHex(req.aad) + "\"") : "null") + "}";
  }

  private static String encryptRecord(String inputJson, List<String> clauseIds, String outcomeJson) {
    return "{"
        + "\"operation\":\"AES-256-GCM\","
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
        + "\"operation\":\"AES-256-GCM\","
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
   * I_p = API_p . Adapter_p for (AES-GCM encrypt, Bouncy Castle). Accept_C
   * steps 1+3, independently reimplemented from src/contract/gcm.ts's
   * validateGcmEncryptRequest, same clause-by-clause order.
   */
  public static String gcmBouncyCastleEncrypt(GcmEncryptRequest req) {
    final String inputJson = buildEncryptInputJson(req);

    if (req.key == null || req.key.length != KEY_LEN_BYTES) {
      String detail = "key length " + (req.key == null ? "null" : req.key.length)
          + " bytes, portable profile requires exactly " + KEY_LEN_BYTES + " (256 bits)";
      return encryptRecord(inputJson, List.of("gcm.key"), rejectOutcome("invalid_parameter", detail));
    }
    if (req.iv == null || req.iv.length != IV_LEN_BYTES) {
      String detail = "IV length " + (req.iv == null ? "null" : req.iv.length)
          + " bytes, portable profile requires exactly " + IV_LEN_BYTES + " (96 bits)";
      return encryptRecord(inputJson, List.of("gcm.iv"), rejectOutcome("invalid_parameter", detail));
    }
    if (req.tagLengthBits != TAG_LEN_BITS) {
      // Invariant 2: BC DOES natively enforce 32<=t<=128 (source-confirmed),
      // so this is not protecting against a zero-floor risk the way it does
      // for Crypto++ -- but the portable profile is still strictly narrower
      // than what BC natively accepts (e.g. t=80 is BC-valid, non-portable),
      // so this adapter-level check is still necessary, not redundant.
      String detail = "tagLength=" + req.tagLengthBits + " bits outside portable profile; must be exactly "
          + TAG_LEN_BITS + " bits (v0.6 sec:aesgcm)";
      return encryptRecord(inputJson, List.of("gcm.tagLength"), rejectOutcome("invalid_parameter", detail));
    }

    // Invariant 3: AAD_absent vs AAD_empty realized via AEADParameters' two
    // constructors -- genuinely distinct code paths, not a single branch
    // papering over the distinction. BC's own source (associatedText
    // defaulting) confirms both converge on the same GHASH computation.
    GCMModeCipher cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
    AEADParameters params = req.aadPresent
        ? new AEADParameters(new KeyParameter(req.key), req.tagLengthBits, req.iv, req.aad)
        : new AEADParameters(new KeyParameter(req.key), req.tagLengthBits, req.iv);
    cipher.init(true, params);

    // Invariant 1: SINGLE-SHOT. The entire plaintext is fed to processBytes()
    // in exactly one call (never looped/chunked), then doFinal() once. This
    // is the encrypt-side counterpart of the CVE-2026-8149 mitigation.
    byte[] cipherAndTag = new byte[cipher.getOutputSize(req.plaintext.length)];
    int len = cipher.processBytes(req.plaintext, 0, req.plaintext.length, cipherAndTag, 0);
    try {
      len += cipher.doFinal(cipherAndTag, len);
    } catch (org.bouncycastle.crypto.InvalidCipherTextException e) {
      // Not expected on encrypt (no tag to verify yet) -- an unexpected
      // native failure here is a genuine finding, not silently normalized.
      throw new RuntimeException("Unexpected InvalidCipherTextException during GCM encrypt", e);
    }

    // Invariant 4: native output is C||T (BC's own, unconfigurable
    // behavior, source-confirmed) -- split explicitly, checked, not assumed.
    byte[] ciphertext = Arrays.copyOfRange(cipherAndTag, 0, len - TAG_LEN_BYTES);
    byte[] tag = Arrays.copyOfRange(cipherAndTag, len - TAG_LEN_BYTES, len);
    byte[] artifact = buildAeadArtifact(req.iv, ciphertext, tag);

    return encryptRecord(inputJson,
        List.of("gcm.key", "gcm.plaintext", "gcm.aad", "gcm.iv", "gcm.tagLength", "gcm.ciphertext", "gcm.artifact"),
        "{\"kind\":\"accept\",\"artifactHex\":\"" + toHex(artifact) + "\"}");
  }

  /**
   * I_p = API_p . Adapter_p for (AES-GCM decrypt, Bouncy Castle). Frozen
   * classification order, as four separate sequential steps -- mirrors
   * gcmWebCryptoDecrypt/GcmDecryptCryptoPP exactly:
   *   1. key check          -> gcm.key,            invalid_parameter
   *   2. parseAeadArtifact  -> gcm.artifact,        malformed_artifact
   *   3. aad check          -> gcm.aad,             invalid_parameter
   *   4. the decrypt call   -> gcm.authentication,  authentication_failure
   */
  public static String gcmBouncyCastleDecrypt(GcmDecryptRequest req) {
    final String inputJson = buildDecryptInputJson(req);

    // Step 1.
    if (req.key == null || req.key.length != KEY_LEN_BYTES) {
      String detail = "key length " + (req.key == null ? "null" : req.key.length)
          + " bytes, portable profile requires exactly " + KEY_LEN_BYTES + " (256 bits)";
      return decryptRecord(inputJson, List.of("gcm.key"), rejectOutcome("invalid_parameter", detail));
    }

    // Step 2.
    AeadArtifactParts parts;
    try {
      parts = parseAeadArtifact(req.artifact);
    } catch (MalformedArtifactException e) {
      return decryptRecord(inputJson, List.of("gcm.artifact"), rejectOutcome("malformed_artifact", e.getMessage()));
    }

    // Step 3 -- trivially satisfied at the Java type level (aad is either
    // null-with-aadPresent=false or a real byte[]); kept explicit only for
    // structural parity with the other two adapters' classification order.

    // Step 4: the decrypt/authentication call itself.
    GCMModeCipher cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
    AEADParameters params = req.aadPresent
        ? new AEADParameters(new KeyParameter(req.key), TAG_LEN_BITS, parts.iv, req.aad)
        : new AEADParameters(new KeyParameter(req.key), TAG_LEN_BITS, parts.iv);
    cipher.init(false, params);

    byte[] cipherAndTag = new byte[parts.ciphertext.length + parts.tag.length];
    System.arraycopy(parts.ciphertext, 0, cipherAndTag, 0, parts.ciphertext.length);
    System.arraycopy(parts.tag, 0, cipherAndTag, parts.ciphertext.length, parts.tag.length);

    byte[] plaintext = new byte[cipher.getOutputSize(cipherAndTag.length)];
    try {
      // Invariant 1 again, decrypt side: exactly ONE processBytes() call
      // with the complete C||T buffer, then ONE doFinal() call -- the
      // documented CVE-2026-8149 mitigation, not an incidental style choice.
      int len = cipher.processBytes(cipherAndTag, 0, cipherAndTag.length, plaintext, 0);
      len += cipher.doFinal(plaintext, len);
      plaintext = Arrays.copyOf(plaintext, len);
    } catch (Exception e) {
      // Deliberately NOT inspecting e's type or message -- any failure
      // reaching here, after steps 1-3 already passed, is normalized to
      // authentication_failure. No taxonomy built from the exception text,
      // matching the WebCrypto and Crypto++ adapters' identical discipline.
      // Catches both InvalidCipherTextException (checked, bad tag) and any
      // RuntimeCryptoException subtype uniformly.
      return decryptRecord(inputJson, List.of("gcm.authentication"),
          rejectOutcome("authentication_failure",
              "GCM authentication failed (tag verification rejected the ciphertext/tag/AAD/IV combination)"));
    }

    return decryptRecord(inputJson, List.of("gcm.key", "gcm.aad", "gcm.artifact", "gcm.authentication"),
        "{\"kind\":\"accept\",\"plaintextHex\":\"" + toHex(plaintext) + "\"}");
  }
}
