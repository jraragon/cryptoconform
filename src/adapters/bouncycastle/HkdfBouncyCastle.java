package paper4.adapters.bouncycastle;

// HKDF x Bouncy Castle adapter.
//
// Pinned artifact: org.bouncycastle:bcprov-jdk18on:1.77 (Maven Central),
// NOT the Debian/Ubuntu system package -- deliberately, to avoid an extra
// unpinned packaging layer (see conversation decision preceding this file).
// SHA-256 of the exact jar used is recorded in the Experimental Evidence
// Base v0.1, sec:environment, alongside the Crypto++ commit pin.
//
// Mirrors src/adapters/webcrypto/hkdf.ts and src/adapters/cryptopp/hkdf.cpp:
// same Accept_C checks (v0.6, D-068), same ClauseId set, same EvidenceRecord
// JSON shape, so cross-backend evidence records are structurally comparable
// without per-language translation.
//
// API used: org.bouncycastle.crypto.generators.HKDFBytesGenerator +
// org.bouncycastle.crypto.params.HKDFParameters (the "lightweight" BC API,
// not JCE/Provider-registered), since HKDF has no javax.crypto.Mac/KeyGenerator
// JCE registration in this BC version -- the lightweight API is the only
// direct route to HKDF-SHA-256 in bcprov.
//
// NOTE on salt semantics (source-verified against BC 1.77
// HKDFBytesGenerator.extractPRK, bundled source jar): BC treats a Java
// `null` salt argument as HashLen zero octets internally -- i.e. passing
// null IS the correct, direct mapping of RFC 5869's "absent salt" case for
// this backend, unlike WebCrypto (needs an explicit empty Uint8Array) or
// Crypto++ (this adapter explicitly builds a HashLen zero-byte vector).
// This adapter passes null for saltPresent=false rather than synthesizing
// a same-length zero array, since BC's own null-handling already performs
// exactly that substitution -- verified by source inspection, not assumed.

import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.DataLengthException;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.List;

public final class HkdfBouncyCastle {

  private static final int HASH_LEN = 32;      // HKDF-SHA-256
  private static final int MIN_L = 1;          // D-068
  private static final int MAX_L = 255 * HASH_LEN;  // 8160, D-068

  private HkdfBouncyCastle() {}

  public static final class HkdfRequest {
    public final byte[] ikm;
    public final byte[] salt;      // meaningful only if saltPresent
    public final boolean saltPresent;
    public final byte[] info;
    public final int length;       // requested OKM length L, in octets

    public HkdfRequest(byte[] ikm, byte[] salt, boolean saltPresent, byte[] info, int length) {
      this.ikm = ikm;
      this.salt = salt;
      this.saltPresent = saltPresent;
      this.info = info;
      this.length = length;
    }
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
    // org.bouncycastle.crypto.generators.HKDFBytesGenerator has no runtime
    // version-introspection API of its own; the exact pinned identity is the
    // Maven coordinate + jar SHA-256 recorded externally (Experimental
    // Evidence Base v0.1, sec:environment) -- mirrors the Crypto++ adapter's
    // provenance-limitation finding: this string is a human-readable
    // cross-check, not the authoritative pin.
    return "bouncycastle:bcprov-jdk18on:1.77 HKDFBytesGenerator(SHA256Digest) (lightweight API; see sec:environment for exact pinned jar + SHA-256)";
  }

  private static String buildInputJson(HkdfRequest req) {
    return "{"
        + "\"ikmHex\":\"" + toHex(req.ikm) + "\","
        + "\"saltHex\":" + (req.saltPresent ? ("\"" + toHex(req.salt) + "\"") : "null") + ","
        + "\"infoHex\":\"" + toHex(req.info) + "\","
        + "\"length\":" + req.length + "}";
  }

  /**
   * Returns a JSON-serialized EvidenceRecord, field-for-field identical in
   * shape to the TypeScript EvidenceRecord (src/evidence/record.ts) and the
   * Crypto++ adapter's output.
   */
  public static String hkdfBouncyCastle(HkdfRequest req) {
    final String realization = realizationId();
    final String inputJson = buildInputJson(req);

    // Accept_C(request) -- SDK-level admission, enforced by the adapter
    // itself, exactly as in the WebCrypto and Crypto++ adapters. Not
    // delegated to HKDFBytesGenerator's own bound-checking (D-054/D-060
    // pattern): the lower bound L>=1 (D-068, portable-profile-only, not
    // RFC-mandated) is NOT enforced natively by BC (generateBytes accepts
    // len=0 silently -- verified by source inspection), so adapter-level
    // enforcement is not merely redundant here, it is necessary.
    if (!(req.length >= MIN_L && req.length <= MAX_L)) {
      String detail = "L=" + req.length + " outside portable-profile bound "
          + MIN_L + "<=L<=" + MAX_L + " (D-068)";
      return "{"
          + "\"operation\":\"HKDF-SHA-256\","
          + "\"backend\":{\"name\":\"bouncycastle\",\"realization\":\"" + realization + "\"},"
          + "\"clauseIds\":" + jsonStringArray(List.of("hkdf.length")) + ","
          + "\"mutationId\":null,"
          + "\"input\":" + inputJson + ","
          + "\"outcome\":{\"kind\":\"reject\",\"errorClass\":\"invalid_parameter\",\"detail\":\"" + detail + "\"},"
          + "\"timestampIso\":\"" + nowIso() + "\""
          + "}";
    }

    // RFC 5869: absent salt = HashLen zero octets. Here this is realized by
    // passing null directly to HKDFParameters, relying on BC's own verified
    // null -> HashLen-zero-octets substitution in extractPRK (see file
    // header) -- NOT a synthesized zero-byte array as in the Crypto++
    // adapter, since that indirection is unnecessary for this backend and
    // would just be re-deriving what BC already does internally.
    byte[] saltArg = req.saltPresent ? req.salt : null;

    HKDFBytesGenerator generator = new HKDFBytesGenerator(new SHA256Digest());
    generator.init(new HKDFParameters(req.ikm, saltArg, req.info));

    byte[] okm = new byte[req.length];
    try {
      generator.generateBytes(okm, 0, req.length);
    } catch (DataLengthException e) {
      // Not normalized away -- an unexpected native failure inside the
      // already-Accept_C-cleared portable-profile bound would itself be a
      // finding, not something to silently paper over. None expected here
      // since Accept_C already enforces D-068's bounds before this point.
      throw new RuntimeException("Unexpected DataLengthException inside portable-profile bound", e);
    }

    return "{"
        + "\"operation\":\"HKDF-SHA-256\","
        + "\"backend\":{\"name\":\"bouncycastle\",\"realization\":\"" + realization + "\"},"
        + "\"clauseIds\":" + jsonStringArray(List.of(
            "hkdf.ikm", "hkdf.salt", "hkdf.info", "hkdf.hash", "hkdf.length", "hkdf.output")) + ","
        + "\"mutationId\":null,"
        + "\"input\":" + inputJson + ","
        + "\"outcome\":{\"kind\":\"accept\",\"okmHex\":\"" + toHex(okm) + "\"},"
        + "\"timestampIso\":\"" + nowIso() + "\""
        + "}";
  }
}
