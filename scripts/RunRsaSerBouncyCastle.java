// M1 vertical slice: RSA-ser x Bouncy Castle, no mutations.
// Mirrors run-rsa-ser-cryptopp.cpp's checklist, plus the five backend-
// specific vigilance points from this session's design review:
//   1. DER-parseable != contractually admissible != materializable by BC.
//   2. Multi-prime: confirmed "parse but discard" (ASN.1 parses
//      version=1+otherPrimeInfos; PrivateKeyFactory's materialization
//      never reads otherPrimeInfos) -- literally confirmed against
//      bcprov-jdk18on:1.77, not `main`.
//   3. RSAPrivateCrtKeyParameters is confirmed to validate NOTHING beyond
//      the inherited modulus screen -- Accept_C never delegates to it.
//   4. AlgorithmIdentifier.parameters=NULL vs absent -- both admitted,
//      both re-export to the same canonical artifact.
//   5. R_byte: compared against BC's OWN independent native writer
//      (SubjectPublicKeyInfoFactory/PrivateKeyInfoFactory), not our own
//      encoder reused.
//
// Build (pinned): org.bouncycastle:bcprov-jdk18on:1.77 (Maven Central).
//   javac -cp bcprov-jdk18on-1.77.jar -d out \
//       src/adapters/bouncycastle/RsaSerBouncyCastle.java \
//       scripts/RunRsaSerBouncyCastle.java
//   java -cp out:bcprov-jdk18on-1.77.jar paper4.scripts.RunRsaSerBouncyCastle

package paper4.scripts;

import paper4.adapters.bouncycastle.RsaSerBouncyCastle;
import paper4.adapters.bouncycastle.RsaSerBouncyCastle.RsaKeyMaterial;
import paper4.adapters.bouncycastle.RsaSerBouncyCastle.RsaSerError;

import java.math.BigInteger;
import java.util.Arrays;

public final class RunRsaSerBouncyCastle {

  private static int failures = 0;

  private static void check(boolean condition, String failMessage) {
    if (!condition) {
      System.err.println("FAILED: " + failMessage);
      failures++;
    }
  }

  public static void main(String[] args) throws Exception {
    System.out.println("=== M1 vertical slice: RSA-ser x Bouncy Castle ===\n");

    System.out.println("--- key generation (RSA-3072, via BC's OWN lightweight generator) ---");
    RsaKeyMaterial priv = RsaSerBouncyCastle.generateRsaSerKeyMaterial(3072);
    RsaKeyMaterial pub = RsaKeyMaterial.ofPublic(priv.n, priv.e);
    System.out.println("PASS: RSA-3072 key pair generated.\n");

    System.out.println("--- round trip (our own canonical encoder) ---");
    {
      byte[] pubDer = RsaSerBouncyCastle.exportRsaSer(pub);
      RsaKeyMaterial pubBack = RsaSerBouncyCastle.importRsaSer(pubDer, "public");
      check(pubBack.n.equals(pub.n) && pubBack.e.equals(pub.e), "public round trip did not preserve material.");

      byte[] privDer = RsaSerBouncyCastle.exportRsaSer(priv);
      RsaKeyMaterial privBack = RsaSerBouncyCastle.importRsaSer(privDer, "private");
      check(privBack.n.equals(priv.n) && privBack.d.equals(priv.d) && privBack.p.equals(priv.p),
          "private round trip did not preserve material.");
    }
    if (failures == 0) System.out.println("PASS: round trip preserves material exactly (R_ser).\n");

    System.out.println("--- R_byte: SDK canonical DER vs Bouncy Castle's OWN independent native SPKI/PKCS8 writer ---");
    {
      byte[] sdkSpki = RsaSerBouncyCastle.exportRsaSer(pub);
      byte[] nativeSpki = RsaSerBouncyCastle.nativeBcSpkiExport(pub);
      check(Arrays.equals(sdkSpki, nativeSpki), "SDK canonical SPKI differs from BC's own native SPKI writer.");

      byte[] sdkPkcs8 = RsaSerBouncyCastle.exportRsaSer(priv);
      byte[] nativePkcs8 = RsaSerBouncyCastle.nativeBcPkcs8Export(priv);
      check(Arrays.equals(sdkPkcs8, nativePkcs8), "SDK canonical PKCS8 differs from BC's own native PKCS8 writer.");
    }
    if (failures == 0) {
      System.out.println(
          "PASS: byte-identical against Bouncy Castle's OWN SubjectPublicKeyInfoFactory/PrivateKeyInfoFactory "
              + "-- a genuinely independent writer, THIRD real cross-provider R_byte data point for RSA-ser.\n");
    }

    System.out.println("--- interop: BC natively imports our own canonical SDK-exported artifacts ---");
    {
      byte[] sdkSpki = RsaSerBouncyCastle.exportRsaSer(pub);
      check(RsaSerBouncyCastle.nativeBcImportSucceeds(sdkSpki, "public"), "BC natively rejected our own canonical SPKI export.");
      byte[] sdkPkcs8 = RsaSerBouncyCastle.exportRsaSer(priv);
      check(RsaSerBouncyCastle.nativeBcImportSucceeds(sdkPkcs8, "private"), "BC natively rejected our own canonical PKCS8 export.");
    }
    if (failures == 0) System.out.println("PASS: BC natively accepts our SDK-canonical artifacts (genuine interop).\n");

    System.out.println("--- rsa-ser.exact-consumption: trailing byte rejected ---");
    {
      byte[] artifact = RsaSerBouncyCastle.exportRsaSer(pub);
      byte[] withTrailer = Arrays.copyOf(artifact, artifact.length + 1);
      withTrailer[artifact.length] = (byte) 0xaa;
      try {
        RsaSerBouncyCastle.importRsaSer(withTrailer, "public");
        check(false, "expected trailing-byte artifact to be rejected.");
      } catch (RsaSerError ex) {
        check("malformed_artifact".equals(ex.errorClass) && "rsa-ser.exact-consumption".equals(ex.clauseId),
            "wrong classification for trailing bytes: " + ex.errorClass + "/" + ex.clauseId);
      }
    }
    if (failures == 0) System.out.println("PASS: exact-consumption enforced.\n");

    System.out.println("--- rsa-ser.role-container: wrong requested role rejected ---");
    {
      byte[] pubDer = RsaSerBouncyCastle.exportRsaSer(pub);
      try {
        RsaSerBouncyCastle.importRsaSer(pubDer, "private");
        check(false, "expected SPKI-as-private to be rejected.");
      } catch (RsaSerError ex) {
        check("invalid_parameter".equals(ex.errorClass) && "rsa-ser.role-container".equals(ex.clauseId),
            "wrong classification for role-container mismatch.");
      }
    }
    if (failures == 0) System.out.println("PASS: role-container mismatch rejected as invalid_parameter.\n");

    System.out.println("--- Accept_C independence: BC's RSAPrivateCrtKeyParameters validates NOTHING on CRT fields -- our own V_rel must catch corruption ---");
    {
      RsaKeyMaterial corrupted = new RsaKeyMaterial("private", priv.n, priv.e, priv.d, priv.p, priv.q,
          priv.dP.add(BigInteger.valueOf(2)), priv.dQ, priv.qInv);
      byte[] artifact = RsaSerBouncyCastle.exportRsaSer(corrupted);
      try {
        RsaSerBouncyCastle.importRsaSer(artifact, "private");
        check(false, "expected corrupted private-relations key to be rejected.");
      } catch (RsaSerError ex) {
        check("invalid_key".equals(ex.errorClass) && "rsa-ser.private-relations".equals(ex.clauseId),
            "wrong classification for corrupted CRT relation: " + ex.errorClass + "/" + ex.clauseId);
      }
      // Confirm BC's OWN RSAPrivateCrtKeyParameters constructor does NOT
      // itself reject this -- i.e. it would have silently admitted the
      // corrupted key had we (incorrectly) delegated to it. Exercised
      // implicitly via nativeBcPkcs8Export, which constructs
      // RSAPrivateCrtKeyParameters directly from the corrupted material.
      try {
        byte[] nativeOut = RsaSerBouncyCastle.nativeBcPkcs8Export(corrupted);
        check(nativeOut.length > 0, "unexpected empty native export for a CRT-corrupted key.");
      } catch (Exception ex) {
        check(false, "BC's own RSAPrivateCrtKeyParameters/PrivateKeyInfoFactory unexpectedly rejected a CRT-corrupted key at construction -- contradicts the confirmed zero-validation finding: " + ex.getMessage());
      }
    }
    if (failures == 0) {
      System.out.println(
          "PASS: corrupted CRT relation rejected via OUR OWN V_rel check; separately confirmed that BC's own "
              + "RSAPrivateCrtKeyParameters constructor raises no exception for the same corrupted material -- "
              + "confirming the zero-validation finding empirically, not just by source inspection.\n");
    }

    System.out.println("--- multi-prime: confirmed 'parse but discard', not native rejection at parse time (different mechanism from Crypto++) ---");
    {
      // CORRECTED (this session's design review): the artifact must have a
      // genuine INNER RSAPrivateKey with version=1 and a real
      // OtherPrimeInfo appended as a 10th field -- NOT a byte-flip of the
      // first "02 01 00" pattern found in the full PKCS8 byte stream,
      // which is the OUTER PrivateKeyInfo.version (always 0, unrelated to
      // multi-prime) and appears BEFORE the inner RSAPrivateKey.version.
      // That earlier version of this test silently validated the wrong
      // field and did not exercise multi-prime detection at all.
      byte[] artifact = buildMultiPrimeArtifact(priv);

      // OUR OWN Accept_C must reject this via its own structural walker
      // (field count == 10, not 9 -- rsa-ser.container).
      try {
        RsaSerBouncyCastle.importRsaSer(artifact, "private");
        check(false, "expected a genuine version=1+otherPrimeInfos artifact to be rejected by our own Accept_C.");
      } catch (RsaSerError ex) {
        check("malformed_artifact".equals(ex.errorClass) && "rsa-ser.container".equals(ex.clauseId),
            "wrong classification for multi-prime: " + ex.errorClass + "/" + ex.clauseId);
      }

      // SEPARATELY: confirm BC's own PrivateKeyFactory does NOT throw for
      // this artifact (unlike Crypto++) -- it is expected to silently
      // materialize an RSAPrivateCrtKeyParameters using only the 8
      // classical fields, discarding otherPrimeInfos entirely. Uses
      // nativeBcImport (returns the actual recovered material) so we can
      // additionally confirm the recovered (n,d,p) match the classical
      // fields we embedded -- i.e. BC genuinely ignored otherPrimeInfos
      // rather than failing to parse the classical fields at all.
      try {
        RsaKeyMaterial nativeRecovered = RsaSerBouncyCastle.nativeBcImport(artifact, "private");
        check(nativeRecovered.n.equals(priv.n) && nativeRecovered.d.equals(priv.d) && nativeRecovered.p.equals(priv.p),
            "BC's native import of the multi-prime artifact did not recover the expected classical fields.");
      } catch (Exception ex) {
        check(false,
            "BC's own PrivateKeyFactory unexpectedly REJECTED a genuine version=1+otherPrimeInfos artifact -- "
                + "contradicts the confirmed 'parse but discard' finding: " + ex.getMessage());
      }
    }
    if (failures == 0) {
      System.out.println(
          "PASS: multi-prime (genuine version=1 RSAPrivateKey with a real OtherPrimeInfo) rejected by our own "
              + "Accept_C (malformed_artifact/container); SEPARATELY confirmed that BC's OWN PrivateKeyFactory "
              + "does NOT reject it natively -- it materializes the classical 8-field RSAPrivateCrtKeyParameters "
              + "correctly and silently discards otherPrimeInfos -- the mechanism-level divergence from "
              + "Crypto++'s native parse-time rejection is now empirically confirmed against a properly "
              + "constructed multi-prime artifact, not a mislocated byte flip, against bcprov-jdk18on:1.77 "
              + "specifically.\n");
    }

    System.out.println("--- AlgorithmIdentifier.parameters=NULL vs absent: both admitted, converge to the same canonical export ---");
    {
      byte[] nullVariantInner = RsaSerBouncyCastle.exportRsaSer(pub); // our own export already uses explicit NULL

      // Hand-build an absent-params variant of the SAME public material.
      RsaKeyMaterial reimportedFromNull = RsaSerBouncyCastle.importRsaSer(nullVariantInner, "public");
      byte[] canonicalFromNull = RsaSerBouncyCastle.exportRsaSer(reimportedFromNull);

      // Build the absent-params SPKI by hand: SEQUENCE{ SEQUENCE{OID}, BIT STRING{ SEQUENCE{n,e} } }
      // reusing the same private DER-writer primitives indirectly is not
      // exposed publicly, so construct it via direct byte concatenation
      // mirroring exportRsaSer's own inner structure, with the AlgorithmIdentifier
      // reduced to just the OID (no NULL child).
      byte[] absentVariant = buildAbsentParamsSpki(pub.n, pub.e);
      RsaKeyMaterial reimportedFromAbsent = RsaSerBouncyCastle.importRsaSer(absentVariant, "public");
      byte[] canonicalFromAbsent = RsaSerBouncyCastle.exportRsaSer(reimportedFromAbsent);

      check(Arrays.equals(canonicalFromNull, canonicalFromAbsent),
          "NULL and absent variants of the same key did not converge to the same canonical export.");
      check(Arrays.equals(canonicalFromNull, nullVariantInner), "canonical export does not match the NULL-bearing form.");
    }
    if (failures == 0) {
      System.out.println(
          "PASS: parameters=NULL and parameters=absent both admitted and converge to the byte-identical "
              + "canonical export -- genuine canonicalization, third backend confirming this pattern.\n");
    }

    System.out.println("=== M1 slice complete for RSA-ser x Bouncy Castle: "
        + (failures == 0 ? "ALL CHECKS PASSED" : (failures + " CHECK(S) FAILED")) + " ===");

    if (failures > 0) {
      System.exit(1);
    }
  }

  /**
   * Hand-builds a PKCS8 PrivateKeyInfo whose INNER RSAPrivateKey is
   * genuinely version=1 with a real, syntactically-valid OtherPrimeInfo
   * appended as a 10th field (OtherPrimeInfo ::= SEQUENCE{prime INTEGER,
   * exponent INTEGER, coefficient INTEGER}, per RFC 8017 A.1.2). The
   * OtherPrimeInfo's numeric content is arbitrary (this tests ASN.1-level
   * acceptance/discard behavior, not multi-prime RSA cryptographic
   * correctness) -- only its syntactic well-formedness matters. The
   * OUTER PrivateKeyInfo.version remains 0 (that field is PKCS8's own,
   * unrelated to RSAPrivateKey's internal version).
   */
  private static byte[] buildMultiPrimeArtifact(RsaKeyMaterial priv) {
    byte[] otherPrimeInfo = tlv(0x30, concat(concat(tlv(0x02, BigInteger.valueOf(5).toByteArray()),
        tlv(0x02, BigInteger.valueOf(3).toByteArray())), tlv(0x02, BigInteger.valueOf(1).toByteArray())));
    byte[] otherPrimeInfos = tlv(0x30, otherPrimeInfo); // SEQUENCE OF OtherPrimeInfo, one entry

    byte[] innerFields = concat(concat(concat(concat(concat(concat(concat(concat(
        tlv(0x02, BigInteger.ONE.toByteArray()),                 // version = 1 (multi-prime)
        tlv(0x02, priv.n.toByteArray())),
        tlv(0x02, priv.e.toByteArray())),
        tlv(0x02, priv.d.toByteArray())),
        tlv(0x02, priv.p.toByteArray())),
        tlv(0x02, priv.q.toByteArray())),
        tlv(0x02, priv.dP.toByteArray())),
        tlv(0x02, priv.dQ.toByteArray())),
        tlv(0x02, priv.qInv.toByteArray()));
    innerFields = concat(innerFields, otherPrimeInfos); // 10th field
    byte[] inner = tlv(0x30, innerFields);

    byte[] algId = tlv(0x30, concat(
        tlv(0x06, new byte[] {0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01}),
        tlv(0x05, new byte[0])));
    byte[] octetString = tlv(0x04, inner);
    byte[] outerVersion = tlv(0x02, BigInteger.ZERO.toByteArray()); // PKCS8's OWN version, unrelated, always 0

    return tlv(0x30, concat(concat(outerVersion, algId), octetString));
  }

  /** Hand-builds an SPKI artifact with AlgorithmIdentifier.parameters ABSENT (no NULL child), for the canonicalization test. */
  private static byte[] buildAbsentParamsSpki(BigInteger n, BigInteger e) {
    byte[] oid = tlv(0x06, new byte[] {0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01});
    byte[] algId = tlv(0x30, oid); // SEQUENCE{OID} only -- no NULL
    byte[] inner = tlv(0x30, concat(tlv(0x02, n.toByteArray()), tlv(0x02, e.toByteArray())));
    byte[] bitString = tlv(0x03, concat(new byte[] {0x00}, inner));
    return tlv(0x30, concat(algId, bitString));
  }

  private static byte[] tlv(int tag, byte[] content) {
    byte[] len;
    if (content.length < 0x80) {
      len = new byte[] {(byte) content.length};
    } else {
      java.util.List<Byte> lenBytes = new java.util.ArrayList<>();
      int n = content.length;
      while (n > 0) {
        lenBytes.add(0, (byte) (n & 0xff));
        n >>>= 8;
      }
      len = new byte[lenBytes.size() + 1];
      len[0] = (byte) (0x80 | lenBytes.size());
      for (int i = 0; i < lenBytes.size(); i++) len[i + 1] = lenBytes.get(i);
    }
    return concat(concat(new byte[] {(byte) tag}, len), content);
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = new byte[a.length + b.length];
    System.arraycopy(a, 0, out, 0, a.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }
}
