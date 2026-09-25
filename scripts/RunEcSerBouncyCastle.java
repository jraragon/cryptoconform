// M1 vertical slice: EC-ser x Bouncy Castle, no mutations.
// Build (pinned): org.bouncycastle:bcprov-jdk18on:1.77 (Maven Central).

package paper4.scripts;

import paper4.adapters.bouncycastle.EcSerBouncyCastle;
import paper4.adapters.bouncycastle.EcSerBouncyCastle.EcKeyMaterial;
import paper4.adapters.bouncycastle.EcSerBouncyCastle.EcPointXY;
import paper4.adapters.bouncycastle.EcSerBouncyCastle.EcSerError;
import paper4.adapters.bouncycastle.EcSerBouncyCastle.EcSerImportResult;

import java.math.BigInteger;
import java.util.Arrays;

public final class RunEcSerBouncyCastle {

  private static int failures = 0;

  private static void check(boolean condition, String failMessage) {
    if (!condition) {
      System.err.println("FAILED: " + failMessage);
      failures++;
    }
  }

  public static void main(String[] args) throws Exception {
    System.out.println("=== M1 vertical slice: EC-ser x Bouncy Castle ===\n");

    System.out.println("--- key generation (P-256, via BC's OWN lightweight generator; Q derived via OUR OWN scalar mult) ---");
    EcKeyMaterial priv = EcSerBouncyCastle.generateEcSerKeyMaterial();
    EcKeyMaterial pub = EcKeyMaterial.ofPublic(priv.q);
    System.out.println("PASS: P-256 key pair generated.\n");

    System.out.println("--- round trip (our own canonical encoder) ---");
    {
      byte[] pubDer = EcSerBouncyCastle.exportEcSer(pub);
      EcKeyMaterial pubBack = EcSerBouncyCastle.importEcSer(pubDer, "public").material;
      check(pubBack.q.x.equals(pub.q.x) && pubBack.q.y.equals(pub.q.y), "public round trip did not preserve Q.");

      byte[] privDer = EcSerBouncyCastle.exportEcSer(priv);
      EcSerImportResult result = EcSerBouncyCastle.importEcSer(privDer, "private");
      check(result.material.d.equals(priv.d) && result.material.q.x.equals(priv.q.x), "private round trip did not preserve material.");
      check(!result.normalized, "our own canonical export should already be portable (normalized=false).");
    }
    if (failures == 0) System.out.println("PASS: round trip preserves material exactly (R_ser), canonical export not normalized.\n");

    System.out.println("--- CONFIRMED FINDING: BC's native PKCS8 writer includes BOTH parameters[0] AND publicKey[1] (third distinct combination among the three backends) ---");
    {
      byte[] nativePkcs8 = EcSerBouncyCastle.nativeBcPkcs8Export(priv);
      EcSerImportResult result = EcSerBouncyCastle.importEcSer(nativePkcs8, "private");
      check(!result.normalized, "expected BC's native PKCS8 (both [0] and [1] present) to be accepted WITHOUT normalization -- unlike Chromium (normalized) and Crypto++ (rejected).");
      check(result.material.d.equals(priv.d), "recovered d from native BC PKCS8 did not match.");
    }
    if (failures == 0) {
      System.out.println(
          "PASS: BC's native PKCS8 (Q:=dG computed explicitly, both [0] and [1] populated) is accepted by our own Accept_C WITHOUT "
              + "normalization -- the third distinct native-export/Accept_C outcome among the three backends (Chromium: normalize; "
              + "Crypto++: reject; BC: accept directly).\n");
    }

    System.out.println("--- R_byte: SDK canonical DER vs BC's OWN independent native SPKI/PKCS8 writers ---");
    {
      byte[] sdkSpki = EcSerBouncyCastle.exportEcSer(pub);
      byte[] nativeSpki = EcSerBouncyCastle.nativeBcSpkiExport(pub);
      check(Arrays.equals(sdkSpki, nativeSpki), "SDK canonical SPKI differs from BC's own native SPKI writer.");

      byte[] sdkPkcs8 = EcSerBouncyCastle.exportEcSer(priv);
      byte[] nativePkcs8 = EcSerBouncyCastle.nativeBcPkcs8Export(priv);
      check(Arrays.equals(sdkPkcs8, nativePkcs8), "SDK canonical PKCS8 differs from BC's own native PKCS8 writer.");
    }
    if (failures == 0) {
      System.out.println("PASS: byte-identical against BC's OWN native SubjectPublicKeyInfoFactory/PrivateKeyInfoFactory, for BOTH SPKI and PKCS8.\n");
    }

    System.out.println("--- interop: BC natively imports our own canonical SDK-exported artifacts ---");
    {
      byte[] sdkSpki = EcSerBouncyCastle.exportEcSer(pub);
      EcKeyMaterial recovered = EcSerBouncyCastle.nativeBcImport(sdkSpki, "public");
      check(recovered.q.x.equals(pub.q.x) && recovered.q.y.equals(pub.q.y), "BC native import of our canonical SPKI did not recover Q.");

      byte[] sdkPkcs8 = EcSerBouncyCastle.exportEcSer(priv);
      EcKeyMaterial recoveredPriv = EcSerBouncyCastle.nativeBcImport(sdkPkcs8, "private");
      check(recoveredPriv.d.equals(priv.d), "BC native import of our canonical PKCS8 did not recover d.");
    }
    if (failures == 0) System.out.println("PASS: BC natively accepts and correctly parses our SDK-canonical artifacts.\n");

    System.out.println("--- [1] absent: contract path REJECTS (invalid_parameter); NATIVE BC ACCEPTS (never reads [1] at all -- structurally different from Chromium's 'derives Q' story) ---");
    {
      byte[] artifactNoPub = buildPrivateArtifact(priv.d, null);

      try {
        EcSerBouncyCastle.importEcSer(artifactNoPub, "private");
        check(false, "expected [1]-absent artifact to be rejected by our own Accept_C.");
      } catch (EcSerError ex) {
        check("invalid_parameter".equals(ex.errorClass) && "ec-ser.private.asn1".equals(ex.clauseId),
            "wrong classification for [1]-absent: " + ex.errorClass + "/" + ex.clauseId);
      }

      boolean nativeAccepted = EcSerBouncyCastle.nativeBcImportSucceeds(artifactNoPub, "private");
      check(nativeAccepted, "expected BC's native PrivateKeyFactory to accept [1]-absent (it never reads publicKey[1] at all).");
    }
    if (failures == 0) {
      System.out.println(
          "PASS: contract path rejects [1]-absent (D-059); native BC accepts it (structurally never reads [1], not by deriving Q like "
              + "Chromium) -- Accept_C != NativeAccept_p confirmed for BC specifically.\n");
    }

    System.out.println("--- ISOLATING STIMULUS (d1, Q2=d2*G), d1!=d2, both individually valid: contract path REJECTS (pairConsistency); NATIVE BC ACCEPTS (Q2 structurally never read, so no comparison is even attempted) ---");
    {
      EcKeyMaterial other = EcSerBouncyCastle.generateEcSerKeyMaterial();
      byte[] mismatchArtifact = buildPrivateArtifact(priv.d, other.q);

      try {
        EcSerBouncyCastle.importEcSer(mismatchArtifact, "private");
        check(false, "expected Q!=dG to be rejected by our own Accept_C.");
      } catch (EcSerError ex) {
        check("invalid_key".equals(ex.errorClass) && "ec-ser.pairConsistency".equals(ex.clauseId),
            "wrong classification for Q!=dG: " + ex.errorClass + "/" + ex.clauseId);
      }

      // Sanity/positive control: (d2, Q2), the genuine matching pair, through the identical hand-built path.
      byte[] genuineArtifact = buildPrivateArtifact(other.d, other.q);
      boolean controlAccepted = EcSerBouncyCastle.nativeBcImportSucceeds(genuineArtifact, "private");
      check(controlAccepted, "sanity control (d2,Q2) must be accepted natively -- confirms the hand-built DER path itself is valid.");

      boolean stimulusAccepted = EcSerBouncyCastle.nativeBcImportSucceeds(mismatchArtifact, "private");
      check(stimulusAccepted, "expected BC's native PrivateKeyFactory to ACCEPT (d1,Q2) -- Q2 structurally never read, so V_pair is inapplicable on this route, not enforced.");
    }
    if (failures == 0) {
      System.out.println(
          "PASS: contract path rejects Q!=dG (never normalized, D-061); native BC ACCEPTS the identical isolating stimulus -- confirmed "
              + "DIFFERENT from Chromium's native REJECTION of the same stimulus. V_pair is classified 'not applicable' for BC's "
              + "PrivateKeyFactory route (Q structurally never read), a genuinely different epistemic state from Chromium's 'enforced'.\n");
    }

    System.out.println("--- ec-ser.curveMembership: off-curve Q rejected as invalid_membership (isolated from pairConsistency) ---");
    {
      EcPointXY offCurve = new EcPointXY(pub.q.x, BigInteger.valueOf(12345));
      byte[] artifact = EcSerBouncyCastle.exportEcSer(EcKeyMaterial.ofPublic(offCurve));
      try {
        EcSerBouncyCastle.importEcSer(artifact, "public");
        check(false, "expected off-curve Q to be rejected.");
      } catch (EcSerError ex) {
        check("invalid_membership".equals(ex.errorClass) && "ec-ser.curveMembership".equals(ex.clauseId),
            "wrong classification for off-curve Q: " + ex.errorClass + "/" + ex.clauseId);
      }
    }
    if (failures == 0) System.out.println("PASS: off-curve Q rejected as invalid_membership.\n");

    System.out.println("--- V_scalar: d=0 rejected as invalid_key (contract path); confirmed literal against 1.77 that BC's OWN ECPrivateKeyParameters ALSO enforces this natively ---");
    {
      byte[] artifact = buildPrivateArtifact(BigInteger.ZERO, priv.q);
      try {
        EcSerBouncyCastle.importEcSer(artifact, "private");
        check(false, "expected d=0 to be rejected by our own Accept_C.");
      } catch (EcSerError ex) {
        check("invalid_key".equals(ex.errorClass) && "ec-ser.private.scalar".equals(ex.clauseId), "wrong classification for d=0.");
      }
      // Confirm BC's own PrivateKeyFactory ALSO rejects natively (validatePrivateScalar), unlike the [1]/pairConsistency cases above.
      boolean nativeAccepted = EcSerBouncyCastle.nativeBcImportSucceeds(artifact, "private");
      check(!nativeAccepted, "expected BC's native PrivateKeyFactory to ALSO reject d=0 (validatePrivateScalar, confirmed enforced).");
    }
    if (failures == 0) {
      System.out.println(
          "PASS: d=0 rejected by both contract path and native BC -- V_scalar is the one property BC enforces at BOTH layers, "
              + "confirmed literal against 1.77's ECDomainParameters.validatePrivateScalar.\n");
    }

    System.out.println("=== M1 slice complete for EC-ser x Bouncy Castle: "
        + (failures == 0 ? "ALL CHECKS PASSED" : (failures + " CHECK(S) FAILED")) + " ===");

    if (failures > 0) System.exit(1);
  }

  private static byte[] buildPrivateArtifact(BigInteger d, EcPointXY q) {
    byte[] dBytes = new byte[32];
    byte[] raw = d.toByteArray();
    int start = 0;
    while (start < raw.length - 1 && raw[start] == 0) start++;
    int len = raw.length - start;
    System.arraycopy(raw, start, dBytes, 32 - len, len);

    java.util.List<byte[]> fields = new java.util.ArrayList<>();
    fields.add(tlv(0x02, new byte[] {0x01}));
    fields.add(tlv(0x04, dBytes));
    if (q != null) {
      byte[] point = new byte[65];
      point[0] = 0x04;
      byte[] xb = fixed32(q.x);
      byte[] yb = fixed32(q.y);
      System.arraycopy(xb, 0, point, 1, 32);
      System.arraycopy(yb, 0, point, 33, 32);
      byte[] bitString = tlv(0x03, concat(new byte[] {0x00}, point));
      fields.add(tlv(0xa1, bitString));
    }
    byte[] inner = tlv(0x30, concatAll(fields));
    byte[] ecOid = new byte[] {0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01};
    byte[] curveOid = new byte[] {0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07};
    byte[] algId = tlv(0x30, concat(tlv(0x06, ecOid), tlv(0x06, curveOid)));
    return tlv(0x30, concatAll(java.util.Arrays.asList(tlv(0x02, new byte[] {0x00}), algId, tlv(0x04, inner))));
  }

  private static byte[] fixed32(BigInteger value) {
    byte[] raw = value.toByteArray();
    int start = 0;
    while (start < raw.length - 1 && raw[start] == 0) start++;
    int len = raw.length - start;
    byte[] out = new byte[32];
    System.arraycopy(raw, start, out, 32 - len, len);
    return out;
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

  private static byte[] concatAll(java.util.List<byte[]> parts) {
    int total = 0;
    for (byte[] p : parts) total += p.length;
    byte[] out = new byte[total];
    int off = 0;
    for (byte[] p : parts) {
      System.arraycopy(p, 0, out, off, p.length);
      off += p.length;
    }
    return out;
  }
}
