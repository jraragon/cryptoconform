package paper4.adapters.bouncycastle;

// EC-ser x Bouncy Castle adapter.
//
// CONFIRMED PRECISELY AGAINST bcprov-jdk18on:1.77 SOURCE
// (not against `main`, not assumed):
//
// (1) NATIVE EXPORT INCLUDES BOTH [0] AND [1] -- the third distinct
//     combination among the three backends (Chromium: [0] absent/[1]
//     present; Crypto++: both absent; BC: both present). Confirmed
//     literal, crypto.util.PrivateKeyInfoFactory's EC branch:
//       ECPoint q = new FixedPointCombMultiplier().multiply(domainParams.getG(), priv.getD());
//       DERBitString publicKey = new DERBitString(q.getEncoded(false));
//       return new PrivateKeyInfo(new AlgorithmIdentifier(id_ecPublicKey, params),
//           new ECPrivateKey(orderBitLength, priv.getD(), publicKey, params), attributes);
//     Q:=dG is computed EXPLICITLY (not merely re-derived by the SDK adapter
//     as with Crypto++/Chromium); ECPrivateKey's own constructor
//     (asn1/sec/ECPrivateKey.java) adds a DERTaggedObject(true,0,parameters)
//     iff parameters!=null and DERTaggedObject(true,1,publicKey) iff
//     publicKey!=null -- both are always non-null on this call path, so
//     BC's native PKCS8 IS already portable-complete on [0]/[1] presence
//     (though NOT necessarily byte-identical to our own canonical writer --
//     that is a separate R_byte question, checked below).
//
// (2) PrivateKeyFactory's EC branch, confirmed literal against 1.77 itself
//     (not `main` -- 1.77 does not even carry the TODO comment `main`
//     has; the underlying no-consistency-check BEHAVIOR is identical,
//     but the comment's presence is version-specific and not claimed here):
//       ECPrivateKey ec = ECPrivateKey.getInstance(keyInfo.parsePrivateKey());
//       BigInteger d = ec.getKey();
//       return new ECPrivateKeyParameters(d, dParams);
//     ec.getPublicKey() is NEVER called in this routine -- publicKey[1] is
//     not consulted, materialized, validated, or compared, confirmed
//     literally. domainParams is built EXCLUSIVELY from the outer
//     AlgorithmIdentifier.parameters; the inner ECPrivateKey.parameters[0]
//     accessor is never consulted either.
//
// (3) V_scalar IS enforced, confirmed literal (STRONGER evidence than the
//     stack-trace-based finding in the frozen design -- this is the actual
//     1.77 source line): ECPrivateKeyParameters's constructor calls
//     `this.d = parameters.validatePrivateScalar(d);`, and
//     ECDomainParameters.validatePrivateScalar throws IllegalArgumentException
//     for `d.compareTo(ONE) < 0 || d.compareTo(getN()) >= 0` -- i.e. exactly
//     1<=d<n.
//
// (4) V_curve (membership) is enforced EXPLICITLY for BOTH compressed and
//     uncompressed point encodings, confirmed literal against 1.77's
//     math.ec.ECCurve.decodePoint: case 0x02/0x03 calls
//     `p.implIsValid(true,true)`, throwing if invalid; case 0x04 calls
//     `validatePoint(X,Y)` directly. PublicKeyFactory's ECConverter calls
//     `ecDomainParameters.getCurve().decodePoint(x9Encoding)` directly, so
//     this validation is inherited automatically. The identity point
//     (0x00) is accepted without rejection at this layer (case 0x00 returns
//     getInfinity() unconditionally) -- irrelevant to our own Accept_C,
//     since our decoder only ever attempts the uncompressed (0x04) form.
//
// (5) V_pair (Q_supplied=dG): NOT applicable on this route -- since
//     publicKey[1] is never read by PrivateKeyFactory at all (confirmed
//     above), there is structurally no code path for BC's own
//     PrivateKeyFactory to compare a supplied Q against dG. This is
//     distinct from "not enforced" (which would imply an attempted-and-
//     absent check) -- confirmed via the canonical isolating stimulus
//     (d1,Q2=d2*G) in the accompanying runner, expected to be silently
//     ACCEPTED by BC natively (Q2 simply never read), a different outcome
//     from Chromium's confirmed native REJECTION of the same stimulus.

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public final class EcSerBouncyCastle {

  private EcSerBouncyCastle() {}

  private static final X9ECParameters P256_PARAMS = CustomNamedCurves.getByName("P-256");
  // ECNamedDomainParameters (not plain ECDomainParameters), so
  // PrivateKeyInfoFactory recognizes this as a namedCurve and emits the
  // compact secp256r1 OID form -- confirmed necessary: PrivateKeyInfoFactory's
  // EC branch checks `domainParams instanceof ECNamedDomainParameters`
  // specifically; a plain ECDomainParameters falls into the explicit
  // X9ECParameters branch instead, producing a full explicit curve
  // SEQUENCE rather than the OID our own portable profile expects.
  private static final ECDomainParameters DOMAIN_PARAMS =
      new ECNamedDomainParameters(X9ObjectIdentifiers.prime256v1, P256_PARAMS.getCurve(), P256_PARAMS.getG(), P256_PARAMS.getN(), P256_PARAMS.getH());

  public static final class EcSerError extends RuntimeException {
    public final String clauseId;
    public final String errorClass;

    public EcSerError(String clauseId, String errorClass, String detail) {
      super(detail);
      this.clauseId = clauseId;
      this.errorClass = errorClass;
    }
  }

  public static final class EcPointXY {
    public final BigInteger x, y;

    public EcPointXY(BigInteger x, BigInteger y) {
      this.x = x;
      this.y = y;
    }
  }

  public static final class EcKeyMaterial {
    public final String role; // "public" | "private"
    public final EcPointXY q;
    public final BigInteger d; // meaningful only when role == "private"

    public EcKeyMaterial(String role, EcPointXY q, BigInteger d) {
      this.role = role;
      this.q = q;
      this.d = d;
    }

    public static EcKeyMaterial ofPublic(EcPointXY q) {
      return new EcKeyMaterial("public", q, null);
    }
  }

  public static final class EcSerImportResult {
    public final EcKeyMaterial material;
    public final boolean normalized;

    public EcSerImportResult(EcKeyMaterial material, boolean normalized) {
      this.material = material;
      this.normalized = normalized;
    }
  }

  // --- Our own P-256 point arithmetic -- mirrors src/contract/p256.ts / the Crypto++ adapter's C++ mirror. ---

  private static final BigInteger P256_P = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
  private static final BigInteger P256_A = P256_P.subtract(BigInteger.valueOf(3));
  private static final BigInteger P256_B = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
  private static final BigInteger P256_GX = new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
  private static final BigInteger P256_GY = new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);
  private static final BigInteger P256_N = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

  private static BigInteger mod(BigInteger x, BigInteger m) {
    BigInteger r = x.mod(m);
    return r;
  }

  private static boolean isOnCurve(EcPointXY p) {
    if (p == null) return false;
    if (p.x.signum() < 0 || p.x.compareTo(P256_P) >= 0 || p.y.signum() < 0 || p.y.compareTo(P256_P) >= 0) return false;
    BigInteger lhs = p.y.multiply(p.y).mod(P256_P);
    BigInteger rhs = p.x.multiply(p.x).mod(P256_P).multiply(p.x).add(P256_A.multiply(p.x)).add(P256_B).mod(P256_P);
    return lhs.equals(rhs);
  }

  private static EcPointXY pointAdd(EcPointXY p1, EcPointXY p2) {
    if (p1 == null) return p2;
    if (p2 == null) return p1;
    if (p1.x.equals(p2.x)) {
      if (mod(p1.y.add(p2.y), P256_P).equals(BigInteger.ZERO)) return null; // infinity
      return pointDouble(p1);
    }
    BigInteger lambda = mod(p2.y.subtract(p1.y).multiply(mod(p2.x.subtract(p1.x), P256_P).modInverse(P256_P)), P256_P);
    BigInteger x3 = mod(lambda.multiply(lambda).subtract(p1.x).subtract(p2.x), P256_P);
    BigInteger y3 = mod(lambda.multiply(p1.x.subtract(x3)).subtract(p1.y), P256_P);
    return new EcPointXY(x3, y3);
  }

  private static EcPointXY pointDouble(EcPointXY p1) {
    if (p1 == null) return null;
    if (p1.y.equals(BigInteger.ZERO)) return null;
    BigInteger lambda = mod(
        BigInteger.valueOf(3).multiply(p1.x).multiply(p1.x).add(P256_A).multiply(mod(BigInteger.valueOf(2).multiply(p1.y), P256_P).modInverse(P256_P)),
        P256_P);
    BigInteger x3 = mod(lambda.multiply(lambda).subtract(BigInteger.valueOf(2).multiply(p1.x)), P256_P);
    BigInteger y3 = mod(lambda.multiply(p1.x.subtract(x3)).subtract(p1.y), P256_P);
    return new EcPointXY(x3, y3);
  }

  private static EcPointXY scalarMultiply(BigInteger d, EcPointXY point) {
    if (point == null || d.equals(BigInteger.ZERO)) return null;
    EcPointXY result = null;
    EcPointXY addend = point;
    BigInteger k = d;
    while (k.signum() > 0) {
      if (k.testBit(0)) result = pointAdd(result, addend);
      addend = pointDouble(addend);
      k = k.shiftRight(1);
    }
    return result;
  }

  private static EcPointXY scalarMultiplyG(BigInteger d) {
    return scalarMultiply(d, new EcPointXY(P256_GX, P256_GY));
  }

  private static boolean isPair(BigInteger d, EcPointXY q) {
    EcPointXY computed = scalarMultiplyG(d);
    if (computed == null || q == null) return false;
    return computed.x.equals(q.x) && computed.y.equals(q.y);
  }

  private static boolean isValidScalar(BigInteger d) {
    return d.compareTo(BigInteger.ONE) >= 0 && d.compareTo(P256_N) < 0;
  }

  // --- Our own minimal DER TLV walker, extended with EXPLICIT context tags ---

  private static final class Tlv {
    final int tag;
    final byte[] content;
    final int nextOffset;

    Tlv(int tag, byte[] content, int nextOffset) {
      this.tag = tag;
      this.content = content;
      this.nextOffset = nextOffset;
    }
  }

  private static Tlv decodeTlv(byte[] buf, int offset) {
    if (offset >= buf.length) throw new IllegalArgumentException("unexpected end of buffer reading tag");
    int tag = buf[offset] & 0xff;
    if ((tag & 0x1f) == 0x1f) throw new IllegalArgumentException("multi-byte tags are not supported by this profile");
    int pos = offset + 1;
    if (pos >= buf.length) throw new IllegalArgumentException("unexpected end of buffer reading length");
    int first = buf[pos] & 0xff;
    pos += 1;
    int len;
    if (first == 0x80) {
      throw new IllegalArgumentException("indefinite length (BER, not DER)");
    } else if (first < 0x80) {
      len = first;
    } else {
      int numLenBytes = first & 0x7f;
      if (numLenBytes == 0 || numLenBytes > 4) throw new IllegalArgumentException("unsupported long-form length");
      if (pos + numLenBytes > buf.length) throw new IllegalArgumentException("unexpected end of buffer reading long-form length");
      len = 0;
      for (int i = 0; i < numLenBytes; i++) len = (len << 8) | (buf[pos + i] & 0xff);
      pos += numLenBytes;
      if (len < 0x80) throw new IllegalArgumentException("non-minimal long-form length (BER, not DER)");
    }
    if (pos + len > buf.length) throw new IllegalArgumentException("declared length exceeds remaining buffer");
    byte[] content = new byte[len];
    System.arraycopy(buf, pos, content, 0, len);
    return new Tlv(tag, content, pos + len);
  }

  private static List<Tlv> decodeSequenceChildren(Tlv tlv, int exactCount) {
    if (tlv.tag != 0x30) throw new IllegalArgumentException("expected SEQUENCE");
    List<Tlv> children = new ArrayList<>();
    int offset = 0;
    while (offset < tlv.content.length) {
      Tlv child = decodeTlv(tlv.content, offset);
      offset = child.nextOffset;
      children.add(child);
    }
    if (exactCount >= 0 && children.size() != exactCount) throw new IllegalArgumentException("unexpected SEQUENCE element count: " + children.size());
    return children;
  }

  private static BigInteger decodeInteger(Tlv tlv) {
    if (tlv.tag != 0x02) throw new IllegalArgumentException("expected INTEGER");
    byte[] c = tlv.content;
    if (c.length == 0) throw new IllegalArgumentException("empty INTEGER content");
    if ((c[0] & 0x80) != 0) throw new IllegalArgumentException("negative INTEGER not supported by this profile");
    return new BigInteger(1, c);
  }

  private static byte[] decodeOctetString(Tlv tlv) {
    if (tlv.tag != 0x04) throw new IllegalArgumentException("expected OCTET STRING");
    return tlv.content;
  }

  private static byte[] decodeBitStringWholeBytes(Tlv tlv) {
    if (tlv.tag != 0x03) throw new IllegalArgumentException("expected BIT STRING");
    if (tlv.content.length == 0) throw new IllegalArgumentException("empty BIT STRING content");
    if (tlv.content[0] != 0x00) throw new IllegalArgumentException("BIT STRING has non-zero unused bits");
    byte[] out = new byte[tlv.content.length - 1];
    System.arraycopy(tlv.content, 1, out, 0, out.length);
    return out;
  }

  private static final byte[] EC_PUBLIC_KEY_OID = {0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01};
  private static final byte[] SECP256R1_OID = {0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07};

  private static boolean isOidTlv(Tlv tlv, byte[] expected) {
    if (tlv.tag != 0x06 || tlv.content.length != expected.length) return false;
    for (int i = 0; i < expected.length; i++) if (tlv.content[i] != expected[i]) return false;
    return true;
  }

  private static boolean isExplicitTag(Tlv tlv, int tagNumber) {
    return tlv.tag == (0xa0 + tagNumber);
  }

  private static byte[] encodeLength(int len) {
    if (len < 0x80) return new byte[] {(byte) len};
    List<Byte> bytes = new ArrayList<>();
    int n = len;
    while (n > 0) {
      bytes.add(0, (byte) (n & 0xff));
      n >>>= 8;
    }
    byte[] out = new byte[bytes.size() + 1];
    out[0] = (byte) (0x80 | bytes.size());
    for (int i = 0; i < bytes.size(); i++) out[i + 1] = bytes.get(i);
    return out;
  }

  private static byte[] encodeTlv(int tag, byte[] content) {
    byte[] lenBytes = encodeLength(content.length);
    byte[] out = new byte[1 + lenBytes.length + content.length];
    out[0] = (byte) tag;
    System.arraycopy(lenBytes, 0, out, 1, lenBytes.length);
    System.arraycopy(content, 0, out, 1 + lenBytes.length, content.length);
    return out;
  }

  private static byte[] encodeIntegerNonneg(BigInteger value) {
    return encodeTlv(0x02, value.toByteArray());
  }

  private static byte[] encodeSequence(byte[]... children) {
    int total = 0;
    for (byte[] c : children) total += c.length;
    byte[] content = new byte[total];
    int off = 0;
    for (byte[] c : children) {
      System.arraycopy(c, 0, content, off, c.length);
      off += c.length;
    }
    return encodeTlv(0x30, content);
  }

  private static byte[] encodeOctetString(byte[] content) {
    return encodeTlv(0x04, content);
  }

  private static byte[] encodeBitStringWholeBytes(byte[] content) {
    byte[] wrapped = new byte[content.length + 1];
    wrapped[0] = 0x00;
    System.arraycopy(content, 0, wrapped, 1, content.length);
    return encodeTlv(0x03, wrapped);
  }

  private static byte[] encodeExplicit(int tagNumber, byte[] innerTlvBytes) {
    return encodeTlv(0xa0 + tagNumber, innerTlvBytes);
  }

  private static byte[] encodeEcPublicKeyOid() {
    return encodeTlv(0x06, EC_PUBLIC_KEY_OID);
  }

  private static byte[] encodeSecp256r1Oid() {
    return encodeTlv(0x06, SECP256R1_OID);
  }

  private static byte[] encodeAlgorithmIdentifier() {
    return encodeSequence(encodeEcPublicKeyOid(), encodeSecp256r1Oid());
  }

  private static byte[] bigIntToFixed32(BigInteger value) {
    byte[] raw = value.toByteArray();
    // strip a possible leading sign byte, then left-pad to 32
    int start = 0;
    while (start < raw.length - 1 && raw[start] == 0) start++;
    int len = raw.length - start;
    if (len > 32) throw new IllegalArgumentException("scalar does not fit in 32 bytes");
    byte[] out = new byte[32];
    System.arraycopy(raw, start, out, 32 - len, len);
    return out;
  }

  private static byte[] encodeUncompressedPoint(EcPointXY p) {
    byte[] out = new byte[65];
    out[0] = 0x04;
    byte[] xb = bigIntToFixed32(p.x);
    byte[] yb = bigIntToFixed32(p.y);
    System.arraycopy(xb, 0, out, 1, 32);
    System.arraycopy(yb, 0, out, 33, 32);
    return out;
  }

  private static EcPointXY decodeUncompressedPoint(byte[] bytes) {
    if (bytes.length != 65) throw new IllegalArgumentException("uncompressed point must be exactly 65 bytes");
    if (bytes[0] != 0x04) throw new IllegalArgumentException("expected uncompressed point form (0x04)");
    BigInteger x = new BigInteger(1, java.util.Arrays.copyOfRange(bytes, 1, 33));
    BigInteger y = new BigInteger(1, java.util.Arrays.copyOfRange(bytes, 33, 65));
    return new EcPointXY(x, y);
  }

  private static final class ParsedContainer {
    final String containerRole;
    final Tlv algIdTlv;
    final Tlv innerTlv;

    ParsedContainer(String containerRole, Tlv algIdTlv, Tlv innerTlv) {
      this.containerRole = containerRole;
      this.algIdTlv = algIdTlv;
      this.innerTlv = innerTlv;
    }
  }

  private static ParsedContainer parseContainerStructural(byte[] artifact) {
    Tlv outer;
    try {
      outer = decodeTlv(artifact, 0);
    } catch (RuntimeException ex) {
      throw new EcSerError("ec-ser.validation.syntax", "malformed_artifact", "DER parse failed: " + ex.getMessage());
    }
    if (outer.nextOffset != artifact.length) {
      throw new EcSerError("ec-ser.validation.syntax", "malformed_artifact", "trailing bytes after the top-level DER object");
    }
    List<Tlv> children;
    try {
      children = decodeSequenceChildren(outer, -1);
    } catch (RuntimeException ex) {
      throw new EcSerError("ec-ser.validation.syntax", "malformed_artifact", "outer SEQUENCE parse failed: " + ex.getMessage());
    }

    if (children.size() == 2 && children.get(1).tag == 0x03) {
      return new ParsedContainer("public", children.get(0), children.get(1));
    }
    if (children.size() == 3 && children.get(0).tag == 0x02 && children.get(2).tag == 0x04) {
      BigInteger version;
      try {
        version = decodeInteger(children.get(0));
      } catch (RuntimeException ex) {
        throw new EcSerError("ec-ser.validation.syntax", "malformed_artifact", "PrivateKeyInfo version field is not a valid INTEGER");
      }
      if (version.signum() != 0) throw new EcSerError("ec-ser.validation.syntax", "malformed_artifact", "PrivateKeyInfo version != 0");
      return new ParsedContainer("private", children.get(1), children.get(2));
    }
    throw new EcSerError("ec-ser.validation.syntax", "malformed_artifact", "valid DER instantiating neither SPKI nor PrivateKeyInfo");
  }

  // --- Accept_C ---

  public static EcSerImportResult importEcSer(byte[] artifact, String requestedRole) {
    ParsedContainer container = parseContainerStructural(artifact);

    if (!container.containerRole.equals(requestedRole)) {
      throw new EcSerError("ec-ser.key.role", "invalid_parameter",
          "artifact instantiates a " + container.containerRole + " container but role=" + requestedRole + " was requested");
    }

    List<Tlv> algChildren;
    try {
      algChildren = decodeSequenceChildren(container.algIdTlv, 2);
    } catch (RuntimeException ex) {
      throw new EcSerError(requestedRole.equals("public") ? "ec-ser.public.asn1" : "ec-ser.private.asn1", "invalid_parameter",
          "AlgorithmIdentifier is not a well-formed two-OID SEQUENCE");
    }
    boolean algOk = isOidTlv(algChildren.get(0), EC_PUBLIC_KEY_OID);
    boolean curveOk = isOidTlv(algChildren.get(1), SECP256R1_OID);
    if (!algOk) {
      throw new EcSerError(requestedRole.equals("public") ? "ec-ser.public.asn1" : "ec-ser.private.asn1", "invalid_parameter",
          "AlgorithmIdentifier.algorithm != id-ecPublicKey");
    }
    if (!curveOk) {
      throw new EcSerError("ec-ser.curve", "invalid_parameter", "curve OID != secp256r1");
    }

    if (requestedRole.equals("public")) {
      EcPointXY point;
      try {
        byte[] pointBytes = decodeBitStringWholeBytes(container.innerTlv);
        point = decodeUncompressedPoint(pointBytes);
      } catch (RuntimeException ex) {
        throw new EcSerError("ec-ser.public.point", "invalid_parameter", "point decode failed: " + ex.getMessage());
      }
      if (!isOnCurve(point)) {
        throw new EcSerError("ec-ser.curveMembership", "invalid_membership", "Q is not a point on secp256r1");
      }
      return new EcSerImportResult(EcKeyMaterial.ofPublic(point), false);
    }

    if (container.innerTlv.tag != 0x04) throw new EcSerError("ec-ser.private.asn1", "malformed_artifact", "PrivateKeyInfo.privateKey is not an OCTET STRING");
    List<Tlv> innerChildren;
    try {
      Tlv innerSeq = decodeTlv(container.innerTlv.content, 0);
      innerChildren = decodeSequenceChildren(innerSeq, -1);
    } catch (RuntimeException ex) {
      throw new EcSerError("ec-ser.private.asn1", "malformed_artifact", "ECPrivateKey inner structure malformed: " + ex.getMessage());
    }
    if (innerChildren.size() < 2) throw new EcSerError("ec-ser.private.asn1", "malformed_artifact", "ECPrivateKey requires at least version and privateKey fields");

    BigInteger version;
    byte[] dBytes;
    try {
      version = decodeInteger(innerChildren.get(0));
      dBytes = decodeOctetString(innerChildren.get(1));
    } catch (RuntimeException ex) {
      throw new EcSerError("ec-ser.private.asn1", "malformed_artifact", "ECPrivateKey version/privateKey malformed: " + ex.getMessage());
    }
    if (version.intValue() != 1) throw new EcSerError("ec-ser.private.asn1", "malformed_artifact", "ECPrivateKey.version != 1");
    if (dBytes.length != 32) throw new EcSerError("ec-ser.private.asn1", "malformed_artifact", "privateKey OCTET STRING is not 32 bytes");
    BigInteger d = new BigInteger(1, dBytes);

    boolean sawParamsZero = false;
    boolean paramsMatch = true;
    boolean sawPub = false;
    byte[] pointBytes = null;

    for (int i = 2; i < innerChildren.size(); i++) {
      Tlv child = innerChildren.get(i);
      if (isExplicitTag(child, 0)) {
        sawParamsZero = true;
        try {
          Tlv inner = decodeTlv(child.content, 0);
          paramsMatch = isOidTlv(inner, SECP256R1_OID);
        } catch (RuntimeException ex) {
          paramsMatch = false;
        }
      } else if (isExplicitTag(child, 1)) {
        try {
          Tlv bitStringTlv = decodeTlv(child.content, 0);
          pointBytes = decodeBitStringWholeBytes(bitStringTlv);
          sawPub = true;
        } catch (RuntimeException ex) {
          sawPub = false;
        }
      }
    }

    if (sawParamsZero && !paramsMatch) {
      throw new EcSerError("ec-ser.private.asn1", "invalid_parameter", "ECPrivateKey.parameters[0] present but != secp256r1");
    }
    if (!sawPub) {
      throw new EcSerError("ec-ser.private.asn1", "invalid_parameter",
          "ECPrivateKey.publicKey[1] is absent -- excluded from D_import^common entirely (D-059)");
    }

    EcPointXY point;
    try {
      point = decodeUncompressedPoint(pointBytes);
    } catch (RuntimeException ex) {
      throw new EcSerError("ec-ser.public.point", "invalid_parameter", "embedded publicKey[1] point decode failed: " + ex.getMessage());
    }

    if (!isValidScalar(d)) throw new EcSerError("ec-ser.private.scalar", "invalid_key", "private scalar fails V_scalar (1<=d<n)");
    if (!isOnCurve(point)) throw new EcSerError("ec-ser.curveMembership", "invalid_membership", "embedded publicKey[1] is not a point on secp256r1");
    if (!isPair(d, point)) throw new EcSerError("ec-ser.pairConsistency", "invalid_key", "Q != dG -- never normalized");

    return new EcSerImportResult(new EcKeyMaterial("private", point, d), !sawParamsZero);
  }

  public static byte[] exportEcSer(EcKeyMaterial m) {
    if (m.role.equals("public")) {
      byte[] point = encodeUncompressedPoint(m.q);
      return encodeSequence(encodeAlgorithmIdentifier(), encodeBitStringWholeBytes(point));
    }
    byte[] dBytes = bigIntToFixed32(m.d);
    byte[] paramsExplicit = encodeExplicit(0, encodeSecp256r1Oid());
    byte[] pubExplicit = encodeExplicit(1, encodeBitStringWholeBytes(encodeUncompressedPoint(m.q)));
    byte[] inner = encodeSequence(encodeIntegerNonneg(BigInteger.ONE), encodeOctetString(dBytes), paramsExplicit, pubExplicit);
    return encodeSequence(encodeIntegerNonneg(BigInteger.ZERO), encodeAlgorithmIdentifier(), encodeOctetString(inner));
  }

  // --- GENUINE native BC export/import, for the R_byte/interop comparisons ONLY ---

  public static byte[] nativeBcSpkiExport(EcKeyMaterial m) throws IOException {
    ECPoint q = DOMAIN_PARAMS.getCurve().createPoint(m.q.x, m.q.y);
    ECPublicKeyParameters pub = new ECPublicKeyParameters(q, DOMAIN_PARAMS);
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((AsymmetricKeyParameter) pub);
    return spki.getEncoded(ASN1Encoding.DER);
  }

  public static byte[] nativeBcPkcs8Export(EcKeyMaterial m) throws IOException {
    ECPrivateKeyParameters priv = new ECPrivateKeyParameters(m.d, DOMAIN_PARAMS);
    PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo((AsymmetricKeyParameter) priv);
    return pki.getEncoded(ASN1Encoding.DER);
  }

  /** GENUINE native BC import returning the recovered material. Confirmed: for private keys, Q is NEVER recovered from a native import (PrivateKeyFactory never reads publicKey[1]) -- m.q is null on the returned private material, matching the confirmed parse-then-discard(-not-even-parse) finding. */
  public static EcKeyMaterial nativeBcImport(byte[] artifact, String role) throws IOException {
    if (role.equals("public")) {
      ECPublicKeyParameters pub = (ECPublicKeyParameters) PublicKeyFactory.createKey(artifact);
      ECPoint q = pub.getQ().normalize();
      return EcKeyMaterial.ofPublic(new EcPointXY(q.getAffineXCoord().toBigInteger(), q.getAffineYCoord().toBigInteger()));
    }
    ECPrivateKeyParameters priv = (ECPrivateKeyParameters) PrivateKeyFactory.createKey(artifact);
    return new EcKeyMaterial("private", null, priv.getD());
  }

  public static boolean nativeBcImportSucceeds(byte[] artifact, String role) {
    try {
      nativeBcImport(artifact, role);
      return true;
    } catch (Exception ex) {
      return false;
    }
  }

  /** Generates a fresh P-256 key pair via BC's OWN lightweight generator -- shared fixture. Q is derived via OUR OWN scalar multiplication, not BC's, to keep the independence principle intact even for fixture construction. */
  public static EcKeyMaterial generateEcSerKeyMaterial() {
    SecureRandom random = new SecureRandom();
    ECKeyPairGenerator gen = new ECKeyPairGenerator();
    gen.init(new ECKeyGenerationParameters(DOMAIN_PARAMS, random));
    AsymmetricCipherKeyPair pair = gen.generateKeyPair();
    ECPrivateKeyParameters priv = (ECPrivateKeyParameters) pair.getPrivate();
    BigInteger d = priv.getD();
    EcPointXY q = scalarMultiplyG(d);
    return new EcKeyMaterial("private", q, d);
  }
}
