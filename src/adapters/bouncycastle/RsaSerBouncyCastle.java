package paper4.adapters.bouncycastle;

// RSA-ser x Bouncy Castle adapter.
//
// CONFIRMED PRECISELY AGAINST bcprov-jdk18on:1.77 SOURCE (this session's
// explicit requirement -- not against `main`, not assumed):
//
// (1) DER-parseable != contractually admissible != materializable by BC.
//     org.bouncycastle.asn1.pkcs.RSAPrivateKey's private constructor
//     accepts version in {0,1} (throws IllegalArgumentException only for
//     version<0 or >1) and, when more than 9 fields are present, stores
//     the trailing content opaquely as `otherPrimeInfos` -- so a
//     multi-prime artifact IS DER-parseable at the ASN.1 layer. But
//     crypto.util.PrivateKeyFactory.createKey's RSA branch calls
//     `new RSAPrivateCrtKeyParameters(keyStructure.getModulus(), ...,
//     keyStructure.getCoefficient())` using ONLY the eight classical
//     fields -- `otherPrimeInfos` is NEVER referenced in that call. This
//     is confirmed, literal "parse but discard": BC's ASN.1 parser CAN
//     represent multi-prime; its materialization into the operational RSA
//     object silently cannot -- a genuinely different mechanism from
//     Crypto++'s native rejection AT PARSE TIME (version range-checked to
//     exactly 0 inside BERDecodePrivateKey itself, confirmed in this
//     project's Crypto++ adapter). This adapter's own Accept_C rejects
//     multi-prime at the STRUCTURAL layer (our own DER walker, before any
//     BC class is touched) regardless of which native mechanism BC itself
//     would have used.
//
// (2) RSAKeyParameters's constructor validates: modulus odd + a small-
//     prime-factor screen (odd primes 3..743) + (for PUBLIC keys only)
//     exponent odd -- matching the Design Freeze's own finding precisely.
//     RSAPrivateCrtKeyParameters's constructor is confirmed to add
//     LITERALLY ZERO validation beyond that inherited modulus check: p,
//     q, dP, dQ, qInv, and the public exponent e are stored directly with
//     no range check and no relational check (n=pq, e*d=1 mod lambda(n),
//     CRT relations) whatsoever -- even weaker than Crypto++'s
//     Validate(), which at least checks ranges/parity at level 0. Accept_C
//     therefore reimplements V_domain/V_rel entirely independently below,
//     using only java.math.BigInteger's isProbablePrime/gcd/modPow as
//     bignum-arithmetic primitives, never BC's own key-parameter classes
//     for admission.
//
// (3) RSAConverter.getPublicKeyParameters (PublicKeyFactory) is confirmed
//     to never read keyInfo.getAlgorithm().getParameters() at all.
//
// (4) SubjectPublicKeyInfoFactory/PrivateKeyInfoFactory's RSA branches
//     both construct `new AlgorithmIdentifier(PKCSObjectIdentifiers
//     .rsaEncryption, DERNull.INSTANCE)` -- explicit NULL, matching
//     WebCrypto and Crypto++ -- via BC's own, architecturally independent
//     ASN.1 object model, used here ONLY for the R_byte comparison
//     (nativeBcSpkiExport/PkcsExport), never for admission.

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public final class RsaSerBouncyCastle {

  private RsaSerBouncyCastle() {}

  public static final class RsaSerError extends RuntimeException {
    public final String clauseId;
    public final String errorClass;

    public RsaSerError(String clauseId, String errorClass, String detail) {
      super(detail);
      this.clauseId = clauseId;
      this.errorClass = errorClass;
    }
  }

  public static final class RsaKeyMaterial {
    public final String role;
    public final BigInteger n, e;
    public final BigInteger d, p, q, dP, dQ, qInv;

    public RsaKeyMaterial(String role, BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q,
        BigInteger dP, BigInteger dQ, BigInteger qInv) {
      this.role = role;
      this.n = n;
      this.e = e;
      this.d = d;
      this.p = p;
      this.q = q;
      this.dP = dP;
      this.dQ = dQ;
      this.qInv = qInv;
    }

    public static RsaKeyMaterial ofPublic(BigInteger n, BigInteger e) {
      return new RsaKeyMaterial("public", n, e, null, null, null, null, null, null);
    }
  }

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
      if (numLenBytes > 1 && buf[pos - numLenBytes] == 0x00) throw new IllegalArgumentException("non-minimal long-form length (leading zero)");
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
    if (exactCount >= 0 && children.size() != exactCount) {
      throw new IllegalArgumentException("unexpected SEQUENCE element count: " + children.size());
    }
    return children;
  }

  private static BigInteger decodeInteger(Tlv tlv) {
    if (tlv.tag != 0x02) throw new IllegalArgumentException("expected INTEGER");
    byte[] c = tlv.content;
    if (c.length == 0) throw new IllegalArgumentException("empty INTEGER content");
    if (c.length > 1 && c[0] == 0x00 && (c[1] & 0x80) == 0) throw new IllegalArgumentException("non-minimal INTEGER encoding");
    if ((c[0] & 0x80) != 0) throw new IllegalArgumentException("negative INTEGER not supported by this profile");
    return new BigInteger(1, c);
  }

  private static final byte[] RSA_ENCRYPTION_OID = {0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01};

  private static boolean isRsaEncryptionOid(Tlv tlv) {
    if (tlv.tag != 0x06 || tlv.content.length != RSA_ENCRYPTION_OID.length) return false;
    for (int i = 0; i < RSA_ENCRYPTION_OID.length; i++) {
      if (tlv.content[i] != RSA_ENCRYPTION_OID[i]) return false;
    }
    return true;
  }

  private static boolean isNull(Tlv tlv) {
    return tlv.tag == 0x05 && tlv.content.length == 0;
  }

  private static byte[] decodeBitStringWholeBytes(Tlv tlv) {
    if (tlv.tag != 0x03) throw new IllegalArgumentException("expected BIT STRING");
    if (tlv.content.length == 0) throw new IllegalArgumentException("empty BIT STRING content");
    if (tlv.content[0] != 0x00) throw new IllegalArgumentException("BIT STRING has non-zero unused bits");
    byte[] out = new byte[tlv.content.length - 1];
    System.arraycopy(tlv.content, 1, out, 0, out.length);
    return out;
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

  private static byte[] encodeInteger(BigInteger value) {
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

  private static byte[] encodeBitStringWholeBytes(byte[] content) {
    byte[] wrapped = new byte[content.length + 1];
    wrapped[0] = 0x00;
    System.arraycopy(content, 0, wrapped, 1, content.length);
    return encodeTlv(0x03, wrapped);
  }

  private static byte[] encodeOctetString(byte[] content) {
    return encodeTlv(0x04, content);
  }

  private static byte[] encodeNull() {
    return encodeTlv(0x05, new byte[0]);
  }

  private static byte[] encodeRsaEncryptionOid() {
    return encodeTlv(0x06, RSA_ENCRYPTION_OID);
  }

  private static byte[] encodeAlgorithmIdentifier() {
    return encodeSequence(encodeRsaEncryptionOid(), encodeNull());
  }

  private static boolean checkPublicValidity(BigInteger n, BigInteger e) {
    return n.compareTo(BigInteger.valueOf(15)) >= 0 && n.testBit(0) && e.compareTo(BigInteger.valueOf(3)) >= 0
        && e.compareTo(n.subtract(BigInteger.ONE)) <= 0 && e.testBit(0);
  }

  private static boolean checkPrivateDomain(RsaKeyMaterial m) {
    return !m.p.equals(m.q) && m.p.isProbablePrime(64) && m.q.isProbablePrime(64) && m.p.testBit(0) && m.q.testBit(0)
        && m.e.compareTo(BigInteger.valueOf(3)) >= 0 && m.e.compareTo(m.n.subtract(BigInteger.ONE)) <= 0
        && m.d.signum() > 0 && m.d.compareTo(m.n) < 0 && m.dP.signum() > 0 && m.dP.compareTo(m.p) < 0
        && m.dQ.signum() > 0 && m.dQ.compareTo(m.q) < 0 && m.qInv.signum() > 0 && m.qInv.compareTo(m.p) < 0;
  }

  private static boolean checkPrivateRelations(RsaKeyMaterial m) {
    BigInteger pMinus1 = m.p.subtract(BigInteger.ONE);
    BigInteger qMinus1 = m.q.subtract(BigInteger.ONE);
    BigInteger lambdaN = pMinus1.divide(pMinus1.gcd(qMinus1)).multiply(qMinus1);
    return m.n.equals(m.p.multiply(m.q)) && m.e.gcd(lambdaN).equals(BigInteger.ONE)
        && m.e.multiply(m.d).mod(lambdaN).equals(BigInteger.ONE.mod(lambdaN))
        && m.e.multiply(m.dP).mod(pMinus1).equals(BigInteger.ONE.mod(pMinus1))
        && m.e.multiply(m.dQ).mod(qMinus1).equals(BigInteger.ONE.mod(qMinus1))
        && m.q.multiply(m.qInv).mod(m.p).equals(BigInteger.ONE.mod(m.p));
  }

  public static RsaKeyMaterial importRsaSer(byte[] artifact, String requestedRole) {
    Tlv outer;
    try {
      outer = decodeTlv(artifact, 0);
    } catch (RuntimeException ex) {
      throw new RsaSerError("rsa-ser.der-syntax", "malformed_artifact", "DER parse failed: " + ex.getMessage());
    }
    if (outer.nextOffset != artifact.length) {
      throw new RsaSerError("rsa-ser.exact-consumption", "malformed_artifact", "trailing bytes after the top-level DER object");
    }

    List<Tlv> children;
    try {
      children = decodeSequenceChildren(outer, -1);
    } catch (RuntimeException ex) {
      throw new RsaSerError("rsa-ser.der-syntax", "malformed_artifact", "outer SEQUENCE parse failed: " + ex.getMessage());
    }

    String containerRole;
    Tlv algIdTlv, innerTlv;
    if (children.size() == 2 && children.get(1).tag == 0x03) {
      containerRole = "public";
      algIdTlv = children.get(0);
      innerTlv = children.get(1);
    } else if (children.size() == 3 && children.get(0).tag == 0x02 && children.get(2).tag == 0x04) {
      BigInteger version;
      try {
        version = decodeInteger(children.get(0));
      } catch (RuntimeException ex) {
        throw new RsaSerError("rsa-ser.container", "malformed_artifact", "PrivateKeyInfo version field is not a valid INTEGER");
      }
      if (version.signum() != 0) {
        throw new RsaSerError("rsa-ser.container", "malformed_artifact",
            "PrivateKeyInfo version != 0 (multi-prime is outside the portable profile, D-053)");
      }
      containerRole = "private";
      algIdTlv = children.get(1);
      innerTlv = children.get(2);
    } else {
      throw new RsaSerError("rsa-ser.container", "malformed_artifact", "valid DER instantiating neither SPKI nor PrivateKeyInfo");
    }

    if (!containerRole.equals(requestedRole)) {
      throw new RsaSerError("rsa-ser.role-container", "invalid_parameter",
          "artifact instantiates a " + containerRole + " container but role=" + requestedRole + " was requested");
    }

    List<Tlv> algChildren;
    try {
      algChildren = decodeSequenceChildren(algIdTlv, -1);
    } catch (RuntimeException ex) {
      throw new RsaSerError("rsa-ser.algorithm-id", "invalid_parameter", "AlgorithmIdentifier is not a well-formed SEQUENCE");
    }
    if (algChildren.isEmpty() || algChildren.size() > 2) {
      throw new RsaSerError("rsa-ser.algorithm-params", "invalid_parameter", "AlgorithmIdentifier has an unexpected number of elements");
    }
    if (!isRsaEncryptionOid(algChildren.get(0))) {
      throw new RsaSerError("rsa-ser.algorithm-id", "invalid_parameter", "AlgorithmIdentifier.algorithm != rsaEncryption (D-053)");
    }
    boolean paramsOk = algChildren.size() == 1 || isNull(algChildren.get(1));
    if (!paramsOk) {
      throw new RsaSerError("rsa-ser.algorithm-params", "invalid_parameter",
          "AlgorithmIdentifier.parameters is neither absent nor explicit NULL (D-053)");
    }

    if (requestedRole.equals("public")) {
      BigInteger n, e;
      try {
        byte[] innerBytes = decodeBitStringWholeBytes(innerTlv);
        Tlv innerSeq = decodeTlv(innerBytes, 0);
        List<Tlv> innerChildren = decodeSequenceChildren(innerSeq, 2);
        n = decodeInteger(innerChildren.get(0));
        e = decodeInteger(innerChildren.get(1));
      } catch (RuntimeException ex) {
        throw new RsaSerError("rsa-ser.container", "malformed_artifact", "RSAPublicKey inner structure malformed: " + ex.getMessage());
      }
      if (!checkPublicValidity(n, e)) {
        throw new RsaSerError("rsa-ser.public-validity", "invalid_key", "public key fails C_math^public (n>=15, n odd, 3<=e<=n-1, e odd)");
      }
      return RsaKeyMaterial.ofPublic(n, e);
    }

    if (innerTlv.tag != 0x04) {
      throw new RsaSerError("rsa-ser.container", "malformed_artifact", "PrivateKeyInfo.privateKey is not an OCTET STRING");
    }
    List<Tlv> innerChildren;
    try {
      Tlv innerSeq = decodeTlv(innerTlv.content, 0);
      innerChildren = decodeSequenceChildren(innerSeq, -1);
    } catch (RuntimeException ex) {
      throw new RsaSerError("rsa-ser.container", "malformed_artifact", "RSAPrivateKey inner structure malformed: " + ex.getMessage());
    }
    if (innerChildren.size() != 9) {
      throw new RsaSerError("rsa-ser.container", "malformed_artifact",
          "RSAPrivateKey is not two-prime (9 fields) -- multi-prime is outside the portable profile (D-053)");
    }
    BigInteger n, e, d, p, q, dP, dQ, qInv;
    try {
      BigInteger version = decodeInteger(innerChildren.get(0));
      if (version.signum() != 0) {
        throw new RsaSerError("rsa-ser.container", "malformed_artifact", "RSAPrivateKey version != 0");
      }
      n = decodeInteger(innerChildren.get(1));
      e = decodeInteger(innerChildren.get(2));
      d = decodeInteger(innerChildren.get(3));
      p = decodeInteger(innerChildren.get(4));
      q = decodeInteger(innerChildren.get(5));
      dP = decodeInteger(innerChildren.get(6));
      dQ = decodeInteger(innerChildren.get(7));
      qInv = decodeInteger(innerChildren.get(8));
    } catch (RsaSerError ex) {
      throw ex;
    } catch (RuntimeException ex) {
      throw new RsaSerError("rsa-ser.container", "malformed_artifact", "RSAPrivateKey field malformed: " + ex.getMessage());
    }

    RsaKeyMaterial m = new RsaKeyMaterial("private", n, e, d, p, q, dP, dQ, qInv);
    if (!checkPrivateDomain(m)) {
      throw new RsaSerError("rsa-ser.private-domain", "invalid_key", "private key fails V_domain^RSA,2 (D-054)");
    }
    if (!checkPrivateRelations(m)) {
      throw new RsaSerError("rsa-ser.private-relations", "invalid_key", "private key fails V_rel^RSA,2 (D-054)");
    }
    return m;
  }

  public static byte[] exportRsaSer(RsaKeyMaterial m) {
    if (m.role.equals("public")) {
      byte[] inner = encodeSequence(encodeInteger(m.n), encodeInteger(m.e));
      return encodeSequence(encodeAlgorithmIdentifier(), encodeBitStringWholeBytes(inner));
    }
    byte[] inner = encodeSequence(encodeInteger(BigInteger.ZERO), encodeInteger(m.n), encodeInteger(m.e),
        encodeInteger(m.d), encodeInteger(m.p), encodeInteger(m.q), encodeInteger(m.dP), encodeInteger(m.dQ),
        encodeInteger(m.qInv));
    return encodeSequence(encodeInteger(BigInteger.ZERO), encodeAlgorithmIdentifier(), encodeOctetString(inner));
  }

  public static byte[] nativeBcSpkiExport(RsaKeyMaterial m) throws IOException {
    RSAKeyParameters pub = new RSAKeyParameters(false, m.n, m.e);
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((AsymmetricKeyParameter) pub);
    return spki.getEncoded(ASN1Encoding.DER);
  }

  public static byte[] nativeBcPkcs8Export(RsaKeyMaterial m) throws IOException {
    RSAPrivateCrtKeyParameters priv = new RSAPrivateCrtKeyParameters(m.n, m.e, m.d, m.p, m.q, m.dP, m.dQ, m.qInv);
    PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo((AsymmetricKeyParameter) priv);
    return pki.getEncoded(ASN1Encoding.DER);
  }

  public static boolean nativeBcImportSucceeds(byte[] artifact, String role) {
    try {
      if (role.equals("public")) {
        PublicKeyFactory.createKey(artifact);
      } else {
        PrivateKeyFactory.createKey(artifact);
      }
      return true;
    } catch (Exception ex) {
      return false;
    }
  }

  /**
   * GENUINE native BC import that returns the RECOVERED MATERIAL itself
   * (not just a success/failure boolean) -- via PublicKeyFactory/
   * PrivateKeyFactory.createKey(), cast to RSAKeyParameters/
   * RSAPrivateCrtKeyParameters, reading the material back out through
   * those classes' own getters. No byte of this project's own DER walker
   * or Accept_C is touched anywhere in this call. Used exclusively by the
   * native-only cross-provider interop matrix.
   */
  public static RsaKeyMaterial nativeBcImport(byte[] artifact, String role) throws IOException {
    if (role.equals("public")) {
      RSAKeyParameters pub = (RSAKeyParameters) PublicKeyFactory.createKey(artifact);
      return RsaKeyMaterial.ofPublic(pub.getModulus(), pub.getExponent());
    }
    RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters) PrivateKeyFactory.createKey(artifact);
    return new RsaKeyMaterial("private", priv.getModulus(), priv.getPublicExponent(), priv.getExponent(),
        priv.getP(), priv.getQ(), priv.getDP(), priv.getDQ(), priv.getQInv());
  }

  public static RsaKeyMaterial generateRsaSerKeyMaterial(int modulusBits) {
    SecureRandom random = new SecureRandom();
    RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
    gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), random, modulusBits, 80));
    AsymmetricCipherKeyPair pair = gen.generateKeyPair();
    RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters) pair.getPrivate();
    return new RsaKeyMaterial("private", priv.getModulus(), priv.getPublicExponent(), priv.getExponent(),
        priv.getP(), priv.getQ(), priv.getDP(), priv.getDQ(), priv.getQInv());
  }
}
