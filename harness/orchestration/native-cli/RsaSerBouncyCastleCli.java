// M2.5.2/M2.5.3.4 -- generic, parametric CLI around the real exportRsaSer /
// importRsaSer adapters (src/adapters/bouncycastle/RsaSerBouncyCastle.java,
// M1, unmodified). Same design as rsa-ser-cryptopp-cli.cpp.
//
// Usage:
//   java RsaSerBouncyCastleCli roundtrip <role> <nHex> <eHex> <dHex-or-empty> <pHex-or-empty> <qHex-or-empty> <dPHex-or-empty> <dQHex-or-empty> <qInvHex-or-empty>
//   java RsaSerBouncyCastleCli export <role> <nHex> <eHex> <dHex-or-empty> <pHex-or-empty> <qHex-or-empty> <dPHex-or-empty> <dQHex-or-empty> <qInvHex-or-empty>
//   java RsaSerBouncyCastleCli import <role> <artifactHex> <expectedNHex> <expectedEHex> <expectedDHex-or-empty> <expectedPHex-or-empty> <expectedQHex-or-empty>

import paper4.adapters.bouncycastle.RsaSerBouncyCastle;
import java.math.BigInteger;

public final class RsaSerBouncyCastleCli {
  private static BigInteger bigIntFromHex(String hex) {
    if (hex.isEmpty()) return null;
    return new BigInteger(hex, 16);
  }
  private static byte[] bytesFromHex(String hex) {
    int len = hex.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
    }
    return out;
  }
  private static String hexFromBytes(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) sb.append(String.format("%02x", b));
    return sb.toString();
  }
  private static String jsonEscape(String s) {
    return s.replace("\\", "\\\\").replace("\"", "\\\"");
  }

  public static void main(String[] args) {
    String mode = args.length >= 1 ? args[0] : "";

    if (mode.equals("export")) {
      if (args.length != 10) { System.err.println("usage: export <role> <nHex> <eHex> <dHex-or-empty> <pHex-or-empty> <qHex-or-empty> <dPHex-or-empty> <dQHex-or-empty> <qInvHex-or-empty>"); System.exit(2); }
      String role = args[1];
      RsaSerBouncyCastle.RsaKeyMaterial material = new RsaSerBouncyCastle.RsaKeyMaterial(
        role, bigIntFromHex(args[2]), bigIntFromHex(args[3]), bigIntFromHex(args[4]),
        bigIntFromHex(args[5]), bigIntFromHex(args[6]), bigIntFromHex(args[7]), bigIntFromHex(args[8]), bigIntFromHex(args[9]));
      try {
        byte[] artifact = RsaSerBouncyCastle.exportRsaSer(material);
        System.out.println("{\"exportOk\":true,\"artifactHex\":\"" + hexFromBytes(artifact) + "\"}");
      } catch (Exception ex) {
        System.out.println("{\"exportOk\":false,\"exportError\":\"" + jsonEscape(String.valueOf(ex.getMessage())) + "\"}");
      }
      return;
    }

    if (mode.equals("import")) {
      if (args.length != 7) { System.err.println("usage: import <role> <artifactHex> <expectedNHex> <expectedEHex> <expectedDHex-or-empty> <expectedPHex-or-empty> <expectedQHex-or-empty>"); System.exit(2); }
      String role = args[1];
      byte[] artifact = bytesFromHex(args[2]); // the OTHER backend's own literal artifact bytes, never re-encoded here
      BigInteger expectedN = bigIntFromHex(args[3]);
      BigInteger expectedE = bigIntFromHex(args[4]);
      BigInteger expectedD = bigIntFromHex(args[5]);
      BigInteger expectedP = bigIntFromHex(args[6]);
      try {
        RsaSerBouncyCastle.RsaKeyMaterial recovered = RsaSerBouncyCastle.importRsaSer(artifact, role);
        boolean preserved = recovered.n.equals(expectedN) && recovered.e.equals(expectedE)
          && (!role.equals("private") || (recovered.d.equals(expectedD) && recovered.p.equals(expectedP)));
        System.out.println("{\"importOk\":true,\"materialPreserved\":" + preserved + "}");
      } catch (RsaSerBouncyCastle.RsaSerError err) {
        System.out.println("{\"importOk\":false,\"errorClass\":\"" + jsonEscape(err.errorClass) + "\",\"detail\":\"" + jsonEscape(String.valueOf(err.getMessage())) + "\"}");
      }
      return;
    }

    if (!mode.equals("roundtrip") || args.length != 10) {
      System.err.println("usage: RsaSerBouncyCastleCli roundtrip|export|import ...");
      System.exit(2);
    }
    String role = args[1];
    BigInteger n = bigIntFromHex(args[2]);
    BigInteger e = bigIntFromHex(args[3]);
    BigInteger d = bigIntFromHex(args[4]);
    BigInteger p = bigIntFromHex(args[5]);
    BigInteger q = bigIntFromHex(args[6]);
    BigInteger dP = bigIntFromHex(args[7]);
    BigInteger dQ = bigIntFromHex(args[8]);
    BigInteger qInv = bigIntFromHex(args[9]);

    RsaSerBouncyCastle.RsaKeyMaterial material = new RsaSerBouncyCastle.RsaKeyMaterial(role, n, e, d, p, q, dP, dQ, qInv);

    byte[] artifact;
    try {
      artifact = RsaSerBouncyCastle.exportRsaSer(material);
    } catch (Exception ex) {
      System.out.println("{\"exportOk\":false,\"exportError\":\"" + jsonEscape(String.valueOf(ex.getMessage())) + "\"}");
      return;
    }

    try {
      RsaSerBouncyCastle.RsaKeyMaterial recovered = RsaSerBouncyCastle.importRsaSer(artifact, role);
      boolean preserved = recovered.n.equals(material.n) && recovered.e.equals(material.e)
        && (!role.equals("private") || (recovered.d.equals(material.d) && recovered.p.equals(material.p) && recovered.q.equals(material.q)));
      System.out.println("{\"exportOk\":true,\"artifactHex\":\"" + hexFromBytes(artifact) + "\",\"importOk\":true,\"materialPreserved\":" + preserved + "}");
    } catch (RsaSerBouncyCastle.RsaSerError err) {
      System.out.println("{\"exportOk\":true,\"artifactHex\":\"" + hexFromBytes(artifact) + "\",\"importOk\":false,\"errorClass\":\"" + jsonEscape(err.errorClass) + "\",\"detail\":\"" + jsonEscape(String.valueOf(err.getMessage())) + "\"}");
    }
  }
}
