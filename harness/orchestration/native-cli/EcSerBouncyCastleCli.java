// M2.5.2/M2.5.3.5 -- generic, parametric CLI around the real exportEcSer /
// importEcSer adapters (src/adapters/bouncycastle/EcSerBouncyCastle.java,
// M1, unmodified). Same design as rsa-ser's own BC CLI.
//
// Usage:
//   java EcSerBouncyCastleCli roundtrip <role> <xHex> <yHex> <dHex-or-empty>
//   java EcSerBouncyCastleCli export <role> <xHex> <yHex> <dHex-or-empty>
//   java EcSerBouncyCastleCli import <role> <artifactHex>

import paper4.adapters.bouncycastle.EcSerBouncyCastle;
import java.math.BigInteger;

public final class EcSerBouncyCastleCli {
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
  private static String hexFromBigInt(BigInteger n) {
    if (n == null) return "";
    byte[] bytes = n.toByteArray();
    // BigInteger.toByteArray() may prepend a sign byte -- strip a leading
    // 0x00 when present, since our own hex convention here is unsigned.
    int offset = (bytes.length > 1 && bytes[0] == 0) ? 1 : 0;
    StringBuilder sb = new StringBuilder();
    for (int i = offset; i < bytes.length; i++) sb.append(String.format("%02x", bytes[i]));
    return sb.toString();
  }
  private static String jsonEscape(String s) {
    return s.replace("\\", "\\\\").replace("\"", "\\\"");
  }

  public static void main(String[] args) {
    String mode = args.length >= 1 ? args[0] : "";

    if (mode.equals("export")) {
      if (args.length != 5) { System.err.println("usage: export <role> <xHex> <yHex> <dHex-or-empty>"); System.exit(2); }
      String role = args[1];
      EcSerBouncyCastle.EcPointXY q = new EcSerBouncyCastle.EcPointXY(bigIntFromHex(args[2]), bigIntFromHex(args[3]));
      EcSerBouncyCastle.EcKeyMaterial material = new EcSerBouncyCastle.EcKeyMaterial(role, q, bigIntFromHex(args[4]));
      try {
        byte[] artifact = EcSerBouncyCastle.exportEcSer(material);
        System.out.println("{\"exportOk\":true,\"artifactHex\":\"" + hexFromBytes(artifact) + "\"}");
      } catch (Exception ex) {
        System.out.println("{\"exportOk\":false,\"exportError\":\"" + jsonEscape(String.valueOf(ex.getMessage())) + "\"}");
      }
      return;
    }

    if (mode.equals("import")) {
      if (args.length != 3) { System.err.println("usage: import <role> <artifactHex>"); System.exit(2); }
      String role = args[1];
      byte[] artifact = bytesFromHex(args[2]); // the OTHER backend's own literal artifact bytes, never re-encoded here
      try {
        EcSerBouncyCastle.EcSerImportResult result = EcSerBouncyCastle.importEcSer(artifact, role);
        System.out.println("{\"importOk\":true,\"normalized\":" + result.normalized
          + ",\"recoveredXHex\":\"" + hexFromBigInt(result.material.q.x) + "\""
          + ",\"recoveredYHex\":\"" + hexFromBigInt(result.material.q.y) + "\""
          + ",\"recoveredDHex\":\"" + (role.equals("private") ? hexFromBigInt(result.material.d) : "") + "\"}");
      } catch (EcSerBouncyCastle.EcSerError err) {
        System.out.println("{\"importOk\":false,\"errorClass\":\"" + jsonEscape(err.errorClass) + "\",\"detail\":\"" + jsonEscape(String.valueOf(err.getMessage())) + "\"}");
      }
      return;
    }

    if (!mode.equals("roundtrip") || args.length != 5) {
      System.err.println("usage: EcSerBouncyCastleCli roundtrip|export|import ...");
      System.exit(2);
    }
    String role = args[1];
    BigInteger x = bigIntFromHex(args[2]);
    BigInteger y = bigIntFromHex(args[3]);
    BigInteger d = bigIntFromHex(args[4]);

    EcSerBouncyCastle.EcPointXY q = new EcSerBouncyCastle.EcPointXY(x, y);
    EcSerBouncyCastle.EcKeyMaterial material = new EcSerBouncyCastle.EcKeyMaterial(role, q, d);

    byte[] artifact;
    try {
      artifact = EcSerBouncyCastle.exportEcSer(material);
    } catch (Exception ex) {
      System.out.println("{\"exportOk\":false,\"exportError\":\"" + jsonEscape(String.valueOf(ex.getMessage())) + "\"}");
      return;
    }

    try {
      EcSerBouncyCastle.EcSerImportResult result = EcSerBouncyCastle.importEcSer(artifact, role);
      boolean qMatches = result.material.q.x.equals(x) && result.material.q.y.equals(y);
      boolean dMatches = !role.equals("private") || result.material.d.equals(d);
      System.out.println("{\"exportOk\":true,\"artifactHex\":\"" + hexFromBytes(artifact) + "\",\"importOk\":true,\"normalized\":"
        + result.normalized + ",\"materialPreserved\":" + (qMatches && dMatches) + "}");
    } catch (EcSerBouncyCastle.EcSerError err) {
      System.out.println("{\"exportOk\":true,\"artifactHex\":\"" + hexFromBytes(artifact) + "\",\"importOk\":false,\"errorClass\":\""
        + jsonEscape(err.errorClass) + "\",\"detail\":\"" + jsonEscape(String.valueOf(err.getMessage())) + "\"}");
    }
  }
}
