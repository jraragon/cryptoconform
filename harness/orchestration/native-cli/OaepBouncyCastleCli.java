// M2.5.2 -- generic, parametric CLI around the real oaepBouncyCastleEncrypt
// / oaepBouncyCastleDecrypt adapters
// (src/adapters/bouncycastle/OaepBouncyCastle.java, M1, unmodified).
//
// Usage:
//   java OaepBouncyCastleCli encrypt <declaredRole> <modulusHex> <pubExpHex> <privExpHex-or-empty> <modulusBits> <plaintextHex> <labelHex-or-empty> <labelPresent:0|1> <hash> <mgfHash>
//   java OaepBouncyCastleCli decrypt <declaredRole> <modulusHex> <pubExpHex> <privExpHex-or-empty> <modulusBits> <ciphertextHex> <labelHex-or-empty> <labelPresent:0|1> <hash> <mgfHash>

import paper4.adapters.bouncycastle.OaepBouncyCastle;
import java.math.BigInteger;

public final class OaepBouncyCastleCli {
  private static byte[] fromHex(String hex) {
    if (hex.isEmpty()) return new byte[0];
    int len = hex.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
    }
    return out;
  }

  private static BigInteger bigIntFromHex(String hex) {
    if (hex.isEmpty()) return BigInteger.ZERO;
    return new BigInteger(hex, 16);
  }

  public static void main(String[] args) {
    if (args.length != 11) {
      System.err.println("usage: OaepBouncyCastleCli encrypt|decrypt <declaredRole> <modulusHex> <pubExpHex> <privExpHex-or-empty> <modulusBits> <plaintext-or-ciphertextHex> <labelHex-or-empty> <labelPresent:0|1> <hash> <mgfHash>");
      System.exit(2);
    }
    String mode = args[0];
    String declaredRole = args[1];
    BigInteger modulus = bigIntFromHex(args[2]);
    BigInteger pubExp = bigIntFromHex(args[3]);
    BigInteger privExp = bigIntFromHex(args[4]);
    int modulusBits = Integer.parseInt(args[5]);
    byte[] messageBytes = fromHex(args[6]);
    boolean labelPresent = args[8].equals("1");
    byte[] label = labelPresent ? fromHex(args[7]) : new byte[0];
    String hash = args[9];
    String mgfHash = args[10];

    OaepBouncyCastle.OaepKeyMaterial key = new OaepBouncyCastle.OaepKeyMaterial(declaredRole, modulus, pubExp, privExp, modulusBits);

    if (mode.equals("encrypt")) {
      OaepBouncyCastle.OaepEncryptRequest req = new OaepBouncyCastle.OaepEncryptRequest(key, messageBytes, label, labelPresent, hash, mgfHash);
      System.out.println(OaepBouncyCastle.oaepBouncyCastleEncrypt(req));
      return;
    }
    if (mode.equals("decrypt")) {
      OaepBouncyCastle.OaepDecryptRequest req = new OaepBouncyCastle.OaepDecryptRequest(key, messageBytes, label, labelPresent, hash, mgfHash);
      System.out.println(OaepBouncyCastle.oaepBouncyCastleDecrypt(req));
      return;
    }
    System.err.println("unknown mode: " + mode);
    System.exit(2);
  }
}
