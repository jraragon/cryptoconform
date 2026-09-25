// M2.5.2 -- generic, parametric CLI around the real pssBouncyCastleSign /
// pssBouncyCastleVerify adapters
// (src/adapters/bouncycastle/PssBouncyCastle.java, M1, unmodified).
//
// Usage:
//   java PssBouncyCastleCli sign <declaredRole> <modulusHex> <pubExpHex> <privExpHex-or-empty> <modulusBits> <messageHex> <hash> <mgfHash> <saltLengthBytes>
//   java PssBouncyCastleCli verify <declaredRole> <modulusHex> <pubExpHex> <privExpHex-or-empty> <modulusBits> <messageHex> <signatureHex> <hash> <mgfHash> <saltLengthBytes>

import paper4.adapters.bouncycastle.PssBouncyCastle;
import java.math.BigInteger;

public final class PssBouncyCastleCli {
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
    if (args.length < 7) {
      System.err.println("usage: PssBouncyCastleCli sign|verify <declaredRole> <modulusHex> <pubExpHex> <privExpHex-or-empty> <modulusBits> <messageHex> [signatureHex] <hash> <mgfHash> <saltLengthBytes>");
      System.exit(2);
    }
    String mode = args[0];
    String declaredRole = args[1];
    BigInteger modulus = bigIntFromHex(args[2]);
    BigInteger pubExp = bigIntFromHex(args[3]);
    BigInteger privExp = bigIntFromHex(args[4]);
    int modulusBits = Integer.parseInt(args[5]);
    byte[] message = fromHex(args[6]);

    PssBouncyCastle.PssKeyMaterial key = new PssBouncyCastle.PssKeyMaterial(declaredRole, modulus, pubExp, privExp, modulusBits);

    if (mode.equals("sign")) {
      if (args.length != 10) { System.err.println("sign requires <messageHex> <hash> <mgfHash> <saltLengthBytes>"); System.exit(2); }
      String hash = args[7];
      String mgfHash = args[8];
      int saltLengthBytes = Integer.parseInt(args[9]);
      PssBouncyCastle.PssSignRequest req = new PssBouncyCastle.PssSignRequest(key, message, hash, mgfHash, saltLengthBytes);
      System.out.println(PssBouncyCastle.pssBouncyCastleSign(req));
      return;
    }
    if (mode.equals("verify")) {
      if (args.length != 11) { System.err.println("verify requires <messageHex> <signatureHex> <hash> <mgfHash> <saltLengthBytes>"); System.exit(2); }
      byte[] signature = fromHex(args[7]);
      String hash = args[8];
      String mgfHash = args[9];
      int saltLengthBytes = Integer.parseInt(args[10]);
      PssBouncyCastle.PssVerifyRequest req = new PssBouncyCastle.PssVerifyRequest(key, message, signature, hash, mgfHash, saltLengthBytes);
      System.out.println(PssBouncyCastle.pssBouncyCastleVerify(req));
      return;
    }
    System.err.println("unknown mode: " + mode);
    System.exit(2);
  }
}
