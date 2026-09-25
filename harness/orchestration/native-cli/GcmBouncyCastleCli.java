// M2.5.2 -- generic, parametric CLI around the real gcmBouncyCastleEncrypt
// / gcmBouncyCastleDecrypt adapters
// (src/adapters/bouncycastle/GcmBouncyCastle.java, M1, unmodified).
//
// Usage:
//   java GcmBouncyCastleCli encrypt <keyHex> <plaintextHex> <aadHex-or-empty> <aadPresent:0|1> <ivHex> <tagLengthBits>
//   java GcmBouncyCastleCli decrypt <keyHex> <artifactHex> <aadHex-or-empty> <aadPresent:0|1>

import paper4.adapters.bouncycastle.GcmBouncyCastle;

public final class GcmBouncyCastleCli {
  private static byte[] fromHex(String hex) {
    int len = hex.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
    }
    return out;
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      System.err.println("usage: GcmBouncyCastleCli encrypt|decrypt ...");
      System.exit(2);
    }
    String mode = args[0];

    if (mode.equals("encrypt")) {
      if (args.length != 7) {
        System.err.println("usage: GcmBouncyCastleCli encrypt <keyHex> <plaintextHex> <aadHex-or-empty> <aadPresent:0|1> <ivHex> <tagLengthBits>");
        System.exit(2);
      }
      byte[] key = fromHex(args[1]);
      byte[] plaintext = fromHex(args[2]);
      boolean aadPresent = args[4].equals("1");
      byte[] aad = aadPresent ? fromHex(args[3]) : new byte[0];
      byte[] iv = fromHex(args[5]);
      int tagLengthBits = Integer.parseInt(args[6]);
      GcmBouncyCastle.GcmEncryptRequest req = new GcmBouncyCastle.GcmEncryptRequest(key, plaintext, aad, aadPresent, iv, tagLengthBits);
      System.out.println(GcmBouncyCastle.gcmBouncyCastleEncrypt(req));
      return;
    }

    if (mode.equals("decrypt")) {
      if (args.length != 5) {
        System.err.println("usage: GcmBouncyCastleCli decrypt <keyHex> <artifactHex> <aadHex-or-empty> <aadPresent:0|1>");
        System.exit(2);
      }
      byte[] key = fromHex(args[1]);
      byte[] artifact = fromHex(args[2]);
      boolean aadPresent = args[4].equals("1");
      byte[] aad = aadPresent ? fromHex(args[3]) : new byte[0];
      GcmBouncyCastle.GcmDecryptRequest req = new GcmBouncyCastle.GcmDecryptRequest(key, artifact, aad, aadPresent);
      System.out.println(GcmBouncyCastle.gcmBouncyCastleDecrypt(req));
      return;
    }

    System.err.println("unknown mode: " + mode);
    System.exit(2);
  }
}
