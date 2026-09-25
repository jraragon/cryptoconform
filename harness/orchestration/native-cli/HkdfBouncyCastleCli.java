// M2.5.2 -- generic, parametric CLI around the real hkdfBouncyCastle
// adapter (src/adapters/bouncycastle/HkdfBouncyCastle.java, M1, unmodified).
// Distinct from M1's own fixed-test-case runner; accepts an arbitrary
// request via argv for the M2 orchestrator's generic ExecutionAdapter
// pattern. Lives under harness/, never src/adapters/, to keep the M1
// boundary unambiguous.
//
// Usage: java HkdfBouncyCastleCli <ikmHex> <saltHex-or-empty> <saltPresent:0|1> <infoHex> <length>

import paper4.adapters.bouncycastle.HkdfBouncyCastle;

public final class HkdfBouncyCastleCli {
  private static byte[] fromHex(String hex) {
    int len = hex.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
    }
    return out;
  }

  public static void main(String[] args) {
    if (args.length != 5) {
      System.err.println("usage: HkdfBouncyCastleCli <ikmHex> <saltHex-or-empty> <saltPresent:0|1> <infoHex> <length>");
      System.exit(2);
    }
    byte[] ikm = fromHex(args[0]);
    boolean saltPresent = args[2].equals("1");
    byte[] salt = saltPresent ? fromHex(args[1]) : null;
    byte[] info = fromHex(args[3]);
    int length = Integer.parseInt(args[4]);

    HkdfBouncyCastle.HkdfRequest req = new HkdfBouncyCastle.HkdfRequest(ikm, salt, saltPresent, info, length);
    System.out.println(HkdfBouncyCastle.hkdfBouncyCastle(req));
  }
}
