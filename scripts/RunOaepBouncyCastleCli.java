// CLI wrapper around OaepBouncyCastle.oaepBouncyCastleEncrypt/Decrypt for
// the 3x3 interoperability orchestrator (scripts/run-oaep-interop-3x3.ts)
// to shell out to. Does not alter adapter logic in any way.
//
// Usage:
//   RunOaepBouncyCastleCli genkey
//     -> prints "modulusHex publicExponentHex privateExponentHex"
//   RunOaepBouncyCastleCli encrypt <modulusHex> <pubExpHex> <ptHex>
//     -> prints ciphertextHex on accept (exit 0), or "REJECT" (exit 1)
//   RunOaepBouncyCastleCli decrypt <modulusHex> <pubExpHex> <privExpHex> <ctHex>
//     -> prints plaintextHex on accept (exit 0), or "REJECT" (exit 1)

package paper4.scripts;

import paper4.adapters.bouncycastle.OaepBouncyCastle;
import paper4.adapters.bouncycastle.OaepBouncyCastle.OaepEncryptRequest;
import paper4.adapters.bouncycastle.OaepBouncyCastle.OaepDecryptRequest;
import paper4.adapters.bouncycastle.OaepBouncyCastle.OaepKeyMaterial;

import java.math.BigInteger;

public final class RunOaepBouncyCastleCli {

  private static byte[] fromHex(String hex) {
    int len = hex.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
    }
    return out;
  }

  private static String toHex(BigInteger n) {
    String h = n.toString(16);
    return h.length() % 2 == 0 ? h : "0" + h;
  }

  private static String extractField(String record, String key) {
    String marker = "\"" + key + "\":\"";
    int start = record.indexOf(marker);
    if (start < 0) return "";
    start += marker.length();
    int end = record.indexOf('"', start);
    return record.substring(start, end);
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      System.err.println("usage: genkey|encrypt|decrypt ...");
      System.exit(2);
    }
    String mode = args[0];

    if (mode.equals("genkey")) {
      OaepKeyMaterial material = OaepBouncyCastle.generateOaepKeyMaterial();
      System.out.println(
          toHex(material.modulus) + " " + toHex(material.publicExponent) + " " + toHex(material.privateExponent));
      return;
    }

    if (mode.equals("encrypt")) {
      if (args.length != 4) {
        System.err.println("usage: encrypt <modulusHex> <pubExpHex> <ptHex>");
        System.exit(2);
      }
      BigInteger modulus = new BigInteger(args[1], 16);
      BigInteger pubExp = new BigInteger(args[2], 16);
      byte[] pt = fromHex(args[3]);
      OaepKeyMaterial key = new OaepKeyMaterial("public", modulus, pubExp, null, modulus.bitLength());
      String record = OaepBouncyCastle.oaepBouncyCastleEncrypt(
          new OaepEncryptRequest(key, pt, new byte[0], false, "SHA-256", "SHA-256"));
      if (record.contains("\"kind\":\"accept\"")) {
        System.out.println(extractField(record, "ciphertextHex"));
      } else {
        System.out.println("REJECT");
        System.exit(1);
      }
      return;
    }

    if (mode.equals("decrypt")) {
      if (args.length != 5) {
        System.err.println("usage: decrypt <modulusHex> <pubExpHex> <privExpHex> <ctHex>");
        System.exit(2);
      }
      BigInteger modulus = new BigInteger(args[1], 16);
      BigInteger pubExp = new BigInteger(args[2], 16);
      BigInteger privExp = new BigInteger(args[3], 16);
      byte[] ct = fromHex(args[4]);
      OaepKeyMaterial key = new OaepKeyMaterial("private", modulus, pubExp, privExp, modulus.bitLength());
      String record = OaepBouncyCastle.oaepBouncyCastleDecrypt(
          new OaepDecryptRequest(key, ct, new byte[0], false, "SHA-256", "SHA-256"));
      if (record.contains("\"kind\":\"accept\"")) {
        System.out.println(extractField(record, "plaintextHex"));
      } else {
        System.out.println("REJECT");
        System.exit(1);
      }
      return;
    }

    System.err.println("unknown mode: " + mode);
    System.exit(2);
  }
}
