// CLI wrapper around PssBouncyCastle.pssBouncyCastleSign/Verify for the 3x3
// interoperability orchestrator (scripts/run-pss-interop-3x3.ts) to shell
// out to. Does not alter adapter logic in any way.
//
// Usage:
//   RunPssBouncyCastleCli genkey
//     -> prints "modulusHex publicExponentHex privateExponentHex"
//   RunPssBouncyCastleCli sign <modulusHex> <pubExpHex> <privExpHex> <msgHex>
//     -> prints signatureHex on accept (exit 0), or "REJECT" (exit 1)
//   RunPssBouncyCastleCli verify <modulusHex> <pubExpHex> <msgHex> <sigHex>
//     -> prints "true"/"false" (exit 0), or "REJECT" (exit 1)

package paper4.scripts;

import paper4.adapters.bouncycastle.PssBouncyCastle;
import paper4.adapters.bouncycastle.PssBouncyCastle.PssSignRequest;
import paper4.adapters.bouncycastle.PssBouncyCastle.PssVerifyRequest;
import paper4.adapters.bouncycastle.PssBouncyCastle.PssKeyMaterial;

import java.math.BigInteger;

public final class RunPssBouncyCastleCli {

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
      System.err.println("usage: genkey|sign|verify ...");
      System.exit(2);
    }
    String mode = args[0];

    if (mode.equals("genkey")) {
      PssKeyMaterial material = PssBouncyCastle.generatePssKeyMaterial();
      System.out.println(
          toHex(material.modulus) + " " + toHex(material.publicExponent) + " " + toHex(material.privateExponent));
      return;
    }

    if (mode.equals("sign")) {
      if (args.length != 5) {
        System.err.println("usage: sign <modulusHex> <pubExpHex> <privExpHex> <msgHex>");
        System.exit(2);
      }
      BigInteger modulus = new BigInteger(args[1], 16);
      BigInteger pubExp = new BigInteger(args[2], 16);
      BigInteger privExp = new BigInteger(args[3], 16);
      byte[] msg = fromHex(args[4]);
      PssKeyMaterial key = new PssKeyMaterial("private", modulus, pubExp, privExp, modulus.bitLength());
      String record =
          PssBouncyCastle.pssBouncyCastleSign(new PssSignRequest(key, msg, "SHA-256", "SHA-256"));
      if (record.contains("\"kind\":\"accept\"")) {
        System.out.println(extractField(record, "signatureHex"));
      } else {
        System.out.println("REJECT");
        System.exit(1);
      }
      return;
    }

    if (mode.equals("verify")) {
      if (args.length != 5) {
        System.err.println("usage: verify <modulusHex> <pubExpHex> <msgHex> <sigHex>");
        System.exit(2);
      }
      BigInteger modulus = new BigInteger(args[1], 16);
      BigInteger pubExp = new BigInteger(args[2], 16);
      byte[] msg = fromHex(args[3]);
      byte[] sig = fromHex(args[4]);
      PssKeyMaterial key = new PssKeyMaterial("public", modulus, pubExp, null, modulus.bitLength());
      String record =
          PssBouncyCastle.pssBouncyCastleVerify(new PssVerifyRequest(key, msg, sig, "SHA-256", "SHA-256"));
      if (record.contains("\"kind\":\"verified\"")) {
        System.out.println(record.contains("\"valid\":true") ? "true" : "false");
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
