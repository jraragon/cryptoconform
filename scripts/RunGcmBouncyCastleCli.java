// CLI wrapper around GcmBouncyCastle.gcmBouncyCastleEncrypt/Decrypt for the
// 3x3 interoperability orchestrator (scripts/run-gcm-interop-3x3.ts) to
// shell out to. Does not alter adapter logic in any way -- purely argv
// parsing and stdout formatting around the existing, already-tested
// functions.
//
// Usage:
//   RunGcmBouncyCastleCli encrypt <keyHex> <ivHex> <aadHexOrABSENT> <ptHex> <tagLengthBits>
//   RunGcmBouncyCastleCli decrypt <keyHex> <artifactHex> <aadHexOrABSENT>
// Prints artifactHex/plaintextHex on accept (exit 0), or "REJECT" (exit 1).

package paper4.scripts;

import paper4.adapters.bouncycastle.GcmBouncyCastle;
import paper4.adapters.bouncycastle.GcmBouncyCastle.GcmEncryptRequest;
import paper4.adapters.bouncycastle.GcmBouncyCastle.GcmDecryptRequest;

public final class RunGcmBouncyCastleCli {

  private static byte[] fromHex(String hex) {
    int len = hex.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
    }
    return out;
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
      System.err.println("usage: encrypt|decrypt ...");
      System.exit(2);
    }
    String mode = args[0];

    if (mode.equals("encrypt")) {
      if (args.length != 6) {
        System.err.println("usage: encrypt <keyHex> <ivHex> <aadHexOrABSENT> <ptHex> <tagLengthBits>");
        System.exit(2);
      }
      byte[] key = fromHex(args[1]);
      byte[] iv = fromHex(args[2]);
      boolean aadPresent = !args[3].equals("ABSENT");
      byte[] aad = aadPresent ? fromHex(args[3]) : new byte[0];
      byte[] pt = fromHex(args[4]);
      int tagLengthBits = Integer.parseInt(args[5]);

      GcmEncryptRequest req = new GcmEncryptRequest(key, pt, aad, aadPresent, iv, tagLengthBits);
      String record = GcmBouncyCastle.gcmBouncyCastleEncrypt(req);
      if (record.contains("\"kind\":\"accept\"")) {
        System.out.println(extractField(record, "artifactHex"));
        System.exit(0);
      } else {
        System.out.println("REJECT");
        System.exit(1);
      }
    } else if (mode.equals("decrypt")) {
      if (args.length != 4) {
        System.err.println("usage: decrypt <keyHex> <artifactHex> <aadHexOrABSENT>");
        System.exit(2);
      }
      byte[] key = fromHex(args[1]);
      byte[] artifact = fromHex(args[2]);
      boolean aadPresent = !args[3].equals("ABSENT");
      byte[] aad = aadPresent ? fromHex(args[3]) : new byte[0];

      GcmDecryptRequest req = new GcmDecryptRequest(key, artifact, aad, aadPresent);
      String record = GcmBouncyCastle.gcmBouncyCastleDecrypt(req);
      if (record.contains("\"kind\":\"accept\"")) {
        System.out.println(extractField(record, "plaintextHex"));
        System.exit(0);
      } else {
        System.out.println("REJECT");
        System.exit(1);
      }
    } else {
      System.err.println("unknown mode: " + mode);
      System.exit(2);
    }
  }
}
