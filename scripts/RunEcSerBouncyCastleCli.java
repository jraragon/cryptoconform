// CLI wrapper around the EC-ser Bouncy Castle adapter for the
// cross-provider interop orchestrator to shell out to.

package paper4.scripts;

import paper4.adapters.bouncycastle.EcSerBouncyCastle;
import paper4.adapters.bouncycastle.EcSerBouncyCastle.EcKeyMaterial;
import paper4.adapters.bouncycastle.EcSerBouncyCastle.EcPointXY;
import paper4.adapters.bouncycastle.EcSerBouncyCastle.EcSerError;
import paper4.adapters.bouncycastle.EcSerBouncyCastle.EcSerImportResult;

import java.math.BigInteger;

public final class RunEcSerBouncyCastleCli {

  private static byte[] fromHex(String hex) {
    int len = hex.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
    return out;
  }

  private static String toHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) sb.append(String.format("%02x", b));
    return sb.toString();
  }

  private static String toHex(BigInteger n) {
    String h = n.toString(16);
    return h.length() % 2 == 0 ? h : "0" + h;
  }

  private static BigInteger fromHexBig(String hex) {
    return new BigInteger(hex, 16);
  }

  public static void main(String[] args) throws Exception {
    if (args.length < 1) {
      System.err.println("usage: <verb> ...");
      System.exit(2);
    }
    String mode = args[0];

    if (mode.equals("genkey")) {
      EcKeyMaterial m = EcSerBouncyCastle.generateEcSerKeyMaterial();
      System.out.println(toHex(m.d) + " " + toHex(m.q.x) + " " + toHex(m.q.y));
      return;
    }

    if (mode.equals("export-spki")) {
      if (args.length != 3) { System.err.println("usage: export-spki <xHex> <yHex>"); System.exit(2); }
      EcKeyMaterial m = EcKeyMaterial.ofPublic(new EcPointXY(fromHexBig(args[1]), fromHexBig(args[2])));
      System.out.println(toHex(EcSerBouncyCastle.exportEcSer(m)));
      return;
    }

    if (mode.equals("export-pkcs8")) {
      if (args.length != 4) { System.err.println("usage: export-pkcs8 <dHex> <xHex> <yHex>"); System.exit(2); }
      EcKeyMaterial m = new EcKeyMaterial("private", new EcPointXY(fromHexBig(args[2]), fromHexBig(args[3])), fromHexBig(args[1]));
      System.out.println(toHex(EcSerBouncyCastle.exportEcSer(m)));
      return;
    }

    if (mode.equals("import-public")) {
      if (args.length != 2) { System.err.println("usage: import-public <artifactHex>"); System.exit(2); }
      try {
        EcSerImportResult r = EcSerBouncyCastle.importEcSer(fromHex(args[1]), "public");
        System.out.println(toHex(r.material.q.x) + " " + toHex(r.material.q.y));
      } catch (EcSerError ex) {
        System.out.println("REJECT " + ex.errorClass + " " + ex.clauseId);
        System.exit(1);
      }
      return;
    }

    if (mode.equals("import-private")) {
      if (args.length != 2) { System.err.println("usage: import-private <artifactHex>"); System.exit(2); }
      try {
        EcSerImportResult r = EcSerBouncyCastle.importEcSer(fromHex(args[1]), "private");
        System.out.println(toHex(r.material.d) + " " + toHex(r.material.q.x) + " " + toHex(r.material.q.y) + " " + (r.normalized ? 1 : 0));
      } catch (EcSerError ex) {
        System.out.println("REJECT " + ex.errorClass + " " + ex.clauseId);
        System.exit(1);
      }
      return;
    }

    if (mode.equals("native-export-spki")) {
      if (args.length != 3) { System.err.println("usage: native-export-spki <xHex> <yHex>"); System.exit(2); }
      EcKeyMaterial m = EcKeyMaterial.ofPublic(new EcPointXY(fromHexBig(args[1]), fromHexBig(args[2])));
      System.out.println(toHex(EcSerBouncyCastle.nativeBcSpkiExport(m)));
      return;
    }

    if (mode.equals("native-export-pkcs8")) {
      if (args.length != 4) { System.err.println("usage: native-export-pkcs8 <dHex> <xHex> <yHex>"); System.exit(2); }
      EcKeyMaterial m = new EcKeyMaterial("private", new EcPointXY(fromHexBig(args[2]), fromHexBig(args[3])), fromHexBig(args[1]));
      System.out.println(toHex(EcSerBouncyCastle.nativeBcPkcs8Export(m)));
      return;
    }

    if (mode.equals("native-import-public")) {
      if (args.length != 2) { System.err.println("usage: native-import-public <artifactHex>"); System.exit(2); }
      try {
        EcKeyMaterial m = EcSerBouncyCastle.nativeBcImport(fromHex(args[1]), "public");
        System.out.println(toHex(m.q.x) + " " + toHex(m.q.y));
      } catch (Exception ex) {
        System.out.println("REJECT native " + ex.getMessage());
        System.exit(1);
      }
      return;
    }

    if (mode.equals("native-import-private")) {
      if (args.length != 2) { System.err.println("usage: native-import-private <artifactHex>"); System.exit(2); }
      try {
        EcKeyMaterial m = EcSerBouncyCastle.nativeBcImport(fromHex(args[1]), "private");
        System.out.println(toHex(m.d));
      } catch (Exception ex) {
        System.out.println("REJECT native " + ex.getMessage());
        System.exit(1);
      }
      return;
    }

    System.err.println("unknown mode: " + mode);
    System.exit(2);
  }
}
