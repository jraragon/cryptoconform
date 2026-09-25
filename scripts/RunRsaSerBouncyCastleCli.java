// CLI wrapper around the RSA-ser Bouncy Castle adapter for the
// cross-provider interop orchestrator to shell out to.

package paper4.scripts;

import paper4.adapters.bouncycastle.RsaSerBouncyCastle;
import paper4.adapters.bouncycastle.RsaSerBouncyCastle.RsaKeyMaterial;
import paper4.adapters.bouncycastle.RsaSerBouncyCastle.RsaSerError;

import java.math.BigInteger;

public final class RunRsaSerBouncyCastleCli {

  private static byte[] fromHex(String hex) {
    int len = hex.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
    }
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

  public static void main(String[] args) {
    if (args.length < 1) {
      System.err.println("usage: genkey|export-spki|export-pkcs8|import-public|import-private ...");
      System.exit(2);
    }
    String mode = args[0];

    if (mode.equals("genkey")) {
      RsaKeyMaterial m = RsaSerBouncyCastle.generateRsaSerKeyMaterial(3072);
      System.out.println(toHex(m.n) + " " + toHex(m.e) + " " + toHex(m.d) + " " + toHex(m.p) + " " + toHex(m.q) + " "
          + toHex(m.dP) + " " + toHex(m.dQ) + " " + toHex(m.qInv));
      return;
    }

    if (mode.equals("export-spki")) {
      if (args.length != 3) { System.err.println("usage: export-spki <nHex> <eHex>"); System.exit(2); }
      RsaKeyMaterial m = RsaKeyMaterial.ofPublic(fromHexBig(args[1]), fromHexBig(args[2]));
      System.out.println(toHex(RsaSerBouncyCastle.exportRsaSer(m)));
      return;
    }

    if (mode.equals("export-pkcs8")) {
      if (args.length != 9) { System.err.println("usage: export-pkcs8 <n> <e> <d> <p> <q> <dP> <dQ> <qInv>"); System.exit(2); }
      RsaKeyMaterial m = new RsaKeyMaterial("private", fromHexBig(args[1]), fromHexBig(args[2]), fromHexBig(args[3]),
          fromHexBig(args[4]), fromHexBig(args[5]), fromHexBig(args[6]), fromHexBig(args[7]), fromHexBig(args[8]));
      System.out.println(toHex(RsaSerBouncyCastle.exportRsaSer(m)));
      return;
    }

    if (mode.equals("import-public")) {
      if (args.length != 2) { System.err.println("usage: import-public <artifactHex>"); System.exit(2); }
      try {
        RsaKeyMaterial m = RsaSerBouncyCastle.importRsaSer(fromHex(args[1]), "public");
        System.out.println(toHex(m.n) + " " + toHex(m.e));
      } catch (RsaSerError ex) {
        System.out.println("REJECT " + ex.errorClass + " " + ex.clauseId);
        System.exit(1);
      }
      return;
    }

    if (mode.equals("import-private")) {
      if (args.length != 2) { System.err.println("usage: import-private <artifactHex>"); System.exit(2); }
      try {
        RsaKeyMaterial m = RsaSerBouncyCastle.importRsaSer(fromHex(args[1]), "private");
        System.out.println(toHex(m.n) + " " + toHex(m.e) + " " + toHex(m.d) + " " + toHex(m.p) + " " + toHex(m.q)
            + " " + toHex(m.dP) + " " + toHex(m.dQ) + " " + toHex(m.qInv));
      } catch (RsaSerError ex) {
        System.out.println("REJECT " + ex.errorClass + " " + ex.clauseId);
        System.exit(1);
      }
      return;
    }

    // --- Genuinely native-only verbs (this session's explicit correction) --
    // NEVER call RsaSerBouncyCastle.exportRsaSer/importRsaSer (the SDK's own
    // contract-level codec/Accept_C) -- only nativeBcSpkiExport/PkcsExport/
    // nativeBcImport, which use SubjectPublicKeyInfoFactory/
    // PrivateKeyInfoFactory/PublicKeyFactory/PrivateKeyFactory exclusively.

    if (mode.equals("native-export-spki")) {
      if (args.length != 3) { System.err.println("usage: native-export-spki <nHex> <eHex>"); System.exit(2); }
      RsaKeyMaterial m = RsaKeyMaterial.ofPublic(fromHexBig(args[1]), fromHexBig(args[2]));
      try {
        System.out.println(toHex(RsaSerBouncyCastle.nativeBcSpkiExport(m)));
      } catch (Exception ex) {
        System.err.println("native export failed: " + ex.getMessage());
        System.exit(1);
      }
      return;
    }

    if (mode.equals("native-export-pkcs8")) {
      if (args.length != 9) { System.err.println("usage: native-export-pkcs8 <n> <e> <d> <p> <q> <dP> <dQ> <qInv>"); System.exit(2); }
      RsaKeyMaterial m = new RsaKeyMaterial("private", fromHexBig(args[1]), fromHexBig(args[2]), fromHexBig(args[3]),
          fromHexBig(args[4]), fromHexBig(args[5]), fromHexBig(args[6]), fromHexBig(args[7]), fromHexBig(args[8]));
      try {
        System.out.println(toHex(RsaSerBouncyCastle.nativeBcPkcs8Export(m)));
      } catch (Exception ex) {
        System.err.println("native export failed: " + ex.getMessage());
        System.exit(1);
      }
      return;
    }

    if (mode.equals("native-import-public")) {
      if (args.length != 2) { System.err.println("usage: native-import-public <artifactHex>"); System.exit(2); }
      try {
        RsaKeyMaterial m = RsaSerBouncyCastle.nativeBcImport(fromHex(args[1]), "public");
        System.out.println(toHex(m.n) + " " + toHex(m.e));
      } catch (Exception ex) {
        System.out.println("REJECT native " + ex.getMessage());
        System.exit(1);
      }
      return;
    }

    if (mode.equals("native-import-private")) {
      if (args.length != 2) { System.err.println("usage: native-import-private <artifactHex>"); System.exit(2); }
      try {
        RsaKeyMaterial m = RsaSerBouncyCastle.nativeBcImport(fromHex(args[1]), "private");
        System.out.println(toHex(m.n) + " " + toHex(m.e) + " " + toHex(m.d) + " " + toHex(m.p) + " " + toHex(m.q)
            + " " + toHex(m.dP) + " " + toHex(m.dQ) + " " + toHex(m.qInv));
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
