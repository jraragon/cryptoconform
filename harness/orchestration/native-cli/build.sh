#!/usr/bin/env bash
# M2.5.2/H1.4 -- builds the native CLI wrappers (Crypto++, Bouncy Castle) from
# source into harness/orchestration/native-build/ (gitignored -- rebuilt on
# demand, never committed as a binary).
#
# CRYPTOPP_DIR and BC_JAR are REQUIRED external experimental prerequisites,
# not sandbox conveniences -- no default is provided. A reproducible build
# must fail loudly and immediately if these are absent, rather than
# silently resolving to a path that only ever existed on one prior
# development machine.
set -euo pipefail

if [ -z "${CRYPTOPP_DIR:-}" ]; then
  echo "ERROR: CRYPTOPP_DIR is required (path to the pinned Crypto++ checkout, commit 782425901d36fe0944b16aae37801b8ec2fa9000)." >&2
  echo "  Example: CRYPTOPP_DIR=/path/to/cryptopp BC_JAR=/path/to/bcprov-jdk18on-1.77.jar npm run build:native" >&2
  exit 1
fi
if [ -z "${BC_JAR:-}" ]; then
  echo "ERROR: BC_JAR is required (path to bcprov-jdk18on-1.77.jar, SHA-256 dabb98c24d72c9b9f585633d1df9c5cd58d9ad373d0cd681367e6a603a495d58)." >&2
  echo "  Example: CRYPTOPP_DIR=/path/to/cryptopp BC_JAR=/path/to/bcprov-jdk18on-1.77.jar npm run build:native" >&2
  exit 1
fi
if [ ! -d "$CRYPTOPP_DIR" ]; then
  echo "ERROR: CRYPTOPP_DIR ('$CRYPTOPP_DIR') does not exist or is not a directory." >&2
  exit 1
fi
if [ ! -f "$BC_JAR" ]; then
  echo "ERROR: BC_JAR ('$BC_JAR') does not exist or is not a file." >&2
  exit 1
fi

OUT_DIR="$(dirname "$0")/../native-build"
CLI_SRC="$(dirname "$0")"

mkdir -p "$OUT_DIR/bc-classes"

echo "== Building Crypto++ CLI wrappers (CRYPTOPP_DIR=$CRYPTOPP_DIR) =="
g++ -std=c++17 -I"$CRYPTOPP_DIR" \
  "$CLI_SRC/hkdf-cryptopp-cli.cpp" \
  "$CLI_SRC/../../../src/adapters/cryptopp/hkdf.cpp" \
  -L"$CRYPTOPP_DIR" -lcryptopp \
  -o "$OUT_DIR/hkdf-cryptopp-cli"

g++ -std=c++17 -I"$CRYPTOPP_DIR" \
  "$CLI_SRC/gcm-cryptopp-cli.cpp" \
  "$CLI_SRC/../../../src/adapters/cryptopp/gcm.cpp" \
  -L"$CRYPTOPP_DIR" -lcryptopp \
  -o "$OUT_DIR/gcm-cryptopp-cli"

g++ -std=c++17 -I"$CRYPTOPP_DIR" \
  "$CLI_SRC/oaep-cryptopp-cli.cpp" \
  "$CLI_SRC/../../../src/adapters/cryptopp/oaep.cpp" \
  -L"$CRYPTOPP_DIR" -lcryptopp \
  -o "$OUT_DIR/oaep-cryptopp-cli"

g++ -std=c++17 -I"$CRYPTOPP_DIR" \
  "$CLI_SRC/pss-cryptopp-cli.cpp" \
  "$CLI_SRC/../../../src/adapters/cryptopp/pss.cpp" \
  -L"$CRYPTOPP_DIR" -lcryptopp \
  -o "$OUT_DIR/pss-cryptopp-cli"

g++ -std=c++17 -I"$CRYPTOPP_DIR" \
  "$CLI_SRC/rsa-ser-cryptopp-cli.cpp" \
  "$CLI_SRC/../../../src/adapters/cryptopp/rsa-ser.cpp" \
  -L"$CRYPTOPP_DIR" -lcryptopp \
  -o "$OUT_DIR/rsa-ser-cryptopp-cli"

g++ -std=c++17 -I"$CRYPTOPP_DIR" \
  "$CLI_SRC/ec-ser-cryptopp-cli.cpp" \
  "$CLI_SRC/../../../src/adapters/cryptopp/ec-ser.cpp" \
  -L"$CRYPTOPP_DIR" -lcryptopp \
  -o "$OUT_DIR/ec-ser-cryptopp-cli"

echo "== Building Bouncy Castle CLI wrappers (BC_JAR=$BC_JAR) =="
javac -cp "$BC_JAR" -d "$OUT_DIR/bc-classes" \
  "$CLI_SRC/../../../src/adapters/bouncycastle/HkdfBouncyCastle.java" \
  "$CLI_SRC/HkdfBouncyCastleCli.java" \
  "$CLI_SRC/../../../src/adapters/bouncycastle/GcmBouncyCastle.java" \
  "$CLI_SRC/GcmBouncyCastleCli.java" \
  "$CLI_SRC/../../../src/adapters/bouncycastle/OaepBouncyCastle.java" \
  "$CLI_SRC/OaepBouncyCastleCli.java" \
  "$CLI_SRC/../../../src/adapters/bouncycastle/PssBouncyCastle.java" \
  "$CLI_SRC/PssBouncyCastleCli.java" \
  "$CLI_SRC/../../../src/adapters/bouncycastle/RsaSerBouncyCastle.java" \
  "$CLI_SRC/RsaSerBouncyCastleCli.java" \
  "$CLI_SRC/../../../src/adapters/bouncycastle/EcSerBouncyCastle.java" \
  "$CLI_SRC/EcSerBouncyCastleCli.java"

echo "== Verifying required artifacts =="
MISSING=0
for cli in hkdf gcm oaep pss rsa-ser ec-ser; do
  path="$OUT_DIR/${cli}-cryptopp-cli"
  if [ ! -x "$path" ]; then
    echo "ERROR: missing or non-executable: $path" >&2
    MISSING=1
  fi
done
for cls in Hkdf Gcm Oaep Pss RsaSer EcSer; do
  path="$OUT_DIR/bc-classes/${cls}BouncyCastleCli.class"
  if [ ! -f "$path" ]; then
    echo "ERROR: missing: $path" >&2
    MISSING=1
  fi
done
if [ "$MISSING" -ne 0 ]; then
  echo "ERROR: native build did not produce all 12 required artifacts (6 Crypto++ binaries + 6 Bouncy Castle CLI classes)." >&2
  exit 1
fi

echo "Built and verified 12/12 required artifacts into $OUT_DIR"
