// H1.4 -- BC_JAR is a REQUIRED external experimental prerequisite at
// runtime (Java has no standalone-binary equivalent: the classpath is
// needed every time the JVM launches, unlike Crypto++'s statically-linked
// CLIs, which need no path once built). No default is provided: falling
// back silently to a path that only ever existed on one prior development
// machine would turn a missing-prerequisite condition into a confusing
// downstream "class not found" error instead of a clear, immediate one.

export function requireBcJar(): string {
  const value = process.env.BC_JAR;
  if (!value) {
    throw new Error(
      "BC_JAR is required (path to bcprov-jdk18on-1.77.jar, SHA-256 " +
      "dabb98c24d72c9b9f585633d1df9c5cd58d9ad373d0cd681367e6a603a495d58). " +
      "Example: BC_JAR=/path/to/bcprov-jdk18on-1.77.jar npm test",
    );
  }
  return value;
}
