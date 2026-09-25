// M3-H2 -- type-safe canonical encoding of heterogeneous values.
//
// Two consumers, ONE primitive (never two competing canonicalizations):
//   baselineCacheKey = canonicalEncode(fixture)          -- orchestrator
//   materialId       = sha256(canonicalEncode(material)) -- frozen pool
// Deliberately named neutrally (not "canonicalizeMaterial"): the
// orchestrator must not conceptually depend on the material-pool module.
//
// WHY THIS EXISTS. The pre-existing canonicalize() in
// harness/aggregation/evidence-export.ts is JSON.stringify(sortKeysDeep(v)),
// which is correct for the EvidenceBundle it was written for (hex strings,
// enums, plain records) but is NOT type-safe for cryptographic fixtures.
// Demonstrated empirically before this module was written:
//   M3-H2a  canonicalize({ n: 3233n })         -> TypeError: Do not know how
//                                                 to serialize a BigInt
//   M3-H2b  canonicalize({ k: Uint8Array[1,2] }) === canonicalize({ k: {0:1,1:2} })
//           -- a structural COLLISION: two values of different types share
//           one representation, so a cache keyed on it cannot distinguish them.
// 31 rsa-ser/ec-ser classes have R_byte applicable and would therefore route
// bigint-bearing material through BaselineCache.key() -- H2a would crash
// Phase C outright. Neither manifestation was reachable from the single real
// precedent (HKDF, whose fixture is raw bytes only).
//
// DESIGN.
// Every encoding is TAGGED (so different types never share a representation)
// and SELF-DELIMITING via explicit length prefixes (so concatenation of
// encoded children is unambiguous, and no value can be crafted to imitate a
// delimiter). Within the admitted domain the encoding is injective:
//   canonicalEncode(x) === canonicalEncode(y)  =>  x equivalent to y
//
// bigint is encoded as sign + canonical magnitude hex WITHOUT arbitrary
// zero-padding. Fixed-width normalization (e.g. P-256's x/y/d at exactly 32
// bytes, the H4 lesson) is deliberately NOT done here: this encoder cannot
// know a field's semantic width -- 2n, 65537n and a 3072-bit modulus are all
// bigint. Width normalization belongs to the material schema, which validates
// and normalizes a field BEFORE handing it here:
//   FieldNormalization  !=  GenericCanonicalization
//
// Anything outside the admitted domain fails CLOSED (throws), never silently
// degrades to some lossy representation.

export class UnsupportedCanonicalValueError extends Error {}

const HEX = '0123456789abcdef';

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += HEX[b >> 4]! + HEX[b & 0x0f]!;
  return out;
}

// Canonical magnitude hex: lowercase, no leading zeros, "0" for zero.
// No padding -- see the FieldNormalization note above.
function bigintMagnitudeHex(v: bigint): string {
  const magnitude = v < 0n ? -v : v;
  return magnitude.toString(16);
}

export function canonicalEncode(value: unknown): string {
  // null / undefined: distinct tags, never conflated with each other or with
  // a missing property.
  if (value === null) return 'z:';
  if (value === undefined) return 'v:';

  const t = typeof value;

  if (t === 'boolean') return `t:${value === true ? '1' : '0'}`;

  if (t === 'bigint') {
    const v = value as bigint;
    const sign = v < 0n ? '-' : '+';
    const hex = bigintMagnitudeHex(v);
    return `b:${sign}:${hex.length}:${hex}`;
  }

  if (t === 'number') {
    const v = value as number;
    if (!Number.isFinite(v)) {
      throw new UnsupportedCanonicalValueError(
        `Non-finite number (${String(v)}) has no canonical encoding -- refusing rather than emitting an ambiguous token.`,
      );
    }
    // String(-0) === '0', so -0 and 0 share an encoding. They are numerically
    // equal; this is a deliberate, documented normalization.
    const s = String(v);
    return `n:${s.length}:${s}`;
  }

  if (t === 'string') {
    const v = value as string;
    return `s:${v.length}:${v}`;
  }

  // Uint8Array (and its subclasses, notably Node's Buffer). Tagged and
  // length-prefixed, so it can never collide with a plain object carrying
  // index-like keys -- M3-H2b's own collision, structurally prevented.
  if (value instanceof Uint8Array) {
    return `u:${value.length}:${bytesToHex(value)}`;
  }

  if (Array.isArray(value)) {
    // Order-preserving: arrays are sequences, never sets.
    const items = value.map((item) => canonicalEncode(item)).join('');
    return `a:${value.length}:${items}`;
  }

  if (t === 'object') {
    // Only plain objects (or null-prototype records) are admitted. A class
    // instance, Map, Set, Date, RegExp, etc. would silently lose its identity
    // if flattened to its enumerable own keys, so it fails closed instead.
    const proto = Object.getPrototypeOf(value as object);
    if (proto !== Object.prototype && proto !== null) {
      throw new UnsupportedCanonicalValueError(
        `Only plain objects, arrays and Uint8Array are admitted; got an instance of ` +
        `'${(value as object).constructor?.name ?? 'unknown'}'. Encoding it by its enumerable own ` +
        'properties would silently discard identity -- refusing.',
      );
    }
    const record = value as Record<string, unknown>;
    // Insertion-order independent: keys are sorted. Each key is itself
    // length-prefixed, so { "a:1b": x } cannot imitate two separate entries.
    const keys = Object.keys(record).sort();
    let pairs = '';
    for (const k of keys) pairs += canonicalEncode(k) + canonicalEncode(record[k]);
    return `o:${keys.length}:${pairs}`;
  }

  throw new UnsupportedCanonicalValueError(
    `Values of type '${t}' have no canonical encoding (functions and symbols are never valid experimental input).`,
  );
}
