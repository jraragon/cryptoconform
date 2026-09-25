// M3.8.4 -- narrow repair of a quoting defect in a frozen CLI's output.
//
// The Bouncy Castle OAEP and PSS CLIs build their rejection message by quoting
// the two hashes, and emit it into a JSON string field WITHOUT escaping the
// inner quotes:
//
//     ..."detail":"mgfHash "SHA-512" != hash "SHA-256"; portable profile ..."
//
// The process is not failing. It answers, it rejects the operation for a
// stated reason, and only the serialisation of that reason is malformed. The
// frozen CLI is not modified -- that would change the instrument -- so the
// transport is repaired on the reading side instead.
//
// This is the difference between a defect that blocks 21 required obligations
// and one that does not, which is why it belongs INSIDE the freeze rather
// than as a prerequisite announced after it.
//
// DETERMINISTIC AND NARROW, deliberately:
//
//   - well-formed output is parsed unchanged, with no preprocessing at all;
//   - on failure, ONLY quotes inside a string value are escaped;
//   - if the result still does not parse, it throws.
//
// No value is reinterpreted, no field is invented, and arbitrary rubbish is
// not accepted: a different defect in a different field must still fail.

export class NativeCliJsonError extends Error {}

/**
 * Escapes quotes that appear INSIDE a JSON string value, leaving the
 * structural quotes intact.
 *
 * A quote closes a string only when the next non-space character is one of
 * `:,}]`. Anything else means the quote was part of the text, which is the
 * CLI's defect.
 *
 * TERMINAL-QUOTE CASE. The CLI's message can END in a citation:
 *
 *     "detail":"hash "SHA-512", portable profile requires exactly "SHA-256""
 *
 * so the field closes with two adjacent quotes -- the text's and the
 * structure's. The first would otherwise be read as structural, because a `}`
 * follows it, and the escape would land on the wrong character. A quote
 * IMMEDIATELY followed by another quote is therefore text, and the second one
 * closes the string.
 */
/**
 * Repairs the ONE field the defect occurs in: `detail`.
 *
 * Scoping the repair to that field is narrower than a general quote-escaper,
 * not wider. The CLI's message is free text that may contain quotes anywhere
 * -- mid-message, before a comma, or as the final characters:
 *
 *     "detail":"mgfHash "SHA-512" != hash "SHA-256"; portable profile"
 *     "detail":"hash "SHA-512", portable profile requires exactly "SHA-256""
 *
 * so no local rule on the following character can tell text from structure.
 * What IS determinate is where the field ends: at the last quote before the
 * next structural token. Everything strictly inside is text, and every quote
 * inside it is escaped.
 *
 * Corruption in any OTHER field is left exactly as it is, so it still fails.
 */
function candidateRepairs(raw: string): readonly string[] {
  const KEY = '"detail":"';
  const start = raw.indexOf(KEY);
  if (start === -1) return [];
  const valueStart = start + KEY.length;
  const tail = raw.slice(valueStart);
  // Every quote followed by a structural token is a CANDIDATE end of the
  // field. Which one it is cannot be told locally, because the message is
  // free text that may contain quotes before a comma, a brace, or at the very
  // end. So each candidate is tried and the one that yields a parseable
  // document wins -- deterministic, bounded, and confined to `detail`.
  const ends: number[] = [];
  const re = /"(\s*[,}\]])/g;
  for (let m = re.exec(tail); m !== null; m = re.exec(tail)) ends.push(m.index);
  return ends.map((end) => raw.slice(0, valueStart)
    + tail.slice(0, end).replace(/\\?"/g, '\\"')
    + tail.slice(end));
}

/** Parses a frozen CLI's stdout, repairing only the known quoting defect. */
export function parseNativeCliJson(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    // Fall through to the single known repair.
  }
  for (const candidate of candidateRepairs(raw)) {
    try {
      return JSON.parse(candidate);
    } catch {
      // Wrong field boundary; try the next candidate.
    }
  }
  throw new NativeCliJsonError(
    'Native CLI output is not JSON and is not the known quoting defect in its `detail` field.',
  );
}
