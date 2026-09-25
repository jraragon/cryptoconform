// M3.8.4 -- the narrow quoting repair, and its narrowness.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { NativeCliJsonError, parseNativeCliJson } from '../../../harness/orchestration/native-cli-json.js';

test('M3.8.4: well-formed output is parsed UNCHANGED, with no preprocessing', () => {
  assert.deepEqual(parseNativeCliJson('{"a":"b","c":1,"d":[1,2]}'), { a: 'b', c: 1, d: [1, 2] });
  // A legitimately escaped quote survives untouched.
  assert.deepEqual(parseNativeCliJson('{"detail":"he said \\"no\\""}'), { detail: 'he said "no"' });
});

test('M3.8.4: the terminal-quote form is repaired too', () => {
  // The message can END in a citation, so the field closes with two adjacent
  // quotes -- the text's and the structure's:
  //   "detail":"hash "SHA-512", portable profile requires exactly "SHA-256""
  const raw = '{"outcome":{"kind":"reject","errorClass":"invalid_parameter",'
    + '"detail":"hash "SHA-512", portable profile requires exactly "SHA-256""},"timestampIso":"x"}';
  const r = parseNativeCliJson(raw) as { outcome: Record<string, unknown>; timestampIso: string };
  assert.equal(r.outcome['detail'], 'hash "SHA-512", portable profile requires exactly "SHA-256"');
  assert.equal(r.outcome['kind'], 'reject');
  assert.equal(r.outcome['errorClass'], 'invalid_parameter');
  assert.equal(r.timestampIso, 'x');
});

test('M3.8.4: the repair is SCOPED to `detail` -- corruption elsewhere still fails', () => {
  // Narrower than a general quote-escaper, not wider: the same malformation in
  // another field is left exactly as it is.
  assert.throws(() => parseNativeCliJson('{"realization":"a "b" c","ok":true}'), NativeCliJsonError);
  assert.throws(() => parseNativeCliJson('{"realization":"a "b" c"}'), /`detail` field/);
});

test('M3.8.4: the known defect is repaired, and every other field stays intact', () => {
  // The literal shape the Bouncy Castle OAEP/PSS CLIs emit.
  const raw = '{"operation":"RSA-OAEP","direction":"encrypt","ok":false,'
    + '"detail":"mgfHash "SHA-512" != hash "SHA-256"; portable profile","errorClass":"unsupported_profile"}';
  const r = parseNativeCliJson(raw) as Record<string, unknown>;
  assert.equal(r['detail'], 'mgfHash "SHA-512" != hash "SHA-256"; portable profile');
  assert.equal(r['operation'], 'RSA-OAEP');
  assert.equal(r['direction'], 'encrypt');
  assert.equal(r['ok'], false);
  assert.equal(r['errorClass'], 'unsupported_profile');
});

test('M3.8.4: rubbish is still rejected -- the repair is not a tolerance', () => {
  for (const bad of ['{"a":', 'not json at all', '', '{"a":1,,}', '<html>error</html>']) {
    assert.throws(() => parseNativeCliJson(bad), NativeCliJsonError, `accepted: ${bad}`);
  }
  assert.throws(() => parseNativeCliJson('{"a":'), /not the known quoting defect/);
});

test('M3.8.4: no value is reinterpreted and no field is invented', () => {
  // Same check on the field the repair actually covers: everything around it
  // survives byte for byte, and nothing is added.
  const r = parseNativeCliJson('{"detail":"a "b" c","y":null,"z":0}') as Record<string, unknown>;
  assert.deepEqual(Object.keys(r).sort(), ['detail', 'y', 'z']);
  assert.equal(r['detail'], 'a "b" c');
  assert.equal(r['y'], null);
  assert.equal(r['z'], 0);
});

test('M3.8.4: the frozen CLI is not modified -- the repair is on the reading side', () => {
  const src = readFileSync(new URL('../../../harness/orchestration/native-cli-json.ts', import.meta.url), 'utf8');
  assert.ok(src.includes('frozen CLI is not modified'), 'the module must state the boundary it respects');
  // And the two wirings read through it.
  for (const w of ['oaep-native-wiring.ts', 'pss-native-wiring.ts']) {
    const s = readFileSync(new URL(`../../../harness/orchestration/${w}`, import.meta.url), 'utf8');
    assert.ok(s.includes('parseNativeCliJson('), w);
    assert.ok(!s.includes('JSON.parse(await runCli('), `${w} still parses directly`);
  }
});
