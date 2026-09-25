#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const [jsonPath, m3Root, outputPath] = process.argv.slice(2);
if (!jsonPath || !m3Root || !outputPath) {
  throw new Error('usage: verify-registry-binding.mjs M4_JSON M3_ROOT OUTPUT_JSON');
}
const load = (p) => import(pathToFileURL(resolve(p)).href);
const binding = await load(resolve(m3Root, 'dist/harness/evidence/registry-binding.js'));
const registry = await load(resolve(m3Root, 'dist/harness/registry/mutations.js'));
const run = JSON.parse(readFileSync(jsonPath, 'utf8'));
const results = run.evidenceBundle.scientificResults;
const byId = new Map(registry.MUTATION_REGISTRY.map((entry) => [entry.mutationId, entry]));
const verified = results.map((result) => {
  if (result.gamma0Ref !== `registry:${result.mutationId}`) throw new Error(`gamma0Ref mismatch: ${result.mutationId}`);
  binding.verifyRegistryBinding(result.mutationId, result.registryEntryHash);
  const entry = byId.get(result.mutationId);
  if (!entry) throw new Error(`missing registry entry: ${result.mutationId}`);
  return {mutationId: result.mutationId, registryEntryHash: result.registryEntryHash,
    gamma0Ref: result.gamma0Ref, gamma0Size: entry.gamma0.length, mechanism: entry.mechanism};
});
writeFileSync(outputPath, JSON.stringify({gate:'PASS', requiredBearingResults:results.length,
  registryEntries:registry.MUTATION_REGISTRY.length, verifiedBindings:verified.length,
  note:'No observedSpectrum, detectionSupport, or observation status field was read.', verified}, null, 2) + '\n');
