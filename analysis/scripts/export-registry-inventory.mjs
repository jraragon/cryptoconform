#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const [m3Root, outputPath] = process.argv.slice(2);
if (!m3Root || !outputPath) throw new Error('usage: export-registry-inventory.mjs M3_ROOT OUTPUT_JSON');
const mod = await import(pathToFileURL(resolve(m3Root, 'dist/harness/registry/mutations.js')).href);
const rows = mod.MUTATION_REGISTRY.map((entry) => ({
  mutationId: entry.mutationId,
  operation: entry.operation,
  mechanism: entry.mechanism,
  gamma0: [...entry.gamma0],
  stimulusInstanceIds: entry.stimulusInstances.map((s) => s.stimulusInstanceId),
}));
writeFileSync(outputPath, JSON.stringify({registryEntries: rows.length, entries: rows}, null, 2) + '\n');
