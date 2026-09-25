#!/usr/bin/env node
// M2.4.6 -- derives the status table from the actual registry + whatever
// mutation-implementation modules exist so far. Never hand-written.
import { MUTATION_REGISTRY } from '../registry/mutations.js';
import { HKDF_ALL_MUTATION_IDS } from '../mutations/hkdf.js';
import { GCM_ALL_MUTATION_IDS } from '../mutations/gcm.js';
import { OAEP_ALL_MUTATION_IDS } from '../mutations/oaep.js';
import { PSS_ALL_MUTATION_IDS } from '../mutations/pss.js';
import { RSA_SER_ALL_MUTATION_IDS } from '../mutations/rsa-ser.js';
import { EC_SER_ALL_MUTATION_IDS } from '../mutations/ec-ser.js';

const IMPLEMENTED_BY_OP = {
  hkdf: new Set(HKDF_ALL_MUTATION_IDS),
  gcm: new Set(GCM_ALL_MUTATION_IDS),
  oaep: new Set(OAEP_ALL_MUTATION_IDS),
  pss: new Set(PSS_ALL_MUTATION_IDS),
  'rsa-ser': new Set(RSA_SER_ALL_MUTATION_IDS),
  'ec-ser': new Set(EC_SER_ALL_MUTATION_IDS),
};

const ops = ['hkdf', 'gcm', 'oaep', 'pss', 'rsa-ser', 'ec-ser'] as const;
let totalRegistry = 0, totalImpl = 0;

console.log('operation | registry | implemented | status');
console.log('----------|----------|-------------|-------');
for (const op of ops) {
  const registryCount = MUTATION_REGISTRY.filter((e) => e.operation === op).length;
  const implCount = IMPLEMENTED_BY_OP[op].size;
  const status = implCount === registryCount ? 'DONE' : 'INCOMPLETE';
  console.log(`${op.padEnd(9)} | ${String(registryCount).padEnd(8)} | ${String(implCount).padEnd(11)} | ${status}`);
  totalRegistry += registryCount; totalImpl += implCount;
}
console.log('----------|----------|-------------|-------');
console.log(`TOTAL     | ${String(totalRegistry).padEnd(8)} | ${String(totalImpl).padEnd(11)} | ${totalImpl}/${totalRegistry} accounted for`);
