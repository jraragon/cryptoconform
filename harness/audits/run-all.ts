// M2.4.2 closure audit: run everything, report pass/fail.
// Criterion (M2.4.2 micro-contract):
//   79 registry entries + 36 applicability cells + 14 portable declarations
//   + 39 provider cells + 9 requirements + 4 frozen hashes + 0 scientific hardcoding
import { auditCardinality } from './cardinality.js';
import { auditUniqueness } from './uniqueness.js';
import { auditHashes } from './hashes.js';
import { auditExecutabilityRederivation } from './executability-rederivation.js';

const allResults = [
  ...auditCardinality(),
  ...auditUniqueness(),
  ...auditHashes(),
  ...auditExecutabilityRederivation(),
];

let failCount = 0;
for (const r of allResults) {
  const mark = r.pass ? 'PASS' : 'FAIL';
  if (!r.pass) failCount++;
  console.log(`[${mark}] ${r.name}  -- ${r.detail}`);
}

console.log('');
console.log(`Total: ${allResults.length} checks, ${allResults.length - failCount} pass, ${failCount} fail.`);
if (failCount > 0) {
  console.log('M2.4.2 closure: NOT YET CLOSED.');
  process.exit(1);
} else {
  console.log('M2.4.2 closure criterion satisfied: 79+36+14+39+9+4 hashes, all audits PASS.');
}
