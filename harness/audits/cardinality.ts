// M2.4.2 closure audit: cardinality checks only. No behavior under test.
import { MUTATION_REGISTRY } from '../registry/mutations.js';
import { APPLICABILITY_MATRIX } from '../applicability/matrix.js';
import { STIMULUS_CAPABILITY_REQUIREMENTS } from '../requirements/stimulus-requirements.js';
import { PORTABLE_DECLARATIONS } from '../../manifests/portable/profile.js';
import { CHROMIUM_DECLARATIONS } from '../../manifests/providers/chromium.js';
import { CRYPTOPP_DECLARATIONS } from '../../manifests/providers/cryptopp.js';
import { BC_DECLARATIONS } from '../../manifests/providers/bc.js';

export interface AuditResult {
  readonly name: string;
  readonly pass: boolean;
  readonly detail: string;
}

export function auditCardinality(): AuditResult[] {
  const results: AuditResult[] = [];

  const byOp: Record<string, number> = {};
  for (const e of MUTATION_REGISTRY) byOp[e.operation] = (byOp[e.operation] ?? 0) + 1;
  const expectedByOp = { hkdf: 8, gcm: 13, oaep: 12, pss: 15, 'rsa-ser': 17, 'ec-ser': 14 };
  const opBreakdownOk = Object.entries(expectedByOp).every(([op, n]) => byOp[op] === n);

  results.push({
    name: '79 mutation registry entries',
    pass: MUTATION_REGISTRY.length === 79 && opBreakdownOk,
    detail: `total=${MUTATION_REGISTRY.length}, byOp=${JSON.stringify(byOp)}`,
  });

  const applicabilityCells = Object.values(APPLICABILITY_MATRIX)
    .reduce((n, row) => n + Object.keys(row).length, 0);
  results.push({
    name: '36 applicability cells (6 ops x 6 relations)',
    pass: Object.keys(APPLICABILITY_MATRIX).length === 6 && applicabilityCells === 36,
    detail: `ops=${Object.keys(APPLICABILITY_MATRIX).length}, cells=${applicabilityCells}`,
  });

  results.push({
    name: '14 portable declarations (11 portable-boundary + 3 interface-exposure)',
    pass: PORTABLE_DECLARATIONS.length === 14
      && PORTABLE_DECLARATIONS.filter((d) => d.kind === 'portable-boundary').length === 11
      && PORTABLE_DECLARATIONS.filter((d) => d.kind === 'interface-exposure').length === 3,
    detail: `total=${PORTABLE_DECLARATIONS.length}`,
  });

  const providerSets = { chromium: CHROMIUM_DECLARATIONS, cryptopp: CRYPTOPP_DECLARATIONS, bc: BC_DECLARATIONS };
  const providerCounts = Object.fromEntries(Object.entries(providerSets).map(([k, v]) => [k, v.length]));
  const totalProviderCells = Object.values(providerCounts).reduce((a, b) => a + b, 0);
  results.push({
    name: '13 x 3 = 39 provider manifest cells',
    pass: Object.values(providerCounts).every((n) => n === 13) && totalProviderCells === 39,
    detail: `counts=${JSON.stringify(providerCounts)}, total=${totalProviderCells}`,
  });

  results.push({
    name: '9 StimulusCapabilityRequirement (6 base + 3 GCM per-instance)',
    pass: STIMULUS_CAPABILITY_REQUIREMENTS.length === 9,
    detail: `total=${STIMULUS_CAPABILITY_REQUIREMENTS.length}`,
  });

  return results;
}
