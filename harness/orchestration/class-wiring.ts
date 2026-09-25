// M3.8.3 -- the missing integration layer.
//
//     frozen fixture  ->  dispatch  ->  adapter
//
// This is the layer M3.7.6 appeared to validate and did not. That gate built
// its plan with a HAND-WRITTEN fixture and two hand-picked adapters, for ONE
// class of an eight-class block, so everything between the frozen corpus and
// the M1 wirings was not exercised by that validation path. This gap
// motivated the explicit class-to-wiring checks below.
//
// It is not convenience. Without it there is no guarantee that the class you
// believe you are executing uses the frozen fixture and the pinned backend
// its scope names.
//
// DELIBERATELY NOT A DRIVER. It resolves; it does not orchestrate, execute,
// aggregate, decide policy or touch the population. One question, one answer:
// for this obligation, which fixture and which adapter.

import type { BackendIdentity } from '../schema/backend-identity.js';
import type { OperationId } from '../schema/capability.js';
import type { BoundObligation } from '../phase-c/execution-binding.js';
import type { FrozenMaterialPool } from '../phase-c/material/pool.js';
import { getFixtureResolver } from '../phase-c/fixture-index.js';
import { getMutationImplementation } from '../phase-c/mutation-index.js';
import { materializeDispatch } from './dispatch-materialization.js';
import { realizeEcSerMaterial, realizeRsaKeyHex, realizeRsaSerMaterial } from '../phase-c/wiring-realization.js';
import { ecArtifactProducerRole } from '../phase-c/fixtures/ec-ser-artifact.js';
import { rsaArtifactProducerRole } from '../phase-c/fixtures/rsa-ser-artifact.js';
import { makeSerializationAdapter } from './serialization-adapter.js';
import { ROLES_BY_OPERATION } from './dispatch.js';
import type { ExecutionAdapter } from './engine.js';

export class ClassWiringError extends Error {}

/* eslint-disable @typescript-eslint/no-explicit-any */

/** What the runner needs for one obligation, and nothing more. */
export type WiringKind = 'operational' | 'declarative';

export interface ClassWiring {
  /**
   * 'declarative' when the class's stimulus is a declaration -- a capability
   * or an error-mapping -- rather than an operational input. Those classes
   * carry no key material and no container, so they have no artifact role to
   * declare and nothing for a backend to execute. Their evidence is the
   * declaration itself, contrasted through R_cap.
   */
  readonly kind: WiringKind;
  readonly mutationId: string;
  readonly operation: OperationId;
  /** The frozen fixture, from the resolver -- never hand-written. */
  readonly baseFixture: unknown;
  /** True when the stimulus carries the operation's own output. */
  readonly artifactSide: boolean;
  readonly adapters: readonly { readonly backend: BackendIdentity; readonly adapter: ExecutionAdapter<any, any> }[];
}

/** The backends an obligation's scope names, in the scope's own order. */
function backendsOf(o: BoundObligation): readonly BackendIdentity[] {
  const s = o.scope as any;
  if (s.kind === 'cross-backend-set') return s.backends as BackendIdentity[];
  if (s.kind === 'backend-pair') return [s.from, s.to] as BackendIdentity[];
  return [s.backend as BackendIdentity];
}

/**
 * The role this obligation's execution needs.
 *
 * A stimulus that CARRIES the operation's output is consumed, not produced: a
 * GCM artifact is decrypted, a signature verified, a container imported.
 */
function roleFor(operation: OperationId, artifactSide: boolean) {
  const roles = ROLES_BY_OPERATION[operation];
  if (roles === undefined || roles.length === 0) throw new ClassWiringError(`No role for '${operation}'.`);
  return artifactSide && roles.length > 1 ? roles[1]! : roles[0]!;
}

/** The artifact role a serialization class's own container declares. */
function serializationRole(o: BoundObligation, fixture: any, pool: FrozenMaterialPool): 'public' | 'private' | undefined {
  if (o.operation !== 'rsa-ser' && o.operation !== 'ec-ser') return undefined;
  try {
    return o.operation === 'rsa-ser'
      ? rsaArtifactProducerRole(o.mutationId, o.stimulusInstanceId, pool)
      : ecArtifactProducerRole(o.mutationId, o.stimulusInstanceId, pool);
  } catch {
    return fixture?.role ?? fixture?.requestedRole;
  }
}

/** Resolves the fixture and every adapter one obligation's scope names. */
export function wireObligation(o: BoundObligation, pool: FrozenMaterialPool): ClassWiring {
  const baseFixture = getFixtureResolver(o.mutationId, o.stimulusInstanceId)(
    o.mutationId, o.stimulusInstanceId, pool);
  const mutated = (getMutationImplementation(o.mutationId) as {
    mutate: (f: unknown, s: string) => unknown;
  }).mutate(baseFixture, o.stimulusInstanceId) as Record<string, unknown>;

  const artifactSide = mutated?.['artifact'] !== undefined
    || mutated?.['signature'] !== undefined
    || mutated?.['ciphertext'] !== undefined;
  const role = roleFor(o.operation, artifactSide);
  const artifactRole = serializationRole(o, mutated, pool);
  const material = (o.binding as { material?: any }).material;

  // A declarative stimulus: no operational input, so no operational route.
  // Detected by SHAPE, not by class name.
  const declarative = mutated?.['capabilityId'] !== undefined
    || mutated?.['declaredErrorClass'] !== undefined
    || mutated?.['adapterReconstructsPubkey'] !== undefined;
  if (declarative) {
    return {
      kind: 'declarative', mutationId: o.mutationId, operation: o.operation,
      baseFixture, artifactSide: false, adapters: [],
    };
  }

  const adapters = backendsOf(o).map((backend) => {
    const dispatch = materializeDispatch(o.operation, backend, role as never);
    const shape = dispatch.entry.shape;

    if (shape === 'execution-adapter') {
      const base = dispatch.wiring as ExecutionAdapter<any, any>;
      if (!artifactSide || material === undefined) return { backend, adapter: base };
      // An artifact-side fixture carries the artifact and NOT the producer's
      // own inputs. The missing ones come from the same nominal frozen
      // material, filled only where the fixture is silent.
      const m = material.value as unknown as Record<string, unknown>;
      return {
        backend,
        adapter: {
          ...base,
          execute: async (f: any) => {
            if (f === null || typeof f !== 'object') return base.execute(f);
            const merged: Record<string, unknown> = { ...(f as object) };
            for (const k of ['key', 'iv', 'aad'] as const) {
              if (merged[k] === undefined && m[k] !== undefined) merged[k] = m[k];
            }
            return base.execute(merged);
          },
        } as ExecutionAdapter<any, any>,
      };
    }

    if (shape === 'execution-adapter-factory') {
      if (material === undefined) {
        throw new ClassWiringError(`${o.mutationId}: ${dispatch.entry.symbol} is a factory and no material is bound.`);
      }
      return { backend, adapter: (dispatch.wiring as (k: unknown) => ExecutionAdapter<any, any>)(realizeRsaKeyHex(material)) };
    }

    if (shape === 'roundtrip-function') {
      if (material === undefined || artifactRole === undefined) {
        throw new ClassWiringError(`${o.mutationId}: serialization needs bound material and an artifact role.`);
      }
      const realized = o.operation === 'rsa-ser'
        ? realizeRsaSerMaterial(material, artifactRole)
        : realizeEcSerMaterial(material, artifactRole);
      // The adapter of 6a33ff5 reads material and artifact from the fixture,
      // so the resolved values are supplied by shaping the fixture it gets --
      // the frozen signature is left alone.
      const base = makeSerializationAdapter(dispatch) as ExecutionAdapter<any, any>;
      return {
        backend,
        adapter: {
          ...base,
          execute: async (f: any) => base.execute({
            artifactRole,
            material: realized,
            ...(f?.artifact instanceof Uint8Array ? { artifactHex: Buffer.from(f.artifact).toString('hex') } : {}),
            ...(typeof f?.artifactHex === 'string' ? { artifactHex: f.artifactHex } : {}),
          }),
        } as ExecutionAdapter<any, any>,
      };
    }

    throw new ClassWiringError(`${o.mutationId}: unknown wiring shape '${String(shape)}'.`);
  });

  return { kind: 'operational', mutationId: o.mutationId, operation: o.operation, baseFixture, artifactSide, adapters };
}

/* eslint-enable @typescript-eslint/no-explicit-any */
