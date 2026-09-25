// M3.8.2 -- the serialization execution adapter, and adapter realization.
//
// M3.8.1 measured the defect: four operations expose wirings the runner can
// already consume, and two do not.
//
//     hkdf, gcm   execution-adapter          usable as-is
//     oaep, pss   execution-adapter-factory  usable once key material is bound
//     rsa-ser     roundtrip-function         NOT an ExecutionAdapter
//     ec-ser      roundtrip-function         NOT an ExecutionAdapter
//
// 666 of the 1246 required obligations -- 53%, across 31 of the 79 classes --
// depend on the two that do not. This module supplies the missing shape and
// nothing else.
//
// --- What it may and may not do -------------------------------------------
//
//     Inputs(Adapter_ser)    ⊆ FrozenState
//     Semantics(Adapter_ser) = Composition(FrozenComponents)
//
// It receives values that are already determined, calls the export/import
// function the frozen dispatch already named, and converts the return through
// the transformation M3.5 already validated. It contains no chooseRole,
// chooseMaterial, chooseEncoding, chooseProducer or chooseDirection, because
// every one of those questions has a frozen answer elsewhere.
//
// --- The one seam, declared ----------------------------------------------
//
// ExecutionAdapter.execute takes ONE argument, and the serialization wirings
// have different arities: export(material) and import(role, artifactHex). So
// TFixture_ser packages the already-resolved values into one object.
//
// THE DISPATCH ROLE IS THE AUTHORITY. The branch is chosen by
// entry.role -- which the frozen table assigned -- and never by a field of
// the fixture. The fixture's own role is the ARTIFACT's role, carried because
// import needs it as an argument; the two are named apart precisely so they
// cannot be confused:
//
//     entry.role          export | import   -- which call to make
//     fixture.artifactRole public | private -- what the container holds

import { makeMutationExecution } from '../evidence/execution-evidence.js';
import type { ExecutionEvidence } from '../evidence/execution-evidence.js';
import type { ExecutionAdapter } from './engine.js';
import type { MaterializedDispatch } from './dispatch-materialization.js';
import type { BoundMaterial } from '../phase-c/execution-binding.js';
import {
  realizeEcSerMaterial,
  realizeMutatedEcSerMaterial,
  realizeGcmDecryptRequest,
  realizePssVerifyRequest,
  realizeRsaKeyHex,
  realizeRsaSerMaterial,
  realizeMutatedRsaSerMaterial,
} from '../phase-c/wiring-realization.js';

export class SerializationAdapterError extends Error {}

/** Everything an export or an import needs, all of it already resolved. */
export interface SerializationFixture {
  /** The actual role of the frozen ARTIFACT/container. */
  readonly artifactRole: 'public' | 'private';
  /**
   * Role requested from an import operation. Normally equal to artifactRole;
   * role-container mutations deliberately make the two differ.
   */
  readonly requestedRole?: 'public' | 'private';
  /** The realized frozen key material. */
  readonly material: unknown;
  /** Present for an import: the artifact to consume. */
  readonly artifactHex?: string;
}

/** Whatever the M1 wiring returned, carried verbatim. */
export type SerializationRecord = Readonly<Record<string, unknown>>;

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Wraps a frozen export/import function in the ExecutionAdapter contract.
 *
 * `operation`, `backend` and the call branch all come from the dispatch entry.
 * The evidence fields are the seven wrapSerializationExecution already builds,
 * and nativeObservation carries the M1 return UNNORMALISED -- RSA-ser and
 * EC-ser return different shapes, and deciding that two heterogeneous
 * observations mean the same thing is the projector's job, not this one's.
 */
export function makeSerializationAdapter(
  dispatch: MaterializedDispatch,
): ExecutionAdapter<SerializationFixture, SerializationRecord> {
  const { entry, wiring } = dispatch;
  if (entry.shape !== 'roundtrip-function') {
    throw new SerializationAdapterError(
      `${entry.symbol} is a '${entry.shape}', not a roundtrip function; it needs no serialization adapter.`,
    );
  }
  if (typeof wiring !== 'function') {
    throw new SerializationAdapterError(`${entry.symbol} did not materialize to a callable.`);
  }
  const call = wiring as (...args: unknown[]) => Promise<SerializationRecord>;

  return {
    operation: entry.operation,
    backend: entry.backend,
    execute: async (fixture: SerializationFixture) => {
      // The BRANCH is entry.role -- the frozen dispatch's own decision --
      // never fixture.artifactRole, which is data about the container.
      if (entry.role === 'export') {
        return call(fixture.material);
      }
      if (entry.role === 'import') {
        if (fixture.artifactHex === undefined) {
          throw new SerializationAdapterError(
            `${entry.symbol}: an import needs the artifact to consume, and none was supplied. Refusing rather ` +
            'than importing something else.',
          );
        }
        const importRole = fixture.requestedRole ?? fixture.artifactRole;
        return call(importRole, fixture.artifactHex, fixture.material);
      }
      throw new SerializationAdapterError(`Role '${entry.role}' is not a serialization call.`);
    },
    toEvidenceFields: (_fixture: SerializationFixture, record: SerializationRecord) => {
      const r = record as any;
      const ok = entry.role === 'export' ? r.exportOk === true : r.importOk === true;
      const artifactHex = typeof r.artifactHex === 'string' ? r.artifactHex : undefined;
      const detail = typeof r.errorClass === 'string' ? r.errorClass
        : typeof r.exportError === 'string' ? r.exportError
          : typeof r.errorMessage === 'string' ? r.errorMessage : undefined;
      return {
        subject: { backend: entry.backend, direction: entry.role, path: 'native' },
        input: { kind: `${entry.operation}-${entry.role}` },
        ...(artifactHex === undefined ? {} : { output: { kind: 'canonical-serialization', bytes: artifactHex } }),
        outcome: ok
          ? { kind: 'accept' as const }
          : { kind: 'reject' as const, ...(detail === undefined ? {} : { detail }) },
        clauseIdsEvaluated: [],
        // Verbatim. Two operations return different shapes and that is theirs
        // to mean, not this adapter's to reconcile.
        nativeObservation: { nativeReturnCode: JSON.stringify(record) },
        executionStatus: 'completed' as const,
      };
    },
  } as unknown as ExecutionAdapter<SerializationFixture, SerializationRecord>;
}

/**
 * The single place that turns a materialized dispatch entry into something
 * the runner can drive, whichever of the three shapes it is.
 *
 * Composition only: every branch calls a frozen constructor with frozen
 * inputs. The driver never sees a shape and never chooses one.
 */
export function realizeAdapter(params: {
  readonly dispatch: MaterializedDispatch;
  readonly material?: BoundMaterial;
  readonly artifactRole?: 'public' | 'private';
  readonly fixtureRealization?:
    | 'gcm-artifact-decrypt'
    | 'oaep-key-role-request'
    | 'pss-key-role-request'
    | 'pss-artifact-verify'
    | 'serialization-artifact-import'
    | 'rsa-material-export'
    | 'ec-material-export';
}): ExecutionAdapter<unknown, unknown> {
  const { dispatch, material, artifactRole, fixtureRealization } = params;
  switch (dispatch.entry.shape) {
    case 'execution-adapter': {
      const underlying =
        dispatch.wiring as ExecutionAdapter<unknown, unknown>;

      if (fixtureRealization === 'gcm-artifact-decrypt') {
        if (dispatch.entry.operation !== 'gcm' || dispatch.entry.role !== 'decrypt') {
          throw new SerializationAdapterError(
            `Fixture realization 'gcm-artifact-decrypt' requires a gcm/decrypt dispatch; got ` +
            `${dispatch.entry.operation}/${dispatch.entry.role}.`,
          );
        }
        if (material === undefined) {
          throw new SerializationAdapterError(
            `${dispatch.entry.symbol}: GCM artifact-side decrypt requires bound AES material.`,
          );
        }

        const realizeFixture = (fixture: unknown) =>
          realizeGcmDecryptRequest(material, fixture);

        return {
          operation: underlying.operation,
          backend: underlying.backend,
          execute: (fixture: unknown) =>
            underlying.execute(realizeFixture(fixture)),
          toEvidenceFields: (fixture: unknown, record: unknown) =>
            underlying.toEvidenceFields(realizeFixture(fixture), record),
        } as ExecutionAdapter<unknown, unknown>;
      }

      return underlying;
    }

    case 'execution-adapter-factory': {
      if (material === undefined) {
        throw new SerializationAdapterError(
          `${dispatch.entry.symbol} is a factory and needs bound key material; none was supplied.`,
        );
      }
      const factory = dispatch.wiring as (key: unknown) => ExecutionAdapter<unknown, unknown>;
      const underlying = factory(realizeRsaKeyHex(material));

      if (fixtureRealization === 'pss-artifact-verify') {
        if (dispatch.entry.operation !== 'pss' || dispatch.entry.role !== 'verify') {
          throw new SerializationAdapterError(
            `Fixture realization 'pss-artifact-verify' requires pss/verify; got `
            + `${dispatch.entry.operation}/${dispatch.entry.role}.`,
          );
        }

        const realizeFixture = (fixture: unknown) =>
          realizePssVerifyRequest(material, fixture);

        return {
          operation: underlying.operation,
          backend: underlying.backend,
          execute: (fixture: unknown) =>
            underlying.execute(realizeFixture(fixture)),
          toEvidenceFields: (fixture: unknown, record: unknown) =>
            underlying.toEvidenceFields(realizeFixture(fixture), record),
        } as ExecutionAdapter<unknown, unknown>;
      }

      if (
        fixtureRealization === 'oaep-key-role-request'
        || fixtureRealization === 'pss-key-role-request'
      ) {
        const expectedOperation =
          fixtureRealization === 'oaep-key-role-request' ? 'oaep' : 'pss';

        if (dispatch.entry.operation !== expectedOperation) {
          throw new SerializationAdapterError(
            `Fixture realization '${fixtureRealization}' requires ${expectedOperation}; got ${dispatch.entry.operation}.`,
          );
        }

        const realizeFixture = (fixture: unknown): unknown => {
          if (
            fixture === null ||
            typeof fixture !== 'object' ||
            !('request' in fixture)
          ) {
            throw new SerializationAdapterError(
              `${dispatch.entry.symbol}: ${expectedOperation.toUpperCase()} key-role stimulus must carry its request envelope.`,
            );
          }
          return (fixture as { request: unknown }).request;
        };

        return {
          operation: underlying.operation,
          backend: underlying.backend,
          execute: (fixture: unknown) =>
            underlying.execute(realizeFixture(fixture)),
          toEvidenceFields: (fixture: unknown, record: unknown) =>
            underlying.toEvidenceFields(realizeFixture(fixture), record),
        } as ExecutionAdapter<unknown, unknown>;
      }

      return underlying;
    }

    case 'roundtrip-function': {
      const underlying =
        makeSerializationAdapter(dispatch) as unknown as ExecutionAdapter<
          SerializationFixture,
          SerializationRecord
        >;

      if (fixtureRealization === 'ec-material-export') {
        if (
          dispatch.entry.operation !== 'ec-ser'
          || dispatch.entry.role !== 'export'
        ) {
          throw new SerializationAdapterError(
            `Fixture realization 'ec-material-export' requires ec-ser/export; got `
            + `${dispatch.entry.operation}/${dispatch.entry.role}.`,
          );
        }

        const realizeFixture = (fixture: unknown): SerializationFixture => {
          // Two already-frozen EC export input shapes legitimately reach this
          // realization:
          //
          // 1. single-backend material-side mutation:
          //      { role, q: { x, y }, d? }
          //
          // 2. artifact-side R_interop producerInputFor():
          //      { role, xHex, yHex, dHex? }
          //
          // The latter is already realized and must only be packaged into the
          // SerializationFixture expected by makeSerializationAdapter.
          const f =
            fixture !== null && typeof fixture === 'object'
              ? fixture as {
                  role?: unknown;
                  xHex?: unknown;
                  yHex?: unknown;
                  dHex?: unknown;
                }
              : undefined;

          const alreadyRealized =
            f !== undefined
            && (f.role === 'public' || f.role === 'private')
            && typeof f.xHex === 'string'
            && typeof f.yHex === 'string'
            && (f.role === 'public' || typeof f.dHex === 'string');

          const exportMaterial = alreadyRealized
            ? fixture as {
                role: 'public' | 'private';
                xHex: string;
                yHex: string;
                dHex?: string;
              }
            : realizeMutatedEcSerMaterial(fixture);

          return {
            artifactRole: exportMaterial.role,
            material: exportMaterial,
          };
        };

        return {
          operation: underlying.operation,
          backend: underlying.backend,
          execute: (fixture: unknown) =>
            underlying.execute(realizeFixture(fixture)),
          toEvidenceFields: (fixture: unknown, record: unknown) =>
            underlying.toEvidenceFields(
              realizeFixture(fixture),
              record as SerializationRecord,
            ),
        } as ExecutionAdapter<unknown, unknown>;
      }

      if (fixtureRealization === 'rsa-material-export') {
        if (
          dispatch.entry.operation !== 'rsa-ser'
          || dispatch.entry.role !== 'export'
        ) {
          throw new SerializationAdapterError(
            `Fixture realization 'rsa-material-export' requires rsa-ser/export; got `
            + `${dispatch.entry.operation}/${dispatch.entry.role}.`,
          );
        }

        const realizeFixture = (fixture: unknown): SerializationFixture => {
          if (fixture === null || typeof fixture !== 'object') {
            throw new SerializationAdapterError(
              `${dispatch.entry.symbol}: RSA export fixture is not an object.`,
            );
          }

          const f = fixture as Record<string, unknown>;

          const exportMaterial =
            (f.role === 'public' || f.role === 'private')
            && typeof f.nHex === 'string'
            && typeof f.eHex === 'string'
              ? fixture
              : realizeMutatedRsaSerMaterial(fixture);

          const materialWithRole = exportMaterial as {
            role: 'public' | 'private';
          };

          return {
            artifactRole: materialWithRole.role,
            material: exportMaterial,
          };
        };

        return {
          operation: underlying.operation,
          backend: underlying.backend,
          execute: (fixture: unknown) =>
            underlying.execute(realizeFixture(fixture)),
          toEvidenceFields: (fixture: unknown, record: unknown) =>
            underlying.toEvidenceFields(
              realizeFixture(fixture),
              record as SerializationRecord,
            ),
        } as ExecutionAdapter<unknown, unknown>;
      }

      if (fixtureRealization !== 'serialization-artifact-import') {
        return underlying as unknown as ExecutionAdapter<unknown, unknown>;
      }

      if (
        (dispatch.entry.operation !== 'rsa-ser'
          && dispatch.entry.operation !== 'ec-ser')
        || dispatch.entry.role !== 'import'
      ) {
        throw new SerializationAdapterError(
          `Fixture realization 'serialization-artifact-import' requires an `
          + `rsa-ser/ec-ser import dispatch; got `
          + `${dispatch.entry.operation}/${dispatch.entry.role}.`,
        );
      }

      if (material === undefined) {
        throw new SerializationAdapterError(
          `${dispatch.entry.symbol}: serialization import requires bound key material.`,
        );
      }

      if (artifactRole === undefined) {
        throw new SerializationAdapterError(
          `${dispatch.entry.symbol}: serialization import requires the frozen artifact role.`,
        );
      }

      const realizedMaterial =
        dispatch.entry.operation === 'rsa-ser'
          ? realizeRsaSerMaterial(material, artifactRole)
          : realizeEcSerMaterial(material, artifactRole);

      const realizeFixture = (fixture: unknown): SerializationFixture => {
        if (fixture === null || typeof fixture !== 'object') {
          throw new SerializationAdapterError(
            `${dispatch.entry.symbol}: serialization import fixture is not an object.`,
          );
        }

        const f = fixture as {
          artifact?: unknown;
          artifactHex?: unknown;
          requestedRole?: unknown;
          expectedMaterial?: unknown;
        };

        const artifactHex =
          f.artifact instanceof Uint8Array
            ? Buffer.from(f.artifact).toString('hex')
            : typeof f.artifactHex === 'string'
              ? f.artifactHex
              : undefined;

        if (artifactHex === undefined) {
          throw new SerializationAdapterError(
            `${dispatch.entry.symbol}: serialization import fixture carries no artifact.`,
          );
        }

        const requestedRole =
          f.requestedRole === 'public' || f.requestedRole === 'private'
            ? f.requestedRole
            : undefined;

        return {
          artifactRole,
          ...(requestedRole === undefined ? {} : { requestedRole }),
          material: f.expectedMaterial ?? realizedMaterial,
          artifactHex,
        };
      };

      return {
        operation: underlying.operation,
        backend: underlying.backend,
        execute: (fixture: unknown) =>
          underlying.execute(realizeFixture(fixture)),
        toEvidenceFields: (fixture: unknown, record: unknown) =>
          underlying.toEvidenceFields(
            realizeFixture(fixture),
            record as SerializationRecord,
          ),
      } as ExecutionAdapter<unknown, unknown>;
    }

    default:
      throw new SerializationAdapterError(`Unknown wiring shape '${String(dispatch.entry.shape)}'.`);
  }
}

/** The serialization fixture, assembled from frozen values only. */
export function serializationFixture(params: {
  readonly operation: 'rsa-ser' | 'ec-ser';
  readonly material: BoundMaterial;
  readonly artifactRole: 'public' | 'private';
  readonly requestedRole?: 'public' | 'private';
  readonly artifactHex?: string;
}): SerializationFixture {
  const material = params.operation === 'rsa-ser'
    ? realizeRsaSerMaterial(params.material, params.artifactRole)
    : realizeEcSerMaterial(params.material, params.artifactRole);
  return {
    artifactRole: params.artifactRole,
    ...(params.requestedRole === undefined
      ? {}
      : { requestedRole: params.requestedRole }),
    material,
    ...(params.artifactHex === undefined ? {} : { artifactHex: params.artifactHex }),
  };
}

/* eslint-enable @typescript-eslint/no-explicit-any */

export type { ExecutionEvidence, MaterializedDispatch };
export { makeMutationExecution };
