import type { ClauseId } from './clause-ids.js';
import { SdkContractError, type SdkErrorClass } from './errors.js';

/**
 * Single point of contact between a frozen v0.6 ClauseId and a runtime
 * obligation. Every precondition enforced by an adapter MUST go through
 * this function -- see Experimental_Evidence_Base v0.1, sec:contract-traceability.
 *
 * `id` is a compile-time-checked literal from the operation's ClauseId union,
 * so a typo or a reference to a clause that does not exist in v0.6 is a
 * TypeScript error, not a silent runtime gap.
 */
export function checkClause(
  id: ClauseId,
  condition: boolean,
  errorClass: SdkErrorClass,
  detail: string,
): void {
  if (!condition) {
    throw new SdkContractError(errorClass, [id], detail);
  }
}
