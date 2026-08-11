/**
 * Gurdy — provenance enrichment for governed agent traffic.
 *
 * What this package is (§5.9, ADR-9): the on-ramp. It marks the task boundary,
 * obtains a transaction credential from the *local* TIS, and stamps it on calls
 * that go to the proxy. That is all.
 *
 * What it is not, and cannot become:
 *
 * - **Not an enforcement point.** The proxy is the authority. Nothing here
 *   decides, blocks, or delays anything.
 * - **Not a holder of signing keys.** It asks the local TIS for tokens; it cannot
 *   make one, and it cannot write a ledger entry.
 * - **Not a second implementation of anything.** The scope algebra, the policy
 *   engine and the ledger live in the Go core. Where this package needs an answer
 *   it asks and reports; a TypeScript copy of a security rule is a copy that will
 *   drift.
 *
 * Everything it supplies is recorded as **asserted** identity — the agent's own
 * claim about itself. The proxy records what it *observed* separately, and that is
 * what policy evaluates on, so an agent cannot pick the identity it is authorized
 * as. The one thing this package must therefore never do is fabricate a claim
 * nobody made: outside a task context a call goes out unenriched, and the record
 * says attested-coarse instead of naming an agent that was not there.
 *
 * Node-only: it uses `node:async_hooks` and an AF_UNIX socket.
 */

export { configure } from './config.js';

export {
  TXN_HEADER,
  adopt,
  bind,
  carrier,
  current,
  detached,
  headers,
  using,
} from './context.js';
export type { Binding, Carrier } from './context.js';

export {
  GurdyError,
  NotConfigured,
  ScopeNarrowingRefused,
  TISUnavailable,
} from './errors.js';

export { WILDCARD_SCOPE } from './tis.js';
export type { Scope } from './tis.js';

export { derive, spawn, startTask, task } from './task.js';
export type { SpawnOptions, TaskOptions } from './task.js';

export { gurdyFetch as fetch, instrumentGlobalFetch, restoreGlobalFetch } from './fetch.js';
