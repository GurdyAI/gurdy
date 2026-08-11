/**
 * The execution-context binding, and the rules for how far it travels.
 *
 * One `AsyncLocalStorage` holds the credential for the task currently running.
 * That is what makes `await`, `.then`, `queueMicrotask`, `process.nextTick` and
 * timers scheduled inside a task work for free, and it is also what makes a
 * `worker_thread` see nothing at all — which is the behaviour we want, because a
 * worker that inherited whatever its creator was doing would stamp one task's
 * identity onto another task's calls.
 *
 * Node has one failure mode Python does not, and it is the dangerous kind. A
 * callback registered inside a task but *invoked* from elsewhere — an
 * `EventEmitter` listener, a stream handler — runs in the context of whoever
 * called `emit()`, not the context it was registered in. So it does not lose the
 * binding, it acquires **someone else's**. {@link bind} exists for that: bind at
 * registration, and the callback carries the context it was written in.
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import { isGoverned } from './config.js';

export const TXN_HEADER = 'Gurdy-Txn';

/**
 * A credential and the claim it carries.
 *
 * Everything here is *asserted* — the agent's own account of itself (§5.2). The
 * proxy records its own observed principal alongside, and that is what policy
 * evaluates on, which is why the SDK accepting these values from the caller
 * unchecked is sound: an agent cannot select the identity it is authorized as.
 *
 * There is no `lineage` field. The chain lives inside the token, the proxy reads
 * it from there, and a copy held on this side could only ever disagree with the
 * signed one.
 */
export interface Binding {
  readonly txn: string;
  readonly agent: string;
  readonly humanActor: string;
}

const storage = new AsyncLocalStorage<Binding | undefined>();

/**
 * Whether a token can be used as a header value at all.
 *
 * `readonly` in TypeScript is a compile-time promise and nothing more, and a
 * carrier arrives from another isolate as plain data, so both the token's *type*
 * and its *shape* have to be checked where they enter. Two failures this
 * prevents, both of which reach the developer rather than us: a whitespace-only
 * token becomes an empty header — an assertion nobody made — and a token
 * containing CR or LF makes `Headers.set` throw at the call site, turning
 * enrichment into an outage.
 */
export function usableToken(txn: unknown): txn is string {
  return typeof txn === 'string' && txn.trim() === txn && txn !== '' && !/[\r\n\0]/.test(txn);
}

/**
 * A frozen copy, so nothing that captured this binding can have it changed
 * underneath.
 *
 * `using(b)` stores the caller's object and `bind()` captures that same
 * reference; a later `b.txn = other` would retroactively re-label every call
 * made under it. TypeScript cannot stop that — `readonly` disappears at runtime —
 * so the value is copied and frozen on the way in.
 */
function seal(binding: Binding): Binding {
  return Object.freeze({
    txn: binding.txn,
    agent: binding.agent,
    humanActor: binding.humanActor,
  });
}

/** The binding in effect here, or `undefined` outside any task context. */
export function current(): Binding | undefined {
  return storage.getStore();
}

/**
 * Run `fn` under `binding`.
 *
 * The counterpart to obtaining a credential without activating it: a spawn
 * helper hands back a binding, and the code that actually runs as that
 * sub-agent enters it here. The store is restored when `fn` settles, including
 * on rejection, so a failing sub-agent cannot leak its identity onto the
 * parent's subsequent calls.
 */
export function using<T>(binding: Binding, fn: () => T): T {
  return storage.run(seal(binding), fn);
}

/**
 * Run `fn` with no task context, so calls inside it go out unenriched.
 *
 * Not a workaround — a real need. Work that is genuinely not part of the task
 * (a health check, a metrics push) should not be recorded as though the task
 * performed it, and the honest way to say so is to say so.
 */
export function detached<T>(fn: () => T): T {
  return storage.run(undefined, fn);
}

/**
 * Headers to attach to a call to `url`.
 *
 * Empty when there is no task context. That is the whole of the "does not
 * fabricate" rule (§5.9): outside a task there is no claim to make, and
 * inventing one would put an assertion nobody made into evidence a third party
 * is meant to be able to trust.
 */
export function headers(url: string): Record<string, string> {
  const binding = current();
  if (!binding || !isGoverned(url)) return {};
  return { [TXN_HEADER]: binding.txn };
}

/**
 * Wrap `fn` so it runs under the binding in effect *now*.
 *
 * Capture happens when `bind` is called, which is the point: a listener bound at
 * registration keeps the context it was written in, rather than borrowing
 * whoever happens to call `emit()` later.
 *
 * Only the Gurdy binding travels, not the whole async context. That keeps the
 * blast radius to this library rather than silently teleporting some other
 * package's context into a callback, and unlike `AsyncResource.bind` it does not
 * hold a resource open for the lifetime of the listener.
 */
export function bind<A extends unknown[], R>(fn: (...args: A) => R): (...args: A) => R {
  const binding = current();
  return (...args: A): R =>
    binding === undefined
      ? // Explicitly *clear* rather than run in whatever context the caller
        // happens to be in. A callback written outside any task must not pick
        // up the identity of the code that ends up invoking it.
        detached(() => fn(...args))
      : using(binding, () => fn(...args));
}

// --- crossing a boundary AsyncLocalStorage cannot ---------------------------

/**
 * A serialisable snapshot of a binding, for a boundary that shares no memory.
 *
 * The same shape as {@link Binding} — a plain object of three strings, which
 * `postMessage` and IPC both carry as-is. Named separately because the *rules*
 * differ: a carrier crosses a trust and type boundary, so {@link adopt}
 * revalidates it rather than believing its declared type.
 */
export type Carrier = Binding;

/**
 * A snapshot of the current binding, or `undefined`.
 *
 * For `worker_threads`, child processes, and anything else with its own isolate.
 * A worker thread is closer to Python's *process* case than its thread case:
 * there is no shared store to inherit, so nothing propagates implicitly and
 * nothing should pretend to. A worker that receives nothing runs unenriched,
 * which the export shows as an attested-coarse principal rather than as somebody
 * else's identity.
 *
 * The token inside is a live bearer credential for the whole transaction — treat
 * a carrier as the secret it is, and do not log it.
 */
export function carrier(): Carrier | undefined {
  return current();
}

/**
 * Re-enter the context described by {@link carrier} on the other side.
 *
 * An absent carrier is not an error: it means the parent had no task context
 * either, and the correct result is an unenriched worker rather than a
 * fabricated one.
 *
 * A long-lived worker serving many tasks should call this **per message**, not
 * once at startup. Adopting once and leaving the store set would attribute
 * every later message to the first task that happened to reach the worker.
 */
export function adopt<T>(carried: Carrier | undefined, fn: () => T): T {
  // Revalidated, not trusted. A carrier arrives from another isolate as plain
  // data whose declared type proves nothing, and an unusable token would either
  // stamp a claim nobody made (`{ txn: null }` → the header "null") or throw
  // inside the caller's HTTP client. A malformed carrier therefore runs the
  // callback *detached*: unenriched is a reading, and neither of the others is.
  if (!carried || !usableToken(carried.txn)) return detached(fn);
  return using(
    {
      txn: carried.txn,
      agent: typeof carried.agent === 'string' ? carried.agent : '',
      humanActor: typeof carried.humanActor === 'string' ? carried.humanActor : '',
    },
    fn,
  );
}
