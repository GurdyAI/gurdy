/** Marking the task boundary, and spawning sub-agents under it. */

import * as config from './config.js';
import { Binding, current, detached, using } from './context.js';
import { NotConfigured, TISUnavailable } from './errors.js';
import { Scope, derive as tisDerive, mint as tisMint } from './tis.js';

export interface TaskOptions {
  agent: string;
  humanActor?: string;
  scope?: Scope;
  ttlSeconds?: number;
}

export interface SpawnOptions {
  agent: string;
  scope?: Scope;
}

function socket(): string {
  const path = config.current().tisSocket;
  if (!path) {
    throw new NotConfigured(
      `no TIS socket configured — set ${config.ENV_TIS_SOCKET} or call ` +
        `gurdy.configure({ tisSocket }). Refusing to run a task that cannot ` +
        `obtain a credential, because silently enriching nothing looks ` +
        `identical to being instrumented.`,
    );
  }
  return path;
}

let warned = false;

/**
 * Say once, loudly, that provenance is being lost — and keep going.
 *
 * Once rather than per call: an outage affects every task, and a warning per
 * call would bury the log of the very application we are asking people to trust
 * us inside. The authoritative signal is in the export anyway — the proxy
 * records these calls as attested-coarse, and a run with no asserted identity is
 * visible to the reporter.
 */
function warnDegraded(err: unknown): void {
  if (warned) return;
  warned = true;
  const reason = err instanceof Error ? err.message : String(err);
  console.warn(
    `gurdy: TIS unavailable (${reason}) — calls will be recorded with the ` +
      `principal the proxy observes, without asserted identity. Traffic is unaffected.`,
  );
}

/** @internal reset the warn-once latch (tests). */
export function resetWarned(): void {
  warned = false;
}

/**
 * Obtain a root transaction credential *without* activating it.
 *
 * The handle form. Use it when the code that runs as this task is somewhere
 * other than the enclosing callback — a worker, a listener, a framework's queue.
 * {@link task} is this plus {@link using}.
 */
export async function startTask(opts: TaskOptions): Promise<Binding> {
  const txn = await tisMint(socket(), {
    agent: opts.agent,
    ...(opts.humanActor === undefined ? {} : { humanActor: opts.humanActor }),
    ...(opts.scope === undefined ? {} : { scope: opts.scope }),
    ...(opts.ttlSeconds === undefined ? {} : { ttlSeconds: opts.ttlSeconds }),
  });
  return { txn, agent: opts.agent, humanActor: opts.humanActor ?? '' };
}

/**
 * Obtain a sub-agent credential from `parent`, eagerly.
 *
 * Eagerly, and not at the child's first governed call, because the refusal has
 * to land on the line that asked for too much scope. A lazy derive surfaces a
 * 422 somewhere in the middle of the child's work, where agent frameworks
 * routinely retry and then continue with a different tool — and a child that
 * continues after a refused derive is a child running with no credential.
 *
 * Rejects with {@link ScopeNarrowingRefused} when the requested scope is not
 * provably a narrowing of the parent's. Never clamps, and never falls back to
 * the parent's token: the child's calls would then be recorded under the
 * parent's identity, which is a false lineage rather than a missing one.
 */
export async function derive(parent: Binding, opts: SpawnOptions): Promise<Binding> {
  const txn = await tisDerive(socket(), {
    parent: parent.txn,
    agent: opts.agent,
    ...(opts.scope === undefined ? {} : { scope: opts.scope }),
  });
  // humanActor is inherited: the person on whose authority the whole
  // transaction runs does not change because a sub-agent was spawned, and the
  // proxy reads it from the token chain regardless.
  return { txn, agent: opts.agent, humanActor: parent.humanActor };
}

/**
 * Acquire a credential and run `fn` under it, degrading if the TIS is down.
 *
 * The SDK enriches; it does not gate. A transient outage must not stop the
 * developer's work — the proxy still sees the traffic and still records an
 * attested-coarse principal, so degrading costs a claim where throwing costs the
 * request.
 *
 * Degrading to *no* binding and never to a neighbouring one: for a spawn, running
 * the child under its parent's credential would record the child's actions as the
 * parent's, and a false lineage is worse than a missing one.
 */
async function runAcquired<T>(
  acquire: () => Promise<Binding>,
  fn: () => T | Promise<T>,
): Promise<T> {
  let binding: Binding;
  try {
    binding = await acquire();
  } catch (err) {
    if (err instanceof TISUnavailable) {
      warnDegraded(err);
      return detached(fn);
    }
    throw err;
  }
  return using(binding, fn);
}

/**
 * Mark the task boundary: obtain a credential and bind it to this async context.
 *
 * ```ts
 * await gurdy.task({ agent: 'orchestrator', humanActor: 'alice@example.com' }, async () => {
 *   await client.post(...);          // enriched automatically
 * });
 * ```
 *
 * A callback rather than a decorator or `await using`. `AsyncLocalStorage` is
 * callback-scoped, so this is the shape with no way to leave a store installed
 * after the block it belongs to — and both alternatives have one. Marked once,
 * at the entry point; everything `await`ed inside inherits it (§5.9).
 */
export function task<T>(opts: TaskOptions, fn: () => T | Promise<T>): Promise<T> {
  return runAcquired(() => startTask(opts), fn);
}

/**
 * Run `fn` as a sub-agent of the current task.
 *
 * Derives before `fn` is called, so a scope that is not a narrowing rejects
 * without the body ever running.
 */
export function spawn<T>(opts: SpawnOptions, fn: () => T | Promise<T>): Promise<T> {
  return runAcquired(() => {
    const parent = current();
    if (!parent) {
      return Promise.reject(
        new NotConfigured(
          'gurdy.spawn() outside a task context: there is no parent credential ' +
            'to derive from. Mark the task boundary with gurdy.task() first, or ' +
            'make the call unenriched on purpose.',
        ),
      );
    }
    return derive(parent, opts);
  }, fn);
}
