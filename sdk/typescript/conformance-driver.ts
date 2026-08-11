#!/usr/bin/env node
/**
 * Conformance driver for the TypeScript SDK.
 *
 * Reads a case on stdin, executes its steps through the SDK's *public surface*,
 * writes a transcript to stdout. See `conformance/README.md` for the contract.
 *
 * The rule that shapes this file: it must not re-implement the wire protocol. A
 * driver that posts to `/mint` itself and sets `Gurdy-Txn` by hand would prove
 * the protocol works — which the built-in reference driver already proves — and
 * would say nothing about the SDK. So every step here goes through the surface a
 * developer would use, and the only thing this file contributes is the mapping
 * from a declarative case to those calls.
 */

import { fork } from 'node:child_process';
import { Worker } from 'node:worker_threads';
import { on } from 'node:events';
import * as gurdy from './src/index.js';
import type { Binding } from './src/index.js';

const WORKER = new URL('./conformance-worker.js', import.meta.url);

interface StepResult {
  index: number;
  refused?: boolean;
  reason?: string;
}

function bodyFor(step: Record<string, any>): string {
  // Absent *or* empty: the runner hands the driver a re-marshalled case, so
  // unset string fields arrive as "" rather than missing. Testing for
  // `undefined` sends an empty body, which the proxy correctly declines to
  // record as a tool call — a silent pass-through that looks exactly like a
  // broken SDK.
  return (
    step['body'] ||
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: step['tool'] ?? '', arguments: step['args'] ?? {} },
    })
  );
}

/** The payload a worker or child needs: a resolved target and the credential. */
function jobFor(step: Record<string, any>, proxyUrl: string, tisSocket: string): Job {
  return {
    carrier: gurdy.carrier(),
    url: proxyUrl + (step['path'] || '/'),
    body: bodyFor(step),
    proxyUrl,
    tisSocket,
  };
}

/** One governed call, inline, through the SDK's instrumented fetch. */
async function call(proxyUrl: string, step: Record<string, any>): Promise<void> {
  const res = await gurdy.fetch(proxyUrl + (step['path'] || '/'), {
    method: 'POST',
    body: bodyFor(step),
    headers: { 'Content-Type': 'application/json' },
  });
  await res.arrayBuffer();
}

/**
 * One governed call from a distinct async resource.
 *
 * `setImmediate` rather than a bare `await`: an already-resolved promise stays
 * in the same async resource, so it would pass whatever the SDK did. A timer
 * callback is a new one, which is where a binding stored anywhere other than the
 * async context would be lost.
 */
async function callAsync(proxyUrl: string, step: Record<string, any>): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve));
  await call(proxyUrl, step);
}

interface Job {
  carrier: gurdy.Carrier | undefined;
  url: string;
  body: string;
  proxyUrl: string;
  tisSocket: string;
}

/** Send one job to a live worker/child and wait for its acknowledgement. */
async function dispatchTo(
  send: (job: Job) => void,
  messages: AsyncIterableIterator<unknown[]>,
  job: Job,
): Promise<void> {
  send(job);
  const [reply] = (await messages.next()).value as [{ ok: boolean; error?: string }];
  if (!reply.ok) throw new Error(`worker failed: ${reply.error}`);
}

async function main(): Promise<number> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  const kase = JSON.parse(Buffer.concat(chunks).toString('utf8'));

  const proxyUrl = process.env['GURDY_PROXY_URL'] ?? '';
  const tisSocket = process.env['GURDY_TIS_SOCKET'] ?? '';
  gurdy.configure({ proxyUrl, tisSocket });

  const bindings = new Map<string, Binding>();
  const steps: StepResult[] = [];

  // One worker and one child for the whole case, deliberately. A fresh isolate
  // per call would hide the failure case 11 exists for: a *reused* worker that
  // retains the identity of the task it served last. Reuse is the adversarial
  // arrangement, so the driver picks it.
  let worker: Worker | undefined;
  let workerMessages: AsyncIterableIterator<unknown[]> | undefined;
  let child: ReturnType<typeof fork> | undefined;
  let childMessages: AsyncIterableIterator<unknown[]> | undefined;

  try {
    for (const [index, step] of (kase.steps ?? []).entries()) {
      if (step.mint) {
        // startTask rather than task(): a case names its credentials and calls
        // under them in an order the case chooses, so the driver holds handles
        // and activates one per call. Same code path — task() is startTask()
        // plus using().
        bindings.set(
          step.mint.as,
          await gurdy.startTask({
            agent: step.mint.agent ?? '',
            humanActor: step.mint.human_actor ?? '',
            scope: step.mint.scope,
          }),
        );
        steps.push({ index });
      } else if (step.derive) {
        try {
          bindings.set(
            step.derive.as,
            await gurdy.derive(bindings.get(step.derive.from)!, {
              agent: step.derive.agent ?? '',
              scope: step.derive.scope,
            }),
          );
        } catch (err) {
          if (err instanceof gurdy.ScopeNarrowingRefused) {
            // Reported as a refusal *of this step*, which is what stops a driver
            // from claiming a refusal it never attempted. Note what does not
            // happen: no retry with a smaller scope, and no falling back to the
            // parent's binding.
            steps.push({ index, refused: true, reason: err.message });
            continue;
          }
          throw err;
        }
        steps.push({ index });
      } else if (step.call) {
        const named: string = step.call.txn || 'none';
        const where: string = step.call.in || '';

        const run = async (): Promise<void> => {
          if (where === 'thread') {
            if (!worker) {
              worker = new Worker(WORKER);
              // node:events `on` buffers unconsumed events and rejects the iterator if
              // the worker emits 'error' — a hand-rolled queue would hang there.
              workerMessages = on(worker, 'message');
            }
            await dispatchTo(
              (job) => worker!.postMessage(job),
              workerMessages!,
              jobFor(step.call, proxyUrl, tisSocket),
            );
          } else if (where === 'process') {
            if (!child) {
              child = fork(WORKER);
              childMessages = on(child, 'message');
            }
            await dispatchTo(
              (job) => child!.send(job),
              childMessages!,
              jobFor(step.call, proxyUrl, tisSocket),
            );
          } else if (where === 'async') {
            await callAsync(proxyUrl, step.call);
          } else {
            await call(proxyUrl, step.call);
          }
        };

        if (named === 'none') {
          // Outside any task context. detached() is explicit because this driver
          // holds live bindings that are not lexically scoped; in ordinary code
          // the call would simply sit outside the task callback. Either way the
          // SDK must send nothing rather than invent one.
          await gurdy.detached(run);
        } else {
          await gurdy.using(bindings.get(named)!, run);
        }
        steps.push({ index });
      }
    }
  } finally {
    await worker?.terminate();
    child?.kill();
  }

  process.stdout.write(JSON.stringify({ steps }));
  return 0;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(err);
    process.exit(1);
  },
);
