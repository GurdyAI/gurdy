/**
 * The other side of a boundary `AsyncLocalStorage` cannot cross.
 *
 * One file serves both a `worker_thread` and a forked child process, because the
 * SDK-side story is identical for both: neither shares a store with the parent,
 * so the credential arrives as an explicit carrier or the call goes out
 * unenriched.
 *
 * The message loop is the part worth reading. It adopts **per message**, inside
 * `adopt`, so a worker that serves many tasks cannot leak the identity of the
 * one before. Adopting once at startup — the `workerData` shape — would pin the
 * first task's identity to every later job, which is the misattribution this
 * whole design exists to prevent.
 */

import { isMainThread, parentPort } from 'node:worker_threads';
import * as gurdy from './src/index.js';
import type { Carrier } from './src/index.js';

interface Job {
  carrier: Carrier | undefined;
  url: string;
  body: string;
  proxyUrl: string;
  tisSocket: string;
}

async function runJob(job: Job): Promise<void> {
  // Configuration is per-isolate: a worker thread has its own module registry
  // and a child process its own everything, so neither inherited the parent's
  // configure() call.
  gurdy.configure({ proxyUrl: job.proxyUrl, tisSocket: job.tisSocket });
  // The driver resolved the target and the body; this side only re-enters the
  // context and makes the call, so there is one body builder rather than two
  // copies that have to stay in agreement.
  await gurdy.adopt(job.carrier, async () => {
    const res = await gurdy.fetch(job.url, {
      method: 'POST',
      body: job.body,
      headers: { 'Content-Type': 'application/json' },
    });
    await res.arrayBuffer();
  });
}

if (!isMainThread && parentPort) {
  // worker_threads: long-lived, one message per governed call.
  parentPort.on('message', (job: Job) => {
    runJob(job).then(
      () => parentPort!.postMessage({ ok: true }),
      (err: unknown) => parentPort!.postMessage({ ok: false, error: String(err) }),
    );
  });
} else {
  // child_process.fork: same contract over the IPC channel.
  process.on('message', (job: Job) => {
    runJob(job).then(
      () => process.send?.({ ok: true }),
      (err: unknown) => process.send?.({ ok: false, error: String(err) }),
    );
  });
}
