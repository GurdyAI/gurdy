/**
 * The properties a conformance case cannot pin, because they need concurrency.
 *
 * Everything here is about one question: can a call end up recorded under an
 * agent that did not make it? A lost binding is a visible gap in the export —
 * the proxy still records an attested-coarse principal. A *wrong* binding is
 * misattributed evidence, and no reader can detect it.
 */

import { EventEmitter } from 'node:events';
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';
import * as gurdy from '../src/index.js';
import { reset as resetConfig } from '../src/config.js';

const PROXY = 'http://proxy.local:8080';

beforeEach(() => {
  gurdy.configure({ proxyUrl: PROXY, tisSocket: '/nonexistent.sock' });
});
after(() => resetConfig());

const binding = (name: string): gurdy.Binding => ({
  txn: `token-${name}`,
  agent: name,
  humanActor: '',
});

/** The token a call made right here would carry, or '' for none. */
const seen = (): string => gurdy.headers(`${PROXY}/`)[gurdy.TXN_HEADER] ?? '';

test('interleaved tasks on one thread do not clobber each other', async () => {
  // AsyncLocalStorage should make this free, but "should" is why it is asserted:
  // a binding kept in a module variable, on a client object, or in a
  // thread-local would pass every sequential conformance case and fail here.
  // The overlap is forced — alpha reads *while* beta's binding is live — because
  // merely alternating proves nothing: any save/restore scheme looks correct
  // when one task enters and leaves inside another's await.
  const observed: Record<string, string> = {};
  let releaseAlpha!: () => void;
  let betaEntered!: () => void;
  const alphaMayRead = new Promise<void>((r) => (releaseAlpha = r));
  const betaIsLive = new Promise<void>((r) => (betaEntered = r));

  const alpha = gurdy.using(binding('alpha'), async () => {
    await betaIsLive;
    observed['alpha'] = seen();
    releaseAlpha();
  });
  const beta = gurdy.using(binding('beta'), async () => {
    betaEntered();
    await alphaMayRead;
    observed['beta'] = seen();
  });

  await Promise.all([alpha, beta]);
  assert.deepEqual(observed, { alpha: 'token-alpha', beta: 'token-beta' });
});

test('a binding survives timers and microtasks scheduled inside the task', async () => {
  const observed = await gurdy.using(binding('alpha'), async () => {
    await new Promise<void>((r) => setImmediate(r));
    await new Promise<void>((r) => setTimeout(r, 1));
    await new Promise<void>((r) => queueMicrotask(r));
    return seen();
  });
  assert.equal(observed, 'token-alpha');
});

test('an unbound listener runs in the EMITTER context — Node, not us', async () => {
  // The Node-specific landmine, asserted so the README's claim is verified and
  // a future "helpful" change is caught. A listener registered inside task
  // alpha but *emitted* while beta is running sees BETA's binding. It does not
  // lose the context, it acquires someone else's, which is the dangerous class:
  // a tool call stamped with an agent that did not make it.
  const emitter = new EventEmitter();
  let observed = 'unset';

  gurdy.using(binding('alpha'), () => {
    emitter.on('go', () => (observed = seen()));
  });
  gurdy.using(binding('beta'), () => emitter.emit('go'));

  assert.equal(observed, 'token-beta', 'if this changed, the README needs updating too');
});

test('gurdy.bind makes a listener keep the context it was registered in', async () => {
  const emitter = new EventEmitter();
  let observed = 'unset';

  gurdy.using(binding('alpha'), () => {
    emitter.on('go', gurdy.bind(() => (observed = seen())));
  });
  gurdy.using(binding('beta'), () => emitter.emit('go'));

  assert.equal(observed, 'token-alpha');
});

test('a listener bound outside any task stays unenriched when fired inside one', () => {
  // The other half of bind: it must *clear*, not merely leave the store alone.
  // A callback written outside a task must not pick up the identity of whatever
  // code ends up invoking it.
  const emitter = new EventEmitter();
  let observed = 'unset';
  emitter.on('go', gurdy.bind(() => (observed = seen())));
  gurdy.using(binding('beta'), () => emitter.emit('go'));
  assert.equal(observed, '');
});

test('a failing sub-agent does not leak its identity onto the parent', async () => {
  await gurdy.using(binding('parent'), async () => {
    await assert.rejects(
      gurdy.using(binding('child'), async () => {
        throw new Error('sub-agent blew up');
      }),
    );
    assert.equal(seen(), 'token-parent');
  });
});

test('carrier round-trips, and an absent one stays absent', async () => {
  const carried = gurdy.using(binding('alpha'), () => gurdy.carrier());
  assert.equal(carried?.txn, 'token-alpha');

  assert.equal(gurdy.adopt(carried, seen), 'token-alpha');

  // A parent with no task context produces no carrier, and a worker that
  // receives none runs unenriched rather than inheriting what is around it.
  assert.equal(gurdy.carrier(), undefined);
  assert.equal(
    gurdy.using(binding('alpha'), () => gurdy.adopt(undefined, seen)),
    '',
  );
});

test('adopting per message is what stops a reused worker leaking a task', () => {
  // The `workerData` shape adopts once at startup, which pins the first task's
  // identity to every later job. Modelled here as the loop a long-lived worker
  // actually runs: one adopt per message, each seeing only its own carrier.
  const jobs = [
    gurdy.using(binding('alpha'), () => gurdy.carrier()),
    undefined,
    gurdy.using(binding('beta'), () => gurdy.carrier()),
  ];
  assert.deepEqual(
    jobs.map((c) => gurdy.adopt(c, seen)),
    ['token-alpha', '', 'token-beta'],
  );
});
