/**
 * How the task and spawn forms behave at their edges: what degrades, what
 * throws, and what must never fall back to a neighbouring identity.
 */

import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, beforeEach, test } from 'node:test';
import * as gurdy from '../src/index.js';
import { reset as resetConfig } from '../src/config.js';
import { resetWarned } from '../src/task.js';

const PROXY = 'http://proxy.local:8080';
const DEAD_SOCKET = '/tmp/gurdy-no-such-socket.sock';

beforeEach(() => {
  gurdy.configure({ proxyUrl: PROXY, tisSocket: DEAD_SOCKET });
  resetWarned(); // the warn-once latch is module-global
});
after(() => resetConfig());

const seen = (): string => gurdy.headers(`${PROXY}/`)[gurdy.TXN_HEADER] ?? '';

/**
 * A stub TIS on a short socket path. Short deliberately: macOS caps AF_UNIX
 * paths near 104 bytes, and a path built from this repo's directory would
 * exceed it and fail with an error that says nothing about length.
 */
async function stubTis(handler: http.RequestListener): Promise<{
  socketPath: string;
  close: () => Promise<void>;
}> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gt'));
  const socketPath = path.join(dir, 't.sock');
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(socketPath, r));
  return {
    socketPath,
    close: async () => {
      await new Promise<void>((r) => server.close(() => r()));
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

/**
 * A stub TIS. Its narrow-only stand-in is "a derive asking for the top of the
 * compartments dimension is refused" — crude next to the real algebra, which
 * lives in the Go TIS and is tested there, but enough to exercise the SDK's
 * handling of a 422 versus a 200.
 */
function tokenServer(): http.RequestListener {
  let n = 0;
  return (req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const parsed = JSON.parse(body || '{}');
      if (req.url === '/derive' && parsed.scope?.compartments?.includes('*')) {
        res.writeHead(422, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'scope widens: not a provable narrowing' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ txn: `tok-${++n}` }));
    });
  };
}

// --- the happy shape --------------------------------------------------------

test('task() binds a credential for the callback and releases it after', async () => {
  const s = await stubTis(tokenServer());
  try {
    gurdy.configure({ tisSocket: s.socketPath });
    const inside = await gurdy.task({ agent: 'orchestrator' }, () => seen());
    assert.equal(inside, 'tok-1');
    assert.equal(seen(), '');
  } finally {
    await s.close();
  }
});

test('task() mints a fresh credential per invocation', async () => {
  // A token obtained once and reused would put every task in one transaction,
  // which is the shape a decorator evaluated at definition time produces.
  const s = await stubTis(tokenServer());
  try {
    gurdy.configure({ tisSocket: s.socketPath });
    const run = () => gurdy.task({ agent: 'orchestrator' }, () => seen());
    assert.notEqual(await run(), await run());
  } finally {
    await s.close();
  }
});

test('spawn() derives from the current task and restores the parent after', async () => {
  const s = await stubTis(tokenServer());
  try {
    gurdy.configure({ tisSocket: s.socketPath });
    await gurdy.task({ agent: 'orchestrator', scope: { compartments: ['billing'] } }, async () => {
      const parent = seen();
      const child = await gurdy.spawn(
        { agent: 'fetcher', scope: { compartments: ['billing'] } },
        () => seen(),
      );
      assert.notEqual(child, parent);
      assert.equal(seen(), parent, 'the parent binding was not restored');
    });
  } finally {
    await s.close();
  }
});

// --- a refused derive is loud and never negotiated down ---------------------

test('a widening scope rejects at the spawn site and the body never runs', async () => {
  const s = await stubTis(tokenServer());
  try {
    gurdy.configure({ tisSocket: s.socketPath });
    await gurdy.task({ agent: 'orchestrator', scope: { compartments: ['billing'] } }, async () => {
      const parent = seen();
      let ran = false;
      await assert.rejects(
        gurdy.spawn({ agent: 'greedy', scope: { compartments: ['*'] } }, () => {
          ran = true;
        }),
        (err: unknown) => err instanceof gurdy.ScopeNarrowingRefused && /narrowing/.test(String(err)),
      );
      assert.equal(ran, false, 'the child ran without a credential of its own');
      assert.equal(seen(), parent, 'the refusal disturbed the parent binding');
    });
  } finally {
    await s.close();
  }
});

test('spawn() outside a task context rejects rather than minting a root', async () => {
  // Deriving needs a parent. Silently minting a fresh root instead would invent
  // a transaction with no relationship to the work that asked for it.
  await assert.rejects(
    gurdy.spawn({ agent: 'orphan' }, () => undefined),
    (err: unknown) => err instanceof gurdy.NotConfigured,
  );
});

// --- a TIS outage degrades, it does not break traffic ----------------------

test('task() runs the callback unenriched when the TIS is down', async () => {
  // The SDK enriches; it does not gate. The proxy sees the traffic either way
  // and records an attested-coarse principal, so degrading costs a claim while
  // throwing costs the request. An on-ramp that makes an agent less reliable
  // than not installing it gets uninstalled, and takes the evidence with it.
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (msg: string) => warnings.push(String(msg));
  try {
    const result = await gurdy.task({ agent: 'orchestrator' }, () => seen());
    assert.equal(result, '', 'a degraded run must be unenriched, not fabricated');
  } finally {
    console.warn = original;
  }
  assert.ok(
    warnings.some((w) => w.includes('TIS unavailable')),
    'silently losing provenance is not a degrade, it is a disappearance',
  );
});

test('spawn() degrades to no binding, never to the parent’s', async () => {
  // Running the child under its parent's credential would record the child's
  // actions as the parent's. That is a *false* lineage, which no reader can
  // detect, where an absent one is a visible gap.
  const parent: gurdy.Binding = { txn: 'parent-tok', agent: 'orchestrator', humanActor: '' };
  const original = console.warn;
  console.warn = () => {};
  try {
    await gurdy.using(parent, async () => {
      assert.equal(seen(), 'parent-tok');
      const child = await gurdy.spawn({ agent: 'fetcher' }, () => seen());
      assert.equal(child, '', 'the child ran as its parent');
      assert.equal(seen(), 'parent-tok', 'the parent binding was not restored');
    });
  } finally {
    console.warn = original;
  }
});

test('the handle forms reject instead of degrading', async () => {
  // startTask/derive return a credential or nothing at all — there is no
  // degraded value to hand back, so they reject where the callback forms
  // degrade. A caller who wants the lenient behaviour has it, by using the form
  // that wraps execution.
  await assert.rejects(gurdy.startTask({ agent: 'a' }), (e: unknown) => e instanceof gurdy.TISUnavailable);
  await assert.rejects(
    gurdy.derive({ txn: 't', agent: 'a', humanActor: '' }, { agent: 'b' }),
    (e: unknown) => e instanceof gurdy.TISUnavailable,
  );
});

test('no socket configured rejects rather than doing nothing', async () => {
  // A missing env var is a deployment error and a deterministic one: it fails
  // identically every run, and the first time anyone tries it. Quietly
  // enriching nothing would let a whole service look instrumented.
  gurdy.configure({ tisSocket: '' });
  await assert.rejects(
    gurdy.task({ agent: 'a' }, () => undefined),
    (err: unknown) => err instanceof gurdy.NotConfigured,
  );
});
