/**
 * The findings from review, each pinned so it cannot come back.
 *
 * Two of these are the failure mode this SDK exists to prevent (a call recorded
 * under an agent that did not make it) and two are its mirror image (the SDK
 * breaking traffic it was only supposed to observe).
 */

import assert from 'node:assert/strict';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { after, beforeEach, test } from 'node:test';
import * as gurdy from '../src/index.js';
import { reset as resetConfig, resetWarnings } from '../src/config.js';

beforeEach(() => {
  resetConfig();
  resetWarnings();
});
after(() => resetConfig());

const binding: gurdy.Binding = { txn: 'tok', agent: 'a', humanActor: '' };

async function echoServer(): Promise<{
  url: string;
  saw: http.IncomingHttpHeaders[];
  close: () => Promise<void>;
}> {
  const saw: http.IncomingHttpHeaders[] = [];
  const server = http.createServer((req, res) => {
    saw.push(req.headers);
    res.writeHead(200).end('{}');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    saw,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

// --- the SDK must not break the traffic it observes --------------------------

test('a Request passed as input keeps the headers it already carries', async () => {
  // `new Headers(init.headers)` does not see headers set on a Request given as
  // `input` — they live on the Request. A wrapper built only from `init` and then
  // handed back as authoritative silently dropped the caller's Authorization and
  // Content-Type. Enrichment breaking traffic is the trade this SDK refuses.
  const s = await echoServer();
  try {
    gurdy.configure({ proxyUrl: s.url });
    const req = new Request(`${s.url}/`, {
      method: 'POST',
      headers: { Authorization: 'Bearer secret', 'X-Trace': 'abc' },
      body: '{}',
    });
    await gurdy.using(binding, async () => {
      await (await gurdy.fetch(req)).arrayBuffer();
    });
    assert.equal(s.saw[0]?.['authorization'], 'Bearer secret');
    assert.equal(s.saw[0]?.['x-trace'], 'abc');
    assert.equal(s.saw[0]?.['gurdy-txn'], 'tok', 'and it still got enriched');
  } finally {
    await s.close();
  }
});

test('a stale credential on a Request to another host is still removed', async () => {
  const s = await echoServer();
  try {
    gurdy.configure({ proxyUrl: 'http://proxy.local' });
    const req = new Request(`${s.url}/`, {
      headers: { [gurdy.TXN_HEADER]: 'stale', 'X-Keep': 'yes' },
    });
    await gurdy.using(binding, async () => {
      await (await gurdy.fetch(req)).arrayBuffer();
    });
    assert.equal(s.saw[0]?.['gurdy-txn'], undefined);
    assert.equal(s.saw[0]?.['x-keep'], 'yes', 'stripping one header must not strip the rest');
  } finally {
    await s.close();
  }
});

test('a malformed carrier runs the callback detached rather than stamping garbage', () => {
  // A carrier crosses an isolate boundary as plain data, so its declared type
  // proves nothing. `{ txn: null }` would stamp the header "null" — a claim
  // nobody made — and a token containing a newline throws inside Headers.set at
  // the caller's own call site. Neither is acceptable; unenriched is.
  gurdy.configure({ proxyUrl: 'http://proxy.local' });
  const seen = (): string => gurdy.headers('http://proxy.local/')[gurdy.TXN_HEADER] ?? '';
  for (const bad of [
    { txn: null },
    { txn: 0 },
    { txn: '' },
    { txn: '   ' },
    { txn: 'bad\nvalue' },
    { txn: ' padded ' },
    {},
  ]) {
    assert.equal(
      gurdy.adopt(bad as unknown as gurdy.Carrier, seen),
      '',
      JSON.stringify(bad),
    );
  }
});

test('a well-formed carrier with junk metadata still works', () => {
  gurdy.configure({ proxyUrl: 'http://proxy.local' });
  const seen = (): string => gurdy.headers('http://proxy.local/')[gurdy.TXN_HEADER] ?? '';
  assert.equal(
    gurdy.adopt({ txn: 'good' } as unknown as gurdy.Carrier, seen),
    'good',
    'a missing agent name is not a reason to drop a valid credential',
  );
});

// --- the SDK must not let a captured identity change underneath it -----------

test('mutating a binding after activation cannot re-label the calls made under it', () => {
  // `readonly` is a compile-time promise and nothing more. `using` stored the
  // caller's object and `bind` captured that same reference, so a later
  // `b.txn = other` retroactively re-labelled every call made under it — direct
  // misattribution, from a line that looks unrelated.
  gurdy.configure({ proxyUrl: 'http://proxy.local' });
  const seen = (): string => gurdy.headers('http://proxy.local/')[gurdy.TXN_HEADER] ?? '';
  const mutable = { txn: 'alpha', agent: 'a', humanActor: '' };

  const captured = gurdy.using(mutable, () => gurdy.bind(seen));
  mutable.txn = 'beta';

  assert.equal(captured(), 'alpha');
});

// --- a proxy URL that cannot identify one origin enriches nothing ------------

test('a proxy URL with a query or fragment enriches nothing, and says why', () => {
  // Comparing origin and path only would hand the credential to every target
  // under that path whatever the query said. Refused rather than widened — and
  // *not* thrown, because enrichment must never break traffic.
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (m: string) => warnings.push(String(m));
  try {
    gurdy.configure({ proxyUrl: 'http://gateway.local/dispatch?target=gurdy' });
    gurdy.using(binding, () => {
      assert.deepEqual(gurdy.headers('http://gateway.local/dispatch?target=tool-server'), {});
      assert.deepEqual(gurdy.headers('http://gateway.local/dispatch'), {});
    });
  } finally {
    console.warn = original;
  }
  assert.ok(warnings.some((w) => w.includes('query or fragment')));
});

test('a garbage proxy URL enriches nothing rather than everything', () => {
  for (const bad of ['not-a-url', '/relative/path', '']) {
    gurdy.configure({ proxyUrl: bad });
    gurdy.using(binding, () => {
      assert.deepEqual(gurdy.headers('http://anywhere/'), {}, bad);
    });
  }
});

// --- the package refuses to be a browser dependency -------------------------

test('the browser entry point fails closed with an actionable message', async () => {
  // A bundler resolving this package for a client bundle would otherwise try to
  // polyfill node:async_hooks and produce an SDK that silently enriches nothing.
  await assert.rejects(
    import('../src/browser.js'),
    (err: unknown) => err instanceof Error && /Node-only/.test(err.message),
  );
});
