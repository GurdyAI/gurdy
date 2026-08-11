/** The two refusals: never invent a claim, never send the token to the wrong hop. */

import assert from 'node:assert/strict';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { after, beforeEach, test } from 'node:test';
import * as gurdy from '../src/index.js';
import { reset as resetConfig } from '../src/config.js';

const PROXY = 'http://127.0.0.1:8080';

beforeEach(() => {
  gurdy.configure({ proxyUrl: PROXY, tisSocket: '/nonexistent.sock' });
});
after(() => resetConfig());

const binding: gurdy.Binding = { txn: 'tok', agent: 'a', humanActor: '' };

test('no task context means no header', () => {
  // §5.9: a call outside a task passes through unenriched. The record then says
  // attested-coarse, which is a true statement about what the proxy observed. A
  // fabricated assertion would be a false one, and the ledger is meant to be
  // worth trusting.
  assert.equal(gurdy.current(), undefined);
  assert.deepEqual(gurdy.headers(`${PROXY}/`), {});
});

test('leaving a task stops the enrichment', () => {
  gurdy.using(binding, () => {
    assert.deepEqual(gurdy.headers(`${PROXY}/`), { [gurdy.TXN_HEADER]: 'tok' });
  });
  assert.deepEqual(gurdy.headers(`${PROXY}/`), {});
});

test('detached suppresses enrichment inside a task', () => {
  gurdy.using(binding, () => {
    gurdy.detached(() => assert.deepEqual(gurdy.headers(`${PROXY}/`), {}));
    assert.deepEqual(gurdy.headers(`${PROXY}/`), { [gurdy.TXN_HEADER]: 'tok' });
  });
});

// --- the credential goes to exactly one origin -------------------------------

test('the token never goes to a hop that is not the proxy', () => {
  // Gurdy-Txn is a live bearer credential for the whole transaction. The proxy
  // consumes it and never forwards it upstream — but that only protects the hop
  // the proxy is on. An upstream tool server that receives one directly can mint
  // call assertions in the agent's name.
  gurdy.using(binding, () => {
    for (const url of [
      'http://evil.example/',
      'http://127.0.0.1:9999/', // right host, wrong port
      'https://127.0.0.1:8080/', // right authority, wrong scheme
    ]) {
      assert.deepEqual(gurdy.headers(url), {}, url);
    }
  });
});

test('a port-less proxy URL does not match lookalike hosts', () => {
  // The bug the Python SDK shipped first: a bare string prefix. Configuring the
  // proxy with no port is the ordinary case, and it makes the configured value a
  // prefix of every host that merely *starts* with it — whoever owns that host
  // then receives the credential. URL.origin is the stdlib answer.
  gurdy.configure({ proxyUrl: 'http://gurdy.internal' });
  gurdy.using(binding, () => {
    for (const url of [
      'http://gurdy.internal.attacker.example/collect',
      'http://gurdy.internalXY/',
      'http://gurdy.internal:9999/',
      'http://gurdy.internal@attacker.example/', // the base becomes userinfo
    ]) {
      assert.deepEqual(gurdy.headers(url), {}, url);
    }
  });
});

test('a port-less proxy URL still matches itself, and its default port', () => {
  gurdy.configure({ proxyUrl: 'http://gurdy.internal' });
  gurdy.using(binding, () => {
    for (const url of [
      'http://gurdy.internal',
      'http://gurdy.internal/',
      'http://gurdy.internal/v1/messages',
      'http://gurdy.internal?x=1',
      'http://gurdy.internal:80/', // same origin; a string compare would miss it
      'http://GURDY.INTERNAL/', // host comparison is case-insensitive
    ]) {
      assert.deepEqual(gurdy.headers(url), { [gurdy.TXN_HEADER]: 'tok' }, url);
    }
  });
});

test('a configured path is matched at a segment boundary', () => {
  gurdy.configure({ proxyUrl: 'http://gurdy.internal/api' });
  gurdy.using(binding, () => {
    assert.deepEqual(gurdy.headers('http://gurdy.internal/api/tools'), {
      [gurdy.TXN_HEADER]: 'tok',
    });
    assert.deepEqual(gurdy.headers('http://gurdy.internal/apiary'), {});
  });
});

test('nothing is sent when no proxy is configured', () => {
  // An unset proxy URL must not mean "match everything".
  gurdy.configure({ proxyUrl: '' });
  gurdy.using(binding, () => {
    assert.deepEqual(gurdy.headers('http://anywhere/'), {});
  });
});

// --- the fetch wrapper -------------------------------------------------------

async function servers(): Promise<{
  proxy: string;
  elsewhere: string;
  proxySaw: http.IncomingHttpHeaders[];
  elsewhereSaw: http.IncomingHttpHeaders[];
  close: () => Promise<void>;
}> {
  const proxySaw: http.IncomingHttpHeaders[] = [];
  const elsewhereSaw: http.IncomingHttpHeaders[] = [];
  const elsewhere = http.createServer((req, res) => {
    elsewhereSaw.push(req.headers);
    res.writeHead(200).end('{}');
  });
  await new Promise<void>((r) => elsewhere.listen(0, '127.0.0.1', r));
  const elsewhereUrl = `http://127.0.0.1:${(elsewhere.address() as AddressInfo).port}`;

  const proxy = http.createServer((req, res) => {
    proxySaw.push(req.headers);
    if (req.url === '/redirect') {
      res.writeHead(302, { Location: `${elsewhereUrl}/steal` }).end();
      return;
    }
    res.writeHead(200).end('{}');
  });
  await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', r));
  const proxyUrl = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;

  return {
    proxy: proxyUrl,
    elsewhere: elsewhereUrl,
    proxySaw,
    elsewhereSaw,
    close: async () => {
      await new Promise<void>((r) => proxy.close(() => r()));
      await new Promise<void>((r) => elsewhere.close(() => r()));
    },
  };
}

test('the instrumented fetch stamps the proxy and strips everything else', async () => {
  const s = await servers();
  try {
    gurdy.configure({ proxyUrl: s.proxy });
    await gurdy.using(binding, async () => {
      await (await gurdy.fetch(`${s.proxy}/`)).arrayBuffer();
      // A caller who set the header themselves, to a host that must not have it.
      await (
        await gurdy.fetch(`${s.elsewhere}/`, { headers: { [gurdy.TXN_HEADER]: 'tok' } })
      ).arrayBuffer();
    });
    assert.equal(s.proxySaw[0]?.['gurdy-txn'], 'tok');
    assert.equal(
      s.elsewhereSaw[0]?.['gurdy-txn'],
      undefined,
      'the wrapper must strip a header the caller supplied for the wrong hop',
    );
  } finally {
    await s.close();
  }
});

test('a governed request does not follow a redirect off the proxy', async () => {
  // Gurdy-Txn is a custom header, so the Fetch standard does not strip it on a
  // cross-origin redirect the way it strips Authorization — undici re-sends it
  // to whatever Location names. fetch offers no per-hop hook, so a governed
  // request is not allowed to follow one at all; the 3xx comes back instead.
  const s = await servers();
  try {
    gurdy.configure({ proxyUrl: s.proxy });
    const res = await gurdy.using(binding, () =>
      gurdy.fetch(`${s.proxy}/redirect`, { redirect: 'follow' }),
    );
    assert.equal(res.status, 302, 'the redirect was followed while holding a credential');
    assert.equal(
      s.elsewhereSaw.length,
      0,
      'the redirect target was contacted, and with the credential attached',
    );
  } finally {
    await s.close();
  }
});

test('an unenriched request still follows redirects normally', async () => {
  // The restriction is scoped to requests that carry the credential; ordinary
  // traffic through the wrapper must behave like ordinary traffic.
  const s = await servers();
  try {
    gurdy.configure({ proxyUrl: s.proxy });
    const res = await gurdy.fetch(`${s.proxy}/redirect`, { redirect: 'follow' });
    assert.equal(res.status, 200);
    assert.equal(s.elsewhereSaw.length, 1);
    assert.equal(s.elsewhereSaw[0]?.['gurdy-txn'], undefined);
  } finally {
    await s.close();
  }
});
