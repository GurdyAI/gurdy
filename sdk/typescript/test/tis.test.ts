/** The TIS client: testing mint and derive behavior over the AF_UNIX socket. */

import assert from 'node:assert/strict';
import http from 'node:http';
import { test } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as tis from '../src/tis.js';
import { ScopeNarrowingRefused, TISUnavailable } from '../src/errors.js';

interface RequestRecord {
  method?: string | undefined;
  url?: string | undefined;
  body?: unknown;
}

async function server(
  respond: (req: http.IncomingMessage, res: http.ServerResponse) => void
): Promise<{
  socketPath: string;
  saw: RequestRecord[];
  close: () => Promise<void>;
}> {
  const saw: RequestRecord[] = [];
  const srv = http.createServer((req, res) => {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      let body: unknown = raw;
      try {
        body = JSON.parse(raw);
      } catch {}
      saw.push({ method: req.method, url: req.url, body });
      respond(req, res);
    });
  });
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gt'));
  const sock = path.join(tempDir, 'tis.sock');
  await new Promise<void>((r) => srv.listen(sock, r));
  return {
    socketPath: sock,
    saw,
    close: async () => {
      await new Promise<void>((r, reject) => srv.close((err) => (err ? reject(err) : r())));
      fs.rmSync(tempDir, { recursive: true, force: true });
    },
  };
}

test('mint posts to /mint with the exact JSON body shape and returns the token', async () => {
  // It must serialize the fields correctly, especially snake_case vs camelCase.
  const s = await server((req, res) => {
    res.writeHead(200).end(JSON.stringify({ txn: 'tok-mint' }));
  });
  try {
    const txn = await tis.mint(s.socketPath, {
      agent: 'a',
      humanActor: 'h',
      scope: { purpose: 'p' },
      ttlSeconds: 60,
    });
    assert.equal(txn, 'tok-mint');
    assert.equal(s.saw.length, 1);
    const req0 = s.saw[0]!;
    assert.equal(req0.method, 'POST');
    assert.equal(req0.url, '/mint');
    assert.deepEqual(req0.body, {
      agent: 'a',
      human_actor: 'h',
      scope: { purpose: 'p' },
      ttl_seconds: 60,
    });
  } finally {
    await s.close();
  }
});

test('derive posts to /derive with parent, agent, and scope and returns the token', async () => {
  const s = await server((req, res) => {
    res.writeHead(200).end(JSON.stringify({ txn: 'tok-derive' }));
  });
  try {
    const txn = await tis.derive(s.socketPath, {
      parent: 'tok-parent',
      agent: 'child',
      scope: { purpose: 'p' },
    });
    assert.equal(txn, 'tok-derive');
    assert.equal(s.saw.length, 1);
    const req0 = s.saw[0]!;
    assert.equal(req0.method, 'POST');
    assert.equal(req0.url, '/derive');
    assert.deepEqual(req0.body, {
      parent: 'tok-parent',
      agent: 'child',
      scope: { purpose: 'p' },
    });
  } finally {
    await s.close();
  }
});

test('HTTP 422 rejects with ScopeNarrowingRefused, preserving the error string', async () => {
  // 422 is the specific signal for a narrowing refusal. The error message from the
  // server must be preserved so the developer knows *why* it was refused.
  const s = await server((req, res) => {
    res.writeHead(422).end(JSON.stringify({ error: 'narrowing too broad' }));
  });
  try {
    try {
      await tis.derive(s.socketPath, { parent: 'p', agent: 'a' });
      assert.fail('should have thrown');
    } catch (e: any) {
      assert.ok(e instanceof ScopeNarrowingRefused);
      assert.match(e.message, /narrowing too broad/);
    }
  } finally {
    await s.close();
  }
});

test('HTTP 400 and 500 reject with TISUnavailable, not ScopeNarrowingRefused', async () => {
  // 422 is the *only* narrowing-refusal signal. Anything else is an infrastructure
  // failure, so it must throw TISUnavailable.
  let status = 400;
  const s = await server((req, res) => {
    res.writeHead(status).end(JSON.stringify({ error: 'some error' }));
  });
  try {
    await assert.rejects(
      tis.derive(s.socketPath, { parent: 'p', agent: 'a' }),
      TISUnavailable,
    );
    status = 500;
    await assert.rejects(
      tis.derive(s.socketPath, { parent: 'p', agent: 'a' }),
      TISUnavailable,
    );
  } finally {
    await s.close();
  }
});

test('a 200 whose body is {"txn": ""} rejects with TISUnavailable', async () => {
  // An empty token cannot be stuffed into a header meaningfully.
  const s = await server((req, res) => {
    res.writeHead(200).end(JSON.stringify({ txn: '' }));
  });
  try {
    await assert.rejects(tis.mint(s.socketPath, { agent: 'a' }), TISUnavailable);
  } finally {
    await s.close();
  }
});

test('a 200 whose body is {"txn": true} rejects with TISUnavailable', async () => {
  // A truthy non-string would blow up the caller's HTTP client if we returned it.
  const s = await server((req, res) => {
    res.writeHead(200).end(JSON.stringify({ txn: true }));
  });
  try {
    await assert.rejects(tis.mint(s.socketPath, { agent: 'a' }), TISUnavailable);
  } finally {
    await s.close();
  }
});

test('a 200 whose body is a JSON array rejects with TISUnavailable', async () => {
  // A JSON array would be indexed as an object and produce undefined.
  const s = await server((req, res) => {
    res.writeHead(200).end(JSON.stringify([{ txn: 'tok' }]));
  });
  try {
    await assert.rejects(tis.mint(s.socketPath, { agent: 'a' }), TISUnavailable);
  } finally {
    await s.close();
  }
});

test('a 200 whose body is not JSON at all rejects with TISUnavailable', async () => {
  const s = await server((req, res) => {
    res.writeHead(200).end('this is not json');
  });
  try {
    await assert.rejects(tis.mint(s.socketPath, { agent: 'a' }), TISUnavailable);
  } finally {
    await s.close();
  }
});

test('a socketPath that does not exist rejects with TISUnavailable', async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gt'));
  const sock = path.join(tempDir, 'nonexistent.sock');
  try {
    await assert.rejects(tis.mint(sock, { agent: 'a' }), TISUnavailable);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('mint with scope omitted sends the all-wildcard scope, and partial scopes are sent verbatim', async () => {
  // The server owns the narrowing algebra, so missing keys must not be implicitly
  // filled with wildcards, which would turn a missing dimension into a wildcard grant.
  const s = await server((req, res) => {
    res.writeHead(200).end(JSON.stringify({ txn: 'tok' }));
  });
  try {
    await tis.mint(s.socketPath, { agent: 'a' });
    await tis.mint(s.socketPath, { agent: 'a', scope: { purpose: 'read' } });

    assert.equal(s.saw.length, 2);

    assert.deepEqual((s.saw[0]!.body as any).scope, {
      compartments: ['*'],
      resource_types: ['*'],
      actions: ['*'],
      purpose: '*',
    });

    assert.deepEqual((s.saw[1]!.body as any).scope, {
      purpose: 'read',
    });
  } finally {
    await s.close();
  }
});
