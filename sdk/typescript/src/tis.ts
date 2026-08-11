/**
 * The whole wire contract this SDK speaks to the local TIS: mint and derive.
 *
 * Two endpoints over a Unix socket, and nothing else. There is deliberately no
 * `/derive-call`: per-call assertions are derived by the proxy from the
 * transaction token it is already handed, so an agent never gets to choose the
 * `tool` its own assertion names.
 *
 * Written against `node:http` with `socketPath` rather than an undici Agent with
 * a connect override. Mint is rare and the payload is two JSON objects over a
 * local socket, so the pooling an undici agent would buy is worth less than not
 * pinning a second HTTP stack into somebody else's process.
 */

import http from 'node:http';
import { usableToken } from './context.js';
import { ScopeNarrowingRefused, TISUnavailable } from './errors.js';

const TIMEOUT_MS = 5_000;

/**
 * The dimensioned task-scope descriptor (§5.2).
 *
 * Mirrored here only so a caller can name the dimensions; the *algebra* lives in
 * the Go TIS and is never reimplemented on this side. A TypeScript copy of
 * `Narrows` would be a second implementation of a security rule, and the two
 * would drift — so the SDK asks and reports the answer.
 *
 * A partial scope is sent **verbatim**, missing keys and all. An absent dimension
 * decodes server-side to an empty list, which the narrow-only algebra treats as
 * the *bottom* of that dimension: a partial scope narrows a wildcard one, and a
 * wildcard one does not narrow it. Filling the gaps with `"*"` would be the
 * opposite — it would silently widen what the caller wrote, and turn a typo into
 * a grant. Use {@link WILDCARD_SCOPE} when wildcards are what you mean.
 */
export interface Scope {
  compartments?: string[];
  resource_types?: string[];
  actions?: string[];
  purpose?: string;
}

export const WILDCARD_SCOPE: Readonly<Required<Scope>> = Object.freeze({
  compartments: ['*'],
  resource_types: ['*'],
  actions: ['*'],
  purpose: '*',
});

async function post(socketPath: string, path: string, payload: unknown): Promise<string> {
  const body = JSON.stringify(payload);
  const { status, raw } = await new Promise<{ status: number; raw: string }>(
    (resolve, reject) => {
      const req = http.request(
        {
          socketPath,
          path,
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
          timeout: TIMEOUT_MS,
        },
        (res) => {
          let chunks = '';
          res.setEncoding('utf8');
          res.on('data', (c: string) => (chunks += c));
          res.on('end', () => resolve({ status: res.statusCode ?? 0, raw: chunks }));
          res.on('error', reject);
        },
      );
      req.on('timeout', () => req.destroy(new Error(`no response within ${TIMEOUT_MS}ms`)));
      req.on('error', reject);
      req.end(body);
    },
  ).catch((err: unknown) => {
    const reason = err instanceof Error ? err.message : String(err);
    // The kernel caps AF_UNIX paths at ~104 bytes on macOS and 108 on Linux,
    // and reports an over-long one as an unhelpful ENOENT/EINVAL. A deep
    // state-dir is an ordinary way to hit it, so say so rather than leaving
    // someone to guess.
    const hint =
      Buffer.byteLength(socketPath) > 100
        ? ` (the path is ${Buffer.byteLength(socketPath)} bytes; the kernel limit is ~104 — use a shorter state dir)`
        : '';
    throw new TISUnavailable(`TIS socket ${JSON.stringify(socketPath)} unreachable: ${reason}${hint}`);
  });

  let decoded: unknown;
  try {
    decoded = JSON.parse(raw);
  } catch {
    throw new TISUnavailable(
      `TIS returned ${status} with an undecodable body: ${JSON.stringify(raw.slice(0, 200))}`,
    );
  }
  if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) {
    // A JSON array or a bare null would otherwise be indexed as an object and
    // produce `undefined`, which is neither a useful diagnosis nor a type any
    // caller is prepared to catch.
    throw new TISUnavailable(
      `TIS returned ${status} with a non-object body: ${JSON.stringify(raw.slice(0, 200))}`,
    );
  }
  const obj = decoded as Record<string, unknown>;

  if (status === 200) {
    const txn = obj['txn'];
    // Checked for usability as a header value, not merely for truthiness. A
    // non-string, a whitespace-only token, or one containing CR/LF would install
    // a binding that either asserts nothing or throws inside the user's HTTP
    // client — at the call site, having passed through the part of the system
    // that was meant to validate it.
    if (!usableToken(txn)) {
      throw new TISUnavailable(`TIS returned 200 with an unusable txn: ${JSON.stringify(txn)}`);
    }
    return txn;
  }

  const error = typeof obj['error'] === 'string' ? obj['error'] : `HTTP ${status}`;
  // 422 is the narrow-only refusal specifically — the proxy distinguishes it
  // from a malformed request precisely so this side can. Reported as its own
  // type because it is the one failure a developer fixes in their code rather
  // than in their deployment.
  if (status === 422) throw new ScopeNarrowingRefused(error);
  throw new TISUnavailable(`TIS refused ${path}: ${error}`);
}

export function mint(
  socketPath: string,
  opts: { agent: string; humanActor?: string; scope?: Scope; ttlSeconds?: number },
): Promise<string> {
  return post(socketPath, '/mint', {
    agent: opts.agent,
    human_actor: opts.humanActor ?? '',
    scope: opts.scope ?? WILDCARD_SCOPE,
    ttl_seconds: opts.ttlSeconds ?? 0,
  });
}

export function derive(
  socketPath: string,
  opts: { parent: string; agent: string; scope?: Scope },
): Promise<string> {
  return post(socketPath, '/derive', {
    parent: opts.parent,
    agent: opts.agent,
    scope: opts.scope ?? WILDCARD_SCOPE,
  });
}
