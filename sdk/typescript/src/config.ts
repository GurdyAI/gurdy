/**
 * Where the proxy and the local TIS are, and nothing else.
 *
 * Both default from the environment, because §5.9's production mode is meant to
 * be "install + env var": the task boundary is marked in code, but *where the
 * governed traffic goes* is a deployment fact and does not belong in a source
 * file.
 */

export const ENV_PROXY_URL = 'GURDY_PROXY_URL';
export const ENV_TIS_SOCKET = 'GURDY_TIS_SOCKET';

export interface Config {
  readonly proxyUrl: string;
  readonly tisSocket: string;
}

let cached: Config | undefined;

function fromEnv(): Config {
  return {
    proxyUrl: (process.env[ENV_PROXY_URL] ?? '').replace(/\/+$/, ''),
    tisSocket: process.env[ENV_TIS_SOCKET] ?? '',
  };
}

export function current(): Config {
  return (cached ??= fromEnv());
}

/** Override the environment. Returns the resulting configuration. */
export function configure(opts: { proxyUrl?: string; tisSocket?: string }): Config {
  const base = cached ?? fromEnv();
  cached = {
    proxyUrl: opts.proxyUrl === undefined ? base.proxyUrl : opts.proxyUrl.replace(/\/+$/, ''),
    tisSocket: opts.tisSocket === undefined ? base.tisSocket : opts.tisSocket,
  };
  return cached;
}

/** Forget the cached configuration; the next read re-reads the environment. */
export function reset(): void {
  cached = undefined;
}

/**
 * Whether `url` is the configured proxy, and may therefore carry the token.
 *
 * One configured origin, compared by *parsing*. `Gurdy-Txn` is a live bearer
 * credential for the whole transaction and the proxy is the only hop meant to
 * consume it, so a permissive rule here is how a mis-aimed call hands a
 * credential to an upstream tool server that can then mint assertions in the
 * agent's name.
 *
 * A string prefix — which is what the Python SDK shipped first — is wrong in
 * the dangerous direction, and `URL.origin` is exactly the stdlib answer to
 * every case that made it wrong:
 *
 * - `http://gurdy.internal` is a *prefix* of
 *   `http://gurdy.internal.attacker.example/collect`, and configuring the proxy
 *   with no port is the ordinary case rather than an exotic misuse.
 * - `http://gurdy.internal@attacker.example/` has the configured value as a
 *   prefix and `attacker.example` as its real host, because userinfo is part of
 *   the authority. `URL.origin` reports the host.
 * - `http://gurdy.internal:80` and `http://gurdy.internal` are the same origin,
 *   and a string comparison would silently stop enriching anything.
 *
 * The path still needs its own boundary check, so `/api` does not match
 * `/apiary`.
 */
let warnedBadProxy = false;

function warnBadProxyUrl(base: string): void {
  if (warnedBadProxy) return;
  warnedBadProxy = true;
  console.warn(
    `gurdy: ${ENV_PROXY_URL}=${JSON.stringify(base)} has a query or fragment, ` +
      `which cannot identify one origin — nothing will be enriched. Configure ` +
      `the proxy's scheme, host, port and path only.`,
  );
}

/** @internal reset the warn-once latch (tests). */
export function resetWarnings(): void {
  warnedBadProxy = false;
}

export function isGoverned(url: string): boolean {
  const base = current().proxyUrl;
  if (!base) return false;
  let want: URL, got: URL;
  try {
    want = new URL(base);
    got = new URL(url);
  } catch {
    return false; // unparseable: not provably the proxy, so no credential
  }
  if (want.origin !== got.origin || want.origin === 'null') return false;
  if (want.search !== '' || want.hash !== '') {
    // A proxy URL carrying a query or fragment cannot be matched meaningfully:
    // comparing origin and path only would hand the credential to every target
    // under that path, whatever the query said. Treated as unconfigured rather
    // than raised, because enrichment must never break traffic — the cost is an
    // unenriched record and a warning, not a failed request.
    warnBadProxyUrl(base);
    return false;
  }
  if (!got.pathname.startsWith(want.pathname)) return false;
  const rest = got.pathname.slice(want.pathname.length);
  return rest === '' || want.pathname.endsWith('/') || rest.startsWith('/');
}
