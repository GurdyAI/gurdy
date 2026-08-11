/**
 * Attaching the credential to outbound calls, and only to the right ones.
 *
 * `fetch` is the mainline: the MCP TypeScript SDK's Streamable HTTP transport
 * uses it, and so does most modern agent code. `node:http` is deliberately not
 * patched — that fights every APM agent in the process for a stack the MCP SDK
 * does not use.
 */

import { TXN_HEADER, headers as contextHeaders } from './context.js';

type FetchFn = typeof globalThis.fetch;
// Derived from `fetch` itself rather than named: @types/node does not expose
// `RequestInfo` globally, and inferring it cannot drift from the real signature.
type FetchInput = Parameters<FetchFn>[0];

/**
 * Apply the header rules to one request, authoritatively.
 *
 * Four rules, and the last two are the ones that were bugs in the Python SDK
 * before review:
 *
 * 1. No task context → no header.
 * 2. Task context and the URL is the proxy → set it.
 * 3. Task context and the URL is *not* the proxy → **remove** any that is there.
 * 4. Never leave a header the caller supplied themselves: this function owns
 *    `Gurdy-Txn` on every request it sees.
 *
 * Rule 3 is not hypothetical. A stale `Gurdy-Txn` on a request to another host
 * hands a live bearer credential for the whole transaction to whoever runs that
 * host, and they can then mint call assertions in the agent's name.
 */
function applyHeader(input: FetchInput, url: string, init: RequestInit | undefined): Headers {
  // Start from the headers the request *actually* has. `new Headers(init.headers)`
  // alone was a real bug: headers set on a `Request` passed as `input` live on the
  // Request, not in `init`, so a wrapper built only from `init` and then handed
  // back as authoritative silently dropped the caller's Authorization and
  // Content-Type. Breaking the developer's traffic to protect an optional claim
  // is the trade this SDK exists to refuse.
  const merged = new Headers(input instanceof Request ? input.headers : undefined);
  for (const [key, value] of new Headers(init?.headers ?? undefined)) {
    merged.set(key, value);
  }
  const stamped = contextHeaders(url);
  const txn = stamped[TXN_HEADER];
  if (txn === undefined) merged.delete(TXN_HEADER);
  else merged.set(TXN_HEADER, txn);
  return merged;
}

/**
 * Resolve what `fetch` would actually request, so the origin check sees the
 * real target rather than whatever shorthand the caller passed.
 */
function targetUrl(input: FetchInput): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

/**
 * `fetch`, with the credential attached when — and only when — it belongs.
 *
 * **Redirects are not followed while a credential is attached.** `Gurdy-Txn` is
 * a custom header, so it is *not* in the set the Fetch standard strips on a
 * cross-origin redirect the way it strips `Authorization`; undici will happily
 * re-send it to whatever the `Location` names. `fetch` gives no per-hop hook to
 * re-evaluate the origin, so the only honest options are to re-implement
 * redirect following or to refuse to follow one. This refuses: a governed
 * request gets `redirect: "manual"` and the 3xx is handed back to the caller,
 * who can decide — at which point this function re-evaluates the new URL from
 * scratch.
 *
 * A caller who explicitly asked for `redirect: "follow"` on a governed request
 * is overruled, deliberately. There is no configuration that turns a credential
 * leak into a supported feature.
 *
 * ponytail: the complete fix is an undici interceptor applying the rules on
 * every hop of the chain, which is also the only way to cover a redirect made
 * by a client this SDK did not wrap. Worth building when something in the field
 * actually redirects; the proxy is a chokepoint and does not.
 */
export function instrumentedFetch(base: FetchFn = globalThis.fetch): FetchFn {
  const wrapped = async (
    input: FetchInput,
    init?: RequestInit,
  ): Promise<Response> => {
    const url = targetUrl(input);
    const merged = applyHeader(input, url, init);
    const carriesCredential = merged.has(TXN_HEADER);
    const next: RequestInit = { ...init, headers: merged };
    if (carriesCredential) next.redirect = 'manual';
    return base(input, next);
  };
  return wrapped as FetchFn;
}

/** The default instrumented client, bound to the ambient `fetch`. */
export const gurdyFetch: FetchFn = instrumentedFetch();

let originalFetch: FetchFn | undefined;

/**
 * Replace `globalThis.fetch` so calls made by code this SDK never sees are
 * enriched too — the MCP transport, an agent framework, a generated client.
 *
 * Opt-in, and never on by default. This is a process-wide change to a function
 * the SDK does not own: it affects the app's health checks, its telemetry
 * exporters, and anything else sharing the process. The rules above make it safe
 * for non-proxy traffic (no context or wrong origin means the header is removed,
 * not added), but "safe" is not the same as "yours to do without being asked".
 *
 * Idempotent; returns true if this call installed the wrapper. Libraries that
 * captured `fetch` before this ran keep the original, which degrades to
 * unenriched rather than to anything wrong.
 */
export function instrumentGlobalFetch(): boolean {
  if (originalFetch !== undefined) return false;
  originalFetch = globalThis.fetch;
  globalThis.fetch = instrumentedFetch(originalFetch);
  return true;
}

/** Undo {@link instrumentGlobalFetch}. Exists so tests can be honest. */
export function restoreGlobalFetch(): boolean {
  if (originalFetch === undefined) return false;
  globalThis.fetch = originalFetch;
  originalFetch = undefined;
  return true;
}
