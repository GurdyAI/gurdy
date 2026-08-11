/**
 * The browser build, which exists only to fail with a sentence someone can act on.
 *
 * This package needs `node:async_hooks` for context propagation and an AF_UNIX
 * socket to reach the local TIS; neither has a browser equivalent, and a polyfill
 * would produce an SDK that silently enriches nothing. Bundlers resolve the
 * `browser` export condition before `node`, so a server-only import pulled into a
 * client bundle lands here instead of on a confusing module-not-found for
 * `node:http`.
 */

throw new Error(
  '@gurdy/sdk is Node-only: it uses node:async_hooks and a Unix-domain socket. ' +
    'Import it from server-side code only.',
);
