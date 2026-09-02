// Browser entry point. Loadable directly as `<script type="module"
// src=".../node_modules/local-srp-auth/src/client/index.js">` — no
// bundler, no build step — or via `import ... from 'local-srp-auth/client'`
// in a bundled app. Pulls in nothing Node-only: no `node:crypto`, no
// `node:fs`. The default crypto adapter uses `window.crypto.subtle`.
//
// Native ESM relative imports require an HTTP(S) origin — they do not
// work loaded from a bare `file://` URL (browsers block cross-module
// fetches there). If your app is served over http(s) (as this package's
// own examples/node-http demo is), this just works with no build step.

export { SrpRegistration, SrpLoginAttempt } from '../srp/srp-client.js'
export { default as GROUPS } from '../common/groups.js'
export { createWebCryptoAdapter, defaultWebCryptoAdapter } from '../common/crypto-adapter-web.js'
