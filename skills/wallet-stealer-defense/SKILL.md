---
name: wallet-stealer-defense
description: Use when investigating a cryptocurrency wallet-stealer or supply-chain infection in a JS/TS repository, when build-config files (postcss.config, .eslintrc, jest.config, vite.config, etc.) look suspicious, when an audit finds obfuscation markers, multi-thousand-character lines, or createRequire shims in source files, when forged-commit timezone mismatches are suspected, or when hardening a JS/TS repo against the 2026-Q2 wallet-stealer incident family.
---

# Wallet-Stealer Defense

Detect, purge, and harden against the 2026-Q2 wallet-stealer / supply-chain malware family (a single operator/toolkit observed across multiple JS/TS repositories). The payload hides as a tail on build-config files behind whitespace padding, runs on routine tooling (`next dev`, ESLint, jest, vite), and exfiltrates credentials & wallet seeds via public-blockchain RPC dead-drops.

## When to use

- A JS/TS repo's build-config file (`*.config.{js,mjs,cjs,ts}`, `.eslintrc*`) has a single line >4000 chars
- Source contains `_$_1e42`, `_$af163278`, `_$_ccfc`, or `global['!']='9-XXXX-X'`
- `.config.mjs` files import `createRequire(import.meta.url)` alongside a very long line
- Suspicious child-process spawning, `api.trongrid.io` / `aptoslabs.com` / `bsc-dataseed.binance.org` references in source
- Commits where committer timezone (`-0700`/`-0800`) doesn't match author timezone (`+0200`/`+0800`/`+0900`)
- Hardening a JS/TS repo against this incident family (rolling out CI scan + LF enforcement)

Not for: generic npm `audit` issues, unrelated supply-chain CVEs (e.g. `event-stream`, `node-ipc`), or non-JS ecosystems.

## Three-phase workflow

```
1. DETECT  → scripts/scan.sh in the repo root; or invoke iocs.md grep set manually
2. PURGE   → auto-heal known carriers (postcss/eslintrc) via scripts/restore-carrier.sh;
             for unknown carriers, show finding and ASK before modifying
3. HARDEN  → install templates/malware-scan.yml + templates/gitattributes + templates/editorconfig,
             THEN install a husky scan hook adapted to the project (mandatory; see 3b)
```

## 1. Detect

Run the bundled scanner from the repo root:

```bash
bash ~/.claude/skills/wallet-stealer-defense/scripts/scan.sh
```

Exit code `0` = clean. Exit code `1` = one or more IoCs found; specific findings printed.

The scanner checks six IoC classes (full catalog in `iocs.md`):
1. Obfuscation string-table markers (`_$_1e42`, `_$af163278`, `_$_ccfc`)
2. Family watermark (`global['!']='9-XXXX-X'`)
3. Blockchain C2 endpoints in source (trongrid, aptoslabs, bsc-dataseed, bsc-rpc.publicnode)
4. Hardcoded C2 TRON wallet addresses
5. Any single line >4000 chars in `.js/.mjs/.cjs/.ts/.tsx/.jsx`
6. `*.config.mjs` files mixing `createRequire(import.meta.url)` with a long line

For commit-metadata forensics (forged-author detection):

```bash
git log --all --pretty=format:'%h %ai author=%ae | %ci committer=%ce' --since="1 year ago" \
  | awk '/[+-][0-9]{4}/ {
      match($0, /[0-9]{4} author/); a=substr($0, RSTART, 5);
      match($0, /[0-9]{4} committer/); c=substr($0, RSTART, 5);
      if (a != c && (c ~ /-07/ || c ~ /-08/)) print
    }'
```

## 2. Purge

**Known carriers — auto-heal.** Run:

```bash
bash ~/.claude/skills/wallet-stealer-defense/scripts/restore-carrier.sh <path>
```

Supports `postcss.config.{js,mjs,cjs}` and `.eslintrc.js`. Strategy:
- **postcss carrier**: strip `import { createRequire }` shim line if present; truncate at first standalone `export default config;` or `module.exports` terminator; remove tail; verify `wc -c` is small and no IoC marker remains.
- **.eslintrc.js**: truncate at the first top-level `};` (the `module.exports` terminator — inner blocks use `},`). Preserves legitimate config verbatim.

After restore, verify:
```bash
grep -E '_\$_1e42|_\$af163278|_\$_ccfc|global\[..!..\]' <path>     # expect empty
awk '{if(length>m)m=length}END{print FILENAME": max line "m+0}' <path>  # expect small
```

**Unknown carriers — ASK before modifying.** If the scanner flags a file that isn't a known carrier:
1. Show the user the file path, the line number, and the offending content (truncated to ~200 chars).
2. Cross-check with `git log -p -S 'global[..!..]' -- <path>` and `git log --follow --oneline <path>` to find the introducing commit.
3. Look at the commit's author vs committer timezone — if forged, this is the inject commit.
4. Find the most recent clean ancestor (`git show <sha>:<path>` from before the long-line first appeared).
5. Ask the user: "Restore `<path>` to its content at commit `<clean-sha>`? Or strip the tail manually?"

**Never force-push, never `git filter-repo` without explicit user consent.** Cleanup uses fast-forward commits authored by a `<repo>-security-response` identity — preserves blame.

**After purge, if any developer ran tooling (`next dev`, `next build`, ESLint, jest) on the infected branch:** the payload may have executed locally. Tell the user to rotate from a clean device: `.env` secrets, JWT secret, DB creds, GitHub PATs, SSH keys, npm tokens, cloud creds, **and move crypto wallet funds first**.

## 3. Harden

Detection-only hardening (per the chosen mode). Install three files at the repo root:

```bash
# CI scanner — fails any push/PR reintroducing IoCs
mkdir -p .github/workflows
cp ~/.claude/skills/wallet-stealer-defense/templates/malware-scan.yml \
   .github/workflows/malware-scan.yml

# LF enforcement at commit time (defeats whitespace/CRLF camouflage)
cp ~/.claude/skills/wallet-stealer-defense/templates/gitattributes .gitattributes

# LF enforcement at editor save time
cp ~/.claude/skills/wallet-stealer-defense/templates/editorconfig .editorconfig

git add .github/workflows/malware-scan.yml .gitattributes .editorconfig
git commit -m "security: add malware signature scan + LF enforcement"
```

If the target repo already has these files, **diff first and merge — do not overwrite** user content.

The CI workflow excludes `node_modules/`, `.git/`, `dist/`, `build/`, `.next/`, `coverage/`, and any `docs/security/` directory (so docs documenting the IoCs don't self-trip the scanner).

### 3b. Husky scan hook (mandatory, adapt per project)

A local hook is mandatory — CI is the backstop, but the husky hook catches the carrier before it ever leaves the dev's machine. It must **not** be a generic copy-paste: install it only **after understanding the project**, adapt it to the project's setup, and verify the project's own hooks and build still run fine afterward. Use a **detection-based** hook (run the scan), never the old hash-pinned self-heal — the per-project SHA-256 was brittle and is abandoned.

**Step 1 — understand the project first.** Before touching anything, inspect:
- `.husky/` — which hooks exist (`pre-commit`, `pre-push`, `commit-msg`) and what they already run (lint-staged, tests, `tsc`).
- `package.json` — the `prepare` script (`husky` / `husky install`), husky version (v9+ uses bare hook scripts; v8 and earlier need the `. "$(dirname -- "$0")/_/husky.sh"` boilerplate), and any `lint-staged` config.
- Whether husky is even installed. If not, ask the user before adding it — installing husky changes their `prepare` flow.

**Step 2 — vendor the scan into the repo.** The hook runs on every developer's machine and in CI, so it cannot reference `~/.claude/...`. Copy the scanner into the repo:
```bash
mkdir -p scripts/security
cp ~/.claude/skills/wallet-stealer-defense/scripts/scan.sh scripts/security/malware-scan.sh
chmod +x scripts/security/malware-scan.sh
```

**Step 3 — merge the guard into an existing hook, preserving the project's rules.** Pick the hook by scan cost: `pre-commit` (earliest, but runs every commit) for small repos; `pre-push` for large repos where the scan is slow. **Append** the guard block from `templates/husky-malware-scan.sh` to the chosen hook — never overwrite the project's existing hook commands. If the hook doesn't exist yet, create it matching the project's husky version format.
```bash
# Example: append to an existing pre-commit (do NOT clobber lint-staged etc.)
cat ~/.claude/skills/wallet-stealer-defense/templates/husky-malware-scan.sh >> .husky/pre-commit
```

**Step 4 — verify the project still runs fine.** This is the acceptance gate:
- A normal commit/push with clean files succeeds and the project's own hooks (lint-staged, tests) still run.
- Re-introducing an IoC into a test file makes the commit/push fail with the scan message.
- Verify with `wc -c` / grep on the carrier, **not** by running `next dev`/`next build` (that's the execution surface).

If anything in the project's own workflow breaks, fix the adaptation (hook choice, ordering, or husky boilerplate) — do not leave the project unable to commit.

Still require per-project tuning (mention as follow-ups, not auto-installed):
- **Branch protection rules** + **commit signing** — GitHub UI / org-policy changes, not file installs.
- **`git filter-repo` history purge** of any plaintext `.env*` secrets — destructive, needs a clean machine, and the team must coordinate force-push.

## Indicators of compromise (quick reference)

| Class | Signal | Strongest in |
|---|---|---|
| Obfuscation | `_$_1e42`, `_$af163278`, `_$_ccfc` | source files |
| Watermark | `global['!']='9-XXXX-X'` (`9-3803-1`, `9-4391-1`, `9-4884`, `9-4955-1`) | source files |
| C2 hosts | `api.trongrid.io`, `fullnode.mainnet.aptoslabs.com`, `bsc-dataseed.binance.org`, `bsc-rpc.publicnode.com` | source/config files |
| C2 wallets | `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP`, `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG` | source files |
| Structural | line >4000 chars in `.js/.mjs/.cjs/.ts/.tsx/.jsx` | build-config files |
| ESM re-entry | `createRequire(import.meta.url)` + long line in `*.config.mjs` | build-config files |
| Forensic | committer tz `-0700`/`-0800` ≠ author tz `+0200`/`+0800`/`+0900` | git history |

Full catalog with context, false-positive notes, and per-class grep recipes: `iocs.md`.

## Common mistakes

- **Trusting `.gitignore`** — it controls tracking only; the payload reads disk as a running process. `.gitignore` is not a security control.
- **Reviewing infected diffs without `-w`** — whitespace-padding camouflage hides the payload past the visible diff. Always use `git diff -w <range>` on review.
- **Rebasing onto an infected branch** — re-introduces the carrier. Always `--ff-only` from a verified-clean remote; rebase work onto cleaned `dev`/`main`.
- **Attributing inject commits to the named author** — they were impersonated. Check committer timezone first.
- **Running `next dev` or `next build` to test the fix** — that's the execution surface. Verify with `wc -c` and grep instead.
- **Force-pushing or `git filter-repo` without team coordination** — destroys other developers' work and breaks open PRs. The reference incident used surgical fast-forward cleanup commits instead.

## Reference

- Full IoC catalog: `iocs.md`
- Local scanner: `scripts/scan.sh`
- Carrier restorer: `scripts/restore-carrier.sh`
- CI workflow template: `templates/malware-scan.yml`
- Husky scan hook (append-to-existing, detection-based): `templates/husky-malware-scan.sh`
- LF enforcement: `templates/gitattributes`, `templates/editorconfig`
- Reference incident variants:
  - Multi-carrier variant — 3 carriers in one repo (postcss + eslintrc).
  - Jest-carrier variant — single `jest.config.js` carrier; has standalone forensic decoder scripts.
