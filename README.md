# Wallet-Stealer Defense — a Claude Code skill

A defensive security skill for [Claude Code](https://claude.com/claude-code) that helps you
**detect, purge, and harden** JavaScript/TypeScript repositories against the **2026-Q2
wallet-stealer / supply-chain malware family**.

This malware family hides an obfuscated payload as a whitespace-padded tail appended to an
ordinary build-config file (`postcss.config`, `.eslintrc`, `jest.config`, `vite.config`, …).
It executes when a developer runs routine tooling (`next dev`, `next build`, ESLint, jest, vite)
and exfiltrates credentials and crypto-wallet seeds through public blockchain RPC "dead-drops".
Inject commits are often **forged** to impersonate a real author.

> **Defensive use only.** This skill detects and removes malware and hardens repos against it.
> It contains indicators of compromise (IoCs) for recognition. It does not contain, build, or
> distribute the malware itself.

---

## What's in the box

```
.
├── .claude-plugin/
│   ├── marketplace.json          # marketplace catalog (lists this plugin)
│   └── plugin.json               # plugin manifest
├── skills/
│   └── wallet-stealer-defense/
│       ├── SKILL.md              # the skill: 3-phase Detect → Purge → Harden workflow
│       ├── iocs.md               # full indicator-of-compromise catalog
│       ├── scripts/
│       │   ├── scan.sh           # local IoC scanner (exit 0 clean / 1 found)
│       │   └── restore-carrier.sh# auto-heals known carrier files (postcss, eslintrc)
│       └── templates/
│           ├── malware-scan.yml      # GitHub Actions CI scanner
│           ├── husky-malware-scan.sh # append-to-existing husky guard (detection-based)
│           ├── gitattributes         # LF enforcement (defeats whitespace camouflage)
│           └── editorconfig          # LF enforcement at editor save time
├── README.md
└── LICENSE                       # MIT
```

---

## Install

The skill ships as a Claude Code **plugin** served from a **git-based marketplace**. Once your
repo is on GitHub (see *For maintainers* below), anyone can install it:

```bash
# 1. Add the marketplace (one time)
/plugin marketplace add Peter-Mfitumukiza/wallet-stealer-defense

# 2. Install the plugin
/plugin install wallet-stealer-defense@security-skills
```

Or from the terminal, non-interactively:

```bash
claude plugin marketplace add Peter-Mfitumukiza/wallet-stealer-defense
claude plugin install wallet-stealer-defense@security-skills
```

For a non-GitHub host, use the full clone URL:

```bash
/plugin marketplace add https://gitlab.example.com/team/wallet-stealer-defense.git
```

After installing, the skill is available to Claude automatically; it activates when you describe
a relevant situation (see *Usage*). Confirm it loaded with `/plugin` (lists installed plugins).

<details>
<summary>Manual install without plugins (alternative)</summary>

Copy the skill folder into your skills directory:

```bash
git clone https://github.com/Peter-Mfitumukiza/wallet-stealer-defense.git
cp -R wallet-stealer-defense/skills/wallet-stealer-defense ~/.claude/skills/    # personal (all your projects)
# or: cp -R wallet-stealer-defense/skills/wallet-stealer-defense .claude/skills/  # one project only
```

The plugin route is recommended — it gives you clean updates and discovery. The manual copy
needs a re-copy whenever the skill changes.
</details>

---

## Usage

You don't call the skill directly — describe the situation and Claude loads it. It triggers on
things like:

- A build-config file has a single line longer than ~4000 characters.
- Source contains the family's obfuscator markers or watermark (catalog in `iocs.md`).
- A `.config.mjs` mixes `createRequire(import.meta.url)` with a very long line.
- Commits where the committer timezone doesn't match the author timezone (forged-author signal).
- You want to harden a JS/TS repo against this incident family.

Example prompts:

> "Scan this repo for the wallet-stealer malware."
> "This postcss.config.mjs has a 5KB single line — is it infected?"
> "Harden our frontend repo against the 2026-Q2 supply-chain stealer."

### The three-phase workflow

1. **Detect** — runs `scripts/scan.sh` (six IoC classes) plus a git forensic check for forged
   commits.
2. **Purge** — auto-heals known carriers via `scripts/restore-carrier.sh`; for unknown carriers
   it shows the finding and **asks before modifying**. It never force-pushes or rewrites history
   without explicit consent. If tooling ran on an infected branch, it tells you to rotate secrets
   from a clean device — **and move crypto wallet funds first**.
3. **Harden** — installs the CI scanner, LF enforcement, and a **husky scan hook adapted to your
   project** so existing hooks and builds keep working.

You can also run the scanner standalone on any repo:

```bash
bash ~/.claude/skills/wallet-stealer-defense/scripts/scan.sh   # exit 0 = clean, 1 = IoC found
```

---

## How it stays safe

- **Detection-based, not heuristic-destructive.** Purge only touches known carrier files
  automatically; everything else requires your confirmation.
- **No history rewriting by default.** It favors surgical fast-forward cleanup commits over
  `git filter-repo` / force-push, which would break teammates and open PRs.
- **Verify with `wc -c` / grep, never by running the build.** Running `next dev`/`next build` is
  the malware's execution surface — the skill refuses to "test the fix" that way.
- **`.gitignore` is not a security control.** The payload reads disk as a running process; the
  skill calls this out explicitly.

---

## Updating

This plugin omits an explicit `version`, so when hosted on git **every pushed commit is a new
version** — users pulling updates always get the latest IoCs. Push a commit and downstream users
get it on their next `/plugin marketplace update`. (If you prefer pinned releases instead, add a
`version` field to `plugin.json` and bump it on each release.)

---

## For maintainers — publishing

Identity fields are set to `Peter Mfitumukiza` /
`github.com/Peter-Mfitumukiza/wallet-stealer-defense`. Optional follow-ups:

- Add a contact `email` to `author` (`plugin.json`) and `owner` (`marketplace.json`) if you want it public.
- Rename the marketplace from `security-skills` if you prefer a different catalog name (also update the install command above).

Publish:

```bash
git add -A
git commit -m "Initial public release of wallet-stealer-defense skill"
git remote add origin https://github.com/Peter-Mfitumukiza/wallet-stealer-defense.git
git push -u origin main
```

Verify it installs end-to-end from a clean machine/profile before announcing it.

> **Note:** the IoC catalog and config files in `skills/` were genericized for public release —
> they describe variants ("multi-carrier", "jest-carrier") rather than naming specific affected
> repositories. Keep it that way when accepting contributions.

---

## License

MIT — see [LICENSE](LICENSE).

Indicators of compromise are published for defensive recognition. No warranty; use at your own
risk, and rotate credentials from a known-clean device after any confirmed infection.
