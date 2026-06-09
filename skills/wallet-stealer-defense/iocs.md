# Indicators of Compromise — 2026-Q2 wallet-stealer family

Reference catalog for the wallet-stealer / supply-chain malware family observed across multiple JS/TS repositories in 2026 Q2. All known incidents share the **same obfuscator string table** and **same blockchain-RPC dead-drop technique**, indicating a common operator/toolkit.

## 1. Obfuscator string-table markers (strongest signal)

Unique to this payload family. Treat any hit in source as definitive infection.

```
_$_1e42
_$af163278
_$_ccfc
```

Grep:
```bash
grep -rIn --exclude-dir={node_modules,.git,dist,build,.next,coverage} \
  -E '_\$_1e42|_\$af163278|_\$_ccfc' .
```

False positives: none observed.

## 2. Family watermark

Present in some variants of the obfuscated tail.

```
global['!']='9-3803-1'
global['!']='9-4391-1'   ← jest-carrier variant
global['!']='9-4884'
global['!']='9-4955-1'
```

Treat any `global['!']='9-` as infection. Grep:
```bash
grep -rIn --exclude-dir={node_modules,.git,dist,build,.next,coverage} \
  -E "global\[..!..\]=..9-" .
```

## 3. C2 endpoints — public blockchain RPCs

Payload uses public blockchain RPC hosts as dead-drops (reads C2 instructions from on-chain data). These hosts are themselves legitimate; finding them **referenced from your own source** is the signal.

```
api.trongrid.io
fullnode.mainnet.aptoslabs.com
bsc-dataseed.binance.org
bsc-rpc.publicnode.com
```

Grep (excludes JSON dependency files because forks/mirrors may legitimately mention these; tune for your repo):
```bash
grep -rIn --exclude-dir={node_modules,.git,dist,build,.next,coverage} \
  --include='*.js' --include='*.mjs' --include='*.cjs' \
  --include='*.ts' --include='*.tsx' --include='*.jsx' \
  -E 'api\.trongrid\.io|fullnode\.mainnet\.aptoslabs\.com|bsc-dataseed\.binance\.org|bsc-rpc\.publicnode\.com' .
```

False positives: legitimate Web3 / blockchain projects intentionally use these RPCs. Cross-check with classes 1, 2, 5, 6 before concluding infection.

## 4. Hardcoded C2 TRON wallet addresses

These specific TRON addresses appear as C2 channels (used to read commands from on-chain transactions).

```
TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP
TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG
```

Any hit in source = infection. Grep:
```bash
grep -rIn --exclude-dir={node_modules,.git,dist,build,.next,coverage} \
  -E 'TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP|TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG' .
```

## 5. Structural — pathologically long lines

The payload is appended on **one physical line** behind whitespace padding, ~5,000–6,000 chars. Any single line >4,000 chars in source is suspicious.

```bash
find . \( -path ./node_modules -o -path ./.git -o -path ./dist \
     -o -path ./build -o -path ./.next -o -path ./coverage \) -prune \
  -o -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' \
              -o -name '*.ts' -o -name '*.tsx' -o -name '*.jsx' \) \
  -print | while read -r f; do
    awk 'length>4000 {print FILENAME":"FNR" line is "length" chars"; exit}' "$f"
  done
```

False positives: minified bundles committed to source, embedded base64 assets, inline SVG dataURIs. Whitelist by file path if needed.

## 6. ESM re-entry shim in build configs

`postcss.config.mjs`, `next.config.mjs`, `vite.config.mjs` are ES modules — no `require()`. The operator prepends:

```js
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
```

so the payload regains CommonJS `require` to reach `child_process`. The shim alone is sometimes legitimate; the shim **combined with a long line in the same `.config.mjs`** is the IoC.

```bash
find . -path ./node_modules -prune -o -type f -name '*.config.mjs' -print | \
while read -r f; do
  if grep -q 'createRequire(import\.meta\.url)' "$f" && \
     awk 'length>2000{f=1} END{exit f?0:1}' "$f"; then
    echo "$f: createRequire + long line = payload pattern"
  fi
done
```

## 7. Forensic — forged commit metadata

The operator commits from a US-Pacific machine (timezone `-0700` PDT or `-0800` PST) but forges author identity & timezone to impersonate non-US contributors. The committer timezone is **not** forged when pushing — only the author timezone is.

**Rule:** `committer tz ∈ {-0700, -0800}` while `author tz ∈ {+0200 (CAT), +0800 (China), +0900 (KST), +0530 (IST), ...}` ⇒ forged.

Find candidates across all branches:
```bash
git log --all --pretty=format:'%h|%an|%ae|%ai|%ci' --since='2 years ago' | \
awk -F'|' '
  { match($4, /[+-][0-9]{4}$/); atz=substr($4, RSTART, 5);
    match($5, /[+-][0-9]{4}$/); ctz=substr($5, RSTART, 5);
    if (atz != ctz && (ctz == "-0700" || ctz == "-0800")) print
  }'
```

Also useful — first introduction of a specific marker (pickaxe):
```bash
git log --all --oneline -S "global['!']" -- '*.js' '*.mjs' '*.cjs' '*.ts'
git log --all --oneline -S "_\$_1e42"
```

## 8. Carrier file inventory (observed so far)

| Carrier path | Variant | Clean size | Infected size | Execution surface |
|---|---|---|---|---|
| `frontend/postcss.config.mjs` | multi-carrier | 116 B | ~5,509 B | `next dev`, `next build` |
| `postcss.config.mjs` (root) | multi-carrier (older layout) | 116 B | ~5,509 B | same |
| `.eslintrc.js` (root) | multi-carrier (backend) | ~600 B | ~5,979 B | every ESLint run (CLI, IDE, pre-commit) |
| `frontend/jest.config.js` | jest-carrier | ~200 B | ~5–6 KB | `npm test` only |

Candidate carriers in other repos (any file in this list with a >4000-char line is suspicious):
```
*.config.{js,mjs,cjs,ts}    # postcss, next, vite, jest, vitest, rollup, webpack, tsup, eslint
.eslintrc{,.js,.cjs,.mjs}
.prettierrc{,.js,.cjs}
babel.config.{js,cjs,mjs}
tailwind.config.{js,mjs,cjs,ts}
playwright.config.{js,ts}
```

## 9. What is NOT an IoC

- `createRequire(import.meta.url)` alone in `*.config.mjs` — legitimate use to load JSON or CJS deps. Only suspicious combined with class 5.
- `node_modules/**/*.js` files with long lines — minified third-party code, scanner excludes by default.
- Mentions of `api.trongrid.io` etc. in a legitimate Web3 / blockchain project source — verify via classes 1, 2, 5, 6.
- Mentions of any of these markers in **this skill, this `iocs.md`, or any `docs/security/` directory** — documentation needs the strings; scanner excludes those paths.

## 10. References

- Multi-carrier variant — three carriers (postcss + eslintrc) in one repo.
- Jest-carrier variant — single `jest.config.js` carrier. Statically decoded with standalone forensic scripts (`extract`, `decompress`, `resolve`) that decode the payload without a JS engine and without `eval`.
