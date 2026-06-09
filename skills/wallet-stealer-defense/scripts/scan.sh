#!/usr/bin/env bash
# Local mirror of the CI malware signature scan.
# Run from the repo root. Exit code 0 = clean, 1 = IoC(s) found.
#
# Scans for the 2026-Q2 wallet-stealer family:
#  - obfuscator string table (_$_1e42, _$af163278, _$_ccfc)
#  - family watermark (global['!']='9-XXXX-X')
#  - public-blockchain C2 endpoints
#  - hardcoded C2 TRON wallet addresses
#  - any single line > 4000 chars in JS/TS source
#  - createRequire(import.meta.url) + long line in *.config.mjs

set -uo pipefail

EXCL=(--exclude-dir=node_modules --exclude-dir=.git
      --exclude-dir=dist --exclude-dir=build --exclude-dir=.next
      --exclude-dir=coverage --exclude-dir=security
      --exclude-dir=.turbo --exclude-dir=.nuxt --exclude-dir=.svelte-kit
      --exclude=malware-scan.yml
      --exclude='*.infected.*.bak')

fail=0
hr() { printf '%s\n' "----------------------------------------------------------------"; }

echo "=== wallet-stealer-defense :: local scan ==="
echo "repo: $(pwd)"
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
hr

echo "[1/6] obfuscator string-table markers..."
if grep -rIn "${EXCL[@]}" -E '_\$_1e42|_\$af163278|_\$_ccfc' . ; then
  echo "  FAIL: known obfuscation marker found"
  fail=1
else
  echo "  OK"
fi
hr

echo "[2/6] family watermark (global['!']='9-XXXX-X')..."
if grep -rInF "${EXCL[@]}" "global['!']='9-" . ; then
  echo "  FAIL: family watermark found"
  fail=1
else
  echo "  OK"
fi
hr

echo "[3/6] public-blockchain C2 hosts referenced from source..."
if grep -rIn "${EXCL[@]}" \
     -E 'api\.trongrid\.io|fullnode\.mainnet\.aptoslabs\.com|bsc-dataseed\.binance\.org|bsc-rpc\.publicnode\.com' \
     --include='*.js' --include='*.mjs' --include='*.cjs' \
     --include='*.ts' --include='*.tsx' --include='*.jsx' \
     --include='*.json' . ; then
  echo "  FAIL: blockchain C2 endpoint referenced from source"
  fail=1
else
  echo "  OK"
fi
hr

echo "[4/6] hardcoded C2 TRON wallet addresses..."
if grep -rIn "${EXCL[@]}" \
     -E 'TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP|TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG' . ; then
  echo "  FAIL: known C2 wallet address found"
  fail=1
else
  echo "  OK"
fi
hr

echo "[5/6] single lines > 4000 chars (JS/TS)..."
long_lines=0
while IFS= read -r -d '' f; do
  case "$f" in ./docs/security/*) continue;; *.infected.*.bak) continue;; esac
  awk 'length($0)>4000{print FILENAME":"FNR" line is "length($0)" chars"; bad=1} END{exit bad?1:0}' "$f"
  if [ $? -ne 0 ]; then
    long_lines=1
  fi
done < <(find . \( -type d \( -name node_modules -o -name .git -o -name dist -o -name build -o -name .next -o -name coverage -o -name .turbo -o -name .nuxt \) \) -prune -o \
              -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' -o -name '*.tsx' -o -name '*.jsx' \) ! -name '*.infected.*.bak' -print0)
if [ "$long_lines" -ne 0 ]; then
  echo "  FAIL: pathologically long line(s) in JS/TS source"
  fail=1
else
  echo "  OK"
fi
hr

echo "[6/6] createRequire shim + long line in *.config.mjs..."
shim_hits=0
while IFS= read -r -d '' f; do
  if grep -q 'createRequire(import\.meta\.url)' "$f" \
     && awk 'length($0)>2000{f=1} END{exit f?0:1}' "$f"; then
    echo "  $f: createRequire + long line = payload pattern"
    shim_hits=1
  fi
done < <(find . \( -type d \( -name node_modules -o -name .git \) \) -prune -o -type f -name '*.config.mjs' -print0)
if [ "$shim_hits" -ne 0 ]; then
  echo "  FAIL: ESM re-entry shim pattern detected"
  fail=1
else
  echo "  OK"
fi
hr

if [ "$fail" -ne 0 ]; then
  echo "RESULT: FAIL — one or more IoCs detected. See output above."
  echo "Next: run restore-carrier.sh <path> for known carriers, or escalate unknown findings."
  exit 1
fi
echo "RESULT: OK — no known IoCs detected."
exit 0
