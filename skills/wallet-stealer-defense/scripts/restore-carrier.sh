#!/usr/bin/env bash
# Restore a known infected carrier file to its canonical clean form.
#
# Supported carriers (auto-handled):
#   - postcss.config.{js,mjs,cjs}
#   - frontend/postcss.config.{js,mjs,cjs}
#   - .eslintrc.js
#
# Strategy:
#   postcss carrier  -> remove `createRequire` shim line if present,
#                       truncate at first standalone `export default` or
#                       `module.exports`, drop the malicious tail.
#   .eslintrc.js     -> truncate at the first top-level `};` (module.exports
#                       terminator; inner blocks use `},`).
#
# For unknown carriers, this script REFUSES and prints triage commands.
# Always work in a git repo with a clean working tree (script makes a backup).

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <path-to-carrier>" >&2
  exit 2
fi

target="$1"
if [ ! -f "$target" ]; then
  echo "error: $target not found" >&2
  exit 2
fi

base="$(basename -- "$target")"

# Quick IoC pre-check: is this file actually infected?
infected=0
if grep -qE '_\$_1e42|_\$af163278|_\$_ccfc' "$target" 2>/dev/null; then infected=1; fi
if grep -qF "global['!']='9-" "$target" 2>/dev/null; then infected=1; fi
if awk 'length>4000{e=1} END{exit e?0:1}' "$target"; then infected=1; fi

if [ "$infected" -eq 0 ]; then
  echo "no IoC found in $target — refusing to modify."
  echo "(if you believe this is a false negative, inspect manually with: less -S '$target')"
  exit 0
fi

# Make a forensic backup
backup="${target}.infected.$(date +%Y%m%d-%H%M%S).bak"
cp -p -- "$target" "$backup"
echo "backup: $backup"

case "$base" in
  postcss.config.js|postcss.config.mjs|postcss.config.cjs)
    echo "carrier type: postcss config"
    # Drop the createRequire shim line(s), then truncate at the export default / module.exports terminator.
    python3 - "$target" <<'PY'
import sys, re, io
p = sys.argv[1]
with io.open(p, 'r', encoding='utf-8', errors='replace') as f:
    src = f.read()

lines = src.splitlines()
out = []
for ln in lines:
    s = ln.strip()
    # remove the ESM re-entry shim added by the payload
    if 'createRequire' in s and 'import.meta.url' in s:
        continue
    if re.match(r"^import\s*\{\s*createRequire\s*\}\s*from\s*['\"]module['\"]\s*;?\s*$", s):
        continue
    out.append(ln)

joined = '\n'.join(out)

# Truncate at the first occurrence of `export default <ident>;` or `module.exports = ...;`
m = re.search(r"^(export\s+default\s+[A-Za-z_][\w]*\s*;)", joined, flags=re.MULTILINE)
if m:
    cleaned = joined[:m.end()] + '\n'
else:
    m = re.search(r"^(module\.exports\s*=\s*[^;]+;)", joined, flags=re.MULTILINE)
    if m:
        cleaned = joined[:m.end()] + '\n'
    else:
        sys.stderr.write("no export-default/module.exports terminator found; aborting\n")
        sys.exit(3)

with io.open(p, 'w', encoding='utf-8', newline='\n') as f:
    f.write(cleaned)
PY
    ;;

  .eslintrc.js|.eslintrc.cjs)
    echo "carrier type: eslintrc (CJS)"
    # Truncate at first top-level `};`. Inner blocks use `},` so this is unambiguous.
    python3 - "$target" <<'PY'
import sys, io
p = sys.argv[1]
with io.open(p, 'r', encoding='utf-8', errors='replace') as f:
    src = f.read()

# find the first occurrence of `};` at the start of a line (top-level terminator)
import re
m = re.search(r"^};", src, flags=re.MULTILINE)
if not m:
    sys.stderr.write("no top-level `};` terminator found; aborting\n")
    sys.exit(3)
cleaned = src[:m.end()] + '\n'

with io.open(p, 'w', encoding='utf-8', newline='\n') as f:
    f.write(cleaned)
PY
    ;;

  *)
    echo "error: $base is not a known carrier." >&2
    echo "" >&2
    echo "Known carriers: postcss.config.{js,mjs,cjs}, .eslintrc.{js,cjs}" >&2
    echo "" >&2
    echo "For unknown carriers, triage manually:" >&2
    echo "  1. Find the introducing commit:" >&2
    echo "       git log --all --oneline -S \"global['!']\" -- '$target'" >&2
    echo "       git log --follow --oneline -- '$target'" >&2
    echo "  2. Find the most recent clean ancestor and verify with:" >&2
    echo "       git show <sha>:'$target' | wc -c" >&2
    echo "  3. Restore that clean content:" >&2
    echo "       git show <sha>:'$target' > '$target'" >&2
    echo "  4. Backup of current (infected) file: $backup" >&2
    exit 4
    ;;
esac

# Verify
size=$(wc -c <"$target" | tr -d ' ')
maxline=$(awk '{ if(length>m) m=length } END{ print m+0 }' "$target")
markers=$(grep -cE '_\$_1e42|_\$af163278|_\$_ccfc' "$target" || true)
watermark=$(grep -cF "global['!']='9-" "$target" || true)

echo "post-restore: size=${size}B  max_line=${maxline}  markers=${markers}  watermark=${watermark}"
if [ "$markers" -ne 0 ] || [ "$watermark" -ne 0 ] || [ "$maxline" -gt 1000 ]; then
  echo "WARNING: residual IoCs present after restore. Inspect $target manually." >&2
  exit 5
fi
echo "OK: $target cleaned. Review the diff, then commit on every infected branch."
echo "Reminder: anyone who ran tooling on the infected branch must rotate secrets and move wallet funds."
