#!/usr/bin/env bash
# blackice: strip scriptlets that inject remote scripts.
#
# Chrome Web Store (MV3) rejects extensions containing code that creates
# <script> tags with remote src, even when it's a filter-list scriptlet
# intended for compatibility (e.g. re-injecting a comment system on one site).
# This sanitizer removes such scriptlets from the compiled output.
#
# Usage: sanitize-scriptlets.sh <build-output-dir>

set -e

BUILD_DIR="$1"
[ -n "$BUILD_DIR" ] || { echo "usage: $0 <build-output-dir>" >&2; exit 1; }
[ -d "$BUILD_DIR" ] || { echo "not a directory: $BUILD_DIR" >&2; exit 1; }

find "$BUILD_DIR" -path "*rulesets/scripting/scriptlet/*" -name "*.js" | while read -r f; do
    if grep -q "cdn\.viafoura\.net" "$f" 2>/dev/null; then
        echo "sanitizing: $f"
        python3 - "$f" << 'PYEOF'
import sys
path = sys.argv[1]
with open(path, 'r', encoding='utf-8', errors='replace') as fh:
    lines = fh.read().split('\n')
# The compiled scriptlet file has one JSON entry per line (roughly).
# Remove any line containing the viafoura CDN URL.
original = len(lines)
lines = [l for l in lines if 'cdn.viafoura.net' not in l]
removed = original - len(lines)
with open(path, 'w', encoding='utf-8') as fh:
    fh.write('\n'.join(lines))
print(f"  removed {removed} line(s) containing viafoura CDN from {path}")
PYEOF
    fi
done

echo "sanitization complete"
