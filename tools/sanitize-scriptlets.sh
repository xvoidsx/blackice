#!/usr/bin/env bash
# blackice: strip scriptlets that inject remote scripts.
#
# Chrome Web Store (MV3) rejects extensions containing code that creates
# <script> tags with remote src, even when it's a filter-list scriptlet
# intended for compatibility (e.g. re-injecting a comment system on one site).
# This sanitizer removes such scriptlets from the compiled output.
#
# Usage: sanitize-scriptlets.sh <build-output-dir>
# Example: sanitize-scriptlets.sh dist/build/blackice.chromium

set -e

BUILD_DIR="$1"
[ -n "$BUILD_DIR" ] || { echo "usage: $0 <build-output-dir>" >&2; exit 1; }
[ -d "$BUILD_DIR" ] || { echo "not a directory: $BUILD_DIR" >&2; exit 1; }

# Find all compiled scriptlet JS files
find "$BUILD_DIR" -path "*rulesets/scripting/scriptlet/*" -name "*.js" | while read -r f; do
    # Check if file contains remote script injection pattern
    if grep -q 'document\.createElement(\\"script\\")' "$f" 2>/dev/null; then
        echo "sanitizing: $f"
        # Remove the specific viafoura re-injection scriptlet.
        # This is a compatibility shim for gocomics.com that re-enables a
        # tracker — removing it aligns with blackice's block-everything philosophy.
        python3 - "$f" << 'PYEOF'
import sys, re
path = sys.argv[1]
with open(path, 'r', encoding='utf-8', errors='replace') as fh:
    content = fh.read()
# Remove the gocomics/viafoura compatibility scriptlet
# Pattern: the rpnt scriptlet that re-injects cdn.viafoura.net
original_len = len(content)
content = re.sub(
    r'gocomics\.com##\+js\(rpnt,[^)]*cdn\.viafoura\.net[^)]*\)',
    '',
    content
)
# Also strip the compiled JS version if present
content = re.sub(
    r'window\.addEventListener\([^)]*load[^)]*ShowComicViewer[^}]*cdn\.viafoura\.net[^}]*\}',
    '',
    content
)
if len(content) != original_len:
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(content)
    print(f"  stripped viafoura scriptlet from {path}")
else:
    print(f"  no viafoura pattern found in {path} (may already be clean)")
PYEOF
    fi
done

echo "sanitization complete"
