#!/usr/bin/env bash
# wp-abspath-check.sh
# Verify every first-party PHP file starts with a defined('ABSPATH') guard.
# Maps to BC-61 / AP-056 — direct-PHP-file-access hardening.
#
# Usage: wp-abspath-check.sh <plugin-dir-or-zip>
#
# Exit code: 0 if all files guarded, 1 if any file unguarded.
# Output:    table of unguarded files for manual review.

set -u

RED=$'\033[0;31m'
GRN=$'\033[0;32m'
YEL=$'\033[0;33m'
BLD=$'\033[1m'
RST=$'\033[0m'

usage() {
    echo "Usage: $0 <plugin-dir-or-zip>" >&2
    exit 2
}

INPUT="${1:-}"
[ -z "$INPUT" ] && usage
[ ! -e "$INPUT" ] && { echo "Input not found: $INPUT" >&2; exit 2; }

TMP_ROOT=""
cleanup() { [ -n "$TMP_ROOT" ] && rm -rf "$TMP_ROOT"; }
trap cleanup EXIT

if [ -d "$INPUT" ]; then
    TARGET_DIR="$INPUT"
elif [ -f "$INPUT" ] && [[ "$INPUT" == *.zip ]]; then
    TMP_ROOT="$(mktemp -d -t wpabspath.XXXXXX)"
    unzip -qq "$INPUT" -d "$TMP_ROOT"
    inner=$(find "$TMP_ROOT" -mindepth 1 -maxdepth 1 -type d | head -1)
    TARGET_DIR="${inner:-$TMP_ROOT}"
else
    usage
fi

# Files in scope: first-party PHP, excluding vendor/build/etc.
# Also exclude class-definition-only files where direct access is harmless
# (they declare a class and return — no top-level executable code). We can't
# detect that automatically; the auditor verifies the listing manually.
PHP_FILES=$(find "$TARGET_DIR" -type f -name '*.php' \
    -not -path '*/vendor/*' -not -path '*/vendor-prod/*' \
    -not -path '*/vendor_prefixed/*' -not -path '*/vendor-prefixed/*' \
    -not -path '*/node_modules/*' -not -path '*/dist/*' -not -path '*/build/*' \
    2>/dev/null)

total=0
guarded=0
unguarded_files=""

while IFS= read -r f; do
    [ -z "$f" ] && continue
    [ -r "$f" ] || continue
    total=$((total + 1))
    # Read first 30 lines — enough for any reasonable docblock + guard.
    head30=$(head -n 30 "$f" 2>/dev/null)
    # Common guard forms:
    #   defined('ABSPATH') or exit;
    #   defined( 'ABSPATH' ) || exit;
    #   if ( ! defined( 'ABSPATH' ) ) { exit; }
    #   if (!defined('ABSPATH')) die;
    #   defined( 'ABSPATH' ) || die;
    if echo "$head30" | grep -qE -e "defined[[:space:]]*\([[:space:]]*['\"]ABSPATH['\"][[:space:]]*\)"; then
        guarded=$((guarded + 1))
    else
        relpath="${f#$TARGET_DIR/}"
        unguarded_files="$unguarded_files$relpath"$'\n'
    fi
done <<< "$PHP_FILES"

printf '%s%sABSPATH guard check: %s%s\n' "$BLD" "$YEL" "$(basename "$TARGET_DIR")" "$RST"
echo "----------------------------------------------------------------"
printf 'PHP files (first-party):  %d\n' "$total"
printf '%sGuarded:%s                  %d\n' "$GRN" "$RST" "$guarded"
unguarded_count=$((total - guarded))
if [ "$unguarded_count" = "0" ]; then
    printf '%sUnguarded:%s                0  — all files have defined(ABSPATH) check\n' "$GRN" "$RST"
    exit 0
fi
printf '%sUnguarded:%s                %d\n' "$RED" "$RST" "$unguarded_count"
echo
echo "Unguarded files (verify each: class-definition-only files are harmless;"
echo "files with top-level executable code are BC-61 candidates):"
echo
echo "$unguarded_files" | grep . | sed 's|^|  |'
exit 1
