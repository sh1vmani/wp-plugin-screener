#!/usr/bin/env bash
# wp-entry-points.sh
# WordPress plugin Phase 0 entry-point inventory.
# Emits a tabular summary of every reachable handler so Coverage Ledger
# (AUDIT-VERIFICATION-PROTOCOL Phase 1) can be filled in deterministically.
#
# Usage: wp-entry-points.sh <plugin-dir-or-zip>

set -u

RED=$'\033[0;31m'
YEL=$'\033[0;33m'
GRN=$'\033[0;32m'
CYA=$'\033[0;36m'
BLD=$'\033[1m'
RST=$'\033[0m'

usage() {
    echo "Usage: $0 <plugin-dir-or-zip>" >&2
    exit 1
}

INPUT="${1:-}"
[ -z "$INPUT" ] && usage
[ ! -e "$INPUT" ] && { echo "Input not found: $INPUT" >&2; exit 1; }

TMP_ROOT=""
cleanup() { [ -n "$TMP_ROOT" ] && rm -rf "$TMP_ROOT"; }
trap cleanup EXIT

if [ -d "$INPUT" ]; then
    TARGET_DIR="$INPUT"
elif [ -f "$INPUT" ] && [[ "$INPUT" == *.zip ]]; then
    command -v unzip >/dev/null || { echo "unzip not installed" >&2; exit 1; }
    TMP_ROOT="$(mktemp -d -t wpentry.XXXXXX)"
    unzip -qq "$INPUT" -d "$TMP_ROOT"
    inner=$(find "$TMP_ROOT" -mindepth 1 -maxdepth 1 -type d | head -1)
    TARGET_DIR="${inner:-$TMP_ROOT}"
else
    usage
fi

PHP_FILES=$(find "$TARGET_DIR" -type f -name '*.php' \
    -not -path '*/vendor/*' \
    -not -path '*/vendor-prod/*' \
    -not -path '*/vendor_prefixed/*' \
    -not -path '*/vendor-prefixed/*' \
    -not -path '*/node_modules/*' \
    -not -path '*/dist/*' \
    -not -path '*/build/*' \
    2>/dev/null)

PHP_COUNT=$(printf '%s\n' "$PHP_FILES" | grep -c . || true)

printf '%s%sWordPress Plugin Entry-Point Inventory%s\n' "$BLD" "$CYA" "$RST"
echo  "Target:  $TARGET_DIR"
echo  "Files:   $PHP_COUNT first-party PHP"
echo  "Scanned: $(date)"
echo  "----------------------------------------------------------------"
echo

# enum <label> <regex> <color> [exclude-regex]
# Optional 4th arg is a regex; lines matching it are filtered out of the count
# and listing. Used to subtract wp_ajax_nopriv_ from wp_ajax_ totals etc.
enum() {
    local label="$1" regex="$2" color="$3" exclude="${4:-}"
    local hits
    hits=$(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE -e "$regex" 2>/dev/null || true)
    if [ -n "$exclude" ]; then
        hits=$(printf '%s\n' "$hits" | grep -vE -e "$exclude" || true)
    fi
    local count
    count=$(printf '%s' "$hits" | grep -c . || true)
    [ -z "$count" ] && count=0
    printf '%s%-32s%s %d\n' "$color" "$label" "$RST" "$count"
    if [ "$count" -gt 0 ]; then
        echo "$hits" | sed 's|'"$TARGET_DIR"'/||; s|^|    |'
        echo
    fi
}

# Unauth channels — highest priority, red
enum "wp_ajax_nopriv_* (UNAUTH)"     "add_action[[:space:]]*\([[:space:]]*['\"]wp_ajax_nopriv_"                                  "$RED"
enum "admin_post_nopriv_* (UNAUTH)"  "add_action[[:space:]]*\([[:space:]]*['\"]admin_post_nopriv_"                               "$RED"

# Auth-required channels — yellow. Match all then exclude nopriv variant.
enum "wp_ajax_* (Subscriber+)"        "add_action[[:space:]]*\([[:space:]]*['\"]wp_ajax_[a-zA-Z]"      "$YEL"  "wp_ajax_nopriv_"
enum "admin_post_* (Subscriber+)"     "add_action[[:space:]]*\([[:space:]]*['\"]admin_post_[a-zA-Z]"   "$YEL"  "admin_post_nopriv_"

# REST — needs permission_callback inspection (use wp-rest-enum.sh for detail)
enum "register_rest_route"            "register_rest_route[[:space:]]*\("                                                        "$YEL"

# Public channels — render in front-end context, also yellow (XSS surface)
enum "add_shortcode"                  "add_shortcode[[:space:]]*\("                                                              "$YEL"
enum "register_block_type"            "register_block_type[[:space:]]*\("                                                        "$YEL"

# Hooks that fire on every request — cyan (file-level code under these is unauth)
enum "add_action('init')"             "add_action[[:space:]]*\([[:space:]]*['\"]init['\"]"                                       "$CYA"
enum "add_action('template_redirect')" "add_action[[:space:]]*\([[:space:]]*['\"]template_redirect['\"]"                         "$CYA"
enum "add_action('wp_loaded')"        "add_action[[:space:]]*\([[:space:]]*['\"]wp_loaded['\"]"                                  "$CYA"
enum "add_action('parse_request')"    "add_action[[:space:]]*\([[:space:]]*['\"]parse_request['\"]"                              "$CYA"

# Admin hooks — green (admin-context, lowest priority for Wordfence bounty scope)
enum "add_action('admin_init')"       "add_action[[:space:]]*\([[:space:]]*['\"]admin_init['\"]"                                 "$GRN"
enum "add_action('admin_menu')"       "add_action[[:space:]]*\([[:space:]]*['\"]admin_menu['\"]"                                 "$GRN"
enum "add_menu_page"                  "add_(menu|submenu)_page[[:space:]]*\("                                                    "$GRN"

# Cron — server-internal, can be triggered via wp_schedule_event with user args
enum "wp_schedule_event/single"       "wp_schedule_(event|single_event)[[:space:]]*\("                                           "$CYA"

# Filters worth knowing about
enum "save_post / pre_update_option"  "add_filter[[:space:]]*\([[:space:]]*['\"](save_post|wp_insert_post_data|pre_update_option|updated_post_meta)['\"]" "$CYA"

# Coverage summary line for AUDIT-VERIFICATION-PROTOCOL Phase 1
echo "----------------------------------------------------------------"
echo "${BLD}Coverage Ledger row (paste into Phase 1):${RST}"
nopriv_ajax=$(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -lE -e "add_action[[:space:]]*\([[:space:]]*['\"]wp_ajax_nopriv_" 2>/dev/null | wc -l)
priv_ajax=$(printf '%s\n' "$PHP_FILES" \
            | xargs -d '\n' -r grep -HnE -e "add_action[[:space:]]*\([[:space:]]*['\"]wp_ajax_[a-zA-Z]" 2>/dev/null \
            | grep -vE -e "wp_ajax_nopriv_" \
            | awk -F: '{print $1}' | sort -u | wc -l)
admin_post=$(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -lE -e "add_action[[:space:]]*\([[:space:]]*['\"]admin_post_" 2>/dev/null | wc -l)
rest=$(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -lE -e "register_rest_route" 2>/dev/null | wc -l)
shortcodes=$(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -lE -e "add_shortcode" 2>/dev/null | wc -l)
blocks=$(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -lE -e "register_block_type" 2>/dev/null | wc -l)
cat <<EOF

| Asset class                          | Total | Read | Skip | Reason |
| First-party PHP                      |  $PHP_COUNT |      |  0   |        |
| wp_ajax_nopriv_* (files)             |  $nopriv_ajax |      |  0   |        |
| wp_ajax_* (files)                    |  $priv_ajax |      |  0   |        |
| admin_post_* / admin_post_nopriv_*   |  $admin_post |      |  0   |        |
| REST routes (register_rest_route)    |  $rest |      |  0   |        |
| Shortcodes                           |  $shortcodes |      |  0   |        |
| Block render_callbacks               |  $blocks |      |  0   |        |
EOF
