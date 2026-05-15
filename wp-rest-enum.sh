#!/usr/bin/env bash
# wp-rest-enum.sh
# Enumerate every register_rest_route call and its permission_callback.
# Flags AP-046 (__return_true), AP-047 (is_user_logged_in), AP-048 (missing).
#
# Usage: wp-rest-enum.sh <plugin-dir-or-zip>

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
    TMP_ROOT="$(mktemp -d -t wprestenum.XXXXXX)"
    unzip -qq "$INPUT" -d "$TMP_ROOT"
    inner=$(find "$TMP_ROOT" -mindepth 1 -maxdepth 1 -type d | head -1)
    TARGET_DIR="${inner:-$TMP_ROOT}"
else
    usage
fi

PHP_FILES=$(find "$TARGET_DIR" -type f -name '*.php' \
    -not -path '*/vendor/*' -not -path '*/vendor-prod/*' \
    -not -path '*/vendor_prefixed/*' -not -path '*/vendor-prefixed/*' \
    -not -path '*/node_modules/*' -not -path '*/dist/*' -not -path '*/build/*' \
    2>/dev/null)

printf '%s%sREST route inventory: %s%s\n' "$BLD" "$CYA" "$(basename "$TARGET_DIR")" "$RST"
echo "----------------------------------------------------------------"

# For each register_rest_route call, slice the next ~25 lines and look for
# `permission_callback => …`. Classify:
#   - __return_true              → UNAUTH    (AP-046)
#   - is_user_logged_in          → SUBSCRIBER (AP-047)
#   - current_user_can('cap')    → cap-band (lookup)
#   - [$this, 'method']          → "see method"
#   - (missing entirely)         → UNAUTH    (AP-048)

unauth_count=0
sub_count=0
admin_count=0
custom_count=0
missing_count=0
total=0

printf '%-3s  %-12s  %-30s  %-50s\n' "#" "AUTH" "CALLBACK / NOTE" "FILE:LINE"
echo "----------------------------------------------------------------"

while IFS= read -r match; do
    [ -z "$match" ] && continue
    total=$((total + 1))
    file="${match%%:*}"; rest="${match#*:}"
    lineno="${rest%%:*}"
    case "$lineno" in ''|*[!0-9]*) continue ;; esac
    # Bidirectional window: 50 lines forward for the common single-call shape,
    # 50 lines backward for the `register_rest_route($ns, $route, $collection)`
    # shape where $collection is built earlier in the same function.
    start=$((lineno - 50)); [ $start -lt 1 ] && start=1
    end=$((lineno + 50))
    window=$(sed -n "${start},${end}p" "$file" 2>/dev/null)

    perm_line=$(echo "$window" | grep -nE -e "permission_callback" | tail -1)
    relpath="${file#$TARGET_DIR/}"

    if [ -z "$perm_line" ]; then
        printf '%s%-3d  %-12s%s  %-30s  %-50s\n' "$RED" "$total" "MISSING" "$RST" "(no permission_callback in 100-line window)" "$relpath:$lineno"
        missing_count=$((missing_count + 1))
        continue
    fi

    perm_content=$(echo "$perm_line" | cut -d: -f2-)
    # Only match current_user_can followed by `(` — otherwise the literal
    # string "ITSEC_Core::current_user_can_manage" gets misclassified as a
    # cap check when it's actually a function-name string callback.
    has_cuc_call=0
    echo "$perm_content" | grep -qE -e "current_user_can[[:space:]]*\(" && has_cuc_call=1

    case "$perm_content" in
        *__return_true*)
            printf '%s%-3d  %-12s%s  %-30s  %-50s\n' "$RED" "$total" "UNAUTH" "$RST" "__return_true (AP-046)" "$relpath:$lineno"
            unauth_count=$((unauth_count + 1))
            ;;
        *is_user_logged_in*)
            printf '%s%-3d  %-12s%s  %-30s  %-50s\n' "$YEL" "$total" "SUBSCRIBER" "$RST" "is_user_logged_in (AP-047)" "$relpath:$lineno"
            sub_count=$((sub_count + 1))
            ;;
        *return_false*)
            printf '%s%-3d  %-12s%s  %-30s  %-50s\n' "$GRN" "$total" "DISABLED" "$RST" "__return_false (route disabled)" "$relpath:$lineno"
            ;;
        *)
            if [ "$has_cuc_call" = "1" ]; then
                cap=$(echo "$perm_content" | grep -oE -e "current_user_can[[:space:]]*\([[:space:]]*['\"][a-zA-Z_][a-zA-Z0-9_]+['\"]" | head -1)
                cap_name=$(echo "$cap" | grep -oE -e "['\"][a-zA-Z_][a-zA-Z0-9_]+['\"]" | head -1 | tr -d "'\"")
                case "$cap_name" in
                    manage_options|activate_plugins|manage_network|update_plugins|install_plugins|edit_plugins|edit_themes|switch_themes|manage_network_options|manage_network_plugins|manage_network_users|manage_network_themes|edit_files|update_core|edit_users|delete_users|create_users|list_users|promote_users|add_users|remove_users)
                        printf '%s%-3d  %-12s%s  %-30s  %-50s\n' "$GRN" "$total" "ADMIN" "$RST" "current_user_can('$cap_name')" "$relpath:$lineno"
                        admin_count=$((admin_count + 1))
                        ;;
                    *)
                        printf '%s%-3d  %-12s%s  %-30s  %-50s\n' "$YEL" "$total" "CAP-CHECK" "$RST" "current_user_can('${cap_name:-?}')" "$relpath:$lineno"
                        custom_count=$((custom_count + 1))
                        ;;
                esac
            else
                # Method ref or string callback. Surface the callback identifier.
                cb=$(echo "$perm_content" | grep -oE -e "['\"][a-zA-Z_][a-zA-Z0-9_:\\\\]+['\"]" | tail -1 | tr -d "'\"")
                # Strip leading namespace separator(s) for display
                cb_disp="${cb##*\\}"
                printf '%s%-3d  %-12s%s  %-30s  %-50s\n' "$CYA" "$total" "DELEGATED" "$RST" "${cb_disp:-callback} (read fn body)" "$relpath:$lineno"
                custom_count=$((custom_count + 1))
            fi
            ;;
    esac
done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE -e "register_rest_route[[:space:]]*\(" 2>/dev/null || true)

echo "----------------------------------------------------------------"
if [ "$total" = "0" ]; then
    echo "(no REST routes registered)"
    exit 0
fi
printf '%sTotal REST routes:%s %d\n' "$BLD" "$RST" "$total"
[ "$unauth_count"  -gt 0 ] && printf '  %sUNAUTH (AP-046):%s     %d  → top-priority manual review\n' "$RED" "$RST" "$unauth_count"
[ "$missing_count" -gt 0 ] && printf '  %sMISSING (AP-048):%s    %d  → top-priority manual review\n' "$RED" "$RST" "$missing_count"
[ "$sub_count"     -gt 0 ] && printf '  %sSUBSCRIBER+ (AP-047):%s %d  → in-scope for Wordfence\n' "$YEL" "$RST" "$sub_count"
[ "$custom_count"  -gt 0 ] && printf '  %sCAP / DELEGATED:%s     %d  → read enclosing callback to verify band\n' "$CYA" "$RST" "$custom_count"
[ "$admin_count"   -gt 0 ] && printf '  %sADMIN-gated:%s         %d  → out-of-scope (Wordfence)\n' "$GRN" "$RST" "$admin_count"
