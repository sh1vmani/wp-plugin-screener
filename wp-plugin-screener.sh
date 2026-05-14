#!/usr/bin/env bash
# wp-plugin-screener.sh
# WordPress plugin security pre-screener.
# Usage: wp-plugin-screener.sh <plugin.zip|plugin-dir>

set -u

RED=$'\033[0;31m'
YEL=$'\033[0;33m'
GRN=$'\033[0;32m'
CYA=$'\033[0;36m'
BLD=$'\033[1m'
RST=$'\033[0m'

HIGH_COUNT=0
MED_COUNT=0
LOW_COUNT=0
FINDINGS=()

# Auth-band counters (in-scope findings, per band).
declare -A HIGH_BY_BAND=(
    [NOPRIV]=0
    [SUBSCRIBER]=0
    [AUTHOR]=0
    [EDITOR]=0
    [ADMIN]=0
    [UNKNOWN]=0
)
declare -A MED_BY_BAND=(
    [NOPRIV]=0
    [SUBSCRIBER]=0
    [AUTHOR]=0
    [EDITOR]=0
    [ADMIN]=0
    [UNKNOWN]=0
)
# Out-of-scope counters: findings filtered out because their auth band is
# above MAX_AUTH. Tracked separately so the user can see how much they're
# dropping vs. what's left.
AUTH_OOS_HIGH=0
AUTH_OOS_MED=0
AUTH_OOS_LOW=0

# Auth-band ordering for filter comparisons. Lower index = more reachable.
declare -A BAND_RANK=(
    [NOPRIV]=0
    [SUBSCRIBER]=1
    [AUTHOR]=2
    [EDITOR]=3
    [ADMIN]=4
    [UNKNOWN]=99   # treat unknown above everything by default; --auth-untagged-show overrides display, not rank
)

# Default MAX_AUTH if not set by CLI yet (defensive — set -u tolerant).
# CLI parsing below will overwrite, then we recompute MAX_AUTH_RANK there.
MAX_AUTH="${MAX_AUTH:-all}"
MAX_AUTH_RANK=99

# Standard WordPress capability → auth-band table. Lookups against the
# capability literal inside `current_user_can('X')` calls. Plugin-defined
# custom caps are discovered at run time by the CAP_DISCOVERY pre-pass below.
#
# Banding rule: choose the SHALLOWEST default role that has the cap on a
# vanilla single-site install. WP standard caps as of WP 6.7. Bands above
# AUTHOR are "Wordfence out of scope" per the bounty rules.
declare -A STD_CAP_BAND=(
    # Subscriber
    [read]=SUBSCRIBER
    # Contributor / Author (we collapse both into AUTHOR band — "mid-level")
    [edit_posts]=AUTHOR
    [delete_posts]=AUTHOR
    [publish_posts]=AUTHOR
    [upload_files]=AUTHOR
    [edit_published_posts]=AUTHOR
    [delete_published_posts]=AUTHOR
    # Editor (out of scope for Wordfence)
    [edit_others_posts]=EDITOR
    [delete_others_posts]=EDITOR
    [edit_pages]=EDITOR
    [publish_pages]=EDITOR
    [delete_pages]=EDITOR
    [edit_others_pages]=EDITOR
    [delete_others_pages]=EDITOR
    [edit_published_pages]=EDITOR
    [delete_published_pages]=EDITOR
    [read_private_posts]=EDITOR
    [read_private_pages]=EDITOR
    [manage_categories]=EDITOR
    [manage_links]=EDITOR
    [moderate_comments]=EDITOR
    [unfiltered_html]=EDITOR
    # Administrator (out of scope)
    [activate_plugins]=ADMIN
    [delete_plugins]=ADMIN
    [edit_plugins]=ADMIN
    [install_plugins]=ADMIN
    [update_plugins]=ADMIN
    [delete_themes]=ADMIN
    [edit_themes]=ADMIN
    [install_themes]=ADMIN
    [update_themes]=ADMIN
    [switch_themes]=ADMIN
    [edit_users]=ADMIN
    [delete_users]=ADMIN
    [create_users]=ADMIN
    [list_users]=ADMIN
    [promote_users]=ADMIN
    [add_users]=ADMIN
    [remove_users]=ADMIN
    [manage_options]=ADMIN
    [edit_dashboard]=ADMIN
    [import]=ADMIN
    [export]=ADMIN
    [update_core]=ADMIN
    [edit_files]=ADMIN
    # Super Admin (multisite) — also ADMIN band for our purposes
    [manage_network]=ADMIN
    [manage_sites]=ADMIN
    [manage_network_users]=ADMIN
    [manage_network_plugins]=ADMIN
    [manage_network_themes]=ADMIN
    [manage_network_options]=ADMIN
    [upgrade_network]=ADMIN
    [setup_network]=ADMIN
    # WooCommerce / common ecommerce — ADMIN band
    [manage_woocommerce]=ADMIN
    [view_woocommerce_reports]=ADMIN
    [edit_shop_orders]=ADMIN
    [edit_others_shop_orders]=ADMIN
    [edit_product]=ADMIN
    [edit_products]=ADMIN
)

# Plugin-defined custom caps: populated by CAP_DISCOVERY pre-pass.
declare -A CUSTOM_CAP_BAND=()

usage() {
    cat >&2 <<EOF
Usage: $0 [--max-auth=<band>] [--auth-untagged-show] <plugin.zip|plugin-directory>

  --max-auth=<band>         Filter findings reachable only by auth bands ABOVE
                            the given level. Use this to focus on Wordfence-
                            bountyable findings (Editor+/Admin are out of scope).
                            Bands (lower = more reachable):
                              nopriv         (unauthenticated)
                              subscriber     (Subscriber / Customer / Student)
                              author         (Contributor / Author)        [default]
                              editor         (Editor)
                              admin          (Administrator / Shop Manager / Super Admin)
                              all            (no filtering — tag only)
                            Findings AT or BELOW the band are kept; ABOVE are
                            counted as auth-out-of-scope in the summary.
  --auth-untagged-show      When --max-auth is set, also show findings whose
                            auth band could not be classified (default: hide).

EOF
    exit 1
}

# CLI parsing
MAX_AUTH="all"
AUTH_UNTAGGED_SHOW=0
INPUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --max-auth=*)        MAX_AUTH="${1#--max-auth=}" ;;
        --max-auth)          shift; MAX_AUTH="${1:-}" ;;
        --auth-untagged-show) AUTH_UNTAGGED_SHOW=1 ;;
        -h|--help)           usage ;;
        --)                  shift; break ;;
        --*)                 echo "Unknown option: $1" >&2; usage ;;
        *)                   INPUT="$1" ;;
    esac
    shift
done
case "$MAX_AUTH" in
    nopriv)     MAX_AUTH_RANK=0 ;;
    subscriber) MAX_AUTH_RANK=1 ;;
    author)     MAX_AUTH_RANK=2 ;;
    editor)     MAX_AUTH_RANK=3 ;;
    admin)      MAX_AUTH_RANK=4 ;;
    all)        MAX_AUTH_RANK=99 ;;
    *) echo "Invalid --max-auth: $MAX_AUTH" >&2; usage ;;
esac
[ -z "$INPUT" ] && usage
[ ! -e "$INPUT" ] && { echo "Input not found: $INPUT" >&2; exit 1; }

OUT_DIR="$HOME/screener-results"
mkdir -p "$OUT_DIR"

TMP_ROOT="$(mktemp -d -t wpscreener.XXXXXX)"
# trap is installed below, after we know OUT_FILE / RAW_LOG

# Resolve target dir
if [ -d "$INPUT" ]; then
    TARGET_DIR="$INPUT"
    PLUGIN_NAME="$(basename "$(realpath "$INPUT")")"
elif [ -f "$INPUT" ]; then
    case "$INPUT" in
        *.zip|*.ZIP)
            command -v unzip >/dev/null || { echo "unzip not installed" >&2; exit 1; }
            unzip -qq "$INPUT" -d "$TMP_ROOT/unpacked"
            # If single top-level dir, use it
            inner=$(find "$TMP_ROOT/unpacked" -mindepth 1 -maxdepth 1 -type d | head -1)
            count=$(find "$TMP_ROOT/unpacked" -mindepth 1 -maxdepth 1 | wc -l)
            if [ "$count" = "1" ] && [ -d "$inner" ]; then
                TARGET_DIR="$inner"
            else
                TARGET_DIR="$TMP_ROOT/unpacked"
            fi
            PLUGIN_NAME="$(basename "$INPUT" .zip)"
            PLUGIN_NAME="${PLUGIN_NAME%.ZIP}"
            ;;
        *)
            echo "Unsupported input. Pass a .zip or directory." >&2
            exit 1
            ;;
    esac
else
    usage
fi

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUT_FILE="$OUT_DIR/${PLUGIN_NAME}-${TIMESTAMP}.txt"
RAW_LOG="$TMP_ROOT/raw.log"

strip_ansi() { sed 's/\x1B\[[0-9;]*[a-zA-Z]//g'; }

# Mirror stdout to a raw log; on exit, strip ANSI into the report file.
exec 3>&1
exec > >(tee "$RAW_LOG" >&3)
TEE_PID=$!
finalize() {
    # Flush and close the tee pipeline cleanly
    exec 1>&3 3>&-
    wait "$TEE_PID" 2>/dev/null || true
    [ -s "$RAW_LOG" ] && strip_ansi < "$RAW_LOG" > "$OUT_FILE"
}
cleanup() { finalize; rm -rf "$TMP_ROOT"; }
trap cleanup EXIT

printf "%s%sWordPress Plugin Security Pre-Screener%s\n" "$BLD" "$CYA" "$RST"
echo "Plugin:    $PLUGIN_NAME"
echo "Source:    $INPUT"
echo "Scanned:   $(date)"
echo "Report:    $OUT_FILE"
echo "----------------------------------------------------------------"
echo

# Build file lists once
# Vendored/compiled paths excluded by default. Override with --include-vendored.
EXCLUDE_VENDORED=1
for arg in "$@"; do
    [ "$arg" = "--include-vendored" ] && EXCLUDE_VENDORED=0
done

if [ "$EXCLUDE_VENDORED" = "1" ]; then
    PHP_FILES=$(find "$TARGET_DIR" -type f -name '*.php' \
                  -not -path '*/vendor/*' \
                  -not -path '*/vendor-prod/*' \
                  -not -path '*/vendor_prefixed/*' \
                  -not -path '*/node_modules/*' \
                  -not -path '*/dist/*' \
                  -not -path '*/build/*' \
                  2>/dev/null)
    JS_FILES=$(find "$TARGET_DIR" -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' -o -name '*.vue' \) \
                  -not -path '*/vendor/*' \
                  -not -path '*/vendor-prod/*' \
                  -not -path '*/vendor_prefixed/*' \
                  -not -path '*/node_modules/*' \
                  -not -path '*/dist/*' \
                  -not -path '*/build/*' \
                  -not -name '*.min.js' \
                  2>/dev/null)
    PHP_VENDOR_FILES=$(find "$TARGET_DIR" -type f -name '*.php' \
                  \( -path '*/vendor/*' -o -path '*/vendor-prod/*' -o -path '*/vendor_prefixed/*' -o -path '*/dist/*' -o -path '*/build/*' \) \
                  2>/dev/null)
    JS_VENDOR_FILES=$(find "$TARGET_DIR" -type f \( -name '*.js' -o -name '*.jsx' \) \
                  \( -path '*/vendor/*' -o -path '*/vendor-prod/*' -o -path '*/vendor_prefixed/*' -o -path '*/dist/*' -o -path '*/build/*' -o -name '*.min.js' \) \
                  2>/dev/null)
else
    PHP_FILES=$(find "$TARGET_DIR" -type f -name '*.php' 2>/dev/null)
    JS_FILES=$(find "$TARGET_DIR" -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' -o -name '*.vue' \) 2>/dev/null)
    PHP_VENDOR_FILES=""
    JS_VENDOR_FILES=""
fi

PHP_COUNT_FILES=$(printf '%s\n' "$PHP_FILES" | grep -c . || true)
JS_COUNT_FILES=$(printf '%s\n' "$JS_FILES" | grep -c . || true)
PHP_VENDOR_COUNT=$(printf '%s\n' "$PHP_VENDOR_FILES" | grep -c . || true)
JS_VENDOR_COUNT=$(printf '%s\n' "$JS_VENDOR_FILES" | grep -c . || true)
echo "Files (first-party): $PHP_COUNT_FILES PHP, $JS_COUNT_FILES JS/Vue/TS"
if [ "$EXCLUDE_VENDORED" = "1" ] && { [ "$PHP_VENDOR_COUNT" -gt 0 ] || [ "$JS_VENDOR_COUNT" -gt 0 ]; }; then
    echo "Files (vendored, EXCLUDED from scan): $PHP_VENDOR_COUNT PHP, $JS_VENDOR_COUNT JS"
fi
echo

color_for() {
    case "$1" in
        HIGH)   printf '%s' "$RED" ;;
        MEDIUM) printf '%s' "$YEL" ;;
        LOW)    printf '%s' "$GRN" ;;
    esac
}

# Load per-plugin suppress list. Format: <plugin_root>/.screener-suppress
# Each line is `file:line:category`. Lines beginning with `#` are comments.
# Use this to mark known-FP locations after audit so the screener doesn't
# re-emit them on subsequent runs.
SUPPRESS_FILE=""
if [ -d "$TARGET_DIR" ] && [ -f "$TARGET_DIR/.screener-suppress" ]; then
    SUPPRESS_FILE="$TARGET_DIR/.screener-suppress"
fi
declare -A SUPPRESS_MAP=()
SUPPRESS_LOADED=0
if [ -n "$SUPPRESS_FILE" ]; then
    while IFS= read -r sl; do
        case "$sl" in ''|'#'*) continue ;; esac
        SUPPRESS_MAP[$sl]=1
        SUPPRESS_LOADED=$((SUPPRESS_LOADED + 1))
    done < "$SUPPRESS_FILE"
    [ "$SUPPRESS_LOADED" -gt 0 ] && echo "  (loaded $SUPPRESS_LOADED suppressions from .screener-suppress)"
fi

SUPPRESSED_COUNT=0

# Color helper for auth-band tag display.
band_color() {
    case "$1" in
        NOPRIV)     echo "$RED" ;;       # bright red — best/worst, best yield
        SUBSCRIBER) echo "$YEL" ;;       # yellow — low auth
        AUTHOR)     echo "$YEL" ;;       # yellow — mid auth
        EDITOR)     echo "$CYA" ;;       # dim — out of scope
        ADMIN)      echo "$CYA" ;;       # dim — out of scope
        *)          echo "$CYA" ;;       # unknown
    esac
}

# add_finding <severity> <category> <file:line> <evidence> [band]
# If the optional 5th arg (band) is omitted, classify_auth_band is called on
# the location. If --max-auth was set on the CLI, findings whose band ranks
# above MAX_AUTH are NOT printed (counted as AUTH_OOS_*) so the user can focus
# on Wordfence-bountyable findings.
add_finding() {
    local sev="$1" cat="$2" loc="$3" ev="$4" band="${5:-}"
    # Strip target dir prefix (used for suppress matching and display)
    loc="${loc#$TARGET_DIR/}"
    # Suppress check: file:line:category triple
    if [ -n "${SUPPRESS_MAP["${loc}:${cat}"]:-}" ]; then
        SUPPRESSED_COUNT=$((SUPPRESSED_COUNT + 1))
        return
    fi

    # Derive band from location if not supplied by caller.
    if [ -z "$band" ]; then
        local _loc_file _loc_line _loc_full
        _loc_full="${loc%%:[!:]*}"; _loc_full="${loc%:*}"  # everything before last :NN
        _loc_file="${loc%:*}"
        _loc_line="${loc##*:}"
        # The location was stripped of TARGET_DIR/, so re-prefix for file read
        case "$_loc_file" in
            /*) ;;
            *) _loc_file="$TARGET_DIR/$_loc_file" ;;
        esac
        band=$(classify_auth_band "$_loc_file" "$_loc_line")
    fi
    [ -z "$band" ] && band="UNKNOWN"

    # Filter by --max-auth (default "all" = no filter).
    local band_rank="${BAND_RANK[$band]:-99}"
    if [ "$MAX_AUTH_RANK" -lt 99 ]; then
        # UNKNOWN: include unless explicitly hidden
        if [ "$band" = "UNKNOWN" ] && [ "$AUTH_UNTAGGED_SHOW" = "0" ]; then
            : # show it (UNKNOWN findings are suspicious; default to display)
        fi
        if [ "$band_rank" -gt "$MAX_AUTH_RANK" ] && [ "$band" != "UNKNOWN" ]; then
            # Drop out-of-scope, count separately
            case "$sev" in
                HIGH)   AUTH_OOS_HIGH=$((AUTH_OOS_HIGH + 1)) ;;
                MEDIUM) AUTH_OOS_MED=$((AUTH_OOS_MED + 1)) ;;
                LOW)    AUTH_OOS_LOW=$((AUTH_OOS_LOW + 1)) ;;
            esac
            FINDINGS+=("$sev|$cat|$loc|$band|OOS")
            return
        fi
    fi

    case "$sev" in
        HIGH)
            HIGH_COUNT=$((HIGH_COUNT + 1))
            HIGH_BY_BAND[$band]=$(( ${HIGH_BY_BAND[$band]:-0} + 1 ))
            ;;
        MEDIUM)
            MED_COUNT=$((MED_COUNT + 1))
            MED_BY_BAND[$band]=$(( ${MED_BY_BAND[$band]:-0} + 1 ))
            ;;
        LOW)
            LOW_COUNT=$((LOW_COUNT + 1))
            ;;
    esac
    local c bc
    c=$(color_for "$sev")
    bc=$(band_color "$band")
    # Truncate evidence
    ev="${ev:0:160}"
    # %-32s + 2-space separator guarantees the validate.py parser's `\s{2,}`
    # gate always fires, even for max-length categories like
    # "ajax handler missing cap/nonce" (30 chars).
    printf '  %s[%s]%s %s[%s]%s %-32s  %s\n' "$c" "$sev" "$RST" "$bc" "$band" "$RST" "$cat" "$loc"
    printf '       %s\n' "$ev"
    FINDINGS+=("$sev|$cat|$loc|$band|IN")
}

section() {
    printf '%s== %s ==%s\n' "$BLD" "$1" "$RST"
}

# Helper: run pcre2grep-like search using grep -RnE; emit finding per match.
# scan_pattern <severity> <category> <regex> <file_list_var>
# Skip lines that are obviously single-line comments or inside docblocks.
is_comment_line() {
    [[ "$1" =~ ^[[:space:]]*(//|#|\*|/\*) ]]
}

scan_pattern_php() {
    # Optional 4th arg: explicit auth band to apply to every emitted finding.
    # Use this when the rule itself implies the band (e.g., rule 4 fires on
    # `wp_ajax_nopriv_*` registrations — band is unambiguously NOPRIV
    # regardless of which file the registration sits in).
    local sev="$1" cat="$2" regex="$3" band="${4:-}"
    [ -z "$PHP_FILES" ] && return
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local file rest lineno content
        file="${line%%:*}"; rest="${line#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        is_comment_line "$content" && continue
        add_finding "$sev" "$cat" "$file:$lineno" "$content" "$band"
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE "$regex" 2>/dev/null || true)
}

scan_pattern_js() {
    local sev="$1" cat="$2" regex="$3" flags="${4:-}" band="${5:-}"
    [ -z "$JS_FILES" ] && return
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local file rest lineno content
        file="${line%%:*}"; rest="${line#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        is_comment_line "$content" && continue
        add_finding "$sev" "$cat" "$file:$lineno" "$content" "$band"
    done < <(printf '%s\n' "$JS_FILES" | xargs -d '\n' -r grep -HnE $flags "$regex" 2>/dev/null || true)
}

############################
# PRE-PASS: plugin-defined sanitizer/escape wrappers
############################
# Inventory the plugin's own sanitization/escape helpers so rule 9 can treat
# them as legitimate sanitizers. Without this, every superglobal piped through
# a custom wrapper (e.g. mailchimp's `mc4wp_kses`, `mc4wp_sanitize_deep`) gets
# flagged HIGH. Names matching common sanitization vocabulary in the function
# identifier are added to rule 9's ±3-line context regex.
#
# Conservative vocabulary: `sanitize`, `escape`/`esc_`, `kses`, `clean`,
# `safe_`, `normalize`, `strip`. Excludes `format`/`filter` (too many WP-hook
# callback false positives — `add_filter('foo', ...)` callback functions).
PLUGIN_SANITIZERS=""
if [ -n "$PHP_FILES" ]; then
    PLUGIN_SANITIZERS=$(printf '%s\n' "$PHP_FILES" \
        | xargs -d '\n' -r grep -hE 'function[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\(' 2>/dev/null \
        | grep -ioE 'function[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]+' \
        | sed -E 's/function[[:space:]]+//' \
        | grep -iE '(sanitize|escape|esc_|kses|safe_|normalize|^strip_|_strip_|^clean_|_clean_)' \
        | sort -u | tr '\n' '|' | sed 's/|$//')
fi

############################
# PRE-PASS: plugin-defined custom capability discovery
############################
# Walk every PHP file looking for capability-assignment patterns:
#   $role->add_cap('foo_bar')           (most common — role object from get_role())
#   $admin->add_cap('foo_bar')          (variant; classify by variable name)
#   add_cap('foo_bar')                  (calls on an implicit role object)
#   get_role('administrator')->add_cap('foo_bar')   (inline)
# and the surrounding role context (the `get_role('X')` or `$role = X` that
# the cap is assigned to) so we can map foo_bar → its highest-priority role.
#
# Result: CUSTOM_CAP_BAND['foo_bar'] = ADMIN | EDITOR | AUTHOR | SUBSCRIBER
# Highest reachable role wins (i.e., if a cap is granted to Author AND
# Administrator, we band it AUTHOR — the threshold the bug actually requires).
if [ -n "$PHP_FILES" ]; then
    # Find every line with an add_cap call AND a window of ~30 lines before it
    # so we can see the get_role / $role = ... assignment. Streamed via awk.
    while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        file="${entry%%:*}"; rest="${entry#*:}"
        lineno="${rest%%:*}"
        # Window: 30 lines before, 1 line after
        start=$((lineno - 30)); [ $start -lt 1 ] && start=1
        end=$((lineno + 1))
        window=$(sed -n "${start},${end}p" "$file" 2>/dev/null)

        # Extract capability name from THIS line.
        cap=$(echo "$rest" | grep -oE "add_cap\s*\(\s*['\"][a-zA-Z0-9_]+['\"]" \
              | head -1 | grep -oE "['\"][a-zA-Z0-9_]+['\"]" | sed -E "s/['\"]//g" | head -1)
        [ -z "$cap" ] && continue

        # Determine the role this cap belongs to. Look in the window for
        # role names mentioned in get_role()/foreach(array(...))/$role =
        # construction. Lower-priority roles win — we report the SHALLOWEST
        # role any add_cap path grants to (because that's the threshold the
        # attacker actually needs).
        band="UNKNOWN"
        if echo "$window" | grep -qE "['\"](subscriber|customer|student)['\"]"; then
            band="SUBSCRIBER"
        elif echo "$window" | grep -qE "['\"](contributor|author)['\"]"; then
            band="AUTHOR"
        elif echo "$window" | grep -qE "['\"]editor['\"]|['\"]shop_manager['\"]"; then
            band="EDITOR"
        elif echo "$window" | grep -qE "['\"](administrator|super_admin)['\"]"; then
            band="ADMIN"
        fi

        # Record the SHALLOWEST band ever seen for this cap.
        prev="${CUSTOM_CAP_BAND[$cap]:-}"
        if [ -z "$prev" ]; then
            CUSTOM_CAP_BAND[$cap]="$band"
        else
            # Keep the lower rank
            prev_rank="${BAND_RANK[$prev]:-99}"
            new_rank="${BAND_RANK[$band]:-99}"
            if [ "$new_rank" -lt "$prev_rank" ]; then
                CUSTOM_CAP_BAND[$cap]="$band"
            fi
        fi
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE "->[[:space:]]*add_cap\s*\(\s*['\"]" 2>/dev/null || true)
fi

############################
# PRE-PASS: AJAX handler → band map (O(scan once), not O(N×M per finding))
############################
# Walk every PHP file ONCE looking for add_action('wp_ajax_*', callback) and
# add_action('wp_ajax_nopriv_*', callback) calls. Extract the callback name
# (string or array form). Build a hash: AJAX_HANDLER_BAND[func_name] = band.
# NOPRIV beats priv (anyone-logged-in) at the same name. classify_auth_band()
# looks up by function name in O(1) instead of grepping every file per call.
declare -A AJAX_HANDLER_BAND=()
if [ -n "$PHP_FILES" ]; then
    while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        line="${entry#*:*:}"  # drop file:lineno: prefix
        # Same callback-extraction logic as Rule 10
        tail_after_hook=$(echo "$line" | sed -E "s/^.*wp_ajax_(nopriv_)?[a-zA-Z0-9_-]+['\"][[:space:]]*,//")
        cb=$(echo "$tail_after_hook" | grep -oE "['\"][a-zA-Z0-9_\\\\]+['\"]" | tail -1 | sed -E "s/['\"]//g")
        [ -z "$cb" ] && continue
        is_nopriv=0
        echo "$line" | grep -q "wp_ajax_nopriv_" && is_nopriv=1
        # Choose the more permissive band (NOPRIV wins).
        prev="${AJAX_HANDLER_BAND[$cb]:-}"
        if [ "$is_nopriv" = "1" ] || [ -z "$prev" ]; then
            if [ "$is_nopriv" = "1" ] || [ "$prev" != "NOPRIV" ]; then
                AJAX_HANDLER_BAND[$cb]=$([ "$is_nopriv" = "1" ] && echo NOPRIV || echo SUBSCRIBER)
            fi
        fi
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE "add_action\s*\(\s*['\"]wp_ajax_" 2>/dev/null || true)
fi

############################
# PRE-PASS: admin-menu callback → band map
############################
# WordPress's `add_menu_page` and `add_submenu_page` register an admin-screen
# callback with an explicit capability. The cap is the 3rd positional arg of
# `add_menu_page` and the 4th of `add_submenu_page`. Any function reached
# through these paths is effectively gated by that cap regardless of what
# `current_user_can` calls live inside the function body — typically NONE,
# because the menu registration already enforced the cap.
#
# Without this pre-pass, classify_auth_band tagged admin-screen handlers as
# SUBSCRIBER (because they had a nonce check but no cap check in the body),
# leading to spurious in-scope HIGHs. Now we map callback → capability and
# resolve the cap to its band via STD_CAP_BAND / CUSTOM_CAP_BAND.
#
# Result: MENU_CALLBACK_BAND[func_name] = NOPRIV | SUBSCRIBER | AUTHOR | EDITOR | ADMIN
declare -A MENU_CALLBACK_BAND=()
if [ -n "$PHP_FILES" ]; then
    # add_menu_page($page_title, $menu_title, $capability, $menu_slug, $callback, ...)
    #   ^ args 1     2            3 cap        4           5 callback
    # add_submenu_page($parent_slug, $page_title, $menu_title, $capability, $menu_slug, $callback, ...)
    #   ^ args 1                     2            3            4 cap        5           6 callback
    while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        line="${entry#*:*:}"
        # Determine which function and slice off the call prefix so positions
        # are predictable. We do a coarse comma-split inside the parens.
        # Conservative: only handle the case where the cap and callback are
        # both on a single line (the common case in WP plugins).
        is_submenu=0
        echo "$line" | grep -q 'add_submenu_page' && is_submenu=1

        # Extract everything between the outermost ( ... )
        args_blob=$(echo "$line" | sed -E 's/^[^(]*\(//; s/\)[^)]*$//')

        # Split by commas at depth 0. Bash doesn't have nested-aware splitter
        # cheaply; for the simple `'literal'` / `array($this,'method')` /
        # `[$this,'method']` shapes used in WP, awk gives us a usable split.
        # Strategy: replace `[$this,'fn']` and `array($this,'fn')` with
        # `<<CB>>'fn'<<CB>>` first so the comma inside the callback array
        # doesn't confuse positional split.
        normalized=$(echo "$args_blob" | sed -E "s/\[[[:space:]]*\\\$this[[:space:]]*,[[:space:]]*(['\"][^'\"]+['\"])[[:space:]]*\]/<<CB>>\1<<CB>>/g; s/array[[:space:]]*\(\s*\\\$this[[:space:]]*,[[:space:]]*(['\"][^'\"]+['\"])[[:space:]]*\)/<<CB>>\1<<CB>>/g")

        # Now split on top-level commas.
        IFS=',' read -ra parts <<< "$normalized"
        # Trim whitespace from each part
        for i in "${!parts[@]}"; do
            parts[$i]="$(echo "${parts[$i]}" | sed -E 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        done

        if [ "$is_submenu" = "1" ]; then
            cap_idx=3
            cb_idx=5
        else
            cap_idx=2
            cb_idx=4
        fi
        cap_raw="${parts[$cap_idx]:-}"
        cb_raw="${parts[$cb_idx]:-}"
        # Strip quotes around cap
        cap=$(echo "$cap_raw" | grep -oE "['\"][a-zA-Z0-9_]+['\"]" | head -1 | sed -E "s/['\"]//g")
        # Callback: the last quoted identifier in the raw (handles both
        # 'fn' and <<CB>>'method'<<CB>>).
        cb=$(echo "$cb_raw" | grep -oE "['\"][a-zA-Z0-9_\\\\]+['\"]" | tail -1 | sed -E "s/['\"]//g")
        [ -z "$cap" ] && continue
        [ -z "$cb" ] && continue

        # Map cap to band.
        band="${STD_CAP_BAND[$cap]:-}"
        [ -z "$band" ] && band="${CUSTOM_CAP_BAND[$cap]:-}"
        [ -z "$band" ] && continue

        # Take the shallowest band ever seen for this callback (a callback
        # registered on multiple menu pages with different caps gets the
        # most-permissive of them).
        prev="${MENU_CALLBACK_BAND[$cb]:-}"
        if [ -z "$prev" ]; then
            MENU_CALLBACK_BAND[$cb]="$band"
        else
            prev_rank="${BAND_RANK[$prev]:-99}"
            new_rank="${BAND_RANK[$band]:-99}"
            if [ "$new_rank" -lt "$prev_rank" ]; then
                MENU_CALLBACK_BAND[$cb]="$band"
            fi
        fi
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE "add_(menu|submenu)_page\s*\(" 2>/dev/null || true)
fi

# PRE-PASS: per-file admin/public hook count cache.
# `classify_auth_band` previously re-ran two `grep -c` calls per finding to
# count admin-vs-public hooks in the enclosing file. On big plugins with
# many findings per file, that's wasteful. Cache it once per file.
# (FILE_ADMIN_HOOKS / FILE_PUBLIC_HOOKS were replaced by FILE_HOOK_BAND in
# _populate_file_cache below — one awk pass extracts everything.)

# Per-file data cache for classify_auth_band. Populated lazily on first call
# per file. One awk pass per file extracts ALL function spans, their caps,
# and the file-level admin/public hook counts. After that, classify_auth_band
# is pure bash hash lookups + in-memory parse — no subprocesses per finding.
#
# FILE_FUNC_DATA[file] format (newline-separated, one line per function):
#   <start>|<end>|<func_name>|<caps_csv>|<has_login_floor>
declare -A FILE_FUNC_DATA=()
declare -A FILE_HOOK_BAND=()   # cached file-level admin/public/none hint

# _populate_file_cache <file>
# Runs ONE awk pass over the file to extract everything classify_auth_band
# needs. After this returns, FILE_FUNC_DATA[file] and FILE_HOOK_BAND[file]
# are populated.
_populate_file_cache() {
    local file="$1"
    [ -n "${FILE_FUNC_DATA[$file]+set}" ] && return
    [ ! -r "$file" ] && { FILE_FUNC_DATA[$file]=""; FILE_HOOK_BAND[$file]="UNKNOWN"; return; }

    # Awk script: tracks current function span and caps within. Emits one
    # record per function when the function ends (next function starts OR
    # EOF). Also counts file-level admin vs public hook patterns.
    local awk_out
    awk_out=$(awk '
        BEGIN { in_func=0; func_start=0; func_name=""; caps=""; floor=0; admin_hooks=0; pub_hooks=0 }
        function emit() {
            if (in_func) {
                printf "F|%d|%d|%s|%s|%d\n", func_start, NR - 1, func_name, caps, floor
            }
            in_func=0; caps=""; floor=0
        }
        # Detect function start
        /^[[:space:]]*(public|private|protected|static|final|abstract)?[[:space:]]*(public|private|protected|static|final|abstract)?[[:space:]]*function[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\(/ {
            emit()
            in_func=1; func_start=NR
            match($0, /function[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*/)
            func_name = substr($0, RSTART + 9, RLENGTH - 9)
            sub(/^[[:space:]]+/, "", func_name)
            next
        }
        # While inside a function, collect caps + login-floor markers.
        in_func {
            # Match current_user_can with single or double quoted cap name.
            line = $0
            while (match(line, /current_user_can[[:space:]]*\([[:space:]]*['\''"][a-zA-Z0-9_]+['\''"]/)) {
                m = substr(line, RSTART, RLENGTH)
                # Extract cap name between quotes
                if (match(m, /['\''"][a-zA-Z0-9_]+['\''"]/)) {
                    cap = substr(m, RSTART + 1, RLENGTH - 2)
                    if (caps == "") caps = cap; else caps = caps "," cap
                }
                line = substr(line, RSTART + RLENGTH)
            }
            if (/is_user_logged_in[[:space:]]*\(\)|check_ajax_referer|check_admin_referer|wp_verify_nonce/) {
                floor = 1
            }
        }
        # Hook counters (file-level — count regardless of in_func).
        /add_action[[:space:]]*\([[:space:]]*['\''"](admin_init|admin_menu|admin_post_|current_screen|admin_notices|in_admin_header|admin_enqueue_scripts)/ { admin_hooks++ }
        /add_action[[:space:]]*\([[:space:]]*['\''"]wp_ajax_[a-zA-Z]/ && !/wp_ajax_nopriv_/ { admin_hooks++ }
        /add_action[[:space:]]*\([[:space:]]*['\''"](wp_ajax_nopriv_|template_redirect|wp_enqueue_scripts|wp_loaded|parse_request|wp_head|wp_footer|template_include)/ { pub_hooks++ }
        END {
            emit()
            printf "H|%d|%d\n", admin_hooks, pub_hooks
        }
    ' "$file" 2>/dev/null)

    # Split: function records + 1 hook record at the end.
    local hook_line
    hook_line=$(printf '%s\n' "$awk_out" | grep '^H|' | tail -1)
    FILE_FUNC_DATA[$file]=$(printf '%s\n' "$awk_out" | grep '^F|')

    # Derive file-level hint from hook counts.
    local _ah _ph
    _ah="${hook_line#H|}"; _ah="${_ah%|*}"
    _ph="${hook_line##*|}"
    : "${_ah:=0}"; : "${_ph:=0}"
    if [ "$_ah" -gt "$_ph" ] && [ "$_ah" -gt 2 ]; then
        FILE_HOOK_BAND[$file]="ADMIN"
    elif [ "$_ph" -gt "$_ah" ] && [ "$_ph" -gt 2 ]; then
        FILE_HOOK_BAND[$file]="NOPRIV"
    else
        FILE_HOOK_BAND[$file]="UNKNOWN"
    fi
}

# classify_auth_band <file> <lineno>
# After _populate_file_cache runs (lazily), this is pure bash hash/string ops.
# Output: prints band ("NOPRIV" / "SUBSCRIBER" / "AUTHOR" / "EDITOR" /
# "ADMIN" / "UNKNOWN") to stdout.
classify_auth_band() {
    local file="$1" lineno="$2"
    [ ! -r "$file" ] && { echo "UNKNOWN"; return; }
    case "$lineno" in ''|*[!0-9]*) echo "UNKNOWN"; return ;; esac

    _populate_file_cache "$file"

    local rec func_name caps floor start end
    local matched_record=""
    while IFS= read -r rec; do
        [ -z "$rec" ] && continue
        # rec format: F|<start>|<end>|<func_name>|<caps_csv>|<has_login_floor>
        IFS='|' read -r _tag start end func_name caps floor <<< "$rec"
        if [ "$lineno" -ge "$start" ] && [ "$lineno" -le "$end" ]; then
            matched_record="$rec"
            break
        fi
    done <<< "${FILE_FUNC_DATA[$file]}"

    # No enclosing function found — file-level code.
    if [ -z "$matched_record" ]; then
        # Path-based check first (admin/public file conventions).
        case "$file" in
            */admin/*|*/Admin/*|*/admin-*/*|*/Admin-*/*|*/wp-admin/*) echo "ADMIN"; return ;;
            */frontend/*|*/Frontend/*|*/public/*|*/Public/*) echo "NOPRIV"; return ;;
            */class-*-admin.php|*admin-ajax*.php) echo "ADMIN"; return ;;
            */class-*-public.php|*/class-*-frontend.php) echo "NOPRIV"; return ;;
        esac
        # File-level code with no cap context — likely runs on every load.
        echo "NOPRIV"; return
    fi

    # AJAX handler lookup (O(1)).
    if [ -n "$func_name" ]; then
        local ajax_band="${AJAX_HANDLER_BAND[$func_name]:-}"
        if [ -n "$ajax_band" ]; then
            echo "$ajax_band"; return
        fi
    fi

    # Admin-menu callback lookup (O(1)). When the function is registered as
    # an admin-page callback via add_menu_page / add_submenu_page, the cap on
    # that registration is what gates the function — usually `manage_options`
    # = ADMIN, but the cap can be any standard or custom cap.
    if [ -n "$func_name" ]; then
        local menu_band="${MENU_CALLBACK_BAND[$func_name]:-}"
        if [ -n "$menu_band" ]; then
            echo "$menu_band"; return
        fi
    fi

    # Caps from the function body — choose the SHALLOWEST band among them.
    local cap band rank shallowest_band="UNKNOWN" shallowest_rank=99
    if [ -n "$caps" ]; then
        IFS=',' read -r -a _cap_arr <<< "$caps"
        for cap in "${_cap_arr[@]}"; do
            [ -z "$cap" ] && continue
            band="${STD_CAP_BAND[$cap]:-}"
            [ -z "$band" ] && band="${CUSTOM_CAP_BAND[$cap]:-}"
            [ -z "$band" ] && continue
            rank="${BAND_RANK[$band]:-99}"
            if [ "$rank" -lt "$shallowest_rank" ]; then
                shallowest_rank="$rank"; shallowest_band="$band"
            fi
        done
    fi

    if [ "$shallowest_band" != "UNKNOWN" ]; then
        echo "$shallowest_band"; return
    fi

    # No cap, but has nonce / is_user_logged_in floor → SUBSCRIBER.
    if [ "$floor" = "1" ]; then
        echo "SUBSCRIBER"; return
    fi

    # 4) Path-based fallback heuristic. By WordPress plugin convention:
    #
    #   - Files under */admin/*, */Admin/*, or named class-*-admin.php /
    #     */admin-ajax*.php run in the wp-admin context. Reachable only by
    #     users who can `read` (Subscriber+) at minimum — admin-side checks
    #     (`is_admin()`, `admin_menu`, `admin_init`) shift the effective floor
    #     to whatever role the admin menu entry is registered at. The safest
    #     conservative assumption is ADMIN unless the function shows otherwise.
    #
    #   - Files under */frontend/*, */Frontend/*, */public/*, or named
    #     class-*-public.php / class-*-frontend.php run on the public site
    #     and may be reached unauthenticated. NOPRIV by convention.
    #
    # This is a heuristic — it can be overridden by an explicit cap check in
    # the function (handled above). Without an explicit cap, the convention
    # is the best signal we have.
    case "$file" in
        */admin/*|*/Admin/*|*/admin-*/*|*/Admin-*/*|*/wp-admin/*|*/wp-Admin/*) echo "ADMIN"; return ;;
        */frontend/*|*/Frontend/*|*/public/*|*/Public/*) echo "NOPRIV"; return ;;
        */class-*-admin.php|*admin-ajax*.php) echo "ADMIN"; return ;;
        */class-*-public.php|*/class-*-frontend.php) echo "NOPRIV"; return ;;
    esac

    # File-level hook hint (cached in _populate_file_cache).
    local hint="${FILE_HOOK_BAND[$file]:-UNKNOWN}"
    echo "$hint"
}

############################
# PHP CHECKS
############################
section "PHP checks"

if [ -n "$PLUGIN_SANITIZERS" ]; then
    n_san=$(echo "$PLUGIN_SANITIZERS" | tr '|' '\n' | grep -c .)
    echo "  (recognizing $n_san plugin-defined sanitizer wrappers)"
fi

# 1. sslverify => false
scan_pattern_php HIGH "sslverify=false" \
    "['\"]sslverify['\"][[:space:]]*=>[[:space:]]*(false|0)\b"

# 2. eval()
scan_pattern_php HIGH "eval()" \
    "(^|[^[:alnum:]_])eval[[:space:]]*\("

# 3. unserialize() — insecure PHP deserialization.
# Calibration showed this rule had 0 TPs / 28 FPs on the corpus. Tighten by
# excluding:
#  - $x->unserialize(...) — method calls on user-defined wrappers (e.g. fluent-smtp's Logger::unserialize)
#  - "function unserialize(...)" — user method definitions
#  - PHP 7+ safe form: unserialize($x, ['allowed_classes' => false])
if [ -n "$PHP_FILES" ]; then
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        file="${match%%:*}"; rest="${match#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        case "$lineno" in ''|*[!0-9]*) continue ;; esac
        is_comment_line "$content" && continue
        # Method call (->unserialize) or method definition skip
        echo "$content" | grep -qE "function[[:space:]]+unserialize[[:space:]]*\(" && continue
        # Safe form: allowed_classes => false
        echo "$content" | grep -qE "allowed_classes['\"]?[[:space:]]*=>[[:space:]]*false" && continue
        add_finding HIGH "unserialize()" "$file:$lineno" "$content"
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE "(^|[^[:alnum:]_>])unserialize[[:space:]]*\(" 2>/dev/null || true)
fi

# 4. wp_ajax_nopriv handlers (unauth AJAX) — band is unambiguously NOPRIV.
scan_pattern_php MEDIUM "wp_ajax_nopriv handler" \
    "add_action[[:space:]]*\([[:space:]]*['\"]wp_ajax_nopriv_" \
    "NOPRIV"

# 5. file_put_contents / move_uploaded_file
scan_pattern_php HIGH "file write / upload" \
    "(^|[^[:alnum:]_])(move_uploaded_file|file_put_contents)[[:space:]]*\("

# 11. superglobal-as-path-component — path-traversal pattern (CWE-22).
# Two-rule pair:
#   11a (this block, same-line) — sink call where the superglobal is in the
#       argument list of the sink directly. Highest precision, lowest recall.
#   11b (block below) — sink call takes a variable; the variable traces back
#       through up to two assignment hops within the same function to a
#       superglobal read. Catches the indirect form seen in Pirate Forms
#       (line 1245-46: `$dir_new = ...$form_id...` / `wp_mkdir_p($dir_new)`).
#
# This pattern matches the Pirate Forms 2.6.1 finding
# (public/class-pirateforms-public.php:1245-46) and Forminator CVE-2025-6463
# (file deletion via entry-id from $_POST).
#
# Higher confidence than Rule 5: Rule 5 just says "there's a file write
# anywhere in the file"; Rule 11 says "the write argument contains
# attacker-controlled input on the SAME LINE."
#
# Sinks covered (write + delete + dir-create + symlink):
#   wp_mkdir_p, mkdir, move_uploaded_file, file_put_contents, fopen, copy,
#   rename, symlink, link, unlink, wp_delete_file
#
# Inline sanitizer skip: if the superglobal is wrapped by sanitize_file_name /
# realpath / absint / wp_unique_filename / basename on the same line, skip —
# those are the canonical safe wrappers for path inputs.
if [ -n "$PHP_FILES" ]; then
    sink_re='(wp_mkdir_p|mkdir|move_uploaded_file|file_put_contents|fopen|copy|rename|symlink|link|unlink|wp_delete_file)[[:space:]]*\([^)]*\$_(GET|POST|REQUEST)'
    safe_re='sanitize_file_name|wp_unique_filename|realpath|absint|intval|\(int\)|basename'
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        file="${match%%:*}"; rest="${match#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        case "$lineno" in ''|*[!0-9]*) continue ;; esac
        is_comment_line "$content" && continue
        # Same-line sanitizer wrap — drop if any standard path-safe wrapper
        # is present on the same line (regardless of position; we don't
        # need to verify the wrapper is around the superglobal specifically,
        # since false positives on path sinks are cheaper than misses).
        if echo "$content" | grep -qE "$safe_re"; then
            continue
        fi
        add_finding HIGH "superglobal in path/file sink" "$file:$lineno" "$content"
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE "$sink_re" 2>/dev/null || true)
fi

# 11b. path/file sink takes a variable that traces back to a superglobal via
# 1-2 assignment hops within the same enclosing function. Uses the function
# span cache built by _populate_file_cache so we don't re-walk the file.
#
# Examples it catches (and the bug class):
#   Pirate Forms 2.6.1, public/class-pirateforms-public.php:1245-46
#     $form_id  = $_POST['pirate_forms_form_id'];   // upstream (somewhere in same fn)
#     $dir_new  = $this->...( "saved/$form_id" );   // 1-hop var
#     wp_mkdir_p( $dir_new );                       // sink — Rule 11b fires HERE
#   Forminator <= 1.44.2, entry deletion: same shape, deletion side.
#
# Bounded to 2 hops to keep cost predictable. Real flow analysis is v0.2.
if [ -n "$PHP_FILES" ]; then
    # Sink call whose FIRST argument is a $variable (not a superglobal directly —
    # 11a above already handles that case). Capture both the sink name and the
    # variable name so the trace can start.
    sink_var_re='(wp_mkdir_p|mkdir|move_uploaded_file|file_put_contents|fopen|copy|rename|symlink|link|unlink|wp_delete_file)[[:space:]]*\([[:space:]]*\$([a-zA-Z_][a-zA-Z0-9_]+)'
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        file="${match%%:*}"; rest="${match#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        case "$lineno" in ''|*[!0-9]*) continue ;; esac
        is_comment_line "$content" && continue

        # Skip if 11a would have already fired (sink line contains a superglobal directly).
        if echo "$content" | grep -qE '\$_(GET|POST|REQUEST)'; then continue; fi

        # Extract the variable name passed as the first arg. Take the first
        # $var on the line that follows a known sink — there can be more
        # than one sink-shaped match in the line, but the first is reliable.
        var=$(echo "$content" | grep -oE "$sink_var_re" | head -1 | sed -E 's/.*\$([a-zA-Z_][a-zA-Z0-9_]+).*/\1/')
        [ -z "$var" ] && continue

        # Find enclosing function span from the cache.
        _populate_file_cache "$file"
        func_start=0; func_end=0
        while IFS= read -r rec; do
            [ -z "$rec" ] && continue
            IFS='|' read -r _tag _s _e _ _ _ <<< "$rec"
            if [ "$lineno" -ge "$_s" ] && [ "$lineno" -le "$_e" ]; then
                func_start="$_s"; func_end="$_e"
                break
            fi
        done <<< "${FILE_FUNC_DATA[$file]}"
        [ "$func_start" = "0" ] && continue

        # Slice the function body once for both hops.
        body=$(sed -n "${func_start},${func_end}p" "$file" 2>/dev/null)

        # 1-hop: $var = ... $_POST/$_GET/$_REQUEST ... on a single line within
        # the function body.
        if echo "$body" | grep -qE "\\\$${var}[[:space:]]*=[^;]*\\\$_(GET|POST|REQUEST)"; then
            add_finding HIGH "path/file sink <- superglobal (1-hop)" "$file:$lineno" "$content"
            continue
        fi

        # 2-hop: $var = ... $other_var ...   and   $other_var = ... $_POST ...
        # Pull the assignment line for $var, extract any other variable names
        # in its RHS, and check each for an upstream superglobal assignment in
        # the same function body.
        var_assign=$(echo "$body" | grep -E "^\s*\\\$${var}[[:space:]]*=" | head -1)
        [ -z "$var_assign" ] && continue
        # Strip the LHS so we don't include $var itself.
        rhs=$(echo "$var_assign" | sed -E "s/^\s*\\\$${var}[[:space:]]*=//")
        other_vars=$(echo "$rhs" | grep -oE '\$[a-zA-Z_][a-zA-Z0-9_]+' | sed 's/^\$//' | sort -u | grep -vE "^(${var}|this)$")
        [ -z "$other_vars" ] && continue
        hit=""
        while IFS= read -r ov; do
            [ -z "$ov" ] && continue
            if echo "$body" | grep -qE "\\\$${ov}[[:space:]]*=[^;]*\\\$_(GET|POST|REQUEST)"; then
                hit="$ov"
                break
            fi
        done <<< "$other_vars"
        if [ -n "$hit" ]; then
            add_finding HIGH "path/file sink <- superglobal (2-hop via \$$hit)" "$file:$lineno" "$content"
        fi
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE "$sink_var_re" 2>/dev/null || true)
fi

# 6. wp_localize_script / wp_add_inline_script with secrets — multi-line aware.
# For each call, scan up to 25 lines ahead for a secret-ish key.
if [ -n "$PHP_FILES" ]; then
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        file="${match%%:*}"; rest="${match#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        case "$lineno" in ''|*[!0-9]*) continue ;; esac
        is_comment_line "$content" && continue
        end=$((lineno + 25))
        window=$(sed -n "${lineno},${end}p" "$file" 2>/dev/null)
        hit=$(echo "$window" | grep -inE "(api[_-]?key|secret|access[_-]?token|auth[_-]?token|bearer|password|passwd|pwd)" | head -1 || true)
        [ -z "$hit" ] && continue
        # offset within window
        off="${hit%%:*}"
        case "$off" in ''|*[!0-9]*) off=1 ;; esac
        actual=$((lineno + off - 1))
        evidence=$(echo "$hit" | cut -d: -f2-)
        add_finding HIGH "secret leaked to JS" "$file:$actual" "$evidence"
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE "(wp_localize_script|wp_add_inline_script)[[:space:]]*\(" 2>/dev/null || true)
fi

# 7. Direct $wpdb queries - flag $wpdb->query/get_results/get_var/get_row using superglobal on same line
scan_pattern_php HIGH "wpdb query w/ superglobal" \
    "\\\$wpdb->(query|get_results|get_var|get_row|get_col)[[:space:]]*\(.*(\\\$_GET|\\\$_POST|\\\$_REQUEST|\\\$_COOKIE)"

# 8. $wpdb->prepare missing - $wpdb->query with concatenation but no prepare
scan_pattern_php MEDIUM "wpdb query w/ concat (no prepare)" \
    "\\\$wpdb->(query|get_results|get_var|get_row)[[:space:]]*\([^)]*\\\$[a-zA-Z_]"

# 9. Unsanitized superglobal usage - find lines using $_GET/$_POST/$_REQUEST,
#    then check ±3 lines for sanitization; if absent, check enclosing function
#    for cap/nonce gates and downgrade if present.
if [ -n "$PHP_FILES" ]; then
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        file="${match%%:*}"; rest="${match#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        case "$lineno" in ''|*[!0-9]*) continue ;; esac
        is_comment_line "$content" && continue

        # Skip comparison-only usage: $_GET['x'] === 'literal' or vice versa.
        # Comparison reads can't write to sinks; they're guards/dispatchers.
        # Calibration showed this is the dominant FP shape in defensive code
        # (iThemes Security, WCML upgrade dispatch).
        if echo "$content" | grep -qE "\\\$_(GET|POST|REQUEST)\[[^]]+\][[:space:]]*(===|!==|==|!=)|(===|!==|==|!=)[[:space:]]*\\\$_(GET|POST|REQUEST)\["; then
            continue
        fi

        # Skip pure validator-call usage: in_array($_X, ...), preg_match(re, $_X),
        # is_string($_X), is_array($_X), is_int($_X), is_numeric($_X), ctype_*($_X),
        # and read-only string-introspection: strpos/stripos/strstr/strlen/strrpos
        # (these inspect the value to decide a branch — they don't pipe to a sink).
        if echo "$content" | grep -qE "(in_array|preg_match|is_string|is_array|is_int|is_numeric|is_bool|ctype_[a-z]+|strpos|stripos|strstr|strlen|strrpos|str_starts_with|str_ends_with|str_contains)[[:space:]]*\([^)]*\\\$_(GET|POST|REQUEST)\["; then
            continue
        fi

        # ±3 line context check (existing logic — sanitization wrappers).
        # Extended with: preg_match, in_array, is_string, is_int, is_numeric,
        # ctype_*, hash_equals — all common validators that flank a read.
        # Also extended at runtime with plugin-defined sanitizer wrappers
        # discovered by the pre-pass (PLUGIN_SANITIZERS).
        start=$((lineno - 3)); [ $start -lt 1 ] && start=1
        end=$((lineno + 3))
        ctx=$(sed -n "${start},${end}p" "$file" 2>/dev/null)
        ctx_regex="sanitize_[a-z_]+|esc_(html|attr|url|js|sql|textarea)|wp_kses|wp_verify_nonce|check_ajax_referer|check_admin_referer|intval|absint|floatval|\(int\)|filter_var|filter_input|preg_match|in_array|is_string|is_int|is_numeric|ctype_[a-z]+|hash_equals"
        [ -n "$PLUGIN_SANITIZERS" ] && ctx_regex="$ctx_regex|$PLUGIN_SANITIZERS"
        if echo "$ctx" | grep -qE "$ctx_regex"; then
            continue
        fi

        # Skip pure isset/empty/array_key_exists guards
        if echo "$content" | grep -qE "^[[:space:]]*(if[[:space:]]*\(?[[:space:]]*)?(!?[[:space:]]*(isset|empty|array_key_exists))"; then
            if ! echo "$content" | grep -qE "=[^=]"; then
                continue
            fi
        fi

        # NEW: Check enclosing function for cap/nonce gate.
        # Find the most recent `function` declaration before lineno.
        # If found within 200 lines above, scan from there to lineno+5 for gates.
        func_search_start=$((lineno - 200)); [ $func_search_start -lt 1 ] && func_search_start=1
        func_line=$(awk -v target="$lineno" '
            /^[[:space:]]*(public|private|protected|static|function)[[:space:]]+/ && /function/ { last=NR }
            NR == target { print last; exit }
        ' "$file" 2>/dev/null)

        is_gated=0
        if [ -n "$func_line" ] && [ "$func_line" -gt 0 ] && [ "$func_line" -lt "$lineno" ]; then
            gate_window=$(sed -n "${func_line},${lineno}p" "$file" 2>/dev/null)
            if echo "$gate_window" | grep -qE "current_user_can|check_ajax_referer|check_admin_referer|wp_verify_nonce|is_user_logged_in|is_admin\(\)"; then
                is_gated=1
            fi
        fi

        if [ "$is_gated" = "1" ]; then
            # Downgrade: function is gated, but the use is unsanitized within gate.
            # Worth a glance but not a HIGH.
            add_finding MEDIUM "superglobal in gated function (verify use)" "$file:$lineno" "$content"
        else
            add_finding HIGH "unsanitized superglobal" "$file:$lineno" "$content"
        fi
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE "\\\$_(GET|POST|REQUEST)\b" 2>/dev/null || true)
fi

# 10. Missing capability checks near AJAX handlers.
# Find `add_action('wp_ajax_*', $callback)`, where $callback is either a string
# 'function_name' or an array form `array($this, 'method')` / `[$this, 'method']`
# / `[Class::class, 'method']`. Locate the function definition in the repo and
# verify the body has current_user_can / check_*_referer / wp_verify_nonce.
#
# Array-callback support added 2026-05-13 after calibration showed rule 10 has
# 100% precision but recall is bottlenecked by skipping array forms — woocommerce-
# multilingual's wcml_hide_notice handler was previously missed for this reason.
if [ -n "$PHP_FILES" ]; then
    declare -A AJAX_SEEN=()
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        file="${match%%:*}"; rest="${match#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"

        # Extract callback method/function name. Strategy: strip through the
        # wp_ajax_xxx hook-name and its trailing comma, then take the LAST
        # quoted identifier in the remainder. This works uniformly for:
        #   'fn_name'  ·  array($this,'method')  ·  [$this,'method']
        #   [Class::class,'method']  ·  array('ClassName','method')
        tail_after_hook=$(echo "$content" | sed -E "s/^.*wp_ajax_(nopriv_)?[a-zA-Z0-9_-]+['\"][[:space:]]*,//")
        cb=$(echo "$tail_after_hook" | grep -oE "['\"][a-zA-Z0-9_\\\\]+['\"]" | tail -1 | sed -E "s/['\"]//g")
        [ -z "$cb" ] && continue

        is_nopriv=0
        echo "$content" | grep -q "wp_ajax_nopriv_" && is_nopriv=1

        # Dedup on callback name — a handler registered as BOTH wp_ajax_ and
        # wp_ajax_nopriv_ used to emit twice (MEDIUM + HIGH for the same
        # function definition). Keep only the most-severe (nopriv if present).
        prev_sev="${AJAX_SEEN[$cb]:-}"
        if [ "$prev_sev" = "HIGH" ]; then
            continue                 # nopriv already reported, skip lesser
        elif [ "$prev_sev" = "MEDIUM" ] && [ "$is_nopriv" = "0" ]; then
            continue                 # same priv form already reported
        fi

        # Find function definition. Prefer same-file match (the common case:
        # a class registers its own methods). Falls back to repo-wide grep
        # only if the same-file lookup fails. This is both more accurate (no
        # cross-class collisions on common names like `init`/`handle`) and
        # dramatically faster on big plugins.
        def=$(grep -HnE "function[[:space:]]+${cb}[[:space:]]*\(" "$file" 2>/dev/null | head -1)
        if [ -z "$def" ]; then
            def=$(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -lE "function[[:space:]]+${cb}[[:space:]]*\(" 2>/dev/null \
                  | head -1 | xargs -r grep -HnE "function[[:space:]]+${cb}[[:space:]]*\(" 2>/dev/null | head -1)
        fi
        [ -z "$def" ] && continue
        deffile="${def%%:*}"; rest2="${def#*:}"; defline="${rest2%%:*}"
        case "$defline" in ''|*[!0-9]*) continue ;; esac
        # Body = from `function NAME(` until next top-level `function ` (or +80 lines).
        body=$(awk -v start="$defline" '
            NR < start { next }
            NR == start { print; next }
            /^[[:space:]]*function[[:space:]]/ { exit }
            NR > start + 80 { exit }
            { print }
        ' "$deffile" 2>/dev/null)
        if echo "$body" | grep -qE "current_user_can|check_ajax_referer|check_admin_referer|wp_verify_nonce"; then
            continue
        fi
        sev="MEDIUM"
        band="SUBSCRIBER"   # priv handler with no cap = any logged-in user (subscriber floor)
        if [ "$is_nopriv" = "1" ]; then
            sev="HIGH"
            band="NOPRIV"
        fi
        AJAX_SEEN[$cb]="$sev"
        add_finding "$sev" "ajax handler missing cap/nonce" "$deffile:$defline" "function ${cb}(...) — no current_user_can / nonce check" "$band"
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE "add_action[[:space:]]*\([[:space:]]*['\"]wp_ajax_" 2>/dev/null \
              | awk '/wp_ajax_nopriv_/ {n=n $0 "\n"; next} {p=p $0 "\n"} END {printf "%s%s", n, p}' || true)
fi

echo

############################
# JS / VUE CHECKS
############################
section "JS / Vue / TS checks"

# v-html
scan_pattern_js HIGH "v-html" \
    "v-html[[:space:]]*="

# innerHTML assignment
scan_pattern_js HIGH "innerHTML assignment" \
    "\\.innerHTML[[:space:]]*(\+)?="

# dangerouslySetInnerHTML
scan_pattern_js HIGH "dangerouslySetInnerHTML" \
    "dangerouslySetInnerHTML"

# Hardcoded API keys / tokens
# Common patterns: AWS AKIA..., Google AIza..., generic key="..."/token="..." with long value
scan_pattern_js HIGH "hardcoded AWS key" \
    "AKIA[0-9A-Z]{16}"
scan_pattern_js HIGH "hardcoded Google API key" \
    "AIza[0-9A-Za-z_-]{35}"
scan_pattern_js HIGH "GitHub token" \
    "gh[pousr]_[A-Za-z0-9]{30,}"
scan_pattern_js HIGH "Slack token" \
    "xox[baprs]-[A-Za-z0-9-]{10,}"
scan_pattern_js MEDIUM "hardcoded secret-like assignment" \
    "(api[_-]?key|secret|access[_-]?token|auth[_-]?token|password|passwd)[[:space:]]*[:=][[:space:]]*['\"][A-Za-z0-9_/+=.-]{16,}['\"]" \
    "-i"

echo

############################
# SUMMARY
############################
section "Summary (first-party code only; vendored excluded)"
printf '  %sHIGH:   %d%s   (first-party)\n' "$RED" "$HIGH_COUNT" "$RST"
printf '  %sMEDIUM: %d%s\n' "$YEL" "$MED_COUNT" "$RST"
printf '  %sLOW:    %d%s\n' "$GRN" "$LOW_COUNT" "$RST"
[ "$SUPPRESSED_COUNT" -gt 0 ] && printf '  suppressed: %d  (per .screener-suppress)\n' "$SUPPRESSED_COUNT"
echo

# Auth-band breakdown — counts ONLY in-scope (or all if --max-auth=all).
# Wordfence eligibility: NOPRIV / SUBSCRIBER / AUTHOR are in-scope; EDITOR
# and ADMIN are explicitly out of scope per the bounty rules. The breakdown
# lets the user see how much of the surface lives in each band without
# re-reading the per-finding output.
WF_IN_SCOPE_HIGH=$(( ${HIGH_BY_BAND[NOPRIV]:-0} + ${HIGH_BY_BAND[SUBSCRIBER]:-0} + ${HIGH_BY_BAND[AUTHOR]:-0} ))
WF_IN_SCOPE_MED=$(( ${MED_BY_BAND[NOPRIV]:-0} + ${MED_BY_BAND[SUBSCRIBER]:-0} + ${MED_BY_BAND[AUTHOR]:-0} ))
WF_OOS_HIGH=$(( ${HIGH_BY_BAND[EDITOR]:-0} + ${HIGH_BY_BAND[ADMIN]:-0} ))
WF_OOS_MED=$(( ${MED_BY_BAND[EDITOR]:-0} + ${MED_BY_BAND[ADMIN]:-0} ))

section "Auth-band breakdown"
printf '  %-12s  HIGH=%2d  MEDIUM=%2d   %s\n' "NOPRIV"      "${HIGH_BY_BAND[NOPRIV]:-0}"     "${MED_BY_BAND[NOPRIV]:-0}"     "(unauthenticated)"
printf '  %-12s  HIGH=%2d  MEDIUM=%2d   %s\n' "SUBSCRIBER"  "${HIGH_BY_BAND[SUBSCRIBER]:-0}" "${MED_BY_BAND[SUBSCRIBER]:-0}" "(Subscriber / Customer / Student)"
printf '  %-12s  HIGH=%2d  MEDIUM=%2d   %s\n' "AUTHOR"      "${HIGH_BY_BAND[AUTHOR]:-0}"     "${MED_BY_BAND[AUTHOR]:-0}"     "(Contributor / Author)"
printf '  %-12s  HIGH=%2d  MEDIUM=%2d   %s\n' "EDITOR"      "${HIGH_BY_BAND[EDITOR]:-0}"     "${MED_BY_BAND[EDITOR]:-0}"     "${CYA}(Wordfence: OUT-OF-SCOPE)${RST}"
printf '  %-12s  HIGH=%2d  MEDIUM=%2d   %s\n' "ADMIN"       "${HIGH_BY_BAND[ADMIN]:-0}"      "${MED_BY_BAND[ADMIN]:-0}"      "${CYA}(Wordfence: OUT-OF-SCOPE)${RST}"
printf '  %-12s  HIGH=%2d  MEDIUM=%2d   %s\n' "UNKNOWN"     "${HIGH_BY_BAND[UNKNOWN]:-0}"    "${MED_BY_BAND[UNKNOWN]:-0}"    "(classifier couldn't tell)"
echo
printf '  '"$BLD"'Wordfence in-scope:'"$RST"'      HIGH=%d  MEDIUM=%d\n' "$WF_IN_SCOPE_HIGH" "$WF_IN_SCOPE_MED"
printf '  Wordfence out-of-scope:  HIGH=%d  MEDIUM=%d\n' "$WF_OOS_HIGH" "$WF_OOS_MED"
if [ "$MAX_AUTH" != "all" ]; then
    printf '  (filtered by --max-auth=%s: dropped HIGH=%d  MEDIUM=%d  LOW=%d above band)\n' "$MAX_AUTH" "$AUTH_OOS_HIGH" "$AUTH_OOS_MED" "$AUTH_OOS_LOW"
fi
echo

# Verdict thresholds — count in-scope only when computing target ranking.
# A plugin with 80 admin-gated HIGHs is OUT-OF-SCOPE for our bounty program
# regardless of total HIGH count.
SCORE="SKIP"
SCORE_COLOR="$GRN"
if [ "$WF_IN_SCOPE_HIGH" -ge 3 ] || { [ "$WF_IN_SCOPE_HIGH" -ge 1 ] && [ "$WF_IN_SCOPE_MED" -ge 3 ]; }; then
    SCORE="HIGH-VALUE-TARGET"
    SCORE_COLOR="$RED"
elif [ "$WF_IN_SCOPE_HIGH" -ge 1 ] || [ "$WF_IN_SCOPE_MED" -ge 2 ]; then
    SCORE="INVESTIGATE"
    SCORE_COLOR="$YEL"
elif [ "$HIGH_COUNT" -ge 3 ]; then
    # Has HIGHs but they're all out-of-scope.
    SCORE="OOS-ONLY"
    SCORE_COLOR="$CYA"
fi

printf '%sOverall: %s%s%s' "$BLD" "$SCORE_COLOR" "$SCORE" "$RST"
if [ "$SCORE" = "OOS-ONLY" ]; then
    printf '  (Editor/Admin-only surface — not Wordfence-bountyable)'
fi
echo
echo
# Machine-readable summary — extended with auth-band columns.
# Format: HIGH MED LOW SCORE | nopriv_H sub_H author_H editor_H admin_H unknown_H | nopriv_M sub_M author_M editor_M admin_M unknown_M
printf 'SCREENER_SUMMARY\t%d\t%d\t%d\t%s\n' "$HIGH_COUNT" "$MED_COUNT" "$LOW_COUNT" "$SCORE"
printf 'SCREENER_AUTHBAND_HIGH\t%d\t%d\t%d\t%d\t%d\t%d\n' \
    "${HIGH_BY_BAND[NOPRIV]:-0}" "${HIGH_BY_BAND[SUBSCRIBER]:-0}" "${HIGH_BY_BAND[AUTHOR]:-0}" \
    "${HIGH_BY_BAND[EDITOR]:-0}" "${HIGH_BY_BAND[ADMIN]:-0}" "${HIGH_BY_BAND[UNKNOWN]:-0}"
printf 'SCREENER_AUTHBAND_MED\t%d\t%d\t%d\t%d\t%d\t%d\n' \
    "${MED_BY_BAND[NOPRIV]:-0}" "${MED_BY_BAND[SUBSCRIBER]:-0}" "${MED_BY_BAND[AUTHOR]:-0}" \
    "${MED_BY_BAND[EDITOR]:-0}" "${MED_BY_BAND[ADMIN]:-0}" "${MED_BY_BAND[UNKNOWN]:-0}"
echo "Report saved: $OUT_FILE"
