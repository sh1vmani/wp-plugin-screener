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
    # Known vendored library subdirs under lib/. Many plugins put their own
    # code under lib/ (so we don't blanket-exclude lib/*) but a handful of
    # third-party libraries get dropped there: Nusoap, PclZip, PHPMailer,
    # Smarty, Twig, OAuth, getID3, ICalEasyReader. Extend this list when
    # new false-positive-prone vendored libs appear.
    #
    # AUTO-DETECT bundled vendor PHP libs at ANY depth (not just under lib/).
    # Real-world case: a `*-php-lib/` SDK bundled at plugin root produced
    # ~13 NOPRIV HIGH false positives from its CI scripts. Heuristic:
    # a subdir containing composer.json AND (name matches *-php-lib / *-php /
    # *-sdk / *-lib / *-client / php-* pattern OR a LICENSE file is present)
    # is treated as a vendored library and excluded. Plugin's own top-level
    # composer.json is NOT considered (it's the plugin's manifest, not a vendor).
    AUTO_VENDOR_DIRS=$(find "$TARGET_DIR" -mindepth 2 -maxdepth 4 -type f -name 'composer.json' 2>/dev/null | \
        while read -r cj; do
            d=$(dirname "$cj")
            # Skip already-excluded canonical paths
            case "$d" in
                */vendor|*/vendor/*|*/node_modules|*/node_modules/*) continue ;;
            esac
            bn=$(basename "$d")
            case "$bn" in
                *-php-lib|*-php|*-sdk|*-lib|*-client|php-*|*-sdk-php)
                    echo "$d" ;;
                *)
                    # Has LICENSE/LICENSE.md/LICENSE.txt → bundled vendor library
                    if [ -f "$d/LICENSE" ] || [ -f "$d/LICENSE.md" ] || [ -f "$d/LICENSE.txt" ]; then
                        echo "$d"
                    fi ;;
            esac
        done | sort -u)
    AUTO_VENDOR_PRUNE=""
    if [ -n "$AUTO_VENDOR_DIRS" ]; then
        while IFS= read -r d; do
            [ -z "$d" ] && continue
            AUTO_VENDOR_PRUNE="$AUTO_VENDOR_PRUNE -not -path '$d/*'"
        done <<<"$AUTO_VENDOR_DIRS"
    fi

    PHP_FILES=$(eval find "$TARGET_DIR" -type f -name "'*.php'" \
                  -not -path "'*/vendor/*'" \
                  -not -path "'*/vendor-prod/*'" \
                  -not -path "'*/vendor_prefixed/*'" \
                  -not -path "'*/vendor-prefixed/*'" \
                  -not -path "'*/node_modules/*'" \
                  -not -path "'*/dist/*'" \
                  -not -path "'*/build/*'" \
                  -not -path "'*/lib/Nusoap/*'" \
                  -not -path "'*/lib/PclZip/*'" \
                  -not -path "'*/lib/Pclzip/*'" \
                  -not -path "'*/lib/PHPMailer/*'" \
                  -not -path "'*/lib/phpmailer/*'" \
                  -not -path "'*/lib/Smarty/*'" \
                  -not -path "'*/lib/Twig/*'" \
                  -not -path "'*/lib/getID3/*'" \
                  -not -path "'*/lib/getid3/*'" \
                  -not -path "'*/lib/OAuth/*'" \
                  -not -path "'*/lib/oauth/*'" \
                  -not -path "'*/lib/ICalEasyReader/*'" \
                  -not -path "'*/lib/composer/*'" \
                  $AUTO_VENDOR_PRUNE \
                  2>/dev/null)
    JS_FILES=$(find "$TARGET_DIR" -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' -o -name '*.vue' \) \
                  -not -path '*/vendor/*' \
                  -not -path '*/vendor-prod/*' \
                  -not -path '*/vendor_prefixed/*' \
                  -not -path '*/vendor-prefixed/*' \
                  -not -path '*/node_modules/*' \
                  -not -path '*/dist/*' \
                  -not -path '*/build/*' \
                  -not -name '*.min.js' \
                  2>/dev/null)
    PHP_VENDOR_FILES=$(find "$TARGET_DIR" -type f -name '*.php' \
                  \( -path '*/vendor/*' -o -path '*/vendor-prod/*' -o -path '*/vendor_prefixed/*' -o -path '*/vendor-prefixed/*' \
                     -o -path '*/dist/*' -o -path '*/build/*' \
                     -o -path '*/lib/Nusoap/*' -o -path '*/lib/PclZip/*' -o -path '*/lib/Pclzip/*' \
                     -o -path '*/lib/PHPMailer/*' -o -path '*/lib/phpmailer/*' \
                     -o -path '*/lib/Smarty/*' -o -path '*/lib/Twig/*' \
                     -o -path '*/lib/getID3/*' -o -path '*/lib/getid3/*' \
                     -o -path '*/lib/OAuth/*' -o -path '*/lib/oauth/*' \
                     -o -path '*/lib/ICalEasyReader/*' -o -path '*/lib/composer/*' \) \
                  2>/dev/null)
    JS_VENDOR_FILES=$(find "$TARGET_DIR" -type f \( -name '*.js' -o -name '*.jsx' \) \
                  \( -path '*/vendor/*' -o -path '*/vendor-prod/*' -o -path '*/vendor_prefixed/*' -o -path '*/vendor-prefixed/*' -o -path '*/dist/*' -o -path '*/build/*' -o -name '*.min.js' \) \
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
    # Record format (added 2026-05-15): F|<start>|<end>|<func_name>|<caps_csv>|<floor>|<wrapper_calls_csv>
    # wrapper_calls_csv lists permission-wrapper helper function names called
    # in the function body (verify_*, check_*, is_admin*, can_*, require_*,
    # ensure_*). classify_auth_band uses these for multi-hop band resolution
    # (fixes the pattern where handler → verify_access() → is_admin_user()
    # → current_user_can('delete_users') was missed by the 1-hop classifier
    # and produced SUBSCRIBER-band FPs on admin-only handlers).
    local awk_out
    awk_out=$(awk '
        BEGIN { in_func=0; func_start=0; func_name=""; caps=""; floor=0; admin_hooks=0; pub_hooks=0; wrapper_calls="" }
        function emit() {
            if (in_func) {
                printf "F|%d|%d|%s|%s|%d|%s\n", func_start, NR - 1, func_name, caps, floor, wrapper_calls
            }
            in_func=0; caps=""; floor=0; wrapper_calls=""
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
            # Permission-wrapper helper calls: verify_*, check_*, can_*,
            # is_admin*, require_*, ensure_*. The function-name pattern is the
            # signal — if the body calls one of these, the band depends on
            # what the wrapper enforces. classify_auth_band resolves to ADMIN
            # for admin-suffixed wrappers and SUBSCRIBER otherwise (still
            # better than UNKNOWN).
            wline = $0
            while (match(wline, /(\$this->|self::|static::|[a-zA-Z_][a-zA-Z0-9_]*::)?(verify_[a-zA-Z_]+|check_[a-zA-Z_]+|can_[a-zA-Z_]+|is_admin[a-zA-Z_]*|require_[a-zA-Z_]+|ensure_[a-zA-Z_]+)[[:space:]]*\(/)) {
                wm = substr(wline, RSTART, RLENGTH)
                # Strip the call prefix and `(`
                sub(/^.*->/, "", wm); sub(/^[^:]*::/, "", wm); sub(/[[:space:]]*\($/, "", wm)
                if (wrapper_calls == "") wrapper_calls = wm; else if (index(wrapper_calls, wm) == 0) wrapper_calls = wrapper_calls "," wm
                wline = substr(wline, RSTART + RLENGTH)
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

    local rec func_name caps floor start end wrapper_calls
    local matched_record=""
    while IFS= read -r rec; do
        [ -z "$rec" ] && continue
        # rec format: F|<start>|<end>|<func_name>|<caps_csv>|<floor>|<wrapper_calls_csv>
        IFS='|' read -r _tag start end func_name caps floor wrapper_calls <<< "$rec"
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

    # AJAX handler lookup (O(1)). NOPRIV is authoritative — unauth dispatch
    # can't be undone by a body cap check. SUBSCRIBER is just the priv-AJAX
    # default; if the body contains a more-restrictive cap (manage_options →
    # ADMIN, edit_others_posts → EDITOR), that cap wins because the meaningful
    # body code is gated by it. We let the body-cap inspection below run and
    # then combine.
    local ajax_band=""
    if [ -n "$func_name" ]; then
        ajax_band="${AJAX_HANDLER_BAND[$func_name]:-}"
        if [ "$ajax_band" = "NOPRIV" ]; then
            echo "NOPRIV"; return
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

    # Combine ajax_band with body-cap shallowest. The effective band is the
    # MORE-RESTRICTIVE (higher-rank) of the two — the band classifier asks
    # "what's the lowest role that can actually reach a sink in this fn?",
    # not "what's the lowest role that can dispatch this fn?". A priv-AJAX
    # handler whose body checks manage_options is effectively ADMIN, not
    # SUBSCRIBER.
    if [ "$shallowest_band" != "UNKNOWN" ]; then
        if [ -n "$ajax_band" ]; then
            local ajax_rank="${BAND_RANK[$ajax_band]:-99}"
            if [ "$shallowest_rank" -gt "$ajax_rank" ]; then
                echo "$shallowest_band"; return    # body cap is more restrictive
            fi
            echo "$ajax_band"; return               # ajax_band is more restrictive
        fi
        echo "$shallowest_band"; return
    fi

    # Wrapper-call resolution (4D, 2026-05-15). When the function body has no
    # direct cap but DOES call a permission-wrapper helper (verify_*, check_*,
    # is_admin*, can_*, require_*, ensure_*), infer band from the wrapper name.
    # This is a heuristic — the *correct* fix would chase through call
    # boundaries to find current_user_can — but name conventions are reliable
    # enough that this catches the common SUBSCRIBER→ADMIN FP shape (e.g.
    # handler → verify_access → is_admin_user →
    # current_user_can('delete_users')). The wrapper name
    # contains the auth tier; if it doesn't, we conservatively raise to
    # SUBSCRIBER (any logged-in user has at minimum been gated).
    #
    # 1-hop transitive expansion (same-file): if a wrapper-call name resolves
    # to a function in the SAME file, inline ITS wrapper_calls + caps. This
    # catches the pattern where a generic-named wrapper (e.g. verify_access,
    # which would classify SUBSCRIBER on its own) itself calls an admin-tier
    # helper (e.g. can_modify_settings). Without this, the handler stays
    # mis-classified as SUBSCRIBER.
    if [ -n "$wrapper_calls" ]; then
        local _expanded_wrappers="$wrapper_calls"
        local _expanded_caps="$caps"
        local _w_rec _w_name _w_caps _w_wrappers _w_inner
        # Walk each wrapper-call name; find its function record in this file;
        # if found, append its caps + wrapper_calls. Single level only.
        IFS=',' read -r -a _walk_arr <<< "$wrapper_calls"
        for _w_name in "${_walk_arr[@]}"; do
            [ -z "$_w_name" ] && continue
            while IFS= read -r _w_rec; do
                [ -z "$_w_rec" ] && continue
                IFS='|' read -r _wt _ws _we _wfn _wcaps _wfl _wwraps <<< "$_w_rec"
                if [ "$_wfn" = "$_w_name" ]; then
                    [ -n "$_wcaps" ] && _expanded_caps="${_expanded_caps:+$_expanded_caps,}$_wcaps"
                    [ -n "$_wwraps" ] && _expanded_wrappers="$_expanded_wrappers,$_wwraps"
                    break
                fi
            done <<< "${FILE_FUNC_DATA[$file]}"
        done
        # Re-run direct cap → band derivation with the expanded caps set.
        if [ -n "$_expanded_caps" ] && [ "$_expanded_caps" != "$caps" ]; then
            local _x_cap _x_band _x_rank _x_shallowest=99 _x_band_result="UNKNOWN"
            IFS=',' read -r -a _x_arr <<< "$_expanded_caps"
            for _x_cap in "${_x_arr[@]}"; do
                [ -z "$_x_cap" ] && continue
                _x_band="${STD_CAP_BAND[$_x_cap]:-}"
                [ -z "$_x_band" ] && _x_band="${CUSTOM_CAP_BAND[$_x_cap]:-}"
                [ -z "$_x_band" ] && continue
                _x_rank="${BAND_RANK[$_x_band]:-99}"
                if [ "$_x_rank" -lt "$_x_shallowest" ]; then
                    _x_shallowest="$_x_rank"; _x_band_result="$_x_band"
                fi
            done
            if [ "$_x_band_result" != "UNKNOWN" ]; then
                # Found a real cap via 1-hop expansion → return that band.
                echo "$_x_band_result"; return
            fi
        fi
        # Otherwise fall back to wrapper-NAME heuristic on the expanded set.
        # In BAND_RANK semantics: NOPRIV=0, SUBSCRIBER=1, AUTHOR=2, EDITOR=3,
        # ADMIN=4. Higher rank = more restrictive. We pick the MOST restrictive
        # (highest rank) band among the wrapper-names.
        wrapper_calls="$_expanded_wrappers"
        local wrap _wname_band _wname_rank wrap_best_rank=-1 wrap_best_band=""
        IFS=',' read -r -a _wrap_arr <<< "$wrapper_calls"
        for wrap in "${_wrap_arr[@]}"; do
            [ -z "$wrap" ] && continue
            _wname_band=""
            case "$wrap" in
                # ADMIN tier — names that strongly imply admin-only enforcement
                is_admin*|verify_admin*|check_admin*|require_admin*|ensure_admin*|can_manage*|verify_manage*|check_manage*|require_manage*|can_modify_settings|verify_capabilities|require_capabilities|can_administer*)
                    _wname_band="ADMIN" ;;
                # EDITOR tier
                verify_editor*|check_editor*|require_editor*|can_edit_others*)
                    _wname_band="EDITOR" ;;
                # AUTHOR tier — post-publishing wrappers
                verify_author*|check_author*|require_author*|can_publish*)
                    _wname_band="AUTHOR" ;;
                # Nonce-only checks (verify_nonce, check_nonce) are not auth gates,
                # they are CSRF gates. Skip them entirely.
                verify_nonce|check_nonce|check_ajax_referer|check_admin_referer) continue ;;
                # Anything else (verify_access, check_perms, ensure_logged_in,
                # can_send_notifications) is too generic — SUBSCRIBER floor.
                *) _wname_band="SUBSCRIBER" ;;
            esac
            _wname_rank="${BAND_RANK[$_wname_band]:-99}"
            if [ "$_wname_rank" != "99" ] && [ "$_wname_rank" -gt "$wrap_best_rank" ]; then
                wrap_best_rank="$_wname_rank"; wrap_best_band="$_wname_band"
            fi
        done
        # Apply only if more restrictive than the ajax_band (priv-AJAX = SUBSCRIBER, rank 1).
        if [ -n "$wrap_best_band" ]; then
            local _ajax_rank="${BAND_RANK[$ajax_band]:-0}"
            if [ "$wrap_best_rank" -gt "$_ajax_rank" ]; then
                echo "$wrap_best_band"; return
            fi
        fi
    fi

    # No body cap found. If ajax_band is set (SUBSCRIBER for priv-AJAX with
    # no body cap), that's the answer.
    if [ -n "$ajax_band" ]; then
        echo "$ajax_band"; return
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
#       superglobal read. Catches the indirect form
#       (`$dir = ...$form_id...` / `wp_mkdir_p($dir)`).
#
# This pattern matches the common "path built from a request id then passed
# to a write/delete sink" shape (e.g. directory-create from a form id, or
# file deletion via an entry id from $_POST).
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
# Example shape it catches (and the bug class):
#     $form_id  = $_POST['form_id'];                // upstream (somewhere in same fn)
#     $dir_new  = $this->...( "saved/$form_id" );   // 1-hop var
#     wp_mkdir_p( $dir_new );                       // sink — Rule 11b fires HERE
#   Entry-deletion-by-id variant: same shape, deletion side (unlink/wp_delete_file).
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

# 15a. Arbitrary options update — option NAME from a superglobal.
# Pattern: update_option($_POST['key'], …)
#          add_option($_GET['x'], …)
#          update_site_option($_REQUEST['name'], …)
# When the attacker controls the option NAME (not the value), they can overwrite
# any wp_options row — siteurl, home, default_role, users_can_register,
# admin_email, template, stylesheet, active_plugins. That's site takeover.
#
# Inline guard: a same-line `sanitize_key`/`sanitize_text_field` wrap on the key
# does NOT make this safe — those normalize characters but don't restrict the
# key to an allowlist. The only safe shape is an explicit whitelist check
# (in_array / switch). Allowlist is harder to detect on a single line, so we
# emit and let auth-banding + the auditor decide.
scan_pattern_php HIGH "update_option w/ user-controlled key" \
    "(^|[^[:alnum:]_>])(update_option|add_option|update_site_option)[[:space:]]*\([[:space:]]*\\\$_(GET|POST|REQUEST)\["

# 15b. Arbitrary user/post/term meta update — meta KEY from a superglobal.
# Pattern: update_user_meta($id, $_POST['meta_key'], $value)
# The meta key is the 2nd positional argument. Require the SECOND arg (after the
# first comma) to be a bare superglobal — not just "any superglobal somewhere
# after the first comma," which would also match the value-from-superglobal
# shape (just an XSS/storage sink, not arbitrary-meta-write).
#
# Severity MEDIUM not HIGH because meta keys are scoped per object_id; the blast
# radius is smaller than wp_options (no `siteurl` equivalent). Still worth a
# look: `_capabilities`, `wp_user_level`, `session_tokens` all live in user_meta.
scan_pattern_php MEDIUM "update_meta w/ user-controlled key" \
    "(^|[^[:alnum:]_>])(update_user_meta|update_post_meta|update_term_meta|add_user_meta|add_post_meta|add_term_meta)[[:space:]]*\([^,]*,[[:space:]]*\\\$_(GET|POST|REQUEST)\["

# 14a. Privilege escalation via wp_update_user / wp_insert_user with role from
# a superglobal. Multi-line aware: the array literal usually spans several
# lines, so we scan a ~30-line window from each call site for the dangerous
# `'role' => $_POST/...` shape.
#
# Pattern recognized:
#   wp_update_user([
#       'ID'   => $uid,
#       'role' => $_POST['role'],   // <-- attacker chooses role
#   ]);
# Same pattern with double quotes or unquoted bareword `role` key.
#
# Corpus calibration (2026-05-14, 25 plugins): 6 call sites, 0 with this shape.
# Expected new FPs: ~0.
if [ -n "$PHP_FILES" ]; then
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        file="${match%%:*}"; rest="${match#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        case "$lineno" in ''|*[!0-9]*) continue ;; esac
        is_comment_line "$content" && continue
        end=$((lineno + 30))
        window=$(sed -n "${lineno},${end}p" "$file" 2>/dev/null)
        hit=$(echo "$window" | grep -nE "['\"]?role['\"]?[[:space:]]*=>[[:space:]]*\\\$_(GET|POST|REQUEST)\[" | head -1)
        [ -z "$hit" ] && continue
        off="${hit%%:*}"
        case "$off" in ''|*[!0-9]*) off=1 ;; esac
        actual=$((lineno + off - 1))
        evidence=$(echo "$hit" | cut -d: -f2-)
        add_finding HIGH "user role from superglobal" "$file:$actual" "$evidence"
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE "(^|[^[:alnum:]_>])(wp_update_user|wp_insert_user)[[:space:]]*\(" 2>/dev/null || true)
fi

# 14b. ->set_role / ->add_cap / ->remove_cap with a superglobal argument.
# The dangerous shape is `$user->set_role($_POST['role'])` — attacker dictates
# the role directly. Bare `$variable` args are too noisy (plugin install code
# iterates over its own cap list); we restrict to superglobal-direct.
#
# Corpus calibration: 0 hits across 25 plugins (no plugin sets role/caps from
# raw superglobals in our audited sample). Expected new FPs: ~0.
scan_pattern_php HIGH "->set_role/->add_cap w/ superglobal" \
    "[a-zA-Z0-9_]->[[:space:]]*(set_role|add_cap|remove_cap)[[:space:]]*\([[:space:]]*\\\$_(GET|POST|REQUEST)\["

# 14c. wp_set_current_user / wp_set_auth_cookie with a user-id directly from a
# superglobal. Pattern: `wp_set_auth_cookie($_POST['user_id'])`.
#
# The bare-variable form (`wp_set_auth_cookie($user_id)`) is excluded because
# every legitimate login flow uses it after a password check — 9 such calls in
# the corpus, all benign post-auth uses. A 1-hop trace to a superglobal is the
# right next step but is deferred (Rule 11b-style work).
#
# Corpus calibration: 0 hits with direct-superglobal arg. Expected new FPs: ~0.
scan_pattern_php HIGH "wp_set_current_user/auth_cookie w/ superglobal" \
    "(wp_set_current_user|wp_set_auth_cookie)[[:space:]]*\([[:space:]]*\\\$_(GET|POST|REQUEST)\["

# 18. SSRF — wp_remote_* with a superglobal directly in the URL position.
# Pattern: wp_remote_get($_POST['url']), wp_remote_post($_GET['endpoint'], ...)
# Corpus calibration: 0 first-party hits (clean plugins).
scan_pattern_php HIGH "SSRF wp_remote_ w/ superglobal" \
    "wp_remote_(get|post|request|head|fopen)[[:space:]]*\([[:space:]]*\\\$_(GET|POST|REQUEST)\["

# 19. Mass assignment via extract() on superglobal — overwrites arbitrary PHP
# variables in the current scope. CWE-915 / AP-030.
# Corpus calibration: 0 first-party hits.
scan_pattern_php HIGH "extract on superglobal (mass assignment)" \
    "(^|[^[:alnum:]_])extract[[:space:]]*\([[:space:]]*\\\$_(GET|POST|REQUEST)"

# 20. Open redirect via wp_redirect (not wp_safe_redirect) with superglobal.
# wp_safe_redirect enforces host allowlist; wp_redirect does not.
# Corpus calibration: 0 first-party hits.
scan_pattern_php HIGH "wp_redirect w/ superglobal (open redirect)" \
    "(^|[^[:alnum:]_])wp_redirect[[:space:]]*\([[:space:]]*\\\$_(GET|POST|REQUEST)\["

# 21. Arbitrary file delete with superglobal in path (CWE-552).
# Skip method definitions (`function unlink(`).
# Corpus calibration: 0 first-party hits.
if [ -n "$PHP_FILES" ]; then
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        file="${match%%:*}"; rest="${match#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        case "$lineno" in ''|*[!0-9]*) continue ;; esac
        is_comment_line "$content" && continue
        echo "$content" | grep -qE "function[[:space:]]+(unlink|wp_delete_file|rmdir)[[:space:]]*\(" && continue
        echo "$content" | grep -qE "(->|::)[[:space:]]*(unlink|wp_delete_file|rmdir)[[:space:]]*\(" && continue
        add_finding HIGH "file delete w/ superglobal" "$file:$lineno" "$content"
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE -e "(^|[^[:alnum:]_>])(unlink|wp_delete_file|rmdir)[[:space:]]*\([^)]*\\\$_(GET|POST|REQUEST)\[" 2>/dev/null || true)
fi

# 22. Arbitrary file read with superglobal in path (BC-69 / CWE-200/22).
# file_get_contents / readfile / fread / fpassthru / show_source / highlight_file.
# Skip method definitions and method/static calls.
# Corpus calibration: 0 first-party hits.
if [ -n "$PHP_FILES" ]; then
    file_read_sinks='(file_get_contents|readfile|fread|fpassthru|show_source|highlight_file)'
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        file="${match%%:*}"; rest="${match#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        case "$lineno" in ''|*[!0-9]*) continue ;; esac
        is_comment_line "$content" && continue
        echo "$content" | grep -qE "function[[:space:]]+${file_read_sinks}[[:space:]]*\(" && continue
        echo "$content" | grep -qE "(->|::)[[:space:]]*${file_read_sinks}[[:space:]]*\(" && continue
        add_finding HIGH "file read w/ superglobal" "$file:$lineno" "$content"
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE -e "(^|[^[:alnum:]_>])${file_read_sinks}[[:space:]]*\([^)]*\\\$_(GET|POST|REQUEST)\[" 2>/dev/null || true)
fi

# 12. Broad RCE sinks beyond eval/unserialize (Rules 2/3 already handle those).
#   12a — system/exec/shell_exec/passthru/popen/proc_open with a variable arg.
#         The danger is shell interpolation: `exec("find $dir ...")` where $dir
#         can be attacker-influenced. Filters:
#           - skip `function exec(` definitions (member-fn collision)
#           - skip `->name(` and `::name(` calls (member/static methods named
#             the same — common in Curl wrappers, regex matchers, etc.)
#           - skip comments (handled by is_comment_line)
#   12b — create_function: deprecated PHP <7.2 code-from-string. Always HIGH.
#   12c — preg_replace with the /e modifier (CWE-94). Tight regex: requires
#         the pattern literal to end with delimiter + modifier-string-with-e.
#
# Corpus calibration (2026-05-14, 25 plugins, vendored excluded):
#   12a: 1 match (sg-cachepress exec with $basedir from server config — auditor
#        confirms FP since basedir is admin-controlled, not user-controlled)
#   12b: 0 matches (no create_function in any plugin)
#   12c: 0 matches (no /e-flag preg_replace)
if [ -n "$PHP_FILES" ]; then
    rce_sinks='(system|exec|shell_exec|passthru|popen|proc_open)'
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        file="${match%%:*}"; rest="${match#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        case "$lineno" in ''|*[!0-9]*) continue ;; esac
        is_comment_line "$content" && continue
        # Skip method definitions: `public function exec(`, `function exec(`
        echo "$content" | grep -qE "function[[:space:]]+(system|exec|shell_exec|passthru|popen|proc_open)[[:space:]]*\(" && continue
        # Skip method/static calls: `->exec(`, `::exec(`, `\Namespace\exec(` (the leading `\` is the namespace-root prefix used in vendor_prefixed code we already exclude, but some first-party code does it too)
        echo "$content" | grep -qE "(->|::)[[:space:]]*(system|exec|shell_exec|passthru|popen|proc_open)[[:space:]]*\(" && continue
        add_finding HIGH "RCE sink (variable arg)" "$file:$lineno" "$content"
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE -e "(^|[^[:alnum:]_>])${rce_sinks}[[:space:]]*\([^)]*\\\$" 2>/dev/null || true)
fi

# 13. Dynamic include / require with a user-controlled path (LFI → RCE).
# Pattern: include $_GET['page'] . '.php';  require_once $_POST['template'];
# WordPress core uses ABSPATH/__DIR__/dirname-prefixed includes; any
# superglobal in the path is suspicious. Matches both function-call form
# `include('x')` and statement form `include 'x';`.
#
# Corpus calibration: 0 first-party hits.
scan_pattern_php HIGH "dynamic include from superglobal (LFI->RCE)" \
    "(^|[^[:alnum:]_])(include|require|include_once|require_once)([[:space:]]+|\()[^;]*\\\$_(GET|POST|REQUEST|COOKIE)\["

# 17. Dynamic dispatch with attacker-controlled callable name.
#   17a — $obj->{$_POST['method']}() or $obj->{$_POST['m']}[0]
#   17b — call_user_func / call_user_func_array with superglobal as callable.
# Both let the attacker pick any callable reachable on the object/class.
#
# Corpus calibration: 0 first-party hits.
scan_pattern_php HIGH "dynamic method dispatch from superglobal" \
    "[a-zA-Z0-9_]->[[:space:]]*\{[[:space:]]*\\\$_(GET|POST|REQUEST)\["
scan_pattern_php HIGH "call_user_func w/ superglobal callable" \
    "(^|[^[:alnum:]_])call_user_func(_array)?[[:space:]]*\([[:space:]]*\\\$_(GET|POST|REQUEST)\["

# 12b. create_function — removed in PHP 8.0; presence in modern code is a smell.
scan_pattern_php HIGH "create_function (deprecated, RCE risk)" \
    "(^|[^[:alnum:]_>])create_function[[:space:]]*\("

# 12c. preg_replace with /e modifier. The pattern literal ends in
# delimiter + alphabetic-modifier-string-containing-e. Delimiters covered:
# / # ~ @ ! | (the common PCRE delimiters). Excludes the trivial "regex
# happens to contain the letter e in the middle" case.
scan_pattern_php HIGH "preg_replace /e flag (CWE-94)" \
    "preg_replace[[:space:]]*\([[:space:]]*['\"][/#~@!|][^'\"]+[/#~@!|][imsuADJSUXJ]*e[imsuADJSUXJ]*['\"]"

# 16. WP upload-handler sinks with no MIME/extension restriction visible in
# the enclosing function. Patterns:
#   wp_handle_upload($_FILES['x'], $overrides)
#   wp_handle_sideload(...)
#   media_handle_upload('field', $post_id)
#   media_handle_sideload($file_array, $post_id)
#   media_sideload_image($url, $post_id, ...)
#   media_sideload_file($url, $post_id, ...)
#
# WP core enforces a default mime allowlist, but the dangerous shapes are:
#  (a) `'test_type' => false` in $overrides — disables MIME check entirely.
#  (b) `'mimes' => array(...)` that includes svg/json/etc — widens the allow-
#      list to types with XSS or RCE potential.
#  (c) No follow-up wp_check_filetype on the returned ['file'] before
#      moving/serving — relies on WP's default to do the right thing.
#
# Detection: for each call site, slice the enclosing function (or ±50 lines
# fallback) and check for one of: `wp_check_filetype`, `'mimes'` array key,
# `wp_check_filetype_and_ext`, explicit `pathinfo(...PATHINFO_EXTENSION)`
# check, in_array(... allowed_extensions). Absence -> MEDIUM (the call exists,
# walk it). HIGH would over-fire on safe wp-default-mime callers; MEDIUM
# leaves auditor judgment intact.
#
# Corpus calibration (2026-05-14, 25 plugins): 7 call sites across 4 plugins.
# Expected emit count: ~5 MEDIUM (the multi-step-form admin caller has a
# downstream wp_check_filetype and would be silenced).
if [ -n "$PHP_FILES" ]; then
    upload_re='(^|[^[:alnum:]_])(wp_handle_upload|wp_handle_sideload|media_handle_upload|media_handle_sideload|media_sideload_image|media_sideload_file)[[:space:]]*\('
    check_re="wp_check_filetype|wp_check_filetype_and_ext|['\"]mimes['\"][[:space:]]*=>|PATHINFO_EXTENSION|in_array[[:space:]]*\([^)]*(jpg|png|gif|pdf|json|svg|csv|xml|zip)"
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        file="${match%%:*}"; rest="${match#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        case "$lineno" in ''|*[!0-9]*) continue ;; esac
        is_comment_line "$content" && continue
        # Slice enclosing function from the cache if available, else ±50 lines.
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
        if [ "$func_start" = "0" ]; then
            func_start=$((lineno - 25)); [ $func_start -lt 1 ] && func_start=1
            func_end=$((lineno + 25))
        fi
        window=$(sed -n "${func_start},${func_end}p" "$file" 2>/dev/null)
        # If a MIME/extension restriction is visible in the window, suppress.
        if echo "$window" | grep -qE -e "$check_re"; then
            continue
        fi
        add_finding MEDIUM "upload handler w/o MIME check" "$file:$lineno" "$content"
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE -e "$upload_re" 2>/dev/null || true)
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

# 23. register_setting() without sanitize_callback (AP-052 / BC-27).
# Settings API saves raw user input to wp_options when no sanitize_callback
# is provided. Often paired with options-page output that doesn't escape.
# Multi-line call patterns are common; we window each call and check the
# 30-line span for the 'sanitize_callback' key.
# Skip if window contains explicit 'type' => 'integer'/'boolean' (those types
# get implicit casting; not bulletproof but lower risk than no type at all).
if [ -n "$PHP_FILES" ]; then
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        file="${match%%:*}"; rest="${match#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        case "$lineno" in ''|*[!0-9]*) continue ;; esac
        is_comment_line "$content" && continue
        # Bound window to THIS register_setting call — stop at next call in
        # the same file (or 30 lines, whichever is first). Without this bound,
        # adjacent calls' windows overlap and a later call's sanitize_callback
        # falsely suppresses the earlier call.
        next_line=$(awk -v start=$((lineno + 1)) 'NR >= start && /register_setting[[:space:]]*\(/ {print NR; exit}' "$file")
        end=$((lineno + 30))
        if [ -n "$next_line" ] && [ "$next_line" -lt "$end" ]; then
            end=$((next_line - 1))
        fi
        window=$(sed -n "${lineno},${end}p" "$file" 2>/dev/null)
        # Has sanitize_callback key (modern WP 4.7+ args form) → safe
        echo "$window" | grep -qE -e "['\"]sanitize_callback['\"][[:space:]]*=>" && continue
        # Pre-WP-4.7 form: 3rd positional arg is a callable directly.
        # Common shapes: array($this, 'method'), [$this, 'method'], 'function_name'
        # (when 3 args present in the call line itself).
        if echo "$window" | grep -qE -e "register_setting[[:space:]]*\([^)]*,[[:space:]]*(array[[:space:]]*\([[:space:]]*\\\$this|\[[[:space:]]*\\\$this)"; then
            continue
        fi
        # Has explicit type → lower risk, still surface as LOW
        if echo "$window" | grep -qE -e "['\"]type['\"][[:space:]]*=>[[:space:]]*['\"](integer|boolean|number)['\"]"; then
            add_finding LOW "register_setting w/ typed but no sanitize_callback" "$file:$lineno" "$content"
            continue
        fi
        add_finding MEDIUM "register_setting w/o sanitize_callback" "$file:$lineno" "$content"
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE -e "register_setting[[:space:]]*\(" 2>/dev/null || true)
fi

# 24. XXE — XML parsing without entity-loader hardening (BC-37 / AP-057).
# PHP 8.0+ disables external entity loading by default; pre-8.0 plugins or
# code that explicitly enables entities are at risk. Detection: per-file,
# check whether the file uses XML parsing AND does NOT call
# libxml_disable_entity_loader(true). MEDIUM by default — auditor confirms
# whether the parser receives attacker-controlled XML.
if [ -n "$PHP_FILES" ]; then
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        file="${match%%:*}"; rest="${match#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        case "$lineno" in ''|*[!0-9]*) continue ;; esac
        is_comment_line "$content" && continue
        # Skip if file disables entity loading anywhere
        if grep -qE -e "libxml_disable_entity_loader[[:space:]]*\([[:space:]]*true" "$file" 2>/dev/null; then
            continue
        fi
        # Skip if LIBXML_NOENT is NOT set AND LIBXML_NONET is set (defensive option flags)
        # We don't try to parse all variants — just emit MEDIUM and let auditor verify.
        add_finding MEDIUM "XML parsing w/o entity-loader disable (XXE candidate)" "$file:$lineno" "$content"
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE -e "(^|[^[:alnum:]_>])(new[[:space:]]+SimpleXMLElement|DOMDocument::loadXML|simplexml_load_(string|file)|xml_parser_create)" 2>/dev/null || true)
fi

# 25. Predictable randomness near security context (BC-57 / AP-055).
# mt_rand / rand / uniqid within 5 lines (above or below) of one of:
#   token, nonce, reset, password, secret, csrf, key, hash, session
# Each fire is a candidate; rand() for non-security purposes (e.g. demo data)
# is legitimate. Auditor confirms whether the random feeds a security primitive.
if [ -n "$PHP_FILES" ]; then
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        file="${match%%:*}"; rest="${match#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        case "$lineno" in ''|*[!0-9]*) continue ;; esac
        is_comment_line "$content" && continue
        # Skip the rand-method definition collision
        echo "$content" | grep -qE -e "function[[:space:]]+(mt_rand|uniqid)[[:space:]]*\(" && continue
        # Context window: 5 lines above, 5 below
        start=$((lineno - 5)); [ $start -lt 1 ] && start=1
        end=$((lineno + 5))
        ctx=$(sed -n "${start},${end}p" "$file" 2>/dev/null)
        if echo "$ctx" | grep -qiE -e '\b(token|nonce|reset|password|secret|csrf|session|hash|salt|api_key)\b'; then
            add_finding MEDIUM "weak random (mt_rand/uniqid) near security context" "$file:$lineno" "$content"
        fi
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE -e "(^|[^[:alnum:]_>])(mt_rand|uniqid)[[:space:]]*\(" 2>/dev/null || true)
fi

# 26. Hardcoded encryption material (BC-56 / BC-58 / AP-054).
# openssl_encrypt / openssl_decrypt with a literal string in the key/iv
# position. Heuristic: if the call line contains a quoted base64-looking
# string of length ≥ 16 chars, flag it.
# Calibration: legitimate hardcoded constants (e.g. AES method name 'aes-256-cbc')
# are excluded by the length floor.
scan_pattern_php MEDIUM "openssl_(en|de)crypt w/ hardcoded literal material" \
    "openssl_(en|de)crypt[[:space:]]*\([^)]*['\"][A-Za-z0-9+/=]{16,}['\"]"

# 27. JWT 'none' algorithm (BC-43).
# `'alg' => 'none'` or `"alg":"none"` in PHP/JSON config — JWT verification
# accepts the 'none' algorithm. CVE-2015-9235-style flaw.
scan_pattern_php HIGH "JWT 'none' algorithm" \
    "['\"]alg['\"][[:space:]]*(=>|:)[[:space:]]*['\"]none['\"]"

# 28. Privilege escalation — 1-hop trace for Rule 14b/14c.
# Rule 14b/14c only fired on direct superglobal: `->set_role($_POST['role'])`.
# This rule extends to: variable assigned from superglobal in the same
# function, then passed to set_role/add_cap/wp_set_auth_cookie/wp_set_current_user.
# Same per-function span tracing pattern as Rule 11b.
if [ -n "$PHP_FILES" ]; then
    priv_sink_re='([a-zA-Z0-9_]->[[:space:]]*(set_role|add_cap|remove_cap)|wp_set_(current_user|auth_cookie))[[:space:]]*\([[:space:]]*\$([a-zA-Z_][a-zA-Z0-9_]+)'
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        file="${match%%:*}"; rest="${match#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        case "$lineno" in ''|*[!0-9]*) continue ;; esac
        is_comment_line "$content" && continue
        # Skip if direct-superglobal form already caught by Rule 14
        if echo "$content" | grep -qE -e '\$_(GET|POST|REQUEST)'; then continue; fi

        # Extract the variable name
        var=$(echo "$content" | grep -oE -e "$priv_sink_re" | head -1 \
              | sed -E 's/.*\$([a-zA-Z_][a-zA-Z0-9_]+).*/\1/')
        [ -z "$var" ] && continue

        # Find enclosing function span
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

        body=$(sed -n "${func_start},${func_end}p" "$file" 2>/dev/null)
        # 1-hop: $var = ... $_POST/$_GET/$_REQUEST ...
        if echo "$body" | grep -qE -e "\\\$${var}[[:space:]]*=[^;]*\\\$_(GET|POST|REQUEST)"; then
            add_finding HIGH "priv-esc sink <- superglobal (1-hop)" "$file:$lineno" "$content"
        fi
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE -e "$priv_sink_re" 2>/dev/null || true)
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
