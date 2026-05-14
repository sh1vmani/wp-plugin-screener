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

usage() {
    echo "Usage: $0 <plugin.zip|plugin-directory>" >&2
    exit 1
}

[ $# -lt 1 ] && usage
INPUT="$1"
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
                  -not -path '*/node_modules/*' \
                  -not -path '*/dist/*' \
                  -not -path '*/build/*' \
                  2>/dev/null)
    JS_FILES=$(find "$TARGET_DIR" -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' -o -name '*.vue' \) \
                  -not -path '*/vendor/*' \
                  -not -path '*/vendor-prod/*' \
                  -not -path '*/node_modules/*' \
                  -not -path '*/dist/*' \
                  -not -path '*/build/*' \
                  -not -name '*.min.js' \
                  2>/dev/null)
    PHP_VENDOR_FILES=$(find "$TARGET_DIR" -type f -name '*.php' \
                  \( -path '*/vendor/*' -o -path '*/vendor-prod/*' -o -path '*/dist/*' -o -path '*/build/*' \) \
                  2>/dev/null)
    JS_VENDOR_FILES=$(find "$TARGET_DIR" -type f \( -name '*.js' -o -name '*.jsx' \) \
                  \( -path '*/vendor/*' -o -path '*/vendor-prod/*' -o -path '*/dist/*' -o -path '*/build/*' -o -name '*.min.js' \) \
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

# add_finding <severity> <category> <file:line> <evidence>
add_finding() {
    local sev="$1" cat="$2" loc="$3" ev="$4"
    # Strip target dir prefix (used for suppress matching and display)
    loc="${loc#$TARGET_DIR/}"
    # Suppress check: file:line:category triple
    if [ -n "${SUPPRESS_MAP["${loc}:${cat}"]:-}" ]; then
        SUPPRESSED_COUNT=$((SUPPRESSED_COUNT + 1))
        return
    fi
    case "$sev" in
        HIGH)   HIGH_COUNT=$((HIGH_COUNT + 1)) ;;
        MEDIUM) MED_COUNT=$((MED_COUNT + 1)) ;;
        LOW)    LOW_COUNT=$((LOW_COUNT + 1)) ;;
    esac
    local c; c=$(color_for "$sev")
    # Truncate evidence
    ev="${ev:0:160}"
    printf '  %s[%s]%s %-38s %s\n' "$c" "$sev" "$RST" "$cat" "$loc"
    printf '       %s\n' "$ev"
    FINDINGS+=("$sev|$cat|$loc")
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
    local sev="$1" cat="$2" regex="$3"
    [ -z "$PHP_FILES" ] && return
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local file rest lineno content
        file="${line%%:*}"; rest="${line#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        is_comment_line "$content" && continue
        add_finding "$sev" "$cat" "$file:$lineno" "$content"
    done < <(printf '%s\n' "$PHP_FILES" | xargs -d '\n' -r grep -HnE "$regex" 2>/dev/null || true)
}

scan_pattern_js() {
    local sev="$1" cat="$2" regex="$3" flags="${4:-}"
    [ -z "$JS_FILES" ] && return
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local file rest lineno content
        file="${line%%:*}"; rest="${line#*:}"
        lineno="${rest%%:*}"; content="${rest#*:}"
        is_comment_line "$content" && continue
        add_finding "$sev" "$cat" "$file:$lineno" "$content"
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

# 4. wp_ajax_nopriv handlers (unauth AJAX)
scan_pattern_php MEDIUM "wp_ajax_nopriv handler" \
    "add_action[[:space:]]*\([[:space:]]*['\"]wp_ajax_nopriv_"

# 5. file_put_contents / move_uploaded_file
scan_pattern_php HIGH "file write / upload" \
    "(^|[^[:alnum:]_])(move_uploaded_file|file_put_contents)[[:space:]]*\("

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
        [ "$is_nopriv" = "1" ] && sev="HIGH"
        AJAX_SEEN[$cb]="$sev"
        add_finding "$sev" "ajax handler missing cap/nonce" "$deffile:$defline" "function ${cb}(...) — no current_user_can / nonce check"
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

# Score thresholds
SCORE="SKIP"
SCORE_COLOR="$GRN"
if [ "$HIGH_COUNT" -ge 3 ] || { [ "$HIGH_COUNT" -ge 1 ] && [ "$MED_COUNT" -ge 3 ]; }; then
    SCORE="HIGH-VALUE-TARGET"
    SCORE_COLOR="$RED"
elif [ "$HIGH_COUNT" -ge 1 ] || [ "$MED_COUNT" -ge 2 ]; then
    SCORE="INVESTIGATE"
    SCORE_COLOR="$YEL"
fi

printf '%sOverall: %s%s%s\n' "$BLD" "$SCORE_COLOR" "$SCORE" "$RST"
echo
printf 'SCREENER_SUMMARY\t%d\t%d\t%d\t%s\n' "$HIGH_COUNT" "$MED_COUNT" "$LOW_COUNT" "$SCORE"
echo "Report saved: $OUT_FILE"
