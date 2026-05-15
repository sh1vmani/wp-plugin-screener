#!/usr/bin/env bash
# wp-svn-diff.sh
# Diff two SVN refs of a wp.org plugin; surface security-relevant changes
# and sibling-function candidates (the F01-incomplete-fix playbook).
#
# Usage:
#   wp-svn-diff.sh <slug>                         # diff last-2-tags
#   wp-svn-diff.sh <slug> <base_ref>              # base_ref vs trunk
#   wp-svn-diff.sh <slug> <base_ref> <head_ref>   # explicit pair
#
# Refs accept any of:
#   tags/X.Y.Z          # /tags/X.Y.Z/
#   X.Y.Z               # shorthand for /tags/X.Y.Z/
#   trunk               # /trunk/
#
# Output sections:
#   1. Resolved refs + changed-file summary
#   2. Per-(file,function) added security signals (cap/nonce/sanitizer/hash_equals)
#   3. Sibling-function candidates: when a cap check was ADDED to function F,
#      list other functions in the same file that DON'T contain the same cap.

set -u

RED=$'\033[0;31m'
YEL=$'\033[0;33m'
GRN=$'\033[0;32m'
CYA=$'\033[0;36m'
BLD=$'\033[1m'
RST=$'\033[0m'

usage() {
    sed -n '1,30p' "$0" >&2
    exit 1
}

SLUG="${1:-}"
BASE_REF="${2:-}"
HEAD_REF="${3:-}"
[ -z "$SLUG" ] && usage
command -v svn >/dev/null || { echo "svn not installed" >&2; exit 2; }

SVN_BASE="https://plugins.svn.wordpress.org/${SLUG}"

resolve_ref() {
    local r="$1"
    case "$r" in
        trunk|trunk/) echo "/trunk" ;;
        tags/*)       echo "/${r%/}" ;;
        *)            echo "/tags/${r%/}" ;;
    esac
}

if [ -z "$BASE_REF" ]; then
    TAGS=$(svn ls "${SVN_BASE}/tags/" 2>/dev/null | grep -E '^[0-9]' | sed 's|/$||' | sort -V)
    [ -z "$TAGS" ] && { echo "No tags found at ${SVN_BASE}/tags/" >&2; exit 1; }
    LAST_TAG=$(echo "$TAGS" | tail -1)
    PREV_TAG=$(echo "$TAGS" | tail -2 | head -1)
    [ "$LAST_TAG" = "$PREV_TAG" ] && { echo "Only one tag found; specify base_ref" >&2; exit 1; }
    BASE_PATH="/tags/$PREV_TAG"
    HEAD_PATH="/tags/$LAST_TAG"
elif [ -z "$HEAD_REF" ]; then
    BASE_PATH=$(resolve_ref "$BASE_REF")
    HEAD_PATH="/trunk"
else
    BASE_PATH=$(resolve_ref "$BASE_REF")
    HEAD_PATH=$(resolve_ref "$HEAD_REF")
fi

BASE_URL="${SVN_BASE}${BASE_PATH}"
HEAD_URL="${SVN_BASE}${HEAD_PATH}"

printf '%s%swp-svn-diff: %s%s\n' "$BLD" "$CYA" "$SLUG" "$RST"
echo "  base: $BASE_URL"
echo "  head: $HEAD_URL"
echo "================================================================"

TMP=$(mktemp -d -t wpsvndiff.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

# Step 1: changed-file summary
echo
printf '%s== Changed files ==%s\n' "$BLD" "$RST"
SUMMARY=$(svn diff --summarize "$BASE_URL" "$HEAD_URL" 2>&1)
[ -z "$SUMMARY" ] && { echo "  (no changes between refs)"; exit 0; }
echo "$SUMMARY" | awk -v b="$BASE_URL/" '{ sub(b, "", $0); print "  " $0 }' \
    | awk '!seen[$0]++' \
    | head -40
nfiles=$(echo "$SUMMARY" | wc -l)
[ "$nfiles" -gt 40 ] && echo "  ... ($nfiles total)"

# Step 2: capture diff with function context
echo
printf '%s== Fetching full diff (with function context) ==%s\n' "$BLD" "$RST"
DIFF_FILE="$TMP/diff.patch"
if ! svn diff -x -p "$BASE_URL" "$HEAD_URL" > "$DIFF_FILE" 2>"$TMP/svn.err"; then
    cat "$TMP/svn.err" >&2
    exit 1
fi
echo "  diff captured: $(wc -l < "$DIFF_FILE") lines"

# Step 3: parse the diff to find added security signals with function context.
# Function context comes from the most-recent `function NAME(` we've seen
# (whether on a +, -, or context line). This is more reliable than the @@
# context hint, which svn -p sets to the nearest CLASS, not function.
SIGNALS="$TMP/signals.tsv"
: > "$SIGNALS"

awk '
function strip_path(p) {
    sub(/^.* tags\/[^\/]+\//, "", p)
    sub(/^.* trunk\//, "", p)
    return p
}
function note(label, line) {
    gsub(/^[ \t]+|[ \t]+$/, "", line)
    # Trim to a sane display length
    if (length(line) > 120) line = substr(line, 1, 117) "..."
    printf "%s\t%s\t%s\t%s\n", current_file, current_fn, label, line
}
BEGIN { current_file = ""; current_fn = "(top-level)"; in_hunk = 0 }
/^Index: / {
    current_file = substr($0, 8)
    current_fn = "(top-level)"
    in_hunk = 0
    next
}
/^---|^\+\+\+/ { next }
/^@@ / {
    in_hunk = 1
    # Try to grab function NAME from the @@ context if present
    if (match($0, /function[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*/)) {
        current_fn = substr($0, RSTART + 9, RLENGTH - 9)
        sub(/^[[:space:]]+/, "", current_fn)
    }
    next
}
in_hunk {
    # Track function name from any line containing `function NAME(` —
    # whether context line, added, or removed.
    raw = $0
    sub(/^[+\- ]/, "", raw)  # strip diff prefix to inspect content
    if (match(raw, /function[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*/)) {
        current_fn = substr(raw, RSTART + 9, RLENGTH - 9)
        sub(/^[[:space:]]+/, "", current_fn)
    }

    # Only inspect added lines for new security signals
    if (substr($0, 1, 1) == "+" && substr($0, 1, 2) != "++") {
        added = substr($0, 2)
        # Order matters: more specific patterns first so they do not get masked
        # by a less specific match later in the chain.
        if (added ~ /current_user_can[[:space:]]*\(/)        note("auth: current_user_can", added)
        else if (added ~ /check_ajax_referer[[:space:]]*\(/)  note("auth: check_ajax_referer", added)
        else if (added ~ /check_admin_referer[[:space:]]*\(/) note("auth: check_admin_referer", added)
        else if (added ~ /wp_verify_nonce[[:space:]]*\(/)     note("auth: wp_verify_nonce", added)
        else if (added ~ /hash_equals[[:space:]]*\(/)         note("crypto: hash_equals", added)
        else if (added ~ /sanitize_[a-z_]+[[:space:]]*\(/)    note("sanitize: sanitize_*", added)
        else if (added ~ /wp_kses[a-z_]*[[:space:]]*\(/)      note("sanitize: wp_kses*", added)
        else if (added ~ /wp_unslash[[:space:]]*\(/)          note("sanitize: wp_unslash", added)
        else if (added ~ /esc_(html|attr|url|js|sql|textarea)[[:space:]]*\(/) note("escape: esc_*", added)
        # Type-juggling fixes — catches patches whose fix is `==`→`===`
        # rather than a capability-check addition.
        else if (added ~ /[^=!<>]===[^=]/)                    note("typesafe: strict equality (===)", added)
        else if (added ~ /!==[^=]/)                           note("typesafe: strict inequality (!==)", added)
        # NEW loose comparison on attacker input — a fresh bug introduced
        # IN the fix code (e.g., a new permission_callback that uses == /!=
        # against $_GET / $_POST / $_REQUEST / $_COOKIE). This shape recurs
        # in the wild: a patch adds an auth helper that compares a request
        # value to a stored option with !=, re-introducing the very bug
        # class it was meant to fix elsewhere. Flagged only when the line
        # ALSO reads a superglobal, so comparisons against literals do not
        # trigger.
        else if ((added ~ /[^=!<>]==[^=]/ || added ~ /!=[^=]/) && added ~ /\$_(GET|POST|REQUEST|COOKIE|SERVER)/) {
            note("smell: NEW loose-compare on attacker input", added)
        }
        # Type-cast additions (intval / absint / (int)$x / floatval) — common
        # fixes for "user input treated as int" SQL/IDOR bugs.
        else if (added ~ /(^|[^a-zA-Z_])intval[[:space:]]*\(/) note("cast: intval()", added)
        else if (added ~ /(^|[^a-zA-Z_])absint[[:space:]]*\(/) note("cast: absint()", added)
        else if (added ~ /(^|[^a-zA-Z_])floatval[[:space:]]*\(/) note("cast: floatval()", added)
        else if (added ~ /\([[:space:]]*int[[:space:]]*\)/)   note("cast: (int) cast", added)
        # Stricter LIKE escapes — WP esc_like is the proper escape for
        # `WHERE x LIKE %s` parameters (without it, attacker-supplied % and _
        # act as wildcards — a classic LIKE-wildcard bypass shape).
        else if (added ~ /esc_like[[:space:]]*\(/)            note("sanitize: esc_like (LIKE-wildcard fix)", added)
        # permission_callback additions on REST routes — when a route gains a
        # real callback (string class::method, array, or function reference)
        # the prior state was likely missing or `__return_true`. A common
        # incomplete-fix shape rewires a route from __return_true to a real
        # auth callback this way. (Quote classes use [\047"]: 047 = single-quote
        # in octal so we avoid breaking awk-inside-shell-single-quotes.)
        else if (added ~ /[\047"]permission_callback[\047"][[:space:]]*=>[[:space:]]*(array|function|\\?[a-zA-Z_])/) {
            if (added !~ /__return_true/) note("auth: permission_callback (non-lax)", added)
        }
    }
    # Removed dangerous patterns — informational only.
    if (substr($0, 1, 1) == "-" && substr($0, 1, 2) != "--") {
        removed = substr($0, 2)
        if (removed ~ /(^|[^a-zA-Z_])(eval|unserialize)[[:space:]]*\(/) {
            note("removed: eval/unserialize", removed)
        }
        # Removed `__return_true` permission_callback → strong signal that a
        # route was hardened. Pairs with the "added permission_callback (non-lax)"
        # signal above to reconstruct the fix.
        else if (removed ~ /[\047"]permission_callback[\047"][[:space:]]*=>[[:space:]]*[\047"]__return_true[\047"]/) {
            note("removed: __return_true permission_callback", removed)
        }
        # Removed loose comparison (only flag when an obvious strict version
        # is added in the same hunk; otherwise too noisy).
        else if (removed ~ /[^=!<>]==[^=]/ || removed ~ /!=[^=]/) {
            note("removed: loose comparison (==/!=)", removed)
        }
    }
}
' "$DIFF_FILE" > "$SIGNALS"

echo
printf '%s== Security signals added in this diff ==%s\n' "$BLD" "$RST"
if [ ! -s "$SIGNALS" ]; then
    echo "  (no security-relevant added lines detected)"
else
    # Group by (file, fn) then list signals under each group
    awk -F'\t' '
        {
            key = $1 "\t" $2
            items[key] = items[key] $3 "\t" $4 "\n"
            order[++n] = key
            seen[key] = 1
        }
        END {
            shown = ""
            for (i = 1; i <= n; i++) {
                k = order[i]
                if (shown ~ ("\t" k "\t")) continue
                shown = shown "\t" k "\t"
                split(k, a, "\t")
                printf "  %s%s%s  fn %s%s%s\n", "'"$YEL"'", a[1], "'"$RST"'", "'"$GRN"'", a[2], "'"$RST"'"
                m = split(items[k], lines, "\n")
                for (j = 1; j <= m; j++) {
                    if (lines[j] == "") continue
                    split(lines[j], p, "\t")
                    printf "      [%s] %s\n", p[1], p[2]
                }
            }
        }
    ' "$SIGNALS"
fi

# Step 4: SIBLING-FUNCTION DETECTOR (the F01 playbook)
echo
printf '%s== Sibling-function candidates (F01 incomplete-fix detector) ==%s\n' "$BLD" "$RST"

# Extract all (file, function, cap_call_string) where current_user_can was added.
# We use the literal cap-call string as the comparison key — if function G
# doesn't contain this exact string, it's a candidate.
CAP_ADDS="$TMP/cap_adds.tsv"
awk -F'\t' '
    $3 == "auth: current_user_can" {
        if (match($4, /current_user_can[[:space:]]*\([^)]*\)/)) {
            cap = substr($4, RSTART, RLENGTH)
            printf "%s\t%s\t%s\n", $1, $2, cap
        }
    }
' "$SIGNALS" | sort -u > "$CAP_ADDS"

if [ ! -s "$CAP_ADDS" ]; then
    echo "  (no current_user_can additions to chase siblings for)"
    exit 0
fi

cap_count=$(wc -l < "$CAP_ADDS")
echo "  ($cap_count cap-check addition$([ $cap_count -gt 1 ] && echo s) found — inspecting siblings)"
echo

HEAD_DIR="$TMP/head"
mkdir -p "$HEAD_DIR"

# Group by file; for each group, fetch HEAD copy once and inspect all sibling
# functions for the absence of any of the added caps.
declare -A CAPS_PER_FILE=()
while IFS=$'\t' read -r f fn cap; do
    [ -z "$f" ] && continue
    CAPS_PER_FILE[$f]+="$fn|$cap"$'\n'
done < "$CAP_ADDS"

for f in "${!CAPS_PER_FILE[@]}"; do
    safe=$(echo "$f" | tr '/' '_')
    local_copy="$HEAD_DIR/$safe"
    if [ ! -f "$local_copy" ]; then
        if ! svn cat "$HEAD_URL/$f" > "$local_copy" 2>/dev/null; then
            echo "  ! could not fetch HEAD of $f — skipping"
            continue
        fi
    fi

    caps_data="${CAPS_PER_FILE[$f]}"
    # Print this file header once
    printf '  %s%s%s\n' "$YEL" "$f" "$RST"

    # Enumerate functions in head copy with their line ranges and bodies.
    # Use awk to extract function spans then check each for each added cap.
    F="$f" CAPS="$caps_data" awk -v file_path="$f" -v caps_blob="$caps_data" '
        # Functions that are almost always wiring/boilerplate — skip them.
        # Adding to this list:
        #   __construct, __destruct, __get/__set (magic methods)
        #   register_hooks, register_routes, register_post_statuses, register_*
        #   init, run, boot, load, activate, deactivate (lifecycle)
        #   add_*_link, get_*_link, *_permalink (URL helpers — usually safe)
        function is_boilerplate(fn_name) {
            if (fn_name ~ /^__/) return 1
            if (fn_name ~ /^(register_|init$|run$|boot$|load$|activate$|deactivate$)/) return 1
            if (fn_name ~ /(_permalink|_link|_url|_edit_url)$/) return 1
            if (fn_name ~ /^(get|set|is|has)_/ && fn_name !~ /(post|user|option|meta|file|action)/) return 1
            return 0
        }
        # Score sibling: presence of $_GET/$_POST/$_REQUEST inside the function body
        # is strong evidence the function is a request handler (real sibling candidate).
        function sibling_score(b) {
            n = 0
            # Direct request-input → strongest signal
            if (b ~ /\$_GET\b|\$_POST\b|\$_REQUEST\b|\$_FILES\b/) n += 3
            # Handler registration in the body → reachable entry point
            if (b ~ /wp_ajax_|admin_post_|register_rest_route/) n += 2
            # Cron-scheduled handler (F01-shape: handler reached via wp_schedule_event)
            if (b ~ /wp_schedule_(event|single_event)/) n += 2
            # Direct DB/option/meta/file/redirect sinks → state-mutating
            if (b ~ /\$wpdb->(query|get_results|get_var|get_row)|update_option|update_(post|user|term)_meta|file_put_contents|wp_delete|wp_handle_upload|wp_redirect/) n += 2
            # Post-mutating WP API → operates on post objects (the F01 sink type)
            if (b ~ /wp_(update|insert|delete|publish|trash)_post\b|wp_set_object_terms|wp_set_post_(categories|tags|terms)/) n += 2
            return n
        }
        function flush_fn(   i, n_caps, c_arr, c, fix_fn, score) {
            if (!in_fn) return
            if (is_boilerplate(current_fn)) { _reset(); return }
            score = sibling_score(body)
            n_caps = split(caps_blob, c_arr, "\n")
            for (i = 1; i <= n_caps; i++) {
                if (c_arr[i] == "") continue
                split(c_arr[i], cf, "|")
                fix_fn = cf[1]; c = cf[2]
                if (c == "" || current_fn == fix_fn) continue
                if (index(body, c) == 0) {
                    pri = (score >= 3) ? "'"$RED"'HIGH'"$RST"'" : (score >= 1) ? "'"$YEL"'MED '"$RST"'" : "'"$CYA"'LOW '"$RST"'"
                    printf "      %s POTENTIAL SIBLING  fn %s%s%s  (lines %d–%d, signal=%d)\n", pri, "'"$GRN"'", current_fn, "'"$RST"'", fn_start, NR-1, score
                    printf "                            patched fn was: %s%s%s\n", "'"$CYA"'", fix_fn, "'"$RST"'"
                    printf "                            missing cap:    %s%s%s\n", "'"$CYA"'", c, "'"$RST"'"
                }
            }
            _reset()
        }
        function _reset() { in_fn = 0; body = ""; depth = 0; current_fn = "" }
        /^[[:space:]]*(public|private|protected|static|final|abstract)?[[:space:]]*(public|private|protected|static|final|abstract)?[[:space:]]*function[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\(/ {
            flush_fn()
            match($0, /function[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*/)
            current_fn = substr($0, RSTART + 9, RLENGTH - 9)
            sub(/^[[:space:]]+/, "", current_fn)
            in_fn = 1
            fn_start = NR
            body = $0 "\n"
            o = gsub(/\{/, "{", $0)
            c2 = gsub(/\}/, "}", $0)
            depth = o - c2
            if (depth <= 0 && body ~ /\{/) flush_fn()
            next
        }
        in_fn {
            body = body $0 "\n"
            o = gsub(/\{/, "{", $0)
            c2 = gsub(/\}/, "}", $0)
            depth += o - c2
            if (depth <= 0) flush_fn()
        }
        END { flush_fn() }
    ' "$local_copy"
done

echo
printf '%s  Verify each POTENTIAL SIBLING manually:%s confirm the function is reachable\n' "$BLD" "$RST"
echo "  by a lower role than the cap requires, and that the sink the cap was meant"
echo "  to gate is present in the sibling. If both → F01-shape incomplete-fix finding."
