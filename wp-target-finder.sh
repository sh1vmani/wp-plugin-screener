#!/usr/bin/env bash
# wp-target-finder.sh
# Token-aware WordPress plugin vulnerability target finder.
#
# Sources (best-effort, results are merged):
#   - WPScan       (WPSCAN_API_TOKEN)        wpscan.com/api/v3/plugins/<slug>
#   - Patchstack   (PATCHSTACK_API_TOKEN)    api.patchstack.com/v2/database/wordpress (per-slug)
#   - Wordfence    (WORDFENCE_API_TOKEN)     wordfence.com/api/intelligence/v3/vulnerabilities/scanner
#   - NVD          (no auth, always on)      services.nvd.nist.gov/rest/json/cves/2.0
#   - wordpress.org plugin info & popular-plugin listing (no auth)
#
# Outputs ranked top 10, downloads top 3 to /tmp/, runs ~/wp-plugin-screener.sh on each,
# and prints a final recommendation.
#
# Usage:
#   ~/wp-target-finder.sh [--limit N] [--min-installs N] [--cache-only] [--no-screener]

set -u

###############################################################################
# config
###############################################################################
RED=$'\033[0;31m'
YEL=$'\033[0;33m'
GRN=$'\033[0;32m'
CYA=$'\033[0;36m'
BLD=$'\033[1m'
RST=$'\033[0m'

LIMIT=200            # how many popular plugins to seed from wp.org
MIN_INSTALLS=100000   # hunt-workflow gate: >=100k floor (watchlist --slug bypasses)
TOP_N=3              # how many to render in the top list (now: one per install bucket)
DOWNLOAD_N=3         # how many to download + screen
MIN_UPDATE_AGE_DAYS=30   # exclude plugins updated within the last N days (active patches)
CACHE_DIR="$HOME/.cache/wp-target-finder"
SCREENER="$HOME/wp-plugin-screener.sh"
SVNDIFF="$HOME/wp-svn-diff.sh"
# Fallback locations if not in $HOME
[ ! -x "$SVNDIFF" ] && [ -x "/mnt/d/wp-security-audit-toolkit/wp-security-audit-toolkit/wp-svn-diff.sh" ] && SVNDIFF="/mnt/d/wp-security-audit-toolkit/wp-security-audit-toolkit/wp-svn-diff.sh"
[ ! -x "$SCREENER" ] && [ -x "/mnt/d/wp-security-audit-toolkit/wp-security-audit-toolkit/wp-plugin-screener.sh" ] && SCREENER="/mnt/d/wp-security-audit-toolkit/wp-security-audit-toolkit/wp-plugin-screener.sh"
DOWNLOAD_DIR="/tmp"
HISTORY_FILE="$HOME/wp-target-history.txt"
YIELD_FILE="$HOME/wp-target-yield.jsonl"   # Tier 3 #11: score -> finding-outcome log
AUDITED_LIST="$HOME/wp-audited-list.txt"   # slugs the user has manually audited; excluded from top output unless --include-audited or new CVE
WORDFENCE_DIR="${WP_AUDIT_WORDFENCE_DIR:-/mnt/d/wp-security-audit-toolkit/wp-security-audit-toolkit/wordfence}"
RESULTS_DIR="$HOME/wp-target-results"

# 4I: Python 3.13.x on WSL2 intermittently SIGSEGVs / raises
# "SystemError: type _thread._localdummy has the Py_TPFLAGS_HAVE_GC flag
# but has no traverse function" under the parallel (`--concurrency N`)
# xargs workers — a known CPython 3.13 GC/free-threading instability.
# Mitigations applied here (lowest-risk, no behaviour change):
#   - PYBIN indirection: prefer a non-3.13 interpreter if one is installed
#     (3.11/3.12 are unaffected); otherwise fall back to python3.
#   - PYTHONMALLOC=malloc: use libc malloc instead of pymalloc — sidesteps
#     the heap-corruption class of the 3.13 crash.
#   - PYTHONDONTWRITEBYTECODE=1: parallel workers racing to write .pyc into
#     the same dir was a secondary crash trigger.
#   - The hot `py()` helper retries once on non-zero exit (SIGSEGV = 139),
#     since the crash is intermittent — a clean re-run almost always works.
PYBIN="python3"
for _cand in python3.12 python3.11; do
    if command -v "$_cand" >/dev/null 2>&1; then PYBIN="$_cand"; break; fi
done
export PYTHONMALLOC=malloc
export PYTHONDONTWRITEBYTECODE=1

NO_SCREENER=0
NO_SVNDIFF=0          # if 1, skip F01-shape sibling-detection pass
CONCURRENCY=4         # how many plugins to screen in parallel
CACHE_ONLY=0          # if 1, skip network entirely (uses whatever's cached)
CACHE_TTL=21600       # 6 hours (default for small JSON responses)
CACHE_TTL_LONG=86400  # 24 hours (Wordfence intel bulk dump, GH advisory index)
CACHE_MAXTIME_LONG=300 # 5 minutes for large dumps (Wordfence intel is ~70MB)
SVNDIFF_TTL_DAYS=7    # F01-shape result cache lifetime
RESET_HISTORY=0
SHOW_HISTORY=0
INCLUDE_AUDITED=0     # if 1, do not filter audited-list slugs from output
MARK_AUDITED=""
UNMARK_AUDITED=""
LIST_AUDITED=0
WATCHLIST_SLUGS=""    # comma-separated slugs to force-include in seed pool (--slug)
CATEGORY_TAGS=""      # comma-separated wp.org tags for tag-biased browse (--category)
JSON_OUT=""           # if set, write ranked top-N JSON to this path
DUMP_WEIGHTS=0        # --dump-weights: print effective scoring weights and exit
RECORD_OUTCOME=""     # --record-outcome SLUG:OUTCOME[:NOTE]
SHOW_YIELD=0          # --yield-report: print score->outcome distribution and exit

while [ $# -gt 0 ]; do
    case "$1" in
        --limit)            LIMIT="$2"; shift 2 ;;
        --min-installs)     MIN_INSTALLS="$2"; shift 2 ;;
        --min-update-age)   MIN_UPDATE_AGE_DAYS="$2"; shift 2 ;;
        --cache-only)       CACHE_ONLY=1; shift ;;
        --no-screener)      NO_SCREENER=1; shift ;;
        --no-svndiff)       NO_SVNDIFF=1; shift ;;
        --concurrency)      CONCURRENCY="$2"; shift 2 ;;
        --slug)             WATCHLIST_SLUGS="$2"; shift 2 ;;
        --category)         CATEGORY_TAGS="$2"; shift 2 ;;
        --json-out)         JSON_OUT="$2"; shift 2 ;;
        --reset-history)    RESET_HISTORY=1; shift ;;
        --history)          SHOW_HISTORY=1; shift ;;
        --dump-weights)     DUMP_WEIGHTS=1; shift ;;
        --record-outcome)   RECORD_OUTCOME="$2"; shift 2 ;;
        --yield-report)     SHOW_YIELD=1; shift ;;
        --include-audited)  INCLUDE_AUDITED=1; shift ;;
        --mark-audited)     MARK_AUDITED="$2"; shift 2 ;;
        --unmark-audited)   UNMARK_AUDITED="$2"; shift 2 ;;
        --list-audited)     LIST_AUDITED=1; shift ;;
        -h|--help)
            cat <<'HELP'
wp-target-finder.sh — WordPress plugin vulnerability target finder

USAGE:
  wp-target-finder.sh [OPTIONS]

DISCOVERY OPTIONS:
  --limit N                Seed pool size (default 200; split across browse modes)
  --min-installs N         Minimum active installs (default 100000; hunt-workflow
                           floor — watchlist --slug bypasses it)
  --min-update-age N       Skip plugins updated within N days (default 30)
  --slug X[,Y,Z]           Force-include specific slugs (bypasses install/update gates)
  --category TAG[,TAG2]    Bias seed pool by wp.org tag (forms,membership,crm,security,...)

PIPELINE OPTIONS:
  --concurrency N          Parallel pre-screen worker count (default 4)
  --no-screener            Skip wp-plugin-screener.sh pre-pass
  --no-svndiff             Skip wp-svn-diff F01-shape detection pass
  --cache-only             Skip network entirely; use whatever's cached
  --json-out PATH          Write machine-readable JSON of top-N results to PATH

HISTORY / AUDIT-LIST:
  --reset-history          Wipe ~/wp-target-history.txt
  --history                Print history file and exit
  --include-audited        Don't filter audited slugs from output (default: filter)
  --mark-audited SLUG      Add SLUG to audited list and exit
  --unmark-audited SLUG    Remove SLUG from audited list and exit
  --list-audited           Print audited list and exit

SCORING CONFIG / YIELD TRACKING (Tier 3):
  --dump-weights           Print effective scoring weights (JSON) and exit.
                           Tune: --dump-weights > ~/.config/wp-target-finder/weights.json
                           (or set $WP_FINDER_WEIGHTS to a path), edit, rescan.
  --record-outcome S:O[:N] Record audit outcome for slug S. O is one of
                           confirmed|dry|oos|duplicate; N optional free note.
                           e.g. --record-outcome some-plugin:confirmed:ref-id
  --yield-report           Print score-bucket x outcome matrix (precision per
                           bucket) and exit. Tells you if high scores predict
                           real findings — the data that justifies retuning.

TOKENS (set in environment or ~/.zshrc, ~/.bashrc):
  WPSCAN_API_TOKEN         WPScan API (free 25 req/day; gives slug-accurate fixed_in)
  WORDFENCE_API_TOKEN      Wordfence intel (free signup; bulk JSON dump)
  PATCHSTACK_API_TOKEN     Patchstack API (Alliance program required)

SCORING TIERS (Python scorer; see also score_reasons in output):

  Install band (one of):
    100K-999K              +10  (Wordfence-eligible sweet spot)
    50K-99K                +3   (lower popularity, still scannable)
    1M+                    -10  (mega-popular, swarmed)

  CVE timing:
    CVE in last 6mo, none in last 30d   +8   (ripe to revisit)
    CVE in last 30d                     +1   (likely already hunted)
    1-4 CVEs in 12mo                    +2
    5+ CVEs in 12mo                     -10  (over-hunted)

  Pattern (developer mistake signature):
    Same vuln type 2+ times in 12mo     +6 per type
    Vague-security phrase in changelog  +3 per hit, cap +15
    Silent-patch in version <90d old    +15

  Maintenance:
    Last update 180-730 days ago        +5  (stale but in scope)

  Screener (when run):
    50+ in-scope HIGH                   +6
    20-49 in-scope HIGH                 +4
    10-19 in-scope HIGH                 +2
    3-9 in-scope HIGH                   +1
    0 HIGH + <3 MEDIUM                  -3  (hardened)
    5+ in-scope MEDIUM                  +1
    verdict OOS-ONLY                    -12
    10+ HIGH all Editor/Admin-band      -10

  F01-shape (from wp-svn-diff sibling detection):
    1+ HIGH-priority sibling            +12  (likely incomplete-fix)
    1+ MED-priority sibling             +6
    3+ LOW-priority siblings            +2

OUTPUT:
  Top targets by install bucket (100K-399K, 400K-999K, 1M+)
  Saved to:
    ~/.cache/wp-target-finder/top.json         (machine-readable)
    ~/wp-target-results/YYYY-MM-DD.txt         (human-readable, ANSI-stripped)

EXAMPLES:
  # Default daily run
  wp-target-finder.sh

  # Force-include duplicate-post regardless of filters
  wp-target-finder.sh --slug duplicate-post --include-audited

  # Seed from forms-category plugins, 6 workers, cache-only
  wp-target-finder.sh --category forms --concurrency 6 --cache-only

  # Fresh discovery — wipe history, refetch everything
  wp-target-finder.sh --reset-history --limit 400
HELP
            exit 0 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

mkdir -p "$CACHE_DIR" "$DOWNLOAD_DIR" "$RESULTS_DIR"
[ "$RESET_HISTORY" = "1" ] && rm -f "$HISTORY_FILE"
touch "$HISTORY_FILE" "$AUDITED_LIST"
# Clear any kill-switch marker from a previous run (rate limits reset daily).
rm -f "$CACHE_DIR/.wpscan-killed"

# Audited-list management CLI handlers (early exit for one-shot ops).
if [ -n "$MARK_AUDITED" ]; then
    if grep -qxF "$MARK_AUDITED" "$AUDITED_LIST"; then
        echo "Already in audited-list: $MARK_AUDITED"
    else
        echo "$MARK_AUDITED" >> "$AUDITED_LIST"
        echo "Marked audited: $MARK_AUDITED"
    fi
    exit 0
fi
if [ -n "$UNMARK_AUDITED" ]; then
    if grep -qxF "$UNMARK_AUDITED" "$AUDITED_LIST"; then
        grep -vxF "$UNMARK_AUDITED" "$AUDITED_LIST" > "$AUDITED_LIST.tmp" && mv "$AUDITED_LIST.tmp" "$AUDITED_LIST"
        echo "Unmarked audited: $UNMARK_AUDITED"
    else
        echo "Not in audited-list: $UNMARK_AUDITED"
    fi
    exit 0
fi
if [ "$LIST_AUDITED" = "1" ]; then
    if [ -s "$AUDITED_LIST" ]; then
        printf 'Audited slugs (%d):\n' "$(wc -l < "$AUDITED_LIST")"
        sort "$AUDITED_LIST"
    else
        echo "(no audited slugs yet at $AUDITED_LIST)"
    fi
    exit 0
fi

# Auto-backfill audited-list from any wordfence/<slug>/ subdirectory. Idempotent;
# treats "I have a working folder for it" as "I've at least started auditing it"
# so the scanner won't keep re-surfacing it.
if [ -d "$WORDFENCE_DIR" ]; then
    backfilled=0
    for plugin_dir in "$WORDFENCE_DIR"/*/; do
        [ -d "$plugin_dir" ] || continue
        slug=$(basename "$plugin_dir")
        [ -z "$slug" ] && continue
        if ! grep -qxF "$slug" "$AUDITED_LIST" 2>/dev/null; then
            echo "$slug" >> "$AUDITED_LIST"
            backfilled=$((backfilled + 1))
        fi
    done
    [ "$backfilled" -gt 0 ] && echo "Backfilled $backfilled slug(s) into audited-list from $WORDFENCE_DIR"
fi

# Auto-load tokens from common rc files when not already in the environment.
# Tokens may be exported in .zshrc (zsh users) but invisible to bash -c.
load_token_from_rc() {
    local var="$1"
    [ -n "${!var:-}" ] && return 0
    for rc in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.wp-target-finder.env"; do
        [ -r "$rc" ] || continue
        # Take the LAST matching export line (later assignments override earlier ones).
        local val
        val=$(grep -E "^[[:space:]]*(export[[:space:]]+)?${var}=" "$rc" 2>/dev/null \
              | tail -1 \
              | sed -E "s/^[[:space:]]*(export[[:space:]]+)?${var}=//; s/^['\"]//; s/['\"][[:space:]]*\$//")
        if [ -n "$val" ]; then
            export "$var=$val"
            return 0
        fi
    done
    return 1
}
load_token_from_rc WPSCAN_API_TOKEN     || true
load_token_from_rc WORDFENCE_API_TOKEN  || true
load_token_from_rc PATCHSTACK_API_TOKEN || true

if [ "$SHOW_HISTORY" = "1" ]; then
    if [ -s "$HISTORY_FILE" ]; then
        printf '%-40s %-12s %-18s %s\n' "SLUG" "LAST_SCAN" "LATEST_CVE" "CHANGELOG_SHA"
        cat "$HISTORY_FILE" | awk -F' \\| ' '{printf "%-40s %-12s %-18s %s\n",$1,$2,$3,$4}'
    else
        echo "(no history yet at $HISTORY_FILE)"
    fi
    exit 0
fi

###############################################################################
# helpers
###############################################################################
say()  { printf '%s\n' "$*"; }
warn() { printf '%s[!]%s %s\n' "$YEL" "$RST" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$RED" "$RST" "$*" >&2; }
hdr()  { printf '\n%s== %s ==%s\n' "$BLD" "$*" "$RST"; }

need() {
    command -v "$1" >/dev/null || { err "$1 not installed"; exit 1; }
}
need curl
need python3
need unzip

# Cached fetch: cache_get <key> <url> [extra curl args...]
# Honors CACHE_ONLY and CACHE_TTL. Prints body to stdout, returns 0 on success.
# Rejects (and does not cache) responses that look like rate-limits or auth
# errors so future runs can retry once the daily quota resets.
WPSCAN_KILLED_MARKER="$CACHE_DIR/.wpscan-killed"
WORDFENCE_COOLDOWN_MARKER="$CACHE_DIR/.wordfence-cooldown"
WORDFENCE_COOLDOWN_SECONDS=3600   # 1h cooldown on 429 from Wordfence intel
# Marker is touched when WPScan returns a rate-limit/auth error. We use a file
# instead of a shell variable because cache_get runs in $() command substitution,
# which executes in a subshell — variable changes there don't propagate to the
# parent and the kill-switch would never fire.
# Wordfence cooldown follows the same pattern.
cache_get() {
    local key="$1"; shift
    local url="$1"; shift
    local file="$CACHE_DIR/$key"

    # Per-URL TTL + timeout overrides. Some endpoints serve bulk dumps (tens of MB)
    # that update once-a-day and need 5-minute timeouts; the default 6h-TTL / 30s
    # timeout is wrong for them.
    local ttl="$CACHE_TTL"
    local maxtime=30
    case "$url" in
        *wordfence.com/api/intelligence/v*/vulnerabilities*)
            ttl="$CACHE_TTL_LONG"
            maxtime="$CACHE_MAXTIME_LONG"
            # If we're in cooldown from a recent 429, skip the call entirely.
            if [ -f "$WORDFENCE_COOLDOWN_MARKER" ]; then
                local cd_age=$(( $(date +%s) - $(stat -c %Y "$WORDFENCE_COOLDOWN_MARKER" 2>/dev/null || echo 0) ))
                if [ "$cd_age" -lt "$WORDFENCE_COOLDOWN_SECONDS" ]; then
                    # Serve stale cache if present (better than nothing).
                    [ -f "$file" ] && [ -s "$file" ] && { cat "$file"; return 0; }
                    return 1
                else
                    rm -f "$WORDFENCE_COOLDOWN_MARKER"
                fi
            fi
            ;;
    esac

    if [ -f "$file" ] && [ "$(( $(date +%s) - $(stat -c %Y "$file" 2>/dev/null || echo 0) ))" -lt "$ttl" ]; then
        cat "$file"; return 0
    fi
    if [ "$CACHE_ONLY" = "1" ]; then
        if [ -f "$file" ]; then cat "$file"; return 0; else return 1; fi
    fi

    # Single-fetch attempt → exit codes: 0 = ok+cached, 1 = transient (retry-worthy), 2 = hard (rate-limit/auth — don't retry).
    _cache_get_attempt() {
        local rc
        curl -sSLg --max-time "$maxtime" -A "wp-target-finder/1.0" "$@" "$url" -o "$file.tmp" 2>/dev/null
        rc=$?
        if [ "$rc" -ne 0 ]; then
            rm -f "$file.tmp"; return 1
        fi
        # Rate-limit / quota / auth — hard fail, no retry.
        #
        # 4H: scan ONLY the first 2KB, and ONLY for structured JSON error
        # envelopes. Genuine WPScan/Wordfence/wp.org rate-limit & auth
        # responses are tiny (<300 bytes) and lead with the error envelope,
        # so they are fully contained in the first 2KB. A *valid* multi-
        # hundred-KB plugin-list response can legitimately contain the words
        # "Unauthorized"/"Forbidden" deep inside a plugin's description
        # (membership/access-control plugins routinely do) — substring-
        # grepping the whole body false-positive-rejected the entire valid
        # response and silently killed the `--category membership` sweep on
        # 2026-05-15. The bare-word patterns are dropped; the structured
        # `"errors":[{"status":4xx}` / `"rate limit hit"` / `"throttled"`
        # envelopes are precise enough on their own.
        if head -c 2048 "$file.tmp" 2>/dev/null | grep -qE '"status":[[:space:]]*"rate limit hit"|"throttled"|"errors":[[:space:]]*\[[[:space:]]*\{[^}]*"status":[[:space:]]*(401|403|429)|"code":[[:space:]]*"rest_(forbidden|cannot|no_route)"|^\{"status":[[:space:]]*"error"'; then
            rm -f "$file.tmp"
            case "$url" in
                *wpscan.com*) touch "$WPSCAN_KILLED_MARKER" ;;
                *wordfence.com*) touch "$WORDFENCE_COOLDOWN_MARKER" ;;
            esac
            return 2
        fi
        # Empty body — transient (server hiccup, mid-stream truncation).
        if [ ! -s "$file.tmp" ]; then
            rm -f "$file.tmp"; return 1
        fi
        mv -f "$file.tmp" "$file"
        return 0
    }

    _cache_get_attempt "$@"
    local rc=$?
    if [ "$rc" -eq 1 ]; then
        # One retry with 2s backoff for transient failures (curl error / empty body / mid-stream truncation).
        sleep 2
        _cache_get_attempt "$@"
        rc=$?
    fi
    if [ "$rc" -ne 0 ]; then
        # On hard fail for Wordfence intel, serve stale cache if present rather than returning nothing.
        case "$url" in
            *wordfence.com/api/intelligence/v*/vulnerabilities*)
                [ -f "$file" ] && [ -s "$file" ] && { cat "$file"; return 0; }
                ;;
        esac
        return 1
    fi

    # Per-host rate-limit cushion (only on real fetches, not cache hits).
    case "$url" in
        *services.nvd.nist.gov*) sleep 0.8 ;;
        *wordfence.com*)         sleep 0.3 ;;
    esac
    cat "$file"
}

###############################################################################
# python helper -- a single JSON pipeline kept in one place.
# Reading JSON from a here-doc is much saner than chaining grep/sed.
###############################################################################
PY_HELPER=$(cat <<'PYHELPER'
import sys, json, re, os, datetime as dt

cmd = sys.argv[1]
data = sys.stdin.read()

def out(obj):
    print(json.dumps(obj))

# ── Tier 3 #12: externalized scoring weights ──────────────────────────────
# Every tunable score delta lives here. Thresholds (install bands, CVE-count
# cutoffs, day windows) stay literal — #12 is about *weights*, not buckets.
# Override file (shallow-merge over defaults), in priority order:
#   $WP_FINDER_WEIGHTS  ->  ~/.config/wp-target-finder/weights.json
# Use `--dump-weights` to print the effective set (good starting point to edit).
_DEFAULT_WEIGHTS = {
    "install_sweet_spot":   10,   # 100K–999K
    "install_low":           3,   # 50K–99K
    "install_mega":        -10,   # 1M+
    "cve_6mo_no_30d":        8,
    "cve_30d":               1,
    "recurring_type_per":    6,   # per recurring vuln-type
    "vague_changelog_per":   3,   # per vague phrase (count capped at 5)
    "fresh_silent_patch":   15,
    "already_hunted":      -10,   # 5+ CVEs / 12mo
    "cve_active_surface":    2,   # 1–4 CVEs / 12mo
    "patch_stale":           5,   # last update 180–730d
    "screener_high_50":      6,
    "screener_high_20":      4,
    "screener_high_10":      2,
    "screener_high_3":       1,
    "screener_hardened":    -3,
    "screener_med_5":        1,
    "screener_oos_only":   -12,
    "screener_oos_pattern":-10,
    "f01_high":             12,
    "f01_med":               6,
    "f01_low":               2,
    "pro_vendor":           -8,   # Wordfence-coordinated pro-vendor (comprehensive
                                  # fixers — sibling-walk tends to come up dry; the
                                  # F01-shape wins on indie/solo reactive-patch devs)
}

# Known Wordfence/Patchstack-coordinated "comprehensive fix" vendors. Matched
# case-insensitively as substrings against the plugin's author + name. Override
# the list with $WP_FINDER_PRO_VENDORS (comma-separated) to add/replace.
_PRO_VENDORS = [s.strip().lower() for s in (
    os.environ.get("WP_FINDER_PRO_VENDORS") or
    "yith,w3 eden,wp rocket,rocketgenius,gravity forms,awesome motive,"
    "wpforms,optinmonster,yoast,team yoast,caseproof,memberpress,stellarwp,"
    "liquid web,sandhills,easy digital downloads,elementor,automattic,"
    "really simple,rank math,wpml,onthego,ithemes,solidwp,solid security,"
    "10up,xwp,modern tribe,saucal,sucuri,wordfence,kinsta,brainstorm force,"
    "wpbeginner,syed balkhi"
).split(",") if s.strip()]

def _load_weights():
    w = dict(_DEFAULT_WEIGHTS)
    path = os.environ.get("WP_FINDER_WEIGHTS") or os.path.join(
        os.path.expanduser("~"), ".config", "wp-target-finder", "weights.json")
    try:
        with open(path) as f:
            ov = json.load(f)
        if isinstance(ov, dict):
            for k, v in ov.items():
                if k in w and isinstance(v, (int, float)):
                    w[k] = v
    except Exception:
        pass
    return w

W = _load_weights()

def _d(n):  # signed label so score_reasons stay accurate when weights are tuned
    return f"+{n}" if n >= 0 else str(n)

if cmd == "popular_slugs":
    # input = wp.org query_plugins JSON; emit list of slugs
    j = json.loads(data)
    slugs = []
    for p in j.get("plugins", []):
        s = p.get("slug")
        if s: slugs.append(s)
    print("\n".join(slugs))

elif cmd == "wporg_meta":
    # input = wp.org plugin_information JSON for ONE slug
    import html
    try:
        j = json.loads(data)
    except Exception:
        sys.exit(0)
    if "error" in j or not j.get("slug"):
        sys.exit(0)
    out({
        "slug": j.get("slug"),
        "name": html.unescape(j.get("name") or ""),
        "author": html.unescape(re.sub("<[^>]+>", "", j.get("author") or "")).strip()[:120],
        "active_installs": j.get("active_installs") or 0,
        "last_updated": (j.get("last_updated") or "")[:10],
        "version": j.get("version"),
        "download_link": j.get("download_link"),
        "homepage": j.get("homepage"),
        "sections_changelog": (j.get("sections") or {}).get("changelog","") or "",
    })

elif cmd == "nvd_cves_for_slug":
    # input: NVD JSON. arg2 = slug (used to filter).
    # Prefer CPE-based matching (precise) when CPE data is present; fall back to
    # a stricter description regex otherwise.
    slug = sys.argv[2]
    try:
        j = json.loads(data)
    except Exception:
        sys.exit(0)
    cves = []
    slug_words = slug.replace("-", "[ -]?")
    # Strict desc patterns intended to match the plugin itself, not addons that
    # mention it. "for SLUG plugin" / "SLUG add-on" are addon signals.
    desc_patterns = [
        re.compile(r"\bthe\s+" + slug_words + r"\s+plugin\b", re.I),
        re.compile(r"^" + slug_words + r"\s+(plugin|<=|before)\b", re.I),
    ]
    addon_signal = re.compile(r"\bfor\s+" + slug_words + r"\b", re.I)
    # Reject if description mentions a non-WP platform — same keyword may match
    # CVEs for Drupal, Joomla, Magento, Shopify, Typo3 plugins of the same name.
    non_wp_signal = re.compile(r"\b(Drupal|Joomla|Magento|Shopify|Typo3|Prestashop|opencart|phpBB|MediaWiki|Moodle)\b", re.I)
    # Require a version qualifier within 80 chars of the slug match.
    # Eliminates "WordPress SEO plugin generally" style false hits.
    version_near_slug = re.compile(
        r"\b" + slug_words + r"\b[^.]{0,80}\b(\d+\.\d+(?:\.\d+)?|<=|<|before|prior\s+to|through|version)",
        re.I
    )
    for v in j.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cve_id = cve.get("id")
        published = (cve.get("published") or "")[:10]
        descs = cve.get("descriptions", [])
        text = ""
        for d in descs:
            if d.get("lang") == "en":
                text = d.get("value",""); break
        if not text and descs:
            text = descs[0].get("value","")
        # CPE check
        cpe_hit = False
        cpes_seen = []
        for c in cve.get("configurations", []) or []:
            for n in c.get("nodes", []) or []:
                for m in n.get("cpeMatch", []) or []:
                    crit = m.get("criteria","")
                    parts = crit.split(":")
                    # cpe:2.3:a:VENDOR:PRODUCT:VERSION:...
                    if len(parts) >= 6:
                        product = parts[4]
                        cpes_seen.append(product)
                        if product == slug:
                            cpe_hit = True
        # Non-WP platform check runs FIRST regardless of CPE — a CVE for a
        # Drupal plugin of the same name shouldn't pass even on CPE match.
        if non_wp_signal.search(text):
            continue
        # Decision: keep if (a) CPE matches exactly, or (b) no CPEs at all and a strict desc pattern matches
        if cpe_hit:
            # Even on CPE hit, require version-near-slug to reduce noise on
            # CPE entries that are auto-assigned for plugin-name substrings.
            if not version_near_slug.search(text):
                continue
        elif cpes_seen:
            # CPE present but for a different product (e.g. "master-addons-for-elementor")
            continue
        else:
            if addon_signal.search(text):
                continue
            if not any(p.search(text) for p in desc_patterns):
                continue
            # Require version qualifier near slug match — eliminates background
            # mentions ("WordPress SEO plugin generally has issues with X").
            if not version_near_slug.search(text):
                continue
        # Try to classify vuln type
        vt = "other"
        for kw, label in [
            (r"\bcross[- ]site scripting|XSS\b", "XSS"),
            (r"SQL injection|SQLi", "SQLi"),
            (r"CSRF|cross[- ]site request forgery", "CSRF"),
            (r"arbitrary file upload|unrestricted file upload", "FileUpload"),
            (r"authorization|broken access|missing capability|privilege escalation", "AuthZ"),
            (r"path traversal|directory traversal", "PathTraversal"),
            (r"deserializ", "Deserialization"),
            (r"remote code execution|RCE", "RCE"),
            (r"open redirect", "OpenRedirect"),
            (r"information disclosure|sensitive data", "InfoDisc"),
        ]:
            if re.search(kw, text, re.I):
                vt = label; break
        cves.append({"id": cve_id, "published": published, "type": vt, "summary": text[:140], "source": "NVD"})
    out(cves)

elif cmd == "wpscan_cves":
    # input = wpscan plugin response JSON
    try:
        j = json.loads(data)
    except Exception:
        sys.exit(0)
    if not isinstance(j, dict): sys.exit(0)
    # response is { "<slug>": { vulnerabilities: [...] } }
    rec = next(iter(j.values()), {}) or {}
    out_list = []
    for v in rec.get("vulnerabilities", []) or []:
        cves = v.get("cve") or []
        if isinstance(cves, str): cves = [cves]
        if cves:
            first = str(cves[0])
            cve_id = first if first.upper().startswith("CVE-") else "CVE-" + first
        else:
            cve_id = v.get("id") or v.get("title","")[:30]
        published = (v.get("published_date") or v.get("created_at") or "")[:10]
        title = v.get("title","")
        vt = "other"
        for kw, label in [
            (r"XSS|cross[- ]site scripting", "XSS"),
            (r"SQLi|SQL injection", "SQLi"),
            (r"CSRF", "CSRF"),
            (r"arbitrary file upload|file upload", "FileUpload"),
            (r"authorization|access|privilege", "AuthZ"),
            (r"traversal", "PathTraversal"),
            (r"deserializ", "Deserialization"),
            (r"RCE|remote code execution", "RCE"),
            (r"open redirect", "OpenRedirect"),
            (r"disclosure", "InfoDisc"),
        ]:
            if re.search(kw, title, re.I):
                vt = label; break
        out_list.append({"id": cve_id, "published": published, "type": vt, "summary": title[:140], "source":"WPScan", "fixed_in": v.get("fixed_in")})
    out(out_list)

elif cmd == "wordfence_cves_for_slug":
    # input = wordfence intelligence response (huge dict keyed by vuln_id), arg2=slug
    slug = sys.argv[2]
    try:
        j = json.loads(data)
    except Exception:
        sys.exit(0)
    out_list = []
    iter_items = j.values() if isinstance(j, dict) else j
    for v in iter_items:
        soft = v.get("software", []) or []
        match = False
        for s in soft:
            if s.get("type") == "plugin" and s.get("slug") == slug:
                match = True; break
        if not match: continue
        cve_id = v.get("cve") or v.get("id")
        published = (v.get("published") or v.get("date_published") or "")[:10]
        title = v.get("title","") or v.get("description","")
        vt = (v.get("cwe") or [{}])[0].get("name","other") if v.get("cwe") else "other"
        out_list.append({"id": cve_id, "published": published, "type": vt, "summary": title[:140], "source":"Wordfence"})
    out(out_list)

elif cmd == "patchstack_cves_for_slug":
    # input = patchstack vulnerabilities response (varies)
    try:
        j = json.loads(data)
    except Exception:
        sys.exit(0)
    items = j if isinstance(j, list) else (j.get("data") or j.get("vulnerabilities") or [])
    out_list = []
    for v in items:
        cve_id = v.get("cve_id") or v.get("id")
        published = (v.get("published_at") or v.get("created_at") or "")[:10]
        title = v.get("title","") or v.get("name","")
        vt = v.get("category") or v.get("type","other")
        out_list.append({"id": cve_id, "published": published, "type": vt, "summary": title[:140], "source":"Patchstack"})
    out(out_list)

elif cmd == "score":
    # New scoring rules — favors mid-popularity plugins with a recent-but-not-fresh
    # CVE, a repeating vuln-type pattern, and vague changelog signals. Penalizes
    # mega-popular and over-hunted targets.
    rec = json.loads(data)
    today = dt.date.today()
    cves = rec.get("cves", [])
    seen = {}
    for c in cves:
        cid = c.get("id") or c.get("summary","")[:30]
        prev = seen.get(cid)
        if not prev or (c.get("published","") > prev.get("published","")):
            seen[cid] = c
    cves = list(seen.values())

    one_year_ago  = (today - dt.timedelta(days=365)).isoformat()
    six_mo_ago    = (today - dt.timedelta(days=180)).isoformat()
    thirty_d_ago  = (today - dt.timedelta(days=30)).isoformat()

    recent_12mo = [c for c in cves if c.get("published","") >= one_year_ago]
    recent_6mo  = [c for c in cves if c.get("published","") >= six_mo_ago]
    recent_30d  = [c for c in cves if c.get("published","") >= thirty_d_ago]
    n_12mo = len(recent_12mo)
    n_6mo  = len(recent_6mo)
    n_30d  = len(recent_30d)

    reasons = []
    score = 0

    # 1. Sweet-spot install band: 100K-999K = +10. Aligned with the
    # Wordfence-eligible bucket per BEST-PRACTICES.md (the 100K-399K +
    # 400K-999K install_bucket sampling downstream). Plugins below 100K
    # are still scored but get no install-band bonus — many are valid
    # targets when surfaced via fresh-CVE or watchlist.
    installs = rec.get("active_installs", 0) or 0
    if 100_000 <= installs <= 999_999:
        w = W["install_sweet_spot"]; score += w
        reasons.append((_d(w), "install sweet-spot 100K–999K (Wordfence-eligible bucket)"))
    elif 50_000 <= installs < 100_000:
        w = W["install_low"]; score += w
        reasons.append((_d(w), f"low-popularity {installs:,} (worth screening but smaller pool)"))
    elif installs >= 1_000_000:
        w = W["install_mega"]; score += w
        reasons.append((_d(w), f"mega-popular ({installs:,}) — too many researchers"))

    # 2. CVE in last 6 months but NONE in last 30 days: +8 (ripe but not just patched/exploited)
    if n_6mo >= 1 and n_30d == 0:
        w = W["cve_6mo_no_30d"]; score += w
        reasons.append((_d(w), "CVE in last 6 mo, none in last 30d (ripe to revisit)"))
    elif n_30d >= 1:
        w = W["cve_30d"]; score += w
        reasons.append((_d(w), "very recent CVE (<30d) — likely already being hunted"))

    # 3. Pattern: same vuln-type 2+ times in last 12 mo (developer mistake pattern)
    type_counts = {}
    for c in recent_12mo:
        t = c.get("type","other") or "other"
        type_counts[t] = type_counts.get(t, 0) + 1
    repeat_types = [t for t,n in type_counts.items() if n >= 2 and t != "other"]
    if repeat_types:
        b = W["recurring_type_per"] * len(repeat_types)
        score += b
        reasons.append((_d(b), "recurring vuln type(s): " + ", ".join(repeat_types)))

    # 4. Vague changelog without CVE detail. Big bonus if a vague-security phrase
    # appeared in the last 60-90 days — that recency window strongly suggests an
    # active vulnerability lifecycle (silent patch, possibly incomplete).
    cl_raw = (rec.get("sections_changelog","") or "")[:16000]
    cl = cl_raw.lower()
    vague_terms = ["security enhancement", "security improvement", "minor improvement",
                   "various fixes", "general improvements", "bug fixes", "hardening",
                   "security fix", "security update", "minor security",
                   "security hardening", "security patch"]
    vague_hits = sum(1 for t in vague_terms if t in cl)
    has_cve_in_changelog = bool(re.search(r"CVE-\d{4}-\d{4,7}", cl_raw, re.I))
    if vague_hits and not has_cve_in_changelog:
        b = min(vague_hits, 5) * W["vague_changelog_per"]
        score += b
        reasons.append((_d(b), f"vague-changelog ({vague_hits} hits, no CVE id)"))

    # 4b. Fresh-silent-patch detector: split changelog into version blocks, check
    # which blocks have a date in the last 60-90 days, see if any contain vague
    # security phrases. Format varies; common patterns:
    #     = 1.2.3 = (2026-04-12)
    #     = 1.2.3 - 2026-04-12 =
    #     1.2.3 — April 12, 2026
    fresh_signal = False
    fresh_match = None
    block_re = re.split(r"(?im)^\s*(?:=+\s*)?(\d+\.\d+(?:\.\d+){0,3})\b[^\n]*", cl_raw)
    # split() result with capture groups: [pre, ver1, body1, ver2, body2, ...]
    if len(block_re) >= 3:
        date_pat = re.compile(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})")
        for i in range(1, len(block_re), 2):
            ver  = block_re[i]
            body = block_re[i+1] if i+1 < len(block_re) else ""
            # collect dates from header line OR within first ~600 chars of body
            header_idx = cl_raw.find(ver)
            scan_text  = cl_raw[max(0,header_idx-50):header_idx + 600]
            d_match = date_pat.search(scan_text)
            if not d_match: continue
            try:
                d = dt.date(int(d_match.group(1)), int(d_match.group(2)), int(d_match.group(3)))
            except Exception:
                continue
            age = (today - d).days
            if 0 <= age <= 90 and any(t in body.lower() for t in vague_terms) and not re.search(r"CVE-\d{4}-\d{4,7}", body, re.I):
                fresh_signal = True
                fresh_match = (ver, d.isoformat(), age)
                break
    if fresh_signal:
        w = W["fresh_silent_patch"]; score += w
        v, d, age = fresh_match
        reasons.append((_d(w), f"vague-security phrase in v{v} on {d} ({age}d ago) — active lifecycle signal"))
    rec["fresh_silent_patch"] = fresh_signal
    rec["fresh_silent_patch_match"] = fresh_match
    rec["vague_hits"] = vague_hits

    # 5. Penalty: 5+ CVEs in last 12 mo (already actively hunted)
    if n_12mo >= 5:
        w = W["already_hunted"]; score += w
        reasons.append((_d(w), f"already hunted ({n_12mo} CVEs in 12 mo)"))
    elif n_12mo >= 1:
        w = W["cve_active_surface"]; score += w
        reasons.append((_d(w), f"{n_12mo} CVE(s) in 12 mo (active surface)"))

    # 6. Patch staleness — last_updated > 6 months suggests neglected maintenance
    last_upd = rec.get("last_updated","") or ""
    days_since_patch = 0
    if last_upd:
        try:
            d = dt.date.fromisoformat(last_upd[:10])
            days_since_patch = (today - d).days
        except Exception:
            pass
    if days_since_patch >= 180 and days_since_patch <= 730:
        w = W["patch_stale"]; score += w
        reasons.append((_d(w), f"last update {days_since_patch}d ago (stale but in scope)"))

    # Screener-derived scoring. Wordfence-eligible scope is NOPRIV +
    # SUBSCRIBER + AUTHOR (Editor / Admin / Super Admin are out of scope).
    # Use IN-SCOPE counts for rewards; raw totals don't matter if the
    # surface is admin-only. UNKNOWN bucket is conservatively included as
    # in-scope until the classifier improves.
    #
    # Back-compat: if SCREENER_AUTHBAND_HIGH lines weren't emitted (older
    # screener), screener_inscope_high will be 0 and we fall back to the
    # raw total via the second branch.
    sh_high       = int(rec.get("screener_high") or 0)
    sh_med        = int(rec.get("screener_medium") or 0)
    in_scope_high = int(rec.get("screener_inscope_high") or 0)
    in_scope_med  = int(rec.get("screener_inscope_med") or 0)
    oos_high      = int(rec.get("screener_oos_high") or 0)
    oos_med       = int(rec.get("screener_oos_med") or 0)
    verdict       = rec.get("screener_verdict") or ""

    # Use in_scope when we have authband data; otherwise fall back to raw.
    eff_high = in_scope_high if (in_scope_high + oos_high) > 0 else sh_high
    eff_med  = in_scope_med  if (in_scope_med  + oos_med ) > 0 else sh_med

    # Only apply screener-derived scoring when we actually ran the screener.
    # Without this check, --no-screener (or any path where the screener wasn't
    # invoked) triggers the "0 HIGH = hardened" -3 penalty even though the
    # signal is just absent, not negative.
    screener_ran = bool(verdict) and verdict != "TIMEOUT"
    if not screener_ran:
        if verdict == "TIMEOUT":
            reasons.append(("0", "screener: TIMEOUT — large plugin, no screener signal applied"))
        # If verdict is empty, we silently skip — no annotation, no penalty.
    elif eff_high >= 50:
        w = W["screener_high_50"]; score += w
        reasons.append((_d(w), f"screener: {eff_high} in-scope HIGH (rich attack surface)"))
    elif eff_high >= 20:
        w = W["screener_high_20"]; score += w
        reasons.append((_d(w), f"screener: {eff_high} in-scope HIGH"))
    elif eff_high >= 10:
        w = W["screener_high_10"]; score += w
        reasons.append((_d(w), f"screener: {eff_high} in-scope HIGH"))
    elif eff_high >= 3:
        w = W["screener_high_3"]; score += w
        reasons.append((_d(w), f"screener: {eff_high} in-scope HIGH (modest)"))
    elif eff_high == 0 and eff_med < 3:
        w = W["screener_hardened"]; score += w
        reasons.append((_d(w), "screener: hardened (no in-scope HIGH)"))

    if eff_med >= 5:
        w = W["screener_med_5"]; score += w
        reasons.append((_d(w), f"screener: {eff_med} in-scope MEDIUM (broad surface)"))

    # Strong demote when the plugin is OOS-ONLY: the screener flagged HIGHs
    # but they all bottom out at Editor/Admin caps. Wordfence won't pay for
    # those — push the plugin to the bottom of the ranking.
    if verdict == "OOS-ONLY":
        w = W["screener_oos_only"]; score += w
        reasons.append((_d(w), f"screener: OOS-ONLY ({oos_high} HIGH all Editor/Admin-gated)"))
    elif oos_high >= 10 and in_scope_high == 0:
        # Defensive — verdict label was missing but the pattern still applies.
        w = W["screener_oos_pattern"]; score += w
        reasons.append((_d(w), f"screener: {oos_high} HIGH all out-of-scope (no NOPRIV/SUBSCRIBER/AUTHOR surface)"))

    # F01-shape sibling signal — incomplete-fix candidate detector.
    # When the latest CVE's patch introduces a cap check, wp-svn-diff
    # identifies sibling functions in the same file that DON'T have the cap.
    # HIGH/MED siblings (functions reading superglobals or calling sinks) are
    # the highest-yield F02 leads — this directly drove F01 discovery.
    f01_h = int(rec.get("f01_siblings_high") or 0)
    f01_m = int(rec.get("f01_siblings_med") or 0)
    f01_l = int(rec.get("f01_siblings_low") or 0)
    if f01_h >= 1:
        w = W["f01_high"]; score += w
        reasons.append((_d(w), f"F01-shape: {f01_h} HIGH-priority sibling(s) likely incomplete-fix"))
    elif f01_m >= 1:
        w = W["f01_med"]; score += w
        reasons.append((_d(w), f"F01-shape: {f01_m} MED-priority sibling(s)"))
    elif f01_l >= 3:
        w = W["f01_low"]; score += w
        reasons.append((_d(w), f"F01-shape: {f01_l} LOW-priority siblings (review)"))

    # Vendor-profile gate (hunt-workflow step 2): deprioritize pro-vendors.
    _vend = ((rec.get("author") or "") + " " + (rec.get("name") or "")).lower()
    _hit = next((v for v in _PRO_VENDORS if v and v in _vend), None)
    if _hit:
        w = W["pro_vendor"]; score += w
        reasons.append((_d(w), f"pro-vendor profile ({_hit}) — comprehensive-fixer, F01-shape low-yield"))
    rec["pro_vendor_match"] = _hit

    rec["cves_dedup"]        = cves
    rec["cves_recent_count"] = n_12mo
    rec["cves_6mo_count"]    = n_6mo
    rec["cves_30d_count"]    = n_30d
    rec["score"]             = score
    rec["score_reasons"]     = reasons
    rec["last_security_patch"] = last_upd

    if recent_12mo:
        recent_12mo.sort(key=lambda c: c.get("published",""), reverse=True)
        rec["latest_cve"] = recent_12mo[0]
    out(rec)

elif cmd == "rank_table":
    # input = JSON list of scored records; emit ranked TSV (top N), and write JSON to fd 3
    n = int(sys.argv[2])
    recs = json.loads(data)
    recs.sort(key=lambda r: r.get("score",0), reverse=True)
    top = recs[:n]
    print("RANK\tSCORE\tCVEs12mo\tINSTALLS\tLAST_UPDATE\tSLUG\tNAME")
    for i, r in enumerate(top, 1):
        score = r.get("score", 0)
        nrec  = r.get("cves_recent_count", 0)
        ins   = r.get("active_installs", 0)
        last  = r.get("last_updated", "")
        slug  = r.get("slug", "")
        name  = (r.get("name") or "")[:40]
        print(f"{i}\t{score}\t{nrec}\t{ins}\t{last}\t{slug}\t{name}")
    # write json to a side file path (arg3)
    with open(sys.argv[3], "w") as f:
        json.dump(top, f)

elif cmd == "render_top":
    # input = ranked top N JSON; emits ranked #1/#2/#3 blocks with full details.
    # screener_results JSON path may be passed as arg2 (slug -> {verdict,high,med})
    recs = json.loads(data)
    screener = {}
    if len(sys.argv) > 2 and sys.argv[2] and os.path.isfile(sys.argv[2]):
        try:
            screener = json.load(open(sys.argv[2]))
        except Exception:
            screener = {}
    for i, r in enumerate(recs, 1):
        slug = r.get("slug",""); name = r.get("name","")
        installs = r.get("active_installs", 0) or 0
        cves = r.get("cves_recent_count", 0)
        last = r.get("last_updated","")
        score = r.get("score", 0)
        svn = f"https://plugins.svn.wordpress.org/{slug}/"
        dl = r.get("download_link") or f"https://downloads.wordpress.org/plugin/{slug}.latest-stable.zip"

        print(f"#{i}  {name}")
        print(f"      slug={slug}  installs={installs:,}")
        print(f"      CVEs(12mo)={cves}  CVEs(6mo)={r.get('cves_6mo_count',0)}  CVEs(30d)={r.get('cves_30d_count',0)}")
        print(f"      last security patch (last update): {last or 'unknown'}")
        if r.get("latest_cve"):
            lc = r["latest_cve"]
            cid = lc.get("id"); cp = lc.get("published"); ct = lc.get("type"); cs = (lc.get("summary","") or "")[:110]
            print(f"      latest CVE: {cid} ({cp}) {ct} -- {cs}")

        # F01-shape annotation (incomplete-fix candidate count)
        f01_h = r.get("f01_siblings_high", 0) or 0
        f01_m = r.get("f01_siblings_med", 0) or 0
        f01_l = r.get("f01_siblings_low", 0) or 0
        if f01_h + f01_m + f01_l > 0:
            base = r.get("f01_diff_base", "")
            head = r.get("f01_diff_head", "")
            print(f"      F01-shape candidates: HIGH={f01_h}  MED={f01_m}  LOW={f01_l}  (diff: {base} → {head})")
            print(f"          inspect: wp-svn-diff.sh {slug} {base} {head}")

        sc = screener.get(slug)
        if sc:
            v = sc.get('verdict','?')
            hi = sc.get('high','?'); md = sc.get('med','?')
            # In-scope = NOPRIV + SUBSCRIBER + AUTHOR + UNKNOWN (Wordfence-eligible).
            # OOS = EDITOR + ADMIN (skip).
            in_h = (sc.get('ah_nopriv',0) + sc.get('ah_subscriber',0)
                    + sc.get('ah_author',0) + sc.get('ah_unknown',0))
            oos_h = sc.get('ah_editor',0) + sc.get('ah_admin',0)
            if (in_h + oos_h) > 0:
                print(f"      screener: {v}   HIGH={hi}  MEDIUM={md}   in-scope-H={in_h}  OOS-H={oos_h}")
                print(f"      auth bands (HIGH):  NOPRIV={sc.get('ah_nopriv',0)}  SUB={sc.get('ah_subscriber',0)}  AUTHOR={sc.get('ah_author',0)}  EDITOR={sc.get('ah_editor',0)}  ADMIN={sc.get('ah_admin',0)}  UNKNOWN={sc.get('ah_unknown',0)}")
            else:
                print(f"      screener: {v}   HIGH={hi}  MEDIUM={md}")
        else:
            print(f"      screener: not run")

        print(f"      SVN:      {svn}")
        print(f"      Download: {dl}")

        hist = r.get("history_note")
        if hist:
            print(f"      previously scanned: {hist}")
        else:
            print(f"      previously scanned: no")

        print(f"      score: {score}")
        print(f"      why this rank:")
        for delta, why in r.get("score_reasons", []):
            print(f"          {delta:>4}  {why}")
        print()

elif cmd == "top_slugs":
    recs = json.loads(data)
    print("\n".join(r.get("slug") for r in recs if r.get("slug")))

elif cmd == "history_filter":
    # arg2 = path to history file. Format per line:
    #   slug | YYYY-MM-DD | latest_cve_id | changelog_sha
    # arg3 = path to audited-list file (one slug per line).
    # arg4 = "1" to include audited slugs anyway (--include-audited), else "0".
    #
    # Behavior:
    #   - Audited slugs are skipped UNLESS a new CVE has appeared since the
    #     last history entry (real re-audit signal, not cosmetic changelog).
    #   - Non-audited slugs use the legacy logic: skip if unchanged, annotate
    #     otherwise. Slugs never seen by the scanner before pass through.
    import hashlib
    history_path = sys.argv[2]
    audited_path = sys.argv[3] if len(sys.argv) > 3 else ""
    include_audited = (len(sys.argv) > 4 and sys.argv[4] == "1")
    recs = json.loads(data)
    hist = {}
    try:
        for line in open(history_path):
            parts = [p.strip() for p in line.rstrip("\n").split("|")]
            if len(parts) >= 4:
                slug, date, cve, csha = parts[0], parts[1], parts[2], parts[3]
                hist[slug] = {"date": date, "cve": cve, "csha": csha}
    except Exception:
        pass

    audited = set()
    if audited_path:
        try:
            for line in open(audited_path):
                s = line.strip()
                if s:
                    audited.add(s)
        except Exception:
            pass

    out_recs = []
    for r in recs:
        slug = r.get("slug")
        latest_cve_id = (r.get("latest_cve") or {}).get("id","") or ""
        cl = (r.get("sections_changelog","") or "")[:8000]
        csha = hashlib.sha256(cl.encode("utf-8","replace")).hexdigest()[:12]
        h = hist.get(slug)

        # Audited slugs: skip unless new CVE since last seen, or --include-audited.
        if slug in audited and not include_audited:
            prev_cve = h.get("cve","") if h else ""
            if latest_cve_id and latest_cve_id != prev_cve:
                r["history_note"] = f"audited; RE-AUDIT signal: new CVE {latest_cve_id} (prev {prev_cve or 'none'})"
                r["_latest_cve_id"] = latest_cve_id
                r["_changelog_sha"] = csha
                out_recs.append(r)
            continue

        # Non-audited slugs: always pass through. History deltas become
        # informational notes ("seen before, CVE list changed"), NOT filters.
        # Rationale: an unaudited plugin is still a valid audit target whether
        # or not its changelog has changed since last scan.
        if h:
            changes = []
            if latest_cve_id and latest_cve_id != h["cve"]:
                changes.append(f"new CVE {latest_cve_id} (prev {h['cve'] or 'none'})")
            if csha != h["csha"]:
                changes.append("changelog updated")
            if changes:
                r["history_note"] = f"seen before {h['date']}; {'; '.join(changes)}"
            else:
                r["history_note"] = f"seen before {h['date']}; unchanged (unaudited)"
        r["_latest_cve_id"] = latest_cve_id
        r["_changelog_sha"] = csha
        out_recs.append(r)
    out(out_recs)

elif cmd == "append_history":
    # arg2 = history path, arg3 = today YYYY-MM-DD
    history_path = sys.argv[2]; today = sys.argv[3]
    recs = json.loads(data)
    # Build dict of existing entries to update by slug
    existing = {}
    try:
        for line in open(history_path):
            parts = [p.strip() for p in line.rstrip("\n").split("|")]
            if len(parts) >= 4:
                existing[parts[0]] = parts
    except Exception:
        pass
    for r in recs:
        slug = r.get("slug")
        if not slug: continue
        existing[slug] = [slug, today, r.get("_latest_cve_id",""), r.get("_changelog_sha","")]
    with open(history_path, "w") as f:
        for slug in sorted(existing):
            f.write(" | ".join(existing[slug]) + "\n")
    print(f"history updated: {len(existing)} entries")

elif cmd == "dump_weights":
    # Tier 3 #12 — print the effective weights as JSON. Redirect to the
    # override path to start tuning:
    #   wp-target-finder.sh --dump-weights > ~/.config/wp-target-finder/weights.json
    print(json.dumps(W, indent=2))

elif cmd == "yield_log":
    # Tier 3 #11 — upsert one yield record per top-N candidate at scan time.
    # arg2 = yield jsonl path, arg3 = today. stdin = ranked top-N JSON list.
    # Outcome starts null; preserved across rescans (filled by yield_outcome).
    ypath = sys.argv[2]; today = sys.argv[3]
    recs  = json.loads(data)
    prior = {}
    try:
        for line in open(ypath):
            line = line.strip()
            if not line: continue
            o = json.loads(line)
            prior[o["slug"]] = o
    except Exception:
        pass
    for r in recs:
        slug = r.get("slug")
        if not slug: continue
        sc = r.get("score", 0)
        old = prior.get(slug, {})
        prior[slug] = {
            "slug": slug,
            "last_scored": today,
            "score": sc,
            "score_bucket": ( "<0" if sc < 0 else "0-9" if sc < 10 else
                              "10-19" if sc < 20 else "20-29" if sc < 30 else
                              "30-39" if sc < 40 else "40+" ),
            "reasons": [w for _, w in r.get("score_reasons", [])],
            "f01_high": r.get("f01_siblings_high", 0) or 0,
            "f01_med":  r.get("f01_siblings_med", 0) or 0,
            "in_scope_high": int(r.get("screener_inscope_high") or 0),
            "first_seen": old.get("first_seen", today),
            "outcome":      old.get("outcome"),       # preserved
            "outcome_note": old.get("outcome_note"),
            "outcome_ts":   old.get("outcome_ts"),
        }
    with open(ypath, "w") as f:
        for slug in sorted(prior):
            f.write(json.dumps(prior[slug]) + "\n")
    print(f"yield log: {len(prior)} tracked candidate(s) -> {ypath}")

elif cmd == "yield_outcome":
    # arg2 = yield path, arg3 = slug, arg4 = outcome, arg5 = today, arg6 = note(optional)
    ypath, slug, outcome, today = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
    note = sys.argv[6] if len(sys.argv) > 6 else ""
    valid = ("confirmed", "dry", "oos", "duplicate")
    if outcome not in valid:
        print(f"ERROR: outcome must be one of {valid}"); sys.exit(2)
    rows, found = [], False
    try:
        for line in open(ypath):
            line = line.strip()
            if not line: continue
            o = json.loads(line)
            if o.get("slug") == slug:
                o["outcome"] = outcome
                o["outcome_note"] = note
                o["outcome_ts"] = today
                found = True
            rows.append(o)
    except FileNotFoundError:
        # No log yet — fine: fall through and create it with this one row
        # (lets you record outcomes for slugs audited before they were scanned).
        pass
    if not found:
        # allow recording an outcome for a slug never surfaced in top-N
        rows.append({"slug": slug, "last_scored": None, "score": None,
                     "score_bucket": "unscored", "reasons": [],
                     "first_seen": today, "outcome": outcome,
                     "outcome_note": note, "outcome_ts": today})
    with open(ypath, "w") as f:
        for o in sorted(rows, key=lambda x: x.get("slug","")):
            f.write(json.dumps(o) + "\n")
    print(f"outcome recorded: {slug} -> {outcome}" + (f"  ({note})" if note else ""))

elif cmd == "yield_report":
    # arg2 = yield path. Score-bucket x outcome matrix + precision.
    ypath = sys.argv[2]
    rows = []
    try:
        for line in open(ypath):
            line = line.strip()
            if line: rows.append(json.loads(line))
    except FileNotFoundError:
        print(f"(no yield log yet at {ypath})"); sys.exit(0)
    order = ["<0", "0-9", "10-19", "20-29", "30-39", "40+", "unscored"]
    outs  = ["confirmed", "dry", "oos", "duplicate"]
    grid  = {b: {o: 0 for o in outs} for b in order}
    grid_pending = {b: 0 for b in order}
    for r in rows:
        b = r.get("score_bucket", "unscored")
        if b not in grid: grid[b] = {o: 0 for o in outs}; grid_pending[b] = 0
        oc = r.get("outcome")
        if oc in outs: grid[b][oc] += 1
        else:          grid_pending[b] += 1
    print(f"Yield report  ({len(rows)} tracked candidates)  source: {ypath}")
    print("=" * 78)
    hdr = f"{'BUCKET':<9}{'CONF':>6}{'DRY':>6}{'OOS':>6}{'DUP':>6}{'PEND':>6}{'RESOLVED':>10}{'PRECISION':>11}"
    print(hdr); print("-" * 78)
    tc = td = to = tu = tp = 0
    for b in order:
        if b not in grid: continue
        c = grid[b]["confirmed"]; d = grid[b]["dry"]
        o = grid[b]["oos"]; u = grid[b]["duplicate"]; p = grid_pending.get(b, 0)
        if c + d + o + u + p == 0: continue
        resolved = c + d + o + u
        prec = f"{(100.0*c/resolved):.0f}%" if resolved else "—"
        print(f"{b:<9}{c:>6}{d:>6}{o:>6}{u:>6}{p:>6}{resolved:>10}{prec:>11}")
        tc+=c; td+=d; to+=o; tu+=u; tp+=p
    print("-" * 78)
    tr = tc+td+to+tu
    tprec = f"{(100.0*tc/tr):.0f}%" if tr else "—"
    print(f"{'TOTAL':<9}{tc:>6}{td:>6}{to:>6}{tu:>6}{tp:>6}{tr:>10}{tprec:>11}")
    print("=" * 78)
    print("PRECISION = confirmed / resolved per bucket. If high score buckets")
    print("don't show higher precision, retune weights (--dump-weights) and rescan.")
PYHELPER
)

py() {
    # Retry once on non-zero exit. 4I: Python 3.13 SIGSEGV (exit 139) under
    # parallel workers is intermittent — a clean re-run almost always
    # succeeds. stdin is consumed on the first attempt, so buffer it.
    local _in _out _rc
    _in="$(cat)"
    _out="$(printf '%s' "$_in" | "$PYBIN" -c "$PY_HELPER" "$@")"; _rc=$?
    if [ "$_rc" -ne 0 ]; then
        _out="$(printf '%s' "$_in" | "$PYBIN" -c "$PY_HELPER" "$@")"; _rc=$?
    fi
    printf '%s' "$_out"
    return "$_rc"
}

# ── Tier 3 #11/#12 early-exit subcommands (need py() / PY_HELPER) ──────────
if [ "$DUMP_WEIGHTS" = "1" ]; then
    echo "" | py dump_weights
    exit 0
fi

if [ -n "$RECORD_OUTCOME" ]; then
    # SLUG:OUTCOME[:NOTE]   outcome in {confirmed,dry,oos,duplicate}
    ro_slug="${RECORD_OUTCOME%%:*}"
    ro_rest="${RECORD_OUTCOME#*:}"
    ro_outcome="${ro_rest%%:*}"
    ro_note=""
    [ "$ro_rest" != "$ro_outcome" ] && ro_note="${ro_rest#*:}"
    if [ -z "$ro_slug" ] || [ -z "$ro_outcome" ] || [ "$ro_slug" = "$RECORD_OUTCOME" ]; then
        err "--record-outcome expects SLUG:OUTCOME[:NOTE] (outcome: confirmed|dry|oos|duplicate)"
        exit 2
    fi
    echo "" | py yield_outcome "$YIELD_FILE" "$ro_slug" "$ro_outcome" "$(date -u +%Y-%m-%d)" "$ro_note"
    exit $?
fi

if [ "$SHOW_YIELD" = "1" ]; then
    echo "" | py yield_report "$YIELD_FILE"
    exit 0
fi

###############################################################################
# 1) seed list: top popular plugins from wordpress.org
###############################################################################
hdr "Seeding plugin list from wordpress.org"
SEED_FILE="$CACHE_DIR/seed-slugs.txt"
RAW_SEED="$CACHE_DIR/seed-raw.txt"
: > "$RAW_SEED"

# Watchlist slugs are PRE-PENDED so they always survive the LIMIT cap.
# Use case: a fresh disclosure bulletin lists plugin X — pass --slug X to
# force-include it without polluting the default seed pool.
if [ -n "$WATCHLIST_SLUGS" ]; then
    echo "$WATCHLIST_SLUGS" | tr ',' '\n' | awk 'NF' >> "$RAW_SEED"
    n_wl=$(echo "$WATCHLIST_SLUGS" | tr ',' '\n' | awk 'NF' | wc -l)
    say "  + Watchlist: $n_wl slug(s) prepended via --slug"
fi

PER_PAGE=100

# Category-biased seed: query wp.org by tag (forms, membership, crm, security, etc.)
# instead of (or in addition to) the default popular/updated/new browse modes.
# This biases the seed pool toward plugin families that exhibit BC-65..72 yield
# patterns (IDOR, mass-assignment, REST over-disclosure).
if [ -n "$CATEGORY_TAGS" ]; then
    say "  + Tag-biased seed: $CATEGORY_TAGS"
    each=$(( (LIMIT + 2) / 3 ))
    pages=$(( (each + PER_PAGE - 1) / PER_PAGE ))
    IFS=',' read -ra _tags <<< "$CATEGORY_TAGS"
    for tag in "${_tags[@]}"; do
        tag_clean=$(echo "$tag" | tr -d ' ')
        [ -z "$tag_clean" ] && continue
        for page in $(seq 1 $pages); do
            url="https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request%5Btag%5D=${tag_clean}&request%5Bpage%5D=${page}&request%5Bper_page%5D=${PER_PAGE}"
            body=$(cache_get "tag-${tag_clean}-page-${page}.json" "$url") \
                || { warn "tag $tag_clean page $page fetch failed"; continue; }
            echo "$body" | py popular_slugs >> "$RAW_SEED"
        done
    done
fi

# Default 3-way split of LIMIT across popular/updated/new browse modes.
# Skip when --category is the only seeding mode requested (so the user can
# narrowly scope to their tag pool); otherwise always include defaults.
if [ -z "$CATEGORY_TAGS" ]; then
    each=$(( (LIMIT + 2) / 3 ))
    for browse in popular updated new; do
        pages=$(( (each + PER_PAGE - 1) / PER_PAGE ))
        for page in $(seq 1 $pages); do
            url="https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request%5Bbrowse%5D=${browse}&request%5Bpage%5D=${page}&request%5Bper_page%5D=${PER_PAGE}"
            body=$(cache_get "${browse}-page-${page}.json" "$url") || { warn "$browse page $page fetch failed"; continue; }
            echo "$body" | py popular_slugs >> "$RAW_SEED"
        done
    done
fi

# Dedupe (preserve order of first occurrence). Watchlist slugs are at the top,
# so they always survive the LIMIT cap.
awk '!seen[$0]++' "$RAW_SEED" | head -n "$LIMIT" > "$SEED_FILE"
SEED_COUNT=$(wc -l < "$SEED_FILE")
src_desc="popular + updated + new"
[ -n "$CATEGORY_TAGS" ] && src_desc="tag=${CATEGORY_TAGS}"
[ -n "$WATCHLIST_SLUGS" ] && src_desc="$src_desc + watchlist"
say "Got $SEED_COUNT unique seed slugs ($src_desc)"
[ "$SEED_COUNT" -eq 0 ] && { err "No seeds. Aborting."; exit 1; }

###############################################################################
# 2) enrich each slug: wp.org metadata + CVEs from each available source
###############################################################################
hdr "Provider availability"
[ -n "${WPSCAN_API_TOKEN:-}" ]    && say "  WPScan:    ${GRN}token present${RST}" || say "  WPScan:    ${YEL}no token${RST}"
[ -n "${PATCHSTACK_API_TOKEN:-}" ]&& say "  Patchstack:${GRN}token present${RST}" || say "  Patchstack:${YEL}no token${RST}"
[ -n "${WORDFENCE_API_TOKEN:-}" ] && say "  Wordfence: ${GRN}token present${RST}" || say "  Wordfence: ${YEL}no token${RST}"
if [ -n "${WPSCAN_API_TOKEN:-}" ] && [ -n "${WORDFENCE_API_TOKEN:-}" ]; then
    say "  NVD:       ${YEL}skipped (other tokens active)${RST}"
else
    say "  NVD:       ${GRN}always on (no auth)${RST}"
fi

# Pre-fetch the Wordfence intel dump (if token) — covers all slugs at once.
# Then index by plugin slug into a smaller per-slug file so per-plugin lookups
# don't re-parse 70+ MB of JSON each time.
WF_INDEX_FILE=""
if [ -n "${WORDFENCE_API_TOKEN:-}" ]; then
    WF_INTEL_FILE="$CACHE_DIR/wordfence-intel.json"
    if cache_get "wordfence-intel.json" \
        "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner" \
        -H "Authorization: Bearer ${WORDFENCE_API_TOKEN}" >/dev/null; then
        WF_INDEX_FILE="$CACHE_DIR/wordfence-by-slug.json"
        if [ ! -s "$WF_INDEX_FILE" ] || [ "$WF_INTEL_FILE" -nt "$WF_INDEX_FILE" ]; then
            say "  indexing Wordfence intel by slug (one-time per fetch)..."
            "$PYBIN" - "$WF_INTEL_FILE" "$WF_INDEX_FILE" <<'PYIDX'
import sys, json, collections, os
src, dst = sys.argv[1], sys.argv[2]
tmp = dst + ".new"
data = json.load(open(src))
idx = collections.defaultdict(list)
items = data.values() if isinstance(data, dict) else data
for v in items:
    if not isinstance(v, dict): continue
    sw = v.get("software", []) or []
    if not isinstance(sw, list): continue
    for s in sw:
        if not isinstance(s, dict): continue
        if s.get("type") == "plugin" and s.get("slug"):
            idx[s["slug"]].append(v)
            break
# Atomic write: serialize fully, then fsync + os.replace (prevents truncation
# if the script exits before buffer flush, which produced a malformed JSON
# index in earlier versions).
with open(tmp, "w") as f:
    json.dump(dict(idx), f)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, dst)
print(f"  Wordfence index: {len(idx)} slugs", file=sys.stderr)
PYIDX
        fi
    else
        warn "Wordfence intel fetch failed"
    fi
fi

# Fresh-CVE discovery channel: pull slugs with any vuln published in the last
# 30 days from the Wordfence intel index and prepend them to the seed pool.
# This widens discovery beyond top-200-popular (which everyone else also scrapes).
if [ -n "$WF_INDEX_FILE" ] && [ -s "$WF_INDEX_FILE" ]; then
    fresh_slugs=$("$PYBIN" - "$WF_INDEX_FILE" <<'PYFRESH'
import sys, json, datetime as dt
idx = json.load(open(sys.argv[1]))
cutoff = (dt.date.today() - dt.timedelta(days=30)).isoformat()
out = []
for slug, vulns in idx.items():
    if not isinstance(vulns, list): continue
    for v in vulns:
        if not isinstance(v, dict): continue
        pub = (v.get("published") or v.get("date_published") or "")[:10]
        if pub >= cutoff:
            out.append(slug)
            break
print("\n".join(sorted(set(out))))
PYFRESH
)
    if [ -n "$fresh_slugs" ]; then
        n_fresh=$(echo "$fresh_slugs" | wc -l)
        say "  + Adding $n_fresh slug(s) with fresh CVE (<30d) to seed pool from Wordfence intel"
        { echo "$fresh_slugs" ; cat "$SEED_FILE" ; } | awk '!seen[$0]++' > "${SEED_FILE}.new"
        mv "${SEED_FILE}.new" "$SEED_FILE"
        SEED_COUNT=$(wc -l < "$SEED_FILE")
    fi
fi

# Patchstack fresh-disclosure channel.
# Patchstack's `/database/feed/` URL was retired (now serves a 404 SPA page).
# Their disclosure data is now API-only. If a PATCHSTACK_API_TOKEN is set, we
# pull the recent-vulnerabilities listing via their authenticated API and
# extract plugin slugs to prepend to the seed pool. Same pattern as the
# Wordfence intel fresh-CVE channel above.
#
# Endpoint: GET https://api.patchstack.com/v2/database/wordpress (no `software`
# param) returns a paginated list of recent vulns; each record has either a
# `software.slug` or `software.title` field we can map back to a wp.org slug.
# Without the token, this channel is skipped with a one-line notice.
if [ -n "${PATCHSTACK_API_TOKEN:-}" ]; then
    ps_feed_url="https://api.patchstack.com/v2/database/wordpress?per_page=100"
    if ps_feed_json=$(cache_get "patchstack-recent.json" "$ps_feed_url" \
            -H "Authorization: Bearer ${PATCHSTACK_API_TOKEN}" 2>/dev/null); then
        fresh_ps_slugs=$(echo "$ps_feed_json" | "$PYBIN" -c '
import sys, json, re
try:
    data = json.loads(sys.stdin.read())
except Exception:
    sys.exit(0)
slugs = set()
# Patchstack response shape varies; try common keys for software slug.
items = data.get("data") if isinstance(data, dict) and "data" in data else data
if not isinstance(items, list): sys.exit(0)
for it in items:
    if not isinstance(it, dict): continue
    sw = it.get("software") or {}
    if isinstance(sw, dict):
        s = sw.get("slug") or sw.get("software_slug")
        if s and re.match(r"^[a-z0-9][a-z0-9-]*$", s):
            slugs.add(s)
    # Also try top-level fields
    for k in ("slug","software_slug","plugin_slug"):
        v = it.get(k)
        if isinstance(v, str) and re.match(r"^[a-z0-9][a-z0-9-]*$", v):
            slugs.add(v)
print("\n".join(sorted(slugs)))
' 2>/dev/null)
        if [ -n "$fresh_ps_slugs" ]; then
            n_fresh_ps=$(echo "$fresh_ps_slugs" | wc -l)
            say "  + Adding $n_fresh_ps slug(s) from Patchstack recent disclosures (API)"
            { echo "$fresh_ps_slugs" ; cat "$SEED_FILE" ; } | awk '!seen[$0]++' > "${SEED_FILE}.new"
            mv "${SEED_FILE}.new" "$SEED_FILE"
            SEED_COUNT=$(wc -l < "$SEED_FILE")
        fi
    fi
else
    say "  Patchstack disclosure channel: ${YEL}no token${RST} — set PATCHSTACK_API_TOKEN to enable"
fi

# Parallel pre-fetch + pre-screen pass. The screener is the runtime bottleneck
# (~30s per plugin × 200 plugins serial = ~100min). Pre-running it across N
# workers cuts that to ~100/N min. Results are cached by (slug, version) so
# subsequent runs skip plugins whose version hasn't changed.
PRESCREEN_CACHE_DIR="$CACHE_DIR/screener-cache"
ZIP_CACHE_DIR="$HOME/.cache/wp-target-finder/zips"
mkdir -p "$PRESCREEN_CACHE_DIR" "$ZIP_CACHE_DIR"

if [ "$NO_SCREENER" != "1" ] && [ -x "$SCREENER" ] && [ "$CACHE_ONLY" != "1" ]; then
    hdr "Pre-fetch + pre-screen ${SEED_COUNT} plugins in parallel (${CONCURRENCY} workers)"
    say "  cache: $PRESCREEN_CACHE_DIR  (version-keyed, 7-day TTL)"
    # Filter seed list to slugs that have wp.org metadata cached (built during
    # seed phase or earlier runs); slugs without metadata are skipped here and
    # will fall back to inline screening in the enrichment loop if needed.
    PRESCREEN_INPUT="$CACHE_DIR/prescreen-input.txt"
    : > "$PRESCREEN_INPUT"
    while IFS= read -r slug; do
        [ -z "$slug" ] && continue
        meta_file="$CACHE_DIR/wporg-${slug}.json"
        if [ ! -f "$meta_file" ]; then
            # Fetch metadata now so the parallel worker can read the version
            meta_url="https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D=${slug}"
            cache_get "wporg-${slug}.json" "$meta_url" >/dev/null 2>&1 || continue
        fi
        echo "$slug" >> "$PRESCREEN_INPUT"
    done < "$SEED_FILE"

    n_to_prescreen=$(wc -l < "$PRESCREEN_INPUT")
    say "  $n_to_prescreen plugins queued for pre-screen"

    # Worker invocation. Args: slug, screener_path, zip_cache, output_cache,
    # timeout_seconds. Bash worker writes summary to output_cache file named
    # <slug>-<version>.txt; skips if cached for ≤7 days.
    if [ "$n_to_prescreen" -gt 0 ]; then
        xargs -d '\n' -P "$CONCURRENCY" -I{} bash -c '
            slug="$1"; SCREENER="$2"; ZIP_CACHE="$3"; OUT_DIR="$4"; TO="$5"
            meta_file="$HOME/.cache/wp-target-finder/wporg-${slug}.json"
            [ ! -f "$meta_file" ] && exit 0
            version=$("$PYBIN" -c "import json,sys;print((json.load(open(\"$meta_file\")).get(\"version\")) or \"unknown\")" 2>/dev/null)
            out_file="$OUT_DIR/${slug}-${version}.txt"
            # Skip if cached ≤7d
            if [ -f "$out_file" ] && [ -z "$(find "$out_file" -mtime +7 2>/dev/null)" ]; then exit 0; fi
            zip_path="$ZIP_CACHE/${slug}.zip"
            dl_url="https://downloads.wordpress.org/plugin/${slug}.latest-stable.zip"
            if [ ! -f "$zip_path" ] || [ -n "$(find "$zip_path" -mtime +1 2>/dev/null)" ]; then
                curl -fsSL --max-time 30 "$dl_url" -o "$zip_path" 2>/dev/null || { rm -f "$zip_path"; exit 0; }
            fi
            timeout "$TO" "$SCREENER" "$zip_path" > "$out_file" 2>&1 || true
            printf "  ✓ %s (v%s)\n" "$slug" "$version" >&2
        ' _ {} "$SCREENER" "$ZIP_CACHE_DIR" "$PRESCREEN_CACHE_DIR" 300 \
            < "$PRESCREEN_INPUT" 2>&1 | tail -10
    fi
    say "  pre-screen pass complete"
fi

ENRICHED_FILE="$CACHE_DIR/enriched.json"
echo "[" > "$ENRICHED_FILE"
first=1

hdr "Enriching ${SEED_COUNT} plugins (this hits the network; cached for 6h)"
processed=0
kept=0
while IFS= read -r slug; do
    [ -z "$slug" ] && continue
    processed=$((processed + 1))
    # Progress every 25
    if [ $((processed % 25)) -eq 0 ]; then
        printf '  ... %d/%d (kept so far: %d)\n' "$processed" "$SEED_COUNT" "$kept"
    fi

    # wp.org metadata
    meta_url="https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D=${slug}"
    meta_json=$(cache_get "wporg-${slug}.json" "$meta_url") || continue
    meta=$(echo "$meta_json" | py wporg_meta) || continue
    [ -z "$meta" ] && continue

    installs=$(echo "$meta" | "$PYBIN" -c 'import sys,json; print(json.load(sys.stdin).get("active_installs",0))')

    # Watchlist slugs (passed via --slug) bypass the install-floor gate — the
    # user explicitly named them, so honor that intent.
    is_watchlist=0
    if [ -n "$WATCHLIST_SLUGS" ] && echo ",$WATCHLIST_SLUGS," | grep -q ",$slug,"; then
        is_watchlist=1
    fi
    if [ "$is_watchlist" != "1" ] && [ "$installs" -lt "$MIN_INSTALLS" ]; then
        continue
    fi

    # NVD CVE lookup. Skipped if WPScan + Wordfence are both configured —
    # those return slug-accurate data, and NVD is the slowest source.
    nvd_combined="[]"
    if [ -z "${WPSCAN_API_TOKEN:-}" ] || [ -z "${WORDFENCE_API_TOKEN:-}" ]; then
    # NVD limits pubStart/pubEnd to a 120-day window AND returns oldest-first
    # when totalResults > page size — query 3 consecutive 120-day windows.
    for offset in 0 120 240; do
        start_d=$(date -u -d "$((offset+120)) days ago" +%Y-%m-%dT00:00:00.000)
        end_d=$(date -u -d "${offset} days ago"        +%Y-%m-%dT00:00:00.000)
        nvd_q="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${slug}&pubStartDate=${start_d}&pubEndDate=${end_d}&resultsPerPage=50"
        nvd_json=$(cache_get "nvd-${slug}-w${offset}.json" "$nvd_q" 2>/dev/null) || nvd_json='{"vulnerabilities":[]}'
        [ -z "$nvd_json" ] && nvd_json='{"vulnerabilities":[]}'
        chunk=$(echo "$nvd_json" | py nvd_cves_for_slug "$slug" 2>/dev/null)
        [ -z "$chunk" ] && chunk="[]"
        # merge JSON arrays
        nvd_combined=$(NVD_A="$nvd_combined" NVD_B="$chunk" "$PYBIN" -c '
import os, json
a = json.loads(os.environ["NVD_A"]); b = json.loads(os.environ["NVD_B"])
print(json.dumps(a + b))
')
        # rate-limit cushion is handled inside cache_get on actual fetches
    done
    fi
    nvd_cves="$nvd_combined"

    wpscan_cves="[]"
    if [ -n "${WPSCAN_API_TOKEN:-}" ] && [ ! -f "$WPSCAN_KILLED_MARKER" ]; then
        ws_url="https://wpscan.com/api/v3/plugins/${slug}"
        if ws_json=$(cache_get "wpscan-${slug}.json" "$ws_url" \
            -H "Authorization: Token token=${WPSCAN_API_TOKEN}" 2>/dev/null); then
            wpscan_cves=$(echo "$ws_json" | py wpscan_cves 2>/dev/null) || wpscan_cves="[]"
            [ -z "$wpscan_cves" ] && wpscan_cves="[]"
        fi
        if [ -f "$WPSCAN_KILLED_MARKER" ] && [ -z "${WPSCAN_WARNED:-}" ]; then
            warn "WPScan rate limit hit (free tier = 25 req/day); falling back to Wordfence for remaining plugins."
            WPSCAN_WARNED=1
        fi
    fi

    patchstack_cves="[]"
    if [ -n "${PATCHSTACK_API_TOKEN:-}" ]; then
        ps_url="https://api.patchstack.com/v2/database/wordpress?software=${slug}"
        ps_json=$(cache_get "patchstack-${slug}.json" "$ps_url" \
            -H "Authorization: Bearer ${PATCHSTACK_API_TOKEN}" 2>/dev/null) || ps_json="{}"
        patchstack_cves=$(echo "$ps_json" | py patchstack_cves_for_slug 2>/dev/null) || patchstack_cves="[]"
        [ -z "$patchstack_cves" ] && patchstack_cves="[]"
    fi

    wf_cves="[]"
    if [ -n "$WF_INDEX_FILE" ] && [ -s "$WF_INDEX_FILE" ]; then
        wf_cves=$(SLUG="$slug" IDX="$WF_INDEX_FILE" "$PYBIN" -c '
import os, json, re
idx = json.load(open(os.environ["IDX"]))
items = idx.get(os.environ["SLUG"], [])
out = []
for v in items:
    # Prefer real CVE ID. Wordfence stores it as a list of strings (or string)
    # under "cve"; fall back to extracting from title; last resort: UUID id.
    cve = v.get("cve")
    cve_id = ""
    if isinstance(cve, list) and cve:
        cve_id = cve[0]
    elif isinstance(cve, str) and cve:
        cve_id = cve
    if cve_id and not cve_id.upper().startswith("CVE-"):
        cve_id = "CVE-" + cve_id
    title = v.get("title","") or v.get("description","")
    if not cve_id:
        m = re.search(r"CVE-\d{4}-\d{4,7}", title or "")
        if m: cve_id = m.group(0)
    if not cve_id:
        cve_id = v.get("id","")
    published = (v.get("published") or v.get("date_published") or "")[:10]
    cwe = v.get("cwe") or []
    vt = (cwe[0].get("name") if cwe and isinstance(cwe[0], dict) else "") or "other"
    # Map CWE descriptions to short type tags for pattern detection
    short = vt
    for kw, label in [
        ("Cross-Site Scripting","XSS"), ("XSS","XSS"),
        ("SQL Injection","SQLi"),
        ("CSRF","CSRF"), ("Cross-Site Request","CSRF"),
        ("Authorization","AuthZ"), ("Authentication","AuthN"),
        ("Path Traversal","PathTraversal"),
        ("Deserialization","Deserialization"),
        ("File Upload","FileUpload"),
        ("Open Redirect","OpenRedirect"),
        ("Information","InfoDisc"),
    ]:
        if kw.lower() in vt.lower():
            short = label; break
    out.append({"id": cve_id, "published": published, "type": short, "summary": title[:140], "source":"Wordfence"})
print(json.dumps(out))
' 2>/dev/null) || wf_cves="[]"
        [ -z "$wf_cves" ] && wf_cves="[]"
    fi

    # Build aggregate record (pass JSON via env vars to avoid heredoc-interpolation hazards)
    rec=$(META_JSON="$meta" \
          NVD_JSON="$nvd_cves" \
          WPSCAN_JSON="$wpscan_cves" \
          PATCHSTACK_JSON="$patchstack_cves" \
          WF_JSON="$wf_cves" \
          "$PYBIN" -c '
import os, json
meta = json.loads(os.environ["META_JSON"])
cves = []
for k in ("NVD_JSON","WPSCAN_JSON","PATCHSTACK_JSON","WF_JSON"):
    try:
        v = json.loads(os.environ.get(k) or "[]")
        if isinstance(v, list): cves.extend(v)
    except Exception:
        pass
meta["cves"] = cves
print(json.dumps(meta))
')
    # We score ALL plugins that pass the install-floor + recency-of-update gate
    # below. Filtering on "must have a CVE" only after we've also looked for
    # silent-patch signals lets sweet-spot plugins surface.
    scored=$(echo "$rec" | py score)
    # Qualify: keep plugins broad enough that each install bucket (100K-399K,
    # 400K-999K, 1M+) has candidates. Mid-band plugins almost never have public
    # CVEs OR vague-security changelog phrases, so the legacy gate filtered
    # them all out and left only mega-popular ones. The screener + final score
    # do the real filtering downstream.
    qual=$(echo "$scored" | "$PYBIN" -c '
import sys, json
r = json.load(sys.stdin)
recent = r.get("cves_recent_count", 0)
ins    = r.get("active_installs", 0) or 0
vague  = r.get("vague_hits", 0)
fresh  = r.get("fresh_silent_patch", False)
# Any CVE in last 12mo → always qualifies (across all install sizes)
if recent >= 1: print("yes"); sys.exit(0)
# Mid-band (100K-999K) → qualify unconditionally so buckets 1 & 2 have candidates
if 100_000 <= ins <= 999_999: print("yes"); sys.exit(0)
# 1M+ → require silent-patch or vague-security signals (legacy strictness — too many to scan otherwise)
if ins >= 1_000_000 and (fresh or vague >= 2): print("yes"); sys.exit(0)
# 50K-99K sweet spot → keep legacy gate (fresh or vague signals required)
if 50_000 <= ins < 100_000 and (fresh or vague >= 2): print("yes"); sys.exit(0)
print("no")
')
    # Watchlist slugs bypass the qualify gate too — explicit-intent override.
    if [ "$qual" != "yes" ] && [ "$is_watchlist" != "1" ]; then continue; fi

    # Update-age gate: plugin must be updated within last 2 years AND at least
    # MIN_UPDATE_AGE_DAYS ago. Fresh updates (<30d) usually mean an active patch
    # cycle — silent fixes by maintainers, public researchers already on it.
    # Watchlist slugs bypass this gate too.
    last_upd=$(echo "$scored" | "$PYBIN" -c 'import sys,json; print(json.load(sys.stdin).get("last_updated",""))')
    if [ -n "$last_upd" ] && [ "$is_watchlist" != "1" ]; then
        upd_age=$("$PYBIN" -c "import datetime; print((datetime.date.today() - datetime.date.fromisoformat('${last_upd}'[:10])).days)" 2>/dev/null || echo 0)
        if [ "$upd_age" -gt 730 ]; then continue; fi
        if [ "$upd_age" -lt "$MIN_UPDATE_AGE_DAYS" ]; then continue; fi
    fi

    # ---- Screener pre-pass ----
    # Download zip to a session cache, run screener with default
    # first-party-only exclusion, parse the SCREENER_SUMMARY footer
    # line, attach counts back onto the scored record. Capped at 60s
    # per plugin; failures degrade gracefully to zeros.
    screener_high=0
    screener_medium=0
    screener_low=0
    screener_verdict=""
    # Auth-band counts (set if SCREENER_AUTHBAND_* lines present). Default
    # to 0 so the python json injection always sees a value.
    ah_nopriv=0; ah_sub=0; ah_author=0; ah_editor=0; ah_admin=0; ah_unknown=0
    am_nopriv=0; am_sub=0; am_author=0; am_editor=0; am_admin=0; am_unknown=0

    if [ "$NO_SCREENER" != "1" ] && [ -x "$SCREENER" ]; then
        slug_for_screen=$(echo "$scored" | "$PYBIN" -c 'import sys,json; print(json.load(sys.stdin).get("slug",""))')
        dl_url=$(echo "$scored" | "$PYBIN" -c 'import sys,json; print(json.load(sys.stdin).get("download_link",""))')
        if [ -n "$slug_for_screen" ] && [ -n "$dl_url" ]; then
            zip_cache_dir="$HOME/.cache/wp-target-finder/zips"
            mkdir -p "$zip_cache_dir"
            zip_path="$zip_cache_dir/${slug_for_screen}.zip"

            # Cache for 24h
            if [ ! -f "$zip_path" ] || [ "$(find "$zip_path" -mtime +1 2>/dev/null)" ]; then
                curl -fsSL --max-time 30 "$dl_url" -o "$zip_path" 2>/dev/null || rm -f "$zip_path"
            fi

            # First check the parallel pre-screen cache (populated by the
            # pre-fetch+pre-screen pass above). Skip inline screening if a
            # version-matched cache file exists. Otherwise fall back to inline
            # screening with the same 300s timeout the pre-screen used.
            slug_version=$(echo "$scored" | "$PYBIN" -c 'import sys,json; print(json.load(sys.stdin).get("version",""))' 2>/dev/null)
            prescreen_file=""
            if [ -n "$slug_version" ]; then
                prescreen_file="$PRESCREEN_CACHE_DIR/${slug_for_screen}-${slug_version}.txt"
            fi
            screener_rc=0
            screener_out=""
            if [ -n "$prescreen_file" ] && [ -s "$prescreen_file" ]; then
                screener_out=$(cat "$prescreen_file")
            elif [ -f "$zip_path" ]; then
                screener_out=$(timeout 300 "$SCREENER" "$zip_path" 2>&1)
                screener_rc=$?
            fi
            if [ -n "$screener_out" ]; then
                # SCREENER_SUMMARY<TAB>HIGH<TAB>MED<TAB>LOW<TAB>VERDICT
                summary_line=$(echo "$screener_out" | grep '^SCREENER_SUMMARY' | head -1)
                if [ -n "$summary_line" ]; then
                    screener_high=$(echo "$summary_line"   | awk -F'\t' '{print $2}')
                    screener_medium=$(echo "$summary_line" | awk -F'\t' '{print $3}')
                    screener_low=$(echo "$summary_line"    | awk -F'\t' '{print $4}')
                    screener_verdict=$(echo "$summary_line" | awk -F'\t' '{print $5}')
                elif [ "$screener_rc" = "124" ]; then
                    # `timeout` returns 124 on signal kill. Mark explicitly so
                    # the scorer doesn't treat the empty summary as "hardened"
                    # (which would falsely apply -3 to large plugins).
                    screener_verdict="TIMEOUT"
                fi
                # SCREENER_AUTHBAND_HIGH/MED<TAB>nopriv<TAB>sub<TAB>author<TAB>editor<TAB>admin<TAB>unknown
                ah_line=$(echo "$screener_out" | grep '^SCREENER_AUTHBAND_HIGH' | head -1)
                if [ -n "$ah_line" ]; then
                    ah_nopriv=$(echo "$ah_line" | awk -F'\t' '{print $2}')
                    ah_sub=$(echo "$ah_line"    | awk -F'\t' '{print $3}')
                    ah_author=$(echo "$ah_line" | awk -F'\t' '{print $4}')
                    ah_editor=$(echo "$ah_line" | awk -F'\t' '{print $5}')
                    ah_admin=$(echo "$ah_line"  | awk -F'\t' '{print $6}')
                    ah_unknown=$(echo "$ah_line" | awk -F'\t' '{print $7}')
                fi
                am_line=$(echo "$screener_out" | grep '^SCREENER_AUTHBAND_MED' | head -1)
                if [ -n "$am_line" ]; then
                    am_nopriv=$(echo "$am_line" | awk -F'\t' '{print $2}')
                    am_sub=$(echo "$am_line"    | awk -F'\t' '{print $3}')
                    am_author=$(echo "$am_line" | awk -F'\t' '{print $4}')
                    am_editor=$(echo "$am_line" | awk -F'\t' '{print $5}')
                    am_admin=$(echo "$am_line"  | awk -F'\t' '{print $6}')
                    am_unknown=$(echo "$am_line" | awk -F'\t' '{print $7}')
                fi
            fi
        fi
    fi

    # ---- F01-shape sibling detection (wp-svn-diff integration) ----
    # When the plugin has a CVE with a known fixed_in version AND it's not
    # already over-hunted (≥5 CVEs in 12mo), pull the SVN diff between
    # version_before_fix and fixed_in, parse POTENTIAL SIBLING counts.
    # Cached per (slug, base, head) for SVNDIFF_TTL_DAYS days.
    #
    # The output of wp-svn-diff has lines like:
    #   HIGH POTENTIAL SIBLING  fn foo  ...
    #   MED  POTENTIAL SIBLING  fn bar  ...
    #   LOW  POTENTIAL SIBLING  fn baz  ...
    # We count each priority level. The scorer rewards HIGH/MED (likely real
    # candidates) and ignores pure-LOW (mostly boilerplate noise).
    f01_high=0; f01_med=0; f01_low=0
    f01_prev_tag=""; f01_fixed_in=""
    if [ "$NO_SVNDIFF" != "1" ] && [ -x "$SVNDIFF" ]; then
        f01_fixed_in=$(echo "$scored" | "$PYBIN" -c '
import sys, json
r = json.load(sys.stdin)
lc = r.get("latest_cve") or {}
print(lc.get("fixed_in", "") or "")
')
        f01_n_cves=$(echo "$scored" | "$PYBIN" -c 'import sys,json; print(json.load(sys.stdin).get("cves_recent_count", 0))')
        f01_slug=$(echo "$scored" | "$PYBIN" -c 'import sys,json; print(json.load(sys.stdin).get("slug", ""))')

        # Skip if no fixed_in (can't pinpoint patch tag) OR already-hunted
        if [ -n "$f01_fixed_in" ] && [ -n "$f01_slug" ] && [ "$f01_n_cves" -lt 5 ]; then
            svndiff_cache_dir="$CACHE_DIR/svndiff"
            mkdir -p "$svndiff_cache_dir"

            # Resolve "previous tag" — tag immediately before fixed_in.
            # Tag list cached for SVNDIFF_TTL_DAYS too.
            tags_cache="$svndiff_cache_dir/tags-${f01_slug}.txt"
            if [ ! -f "$tags_cache" ] || [ -n "$(find "$tags_cache" -mtime +${SVNDIFF_TTL_DAYS} 2>/dev/null)" ]; then
                svn ls "https://plugins.svn.wordpress.org/${f01_slug}/tags/" 2>/dev/null \
                    | sed 's|/$||' | grep -E '^[0-9]' | sort -V > "$tags_cache" 2>/dev/null || true
            fi

            if [ -s "$tags_cache" ]; then
                f01_prev_tag=$(awk -v fixed="$f01_fixed_in" '
                    { if ($0 == fixed) { print prev; exit } prev = $0 }
                ' "$tags_cache")
            fi

            if [ -n "$f01_prev_tag" ]; then
                # Cache file per (slug, prev, head) — 7-day TTL.
                cache_key="${f01_slug}_${f01_prev_tag}_${f01_fixed_in}"
                # Filesystem-safe key
                cache_key=$(echo "$cache_key" | tr '/' '_' | tr ' ' '_')
                svndiff_out="$svndiff_cache_dir/${cache_key}.txt"

                if [ ! -f "$svndiff_out" ] || [ -n "$(find "$svndiff_out" -mtime +${SVNDIFF_TTL_DAYS} 2>/dev/null)" ]; then
                    # Run wp-svn-diff with a hard timeout — big plugins can have
                    # 10K+ line diffs that take minutes.
                    timeout 90 "$SVNDIFF" "$f01_slug" "$f01_prev_tag" "$f01_fixed_in" \
                        > "$svndiff_out" 2>/dev/null || true
                fi

                if [ -s "$svndiff_out" ]; then
                    # Strip ANSI for grep (wp-svn-diff colors its output)
                    f01_clean=$(sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' "$svndiff_out")
                    f01_high=$(echo "$f01_clean" | grep -c -e 'HIGH POTENTIAL SIBLING' || true)
                    f01_med=$(echo  "$f01_clean" | grep -c -e 'MED  POTENTIAL SIBLING' || true)
                    f01_low=$(echo  "$f01_clean" | grep -c -e 'LOW  POTENTIAL SIBLING' || true)
                    [ -z "$f01_high" ] && f01_high=0
                    [ -z "$f01_med" ]  && f01_med=0
                    [ -z "$f01_low" ]  && f01_low=0
                fi
            fi
        fi
    fi

    # Inject screener counts into the record, then re-run the scorer so
    # the screener-derived rules can fire (the first scoring pass at the
    # top of the loop ran before these counts were available).
    scored=$(echo "$scored" | "$PYBIN" -c "
import sys, json
r = json.load(sys.stdin)
r['screener_high']    = int('$screener_high' or 0)
r['screener_medium']  = int('$screener_medium' or 0)
r['screener_low']     = int('$screener_low' or 0)
r['screener_verdict'] = '$screener_verdict' or ''
# Per-band auth counters from SCREENER_AUTHBAND_HIGH / _MED. Allow blanks for
# back-compat with older screener output that didn't emit these lines.
r['screener_authband_high'] = {
    'nopriv':     int('${ah_nopriv:-0}'    or 0),
    'subscriber': int('${ah_sub:-0}'       or 0),
    'author':     int('${ah_author:-0}'    or 0),
    'editor':     int('${ah_editor:-0}'    or 0),
    'admin':      int('${ah_admin:-0}'     or 0),
    'unknown':    int('${ah_unknown:-0}'   or 0),
}
r['screener_authband_med'] = {
    'nopriv':     int('${am_nopriv:-0}'    or 0),
    'subscriber': int('${am_sub:-0}'       or 0),
    'author':     int('${am_author:-0}'    or 0),
    'editor':     int('${am_editor:-0}'    or 0),
    'admin':      int('${am_admin:-0}'     or 0),
    'unknown':    int('${am_unknown:-0}'   or 0),
}
# Wordfence-eligible scope: NOPRIV + SUBSCRIBER + AUTHOR (Editor+ is OOS).
# UNKNOWN is conservatively kept in-scope until classification improves.
ah = r['screener_authband_high']
am = r['screener_authband_med']
r['screener_inscope_high'] = ah['nopriv'] + ah['subscriber'] + ah['author'] + ah['unknown']
r['screener_inscope_med']  = am['nopriv'] + am['subscriber'] + am['author'] + am['unknown']
r['screener_oos_high']     = ah['editor'] + ah['admin']
r['screener_oos_med']      = am['editor'] + am['admin']
# F01-shape sibling counts (from wp-svn-diff). 0/0/0 = not run or no signal.
r['f01_siblings_high']     = int('$f01_high' or 0)
r['f01_siblings_med']      = int('$f01_med' or 0)
r['f01_siblings_low']      = int('$f01_low' or 0)
r['f01_diff_base']         = '$f01_prev_tag' or ''
r['f01_diff_head']         = '$f01_fixed_in' or ''
print(json.dumps(r))
")
    scored=$(echo "$scored" | py score)

    if [ $first -eq 1 ]; then first=0; else echo "," >> "$ENRICHED_FILE"; fi
    echo "$scored" >> "$ENRICHED_FILE"
    kept=$((kept + 1))
done < "$SEED_FILE"
echo "]" >> "$ENRICHED_FILE"
say "Kept $kept candidates after filtering."

[ "$kept" -eq 0 ] && { err "No candidates passed filters. Try lowering --min-installs or wait for cache to populate."; exit 1; }

###############################################################################
# 3) sort all candidates by score, then dedupe against history
###############################################################################
# Each stage below writes to a .tmp, validates JSON, then atomically moves
# into place. An interrupted run (SIGINT, OOM, WSL2 stall) leaves only a .tmp
# behind; the previous good output stays untouched, and we exit loudly instead
# of cascading partial data into top.json.
SORTED_FILE="$CACHE_DIR/sorted.json"
SORTED_TMP="$SORTED_FILE.tmp"
if ! cat "$ENRICHED_FILE" | "$PYBIN" -c '
import sys, json
recs = json.load(sys.stdin)
recs.sort(key=lambda r: r.get("score",0), reverse=True)
json.dump(recs, sys.stdout)
' > "$SORTED_TMP"; then
    err "sort pipeline failed (python exited non-zero)"
    rm -f "$SORTED_TMP"
    exit 1
fi
if ! "$PYBIN" -c "import json,sys; d=json.load(open('$SORTED_TMP')); sys.exit(0 if isinstance(d,list) else 1)" 2>/dev/null; then
    err "sort produced invalid JSON: $SORTED_TMP (truncated mid-write?)"
    rm -f "$SORTED_TMP"
    exit 1
fi
mv -f "$SORTED_TMP" "$SORTED_FILE"

# Dedup: drop slugs already in history with no change; annotate the rest.
DEDUP_FILE="$CACHE_DIR/dedup.json"
DEDUP_TMP="$DEDUP_FILE.tmp"
if ! cat "$SORTED_FILE" | py history_filter "$HISTORY_FILE" "$AUDITED_LIST" "$INCLUDE_AUDITED" > "$DEDUP_TMP"; then
    err "history_filter pipeline failed"
    rm -f "$DEDUP_TMP"
    exit 1
fi
if ! "$PYBIN" -c "import json,sys; d=json.load(open('$DEDUP_TMP')); sys.exit(0 if isinstance(d,list) else 1)" 2>/dev/null; then
    err "history_filter produced invalid JSON: $DEDUP_TMP"
    rm -f "$DEDUP_TMP"
    exit 1
fi
mv -f "$DEDUP_TMP" "$DEDUP_FILE"

total_after_dedup=$("$PYBIN" -c 'import json; print(len(json.load(open("'"$DEDUP_FILE"'"))))')
hdr "Candidate pool"
say "  $kept passed filters"
say "  $total_after_dedup remain after history dedup ($((kept - total_after_dedup)) skipped as unchanged)"

# Install-bucket sampling: pick the highest-scoring plugin in each band so the
# top 3 always covers a spread of install sizes (instead of all being from the
# same mega-popular cluster).
#   bucket 1: 100K - 399K installs
#   bucket 2: 400K - 999K installs
#   bucket 3: 1M+ installs
# A bucket with no matching candidate is simply omitted from the output.
TOP_JSON="$CACHE_DIR/top.json"
TOP_TMP="$TOP_JSON.tmp"
if ! "$PYBIN" -c "
import json
recs = json.load(open('$DEDUP_FILE'))
buckets = [(100_000, 399_999), (400_000, 999_999), (1_000_000, 10**12)]
picks = []
for lo, hi in buckets:
    band = [r for r in recs if lo <= (r.get('active_installs') or 0) <= hi]
    band.sort(key=lambda r: r.get('score', 0), reverse=True)
    if band:
        picks.append(band[0])
json.dump(picks, open('$TOP_TMP', 'w'))
"; then
    err "top.json write failed"
    rm -f "$TOP_TMP"
    exit 1
fi
if ! "$PYBIN" -c "import json,sys; d=json.load(open('$TOP_TMP')); sys.exit(0 if isinstance(d,list) else 1)" 2>/dev/null; then
    err "top.json is invalid: $TOP_TMP"
    rm -f "$TOP_TMP"
    exit 1
fi
mv -f "$TOP_TMP" "$TOP_JSON"
top_count=$("$PYBIN" -c 'import json; print(len(json.load(open("'"$TOP_JSON"'"))))')
[ "$top_count" -eq 0 ] && { warn "Nothing new to recommend (all top candidates already in history). Use --reset-history to start fresh."; exit 0; }

###############################################################################
# 4) download + screen the top N (BEFORE rendering, so screener data appears inline)
###############################################################################
mapfile -t TOP_SLUGS < <(cat "$TOP_JSON" | py top_slugs)

hdr "Downloading top ${#TOP_SLUGS[@]} to $DOWNLOAD_DIR"
declare -A ZIP_PATH=()
for slug in "${TOP_SLUGS[@]}"; do
    [ -z "$slug" ] && continue
    zip_url="https://downloads.wordpress.org/plugin/${slug}.latest-stable.zip"
    zip_path="$DOWNLOAD_DIR/${slug}.zip"
    say "  fetching $slug -> $zip_path"
    if curl -sSLg --max-time 90 -o "$zip_path" "$zip_url"; then
        ZIP_PATH[$slug]="$zip_path"
    else
        warn "  download failed for $slug"
    fi
done

# Run screener and capture verdict / counts to a JSON file the renderer can read.
SCREENER_JSON="$CACHE_DIR/screener-results.json"
echo '{}' > "$SCREENER_JSON"
if [ "$NO_SCREENER" = "1" ]; then
    warn "Skipping screener (--no-screener)"
elif [ ! -x "$SCREENER" ]; then
    warn "Screener not executable at $SCREENER; skipping (chmod +x to enable)."
else
    hdr "Running screener on top ${#ZIP_PATH[@]}"
    for slug in "${TOP_SLUGS[@]}"; do
        zp="${ZIP_PATH[$slug]:-}"
        [ -z "$zp" ] && continue
        say "  ----- $slug -----"
        # 300s timeout — large plugins (W3TC, WooCommerce-class) routinely
        # exceed 60s. Without an explicit timeout this loop could hang on a
        # single top-N pick and never complete.
        out=$(timeout 300 "$SCREENER" "$zp" 2>&1)
        screener_rc=$?
        clean=$(echo "$out" | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g')
        verdict=$(echo "$clean" | grep -E '^Overall:' | tail -1 | awk -F': ' '{print $2}')
        if [ -z "$verdict" ] && [ "$screener_rc" = "124" ]; then
            verdict="TIMEOUT"
            say "    -> TIMEOUT after 300s — large plugin, no screener data"
        fi
        highs=$(echo "$clean" | grep -oE 'HIGH:[[:space:]]+[0-9]+' | tail -1 | grep -oE '[0-9]+')
        meds=$(echo  "$clean" | grep -oE 'MEDIUM:[[:space:]]+[0-9]+' | tail -1 | grep -oE '[0-9]+')
        # Auth-band breakdown from SCREENER_AUTHBAND_HIGH (tab-separated).
        ab_h=$(echo "$out" | grep '^SCREENER_AUTHBAND_HIGH' | head -1)
        ab_m=$(echo "$out" | grep '^SCREENER_AUTHBAND_MED'  | head -1)
        if [ -n "$ab_h" ]; then
            ah_n=$(echo "$ab_h" | awk -F'\t' '{print $2}')   # NOPRIV
            ah_s=$(echo "$ab_h" | awk -F'\t' '{print $3}')   # SUBSCRIBER
            ah_a=$(echo "$ab_h" | awk -F'\t' '{print $4}')   # AUTHOR
            ah_e=$(echo "$ab_h" | awk -F'\t' '{print $5}')   # EDITOR
            ah_d=$(echo "$ab_h" | awk -F'\t' '{print $6}')   # ADMIN
            ah_u=$(echo "$ab_h" | awk -F'\t' '{print $7}')   # UNKNOWN
        else
            ah_n=0; ah_s=0; ah_a=0; ah_e=0; ah_d=0; ah_u=0
        fi
        if [ -n "$ab_m" ]; then
            am_n=$(echo "$ab_m" | awk -F'\t' '{print $2}')
            am_s=$(echo "$ab_m" | awk -F'\t' '{print $3}')
            am_a=$(echo "$ab_m" | awk -F'\t' '{print $4}')
            am_e=$(echo "$ab_m" | awk -F'\t' '{print $5}')
            am_d=$(echo "$ab_m" | awk -F'\t' '{print $6}')
            am_u=$(echo "$ab_m" | awk -F'\t' '{print $7}')
        else
            am_n=0; am_s=0; am_a=0; am_e=0; am_d=0; am_u=0
        fi
        verdict="${verdict:-UNKNOWN}"
        say "    -> $verdict  HIGH=${highs:-0} MEDIUM=${meds:-0}  (NOPRIV-H=$ah_n  ADMIN-H=$ah_d)"
        SLUG="$slug" V="$verdict" H="${highs:-0}" M="${meds:-0}" \
        AHN="$ah_n" AHS="$ah_s" AHA="$ah_a" AHE="$ah_e" AHD="$ah_d" AHU="$ah_u" \
        AMN="$am_n" AMS="$am_s" AMA="$am_a" AME="$am_e" AMD="$am_d" AMU="$am_u" \
            "$PYBIN" -c '
import os, json
p = "'"$SCREENER_JSON"'"
d = json.load(open(p))
def i(k): return int(os.environ.get(k) or 0)
d[os.environ["SLUG"]] = {
    "verdict":  os.environ["V"],
    "high":     int(os.environ["H"]),
    "med":      int(os.environ["M"]),
    "ah_nopriv":i("AHN"), "ah_subscriber":i("AHS"), "ah_author":i("AHA"),
    "ah_editor":i("AHE"), "ah_admin":    i("AHD"),  "ah_unknown":i("AHU"),
    "am_nopriv":i("AMN"), "am_subscriber":i("AMS"), "am_author":i("AMA"),
    "am_editor":i("AME"), "am_admin":    i("AMD"),  "am_unknown":i("AMU"),
}
json.dump(d, open(p,"w"))
'
    done
fi

###############################################################################
# 5) render top N with screener data inline + write daily results file
###############################################################################
hdr "Top ${#TOP_SLUGS[@]} targets"
RENDERED=$(cat "$TOP_JSON" | py render_top "$SCREENER_JSON")
echo "$RENDERED"

# Final recommendation = #1 in the dedup'd list
best_slug="${TOP_SLUGS[0]:-}"
if [ -n "$best_slug" ]; then
    hdr "Best target to audit today"
    best_rec=$(SLUG="$best_slug" "$PYBIN" -c '
import os, json
recs = json.load(open("'"$TOP_JSON"'"))
for r in recs:
    if r.get("slug") == os.environ["SLUG"]:
        print(json.dumps(r)); break
')
    best_name=$(echo "$best_rec"  | "$PYBIN" -c 'import sys,json; print(json.load(sys.stdin).get("name",""))')
    best_score=$(echo "$best_rec" | "$PYBIN" -c 'import sys,json; print(json.load(sys.stdin).get("score",0))')
    printf '%s%s%s (slug: %s)  score=%s\n' "$BLD" "$best_name" "$RST" "$best_slug" "$best_score"
    printf '  SVN:      %shttps://plugins.svn.wordpress.org/%s/%s\n' "$CYA" "$best_slug" "$RST"
    printf '  Download: %shttps://downloads.wordpress.org/plugin/%s.latest-stable.zip%s\n' "$CYA" "$best_slug" "$RST"
fi

# Write daily results (ANSI-stripped) to ~/wp-target-results/YYYY-MM-DD.txt
TODAY=$(date -u +%Y-%m-%d)
RESULT_FILE="$RESULTS_DIR/${TODAY}.txt"
{
    echo "wp-target-finder run: $(date)"
    echo "limit=$LIMIT min_installs=$MIN_INSTALLS top=$TOP_N kept=$kept after_dedup=$total_after_dedup"
    nvd_state="on"
    [ -n "${WPSCAN_API_TOKEN:-}" ] && [ -n "${WORDFENCE_API_TOKEN:-}" ] && nvd_state="skipped"
    wpscan_state="off"
    if [ -n "${WPSCAN_API_TOKEN:-}" ]; then
        [ -f "$WPSCAN_KILLED_MARKER" ] && wpscan_state="rate-limited" || wpscan_state="on"
    fi
    echo "providers: WPScan=$wpscan_state Wordfence=$([ -n "${WORDFENCE_API_TOKEN:-}" ] && echo on || echo off) Patchstack=$([ -n "${PATCHSTACK_API_TOKEN:-}" ] && echo on || echo off) NVD=$nvd_state"
    echo "----------------------------------------------------------------"
    echo "$RENDERED"
    echo "----------------------------------------------------------------"
    if [ -n "$best_slug" ]; then
        echo "Best target today: $best_slug"
        echo "  SVN:      https://plugins.svn.wordpress.org/${best_slug}/"
        echo "  Download: https://downloads.wordpress.org/plugin/${best_slug}.latest-stable.zip"
    fi
} | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' > "$RESULT_FILE"
say ""
say "Daily results: $RESULT_FILE"
say "History:       $HISTORY_FILE"

# Optional machine-readable export (--json-out PATH). Includes everything in
# top.json plus screener counts and the path to the daily results file. Useful
# for ingest into a tracker / spreadsheet / CI pipeline.
if [ -n "$JSON_OUT" ]; then
    "$PYBIN" -c "
import json, os
top = json.load(open('$TOP_JSON'))
screener = {}
try:
    screener = json.load(open('$SCREENER_JSON'))
except Exception:
    pass
for r in top:
    sc = screener.get(r.get('slug', ''))
    if sc:
        r['screener'] = sc
out = {
    'ran_at': '$TODAY',
    'daily_results_path': '$RESULT_FILE',
    'history_file': '$HISTORY_FILE',
    'top': top,
}
json.dump(out, open('$JSON_OUT', 'w'), indent=2)
print(f'JSON export: $JSON_OUT ({len(top)} top candidates)')
" 2>&1
fi

# 6) Append ALL kept (deduped) candidates to history, not just the rendered top.
#    Previously only top-N were recorded — plugins ranked 4..N silently dropped
#    out of history and were treated as "new" on the next run. Now every plugin
#    that survives dedup gets its current changelog_sha recorded.
cat "$DEDUP_FILE" | py append_history "$HISTORY_FILE" "$TODAY" >/dev/null

# Tier 3 #11: log the surfaced top-N (score + reasons) for yield tracking.
# Outcomes are filled later via --record-outcome; --yield-report reads this.
if [ -s "$TOP_JSON" ]; then
    yl=$(cat "$TOP_JSON" | py yield_log "$YIELD_FILE" "$TODAY" 2>/dev/null) && say "$yl"
fi
say "Yield log:     $YIELD_FILE"
say "Cache:         $CACHE_DIR"
