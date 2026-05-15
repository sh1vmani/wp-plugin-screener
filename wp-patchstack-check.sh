#!/usr/bin/env bash
# wp-patchstack-check.sh — per-candidate Patchstack dup-check (no token).
#
# Fetches the PUBLIC, server-rendered Patchstack advisory page for ONE plugin
# and lists every advisory Patchstack knows about (version / type / title).
# Use at hunt-workflow steps 2 (early dup-gate), 4 (sink-specific dup-check)
# and 6 (final dup re-confirm) — alongside the Wordfence advisory check.
#
# Why this exists: duplicate rejections are the main wasted-effort cost in
# bounty hunting. Wordfence's own advisory pages are JS-rendered (a plain
# fetch returns empty); Patchstack's per-plugin page is server-rendered with
# the advisory list embedded as JSON, so it is the reliable free dup-check
# source to pair with a Wordfence check.
#
# STRICTLY per-candidate / on-demand. Not a bulk scraper — one slug per call,
# 6h local cache, polite UA + timeout. Does NOT replace the sweep's CVE
# enrichment (no public bulk feed exists).
#
# Usage:
#   wp-patchstack-check.sh <slug> [--grep REGEX] [--refresh]
#     <slug>        wordpress.org plugin slug
#     --grep REGEX  highlight advisories whose title/slug matches REGEX
#                   (e.g. a sink fn / parameter you are about to report)
#     --refresh     ignore cache, refetch
#
# Exit: 0 advisories listed · 2 fetch failed · 3 plugin not in Patchstack DB

set -euo pipefail

SLUG="${1:-}"
[ -z "$SLUG" ] && { echo "usage: $0 <slug> [--grep REGEX] [--refresh]" >&2; exit 1; }
shift || true

GREP_RE=""
REFRESH=0
while [ $# -gt 0 ]; do
    case "$1" in
        --grep)    GREP_RE="$2"; shift 2 ;;
        --refresh) REFRESH=1; shift ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

PYBIN="$(command -v python3.12 || command -v python3.11 || command -v python3)"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36'
URL="https://patchstack.com/database/wordpress/plugin/${SLUG}/vulnerabilities"
CACHE_DIR="/tmp/.wp-patchstack-cache"
CACHE="$CACHE_DIR/${SLUG}.html"
mkdir -p "$CACHE_DIR"

# 6h cache: respectful to their site + fast for repeated step-2/4/6 checks.
if [ "$REFRESH" = "1" ] || [ ! -f "$CACHE" ] || \
   [ "$(( $(date +%s) - $(stat -c %Y "$CACHE" 2>/dev/null || echo 0) ))" -gt 21600 ]; then
    if ! curl -fsS -A "$UA" -m 25 "$URL" -o "$CACHE" 2>/dev/null; then
        echo "[x] Patchstack fetch failed for '$SLUG' ($URL)" >&2
        rm -f "$CACHE"
        exit 2
    fi
fi

"$PYBIN" - "$CACHE" "$SLUG" "$GREP_RE" <<'PY'
import sys, re, json, html

path, slug, grep_re = sys.argv[1], sys.argv[2], sys.argv[3]
doc = open(path, encoding="utf-8", errors="replace").read()

m = re.search(r'<script type="application/json"[^>]*id="__NUXT_DATA__">(.*?)</script>',
              doc, re.S)
if not m:
    print(f"[!] No Patchstack advisory data found for '{slug}'.")
    print("    Either the plugin has no Patchstack record, or the page layout changed.")
    sys.exit(3)

try:
    arr = json.loads(m.group(1))
except Exception as e:
    print(f"[x] Could not parse Patchstack payload: {e}")
    sys.exit(2)

strs = [x for x in arr if isinstance(x, str)]

# Advisory SEO slugs: one per advisory, encode plugin+version+type, stable kebab.
adv_slugs = sorted({s for s in strs
                    if s.startswith("wordpress-")
                    and re.search(r"-\d+-\d+(-\d+){0,2}-", s)
                    and s.endswith("vulnerability")})
# Human titles: full type + auth tier + (often) the exact parameter/sink.
titles = sorted({s for s in strs
                 if s.endswith("vulnerability")
                 and not s.startswith("wordpress-")
                 and len(s) < 240})
affected = sorted({s for s in strs if re.fullmatch(r"<=?\s?\d+\.\d+(\.\d+){0,3}", s)})
fixed    = sorted({s for s in strs if re.fullmatch(r"\d+\.\d+(\.\d+){0,3}", s)})

if not adv_slugs and not titles:
    print(f"[ok] '{slug}' has NO advisories in the Patchstack database "
          f"(clean — good dup-check signal).")
    sys.exit(3)

def slug_version(s):
    mm = re.search(r"-(\d+(?:-\d+){1,3})-(?=[a-z])", s)
    return mm.group(1).replace("-", ".") if mm else "?"

def slug_type(s):
    body = re.sub(r"^wordpress-.*?-\d+(?:-\d+){1,3}-", "", s)
    body = re.sub(r"-vulnerability$", "", body)
    return body.replace("-", " ")

rx = re.compile(grep_re, re.I) if grep_re else None
hit_any = False

print(f"== Patchstack advisories for '{slug}'  ({len(adv_slugs)} record(s)) ==")
print(f"   source: https://patchstack.com/database/wordpress/plugin/{slug}/vulnerabilities")
print(f"   {'VERSION':<12} TYPE (from advisory slug)")
print(f"   {'-'*11}  {'-'*55}")
for s in sorted(adv_slugs, key=slug_version):
    ver = slug_version(s)
    typ = slug_type(s)
    mark = ""
    if rx and (rx.search(s) or rx.search(typ)):
        mark = "  >>> POSSIBLE DUP (matches --grep)"
        hit_any = True
    print(f"   {ver:<12} {typ}{mark}")

print()
print("   -- advisory titles (type / auth-tier / parameter detail) --")
for t in titles:
    mark = ""
    if rx and rx.search(t):
        mark = "  >>> POSSIBLE DUP (matches --grep)"
        hit_any = True
    print(f"     - {html.unescape(t)}{mark}")

if affected or fixed:
    print()
    print(f"   affected tokens: {', '.join(affected) if affected else '-'}")
    print(f"   fixed tokens:    {', '.join(fixed) if fixed else '-'}")

print()
if rx:
    if hit_any:
        print(f"[DUP-RISK] '{grep_re}' matched an existing Patchstack advisory above.")
        print("           Treat as likely duplicate unless your sink is provably distinct")
        print("           (different function/parameter AND a later, still-affected version).")
    else:
        print(f"[clear] No existing Patchstack advisory matches '{grep_re}'.")
        print("        Still cross-check Wordfence advisories before deep work.")
else:
    print("[i] Re-run with --grep '<sink-fn|parameter>' to flag a specific dup.")
    print("    Always cross-check the Wordfence advisory page too (different coverage).")
PY
