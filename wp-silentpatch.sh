#!/usr/bin/env bash
# wp-silentpatch.sh — A1: silent-patch radar (the yield pivot).
#
# Thesis (ROADMAP ★ A1): the highest-yield, STRUCTURALLY NON-DUPLICATE WP
# strategy is to catch a security fix in the latest release *before an
# advisory exists for it*. F01/F02 failed because CVE-sibling hunting is the
# most duplicate-prone lane; 8/8 dry because vendors comprehensive-fix. This
# tool sidesteps both: you are AHEAD of the advisory, so a sibling cannot
# already be advisoried — by construction.
#
# Method (all engines REUSED per the anti-dup map — this tool is orchestration
# + the silent correlation ONLY):
#   universe : wp.org popular plugins (same fetch as wp-screener-hunt)
#   gate     : lib/wp_gates.py  (>=100k floor, pro-vendor exclusion) + a
#              FRESH-update filter (silent patches are recent: updated within
#              --max-age days; this is A1's own recency semantic — the
#              opposite emphasis to the hunt-scoring curve, by design)
#   diff     : wp-svn-diff.sh <slug>  (last-2-tags; emits the security-signal
#              section — auth/cast/typesafe/esc_like/loose-compare/...)
#   dup-gate : lib/wp-intel.sh intel::advisories  — if the diff's HEAD release
#              has security-shaped signals AND NO advisory covers a version
#              >= that release => SILENT PATCH (un-advisoried = non-dup).
#
# Output: ranked silent-patch candidates with the changed file/fn + the
# exact HIGH signal lines = direct, non-duplicate audit targets.
#
# Usage:
#   wp-silentpatch.sh [--pages P] [--max-age D] [--screen-top N]
#                     [--min-installs N] [--limit N] [--refresh]
#     --max-age D     only plugins updated within D days (default 45 — the
#                     silent-patch window; a silent fix is by nature recent)
#     --screen-top N  how many gated candidates to svn-diff (default 25)

set -euo pipefail

PAGES=4 ; MAX_AGE=45 ; SCREEN_TOP=25 ; LIMIT=20 ; REFRESH=0
MIN_INSTALLS=100000
while [ $# -gt 0 ]; do
    case "$1" in
        --pages) PAGES="$2"; shift 2 ;;
        --max-age) MAX_AGE="$2"; shift 2 ;;
        --screen-top) SCREEN_TOP="$2"; shift 2 ;;
        --min-installs) MIN_INSTALLS="$2"; shift 2 ;;
        --limit) LIMIT="$2"; shift 2 ;;
        --refresh) REFRESH=1; shift ;;
        -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

HERE="$(dirname "${BASH_SOURCE[0]}")"
PYBIN="$(command -v python3.12 || command -v python3.11 || command -v python3)"
. "$HERE/lib/wp-intel.sh"
export WP_GATES_LIB="$HERE/lib"
SVNDIFF="$HERE/wp-svn-diff.sh"
AUDITED="$HOME/wp-audited-list.txt"
CACHE="/tmp/.wp-silentpatch"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
mkdir -p "$CACHE/pop" "$CACHE/diff" ; touch "$AUDITED"

# ---- 1) universe: popular plugins, gated (>=100k, not pro, FRESH) ----------
echo "[*] wp-silentpatch is a SLOW network-bound batch radar (svn-diff confirms" >&2
echo "    fetch full tag trees). Run it backgrounded: nohup wp-silentpatch.sh ... &" >&2
echo "[*] fetching $PAGES popular page(s) ..." >&2
for p in $(seq 1 "$PAGES"); do
    f="$CACHE/pop/$p.json"
    if [ "$REFRESH" = 1 ] || [ ! -s "$f" ]; then
        curl -sS -m 20 -A "$UA" "https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request%5Bbrowse%5D=popular&request%5Bper_page%5D=100&request%5Bpage%5D=$p&request%5Bfields%5D%5Bactive_installs%5D=1&request%5Bfields%5D%5Blast_updated%5D=1" -o "$f" 2>/dev/null || true
    fi
done
GATED="$("$PYBIN" - "$CACHE/pop" "$PAGES" "$AUDITED" "$MIN_INSTALLS" "$MAX_AGE" <<'PY'
import json, os, re, sys, datetime as dt
popdir, pages, aud_p, min_inst, max_age = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
sys.path.insert(0, os.environ["WP_GATES_LIB"]); import wp_gates
aud = set(x.strip() for x in open(aud_p) if x.strip())
today = dt.date.today(); seen = set(); rows = []
for p in range(1, pages + 1):
    try:
        d = json.load(open(os.path.join(popdir, f"{p}.json")))
    except Exception:
        continue
    for pl in d.get("plugins", []):
        s = pl.get("slug", "")
        if not s or s in seen or s in aud:
            continue
        seen.add(s)
        ai = pl.get("active_installs", 0) or 0
        if ai < min_inst:
            continue
        au = re.sub("<[^>]+>", "", pl.get("author", "") or "")
        if wp_gates.PRO_VENDOR_RE.search(au) or wp_gates.PRO_VENDOR_RE.search(s):
            continue
        lu = (pl.get("last_updated", "") or "")[:10]
        try:
            age = (today - dt.date.fromisoformat(lu)).days
        except Exception:
            continue
        if age < 0 or age > max_age:        # silent patch must be RECENT
            continue
        rows.append((age, ai, s, au[:24]))
rows.sort(key=lambda r: (r[0], -r[1]))      # freshest first
for age, ai, s, au in rows:
    print(f"{age}\t{ai}\t{s}\t{au}")
PY
)"
NG=$(printf '%s\n' "$GATED" | grep -c . || true)
echo "[*] $NG gated (>=${MIN_INSTALLS}, not pro, updated <=${MAX_AGE}d). svn-diffing top $SCREEN_TOP ..." >&2

# ---- 2a) CHEAP funnel: readme changelog + advisory dup-gate (1 small fetch
#          per candidate). svn-diff (slow: 2 full tag-tree fetches) is NOT run
#          here — only on the few that flag silent in 2b. This is the fix for
#          the radar-scale problem (full diff per candidate is hours).
FLAGGED="$CACHE/flagged.tsv"; : > "$FLAGGED"
VAGUE='secur|harden|sanitiz|escap|\bxss\b|csrf|nonce|unauthor|auth\b|bypass|injection|idor|disclos|permission|capabilit|vulnerab|\bfix(e[ds])?\b'
i=0
while IFS=$'\t' read -r age ai slug au; do
    [ -z "$slug" ] && continue
    i=$((i+1)); [ "$i" -gt "$SCREEN_TOP" ] && break
    rf="$CACHE/diff/$slug.readme"
    if [ "$REFRESH" = 1 ] || [ ! -s "$rf" ]; then
        curl -sS -m 15 -A "$UA" "https://plugins.svn.wordpress.org/$slug/trunk/readme.txt" -o "$rf" 2>/dev/null || true
    fi
    adv_latest="$(intel::advisories "$slug" 2>/dev/null | awk -F'\t' '{print $1}' | grep -oE '[0-9]+(\.[0-9]+){1,3}' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | tail -1)"
    VAGUE="$VAGUE" "$PYBIN" - "$rf" "$slug" "$age" "$ai" "$au" "${adv_latest:-}" >> "$FLAGGED" <<'PY'
import sys, os, re
rf, slug, age, ai, au, adv_latest = sys.argv[1:7]
try:
    txt = open(rf, encoding="utf-8", errors="replace").read()
except Exception:
    sys.exit(0)
ms = re.search(r'Stable tag:\s*([0-9][0-9.]*)', txt, re.I)
stable = ms.group(1) if ms else ""
# latest changelog block: from the first "= X.Y.Z =" to the next "= "
cm = re.search(r'==+\s*Changelog\s*==+(.*)', txt, re.S | re.I)
body = cm.group(1) if cm else txt
bm = re.split(r'(?m)^\s*=\s*v?([0-9][0-9.]*)\s*[-–—]?[^\n=]*=\s*$', body)
latest_ver, latest_notes = "", ""
if len(bm) >= 3:
    latest_ver, latest_notes = bm[1], bm[2]
ver = stable or latest_ver
if not ver:
    sys.exit(0)
vague = bool(re.search(os.environ["VAGUE"], latest_notes, re.I))
def vt(v):
    return tuple(int(x) for x in re.findall(r'\d+', v)[:4]) if v else ()
# SILENT = newest release is past every known advisory (un-advisoried)
silent = (not adv_latest) or (vt(ver) > vt(adv_latest))
if not (vague and silent):
    sys.exit(0)             # only changelog-suspicious AND un-advisoried go on
note = re.sub(r'\s+', ' ', latest_notes).strip()[:120]
print("\t".join([slug, ver, adv_latest or "-", age, ai, au, note]))
PY
done < <(printf '%s\n' "$GATED")
NF=$(grep -c . "$FLAGGED" || true)
echo "[*] $NF changelog-silent + un-advisoried candidates. Confirming with svn-diff (capped 12) ..." >&2

# ---- 2b) EXPENSIVE confirm: wp-svn-diff (reuse) ONLY on flagged ----------
RESULTS="$CACHE/results.tsv"; : > "$RESULTS"
j=0
while IFS=$'\t' read -r slug ver adv age ai au note; do
    [ -z "$slug" ] && continue
    j=$((j+1)); [ "$j" -gt 12 ] && break
    df="$CACHE/diff/$slug.txt"
    if [ "$REFRESH" = 1 ] || [ ! -s "$df" ]; then
        timeout 120 bash "$SVNDIFF" "$slug" 2>/dev/null | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' > "$df" || true
    fi
    "$PYBIN" - "$df" "$slug" "$age" "$ai" "$au" "$ver" "$adv" "$note" >> "$RESULTS" <<'PY'
import sys, re
df, slug, age, ai, au, ver, adv, note = sys.argv[1:9]
try:
    txt = open(df, encoding="utf-8", errors="replace").read()
except Exception:
    txt = ""
# MODIFIED-files-only. A security signal in an ADDED file is NEW code that
# correctly contains auth — NOT a silently-patched vuln (validated: ewww
# 8.6.0 added classes/class-image-detective.php, a new feature with auth
# from the start; A1 wrongly read it as a silent fix). Parse the "Changed
# files" block (status M/A/D) and keep signals only from M files.
mod = set()
cf = txt.split("== Changed files ==")
if len(cf) > 1:
    for ln in cf[1].split("==", 1)[0].splitlines():
        mm = re.match(r'^\s*M\s+(\S.*)$', ln)
        if mm:
            mod.add(mm.group(1).strip())
seg = txt.split("== Security signals added in this diff ==")
sig = seg[1].split("== Sibling-function")[0] if len(seg) > 1 else ""
# HIGH = genuinely security-shaped SILENT-FIX signals only. Validated 2026-05-15:
# bare `typesafe: ===`, `cast:`, and generic `removed: loose comparison` fire on
# pure REFACTORS (limit-login-attempts-reloaded 3.2.2->3.2.3 was an
# extract-method + ==/=== on trusted Config literals — zero vuln). Those are
# NOT silent-patch signals. Kept: a silently-ADDED cap/nonce/permission_callback
# (auth:), esc_like (silent LIKE-injection fix), hash_equals (silent timing/auth
# fix), a NEW loose-compare on ATTACKER input (fresh bug), or a removed
# __return_true (permission silently opened). Those mean "a security bug was
# quietly fixed/created HERE".
HIGH = re.compile(r'\[(auth:|sanitize: esc_like|smell: NEW loose-compare|crypto: hash_equals|removed: __return_true)', re.I)
# First-party PHP only. Minified/build assets (.css/.js/.min.js/.map under
# build/dist/assets) produce huge fake-signal counts (wordfence: 839 from
# cache-busting CSS/JS). Same FP class fixed in the screener — apply here.
NOISE = re.compile(r'\.(css|js|jsx|ts|tsx|map|min\.js|scss|less|po|mo|svg|png)$|/(build|dist|node_modules|vendor)/', re.I)
hi, loci, cur, cur_is_php = 0, [], "", False
for ln in sig.splitlines():
    mf = re.match(r'^  (\S.*?)  fn (.+)$', ln)
    if mf:
        path = mf.group(1)
        cur = f"{path} :: {mf.group(2)}"
        cur_is_php = (path.endswith(".php") and not NOISE.search(path)
                      and path in mod)   # MODIFIED file only — not new/added
        continue
    msg = re.match(r'^      \[(.+?)\]', ln)
    if msg and cur_is_php and HIGH.search("[" + msg.group(1)):
        hi += 1
        if len(loci) < 4:
            loci.append(f"[{msg.group(1)}] {cur}")
# changelog-silent already established in 2a; svn-diff HIGH signals = strong
# confirm (code actually changed in a security-shaped way), but a vague
# changelog with no clear diff signal is still a SILENT lead worth a look.
conf = "diff-confirmed" if hi else "changelog-only"
score = (hi * 6 + 10) if hi else 4
print("\t".join([str(score), conf, str(hi), ver, adv, age, ai, slug, au,
                  (" | ".join(loci) or note)]))
PY
done < "$FLAGGED"

# ---- 3) rank + report ------------------------------------------------------
"$PYBIN" - "$RESULTS" "$LIMIT" <<'PY'
import sys
rows = []
for ln in open(sys.argv[1]):
    c = ln.rstrip("\n").split("\t")
    if len(c) >= 10:
        rows.append(c)
# diff-confirmed first, then by score
rows.sort(key=lambda c: (int(c[0]), c[1] == "diff-confirmed"), reverse=True)
lim = int(sys.argv[2])
print(f"\n{'SCORE':>5} {'CONFIRM':<14} {'HI':>3} {'VER':>9} {'ADV<=':>8} "
      f"{'AGE':>4} {'INSTALLS':>9}  SLUG  [author]")
print("=" * 118)
for c in rows[:lim]:
    sc, conf, hi, ver, adv, age, ai, slug, au, loci = c[:10]
    print(f"{sc:>5} {conf:<14} {hi:>3} {ver:>9} {adv:>8} {age+'d':>4} {ai:>9}  {slug}  [{au}]")
    print(f"        {loci}")
dc = sum(1 for c in rows if c[1] == "diff-confirmed")
print(f"\n[{len(rows)} SILENT (changelog-suspicious + un-advisoried); "
      f"{dc} also svn-diff-confirmed (security-shaped code change); "
      f"showing {min(lim,len(rows))}]")
if rows:
    print("ALL rows are NON-DUP by construction: the release is newer than every")
    print("known advisory yet its changelog hints security. diff-confirmed = the")
    print("code change is security-shaped (strongest). Next: read the changed fn;")
    print("if a real bug, you are ahead of disclosure -> DAST -> submit.")
else:
    print("(no changelog-silent + un-advisoried candidates in the fresh window —")
    print(" widen --pages / --max-age, or the fresh popular set is quiet)")
PY
