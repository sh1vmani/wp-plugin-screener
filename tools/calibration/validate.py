#!/usr/bin/env python3
"""
Screener calibration harness.

Runs ~/wp-plugin-screener.sh over each plugin in the corpus, parses output,
and produces precision/recall numbers measured against the ground-truth F01
sink locations in corpus.json.

Usage:
    python3 validate.py [--screener PATH] [--corpus PATH] [--out PATH]
"""

import argparse, json, os, re, subprocess, sys, time
from pathlib import Path

# ---- args -------------------------------------------------------------------

DEFAULT_SCREENER = os.path.expanduser("~/wp-plugin-screener.sh")
HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent.parent
DEFAULT_CORPUS = HERE / "corpus.json"
DEFAULT_OUT = HERE / "baseline.json"

p = argparse.ArgumentParser()
p.add_argument("--screener", default=DEFAULT_SCREENER)
p.add_argument("--corpus", default=str(DEFAULT_CORPUS))
p.add_argument("--out", default=str(DEFAULT_OUT))
p.add_argument("--wordfence-dir", default=str(PROJECT_ROOT / "wordfence"))
args = p.parse_args()

screener = Path(args.screener)
corpus = json.load(open(args.corpus))
wf_dir = Path(args.wordfence_dir)

if not screener.exists():
    sys.exit(f"screener not found: {screener}")

# ---- helpers ----------------------------------------------------------------

def resolve_source(slug):
    """Return the directory the screener should scan for this slug. None if missing."""
    base = wf_dir / slug / "source"
    if not base.exists():
        return None
    for candidate in [base / slug, base / "trunk", base / "better-wp-security"]:
        if candidate.is_dir():
            return candidate
    # plugin files unpacked directly at source/ root (betterdocs)
    if any(base.glob("*.php")):
        return base
    # zip
    zips = list(base.glob("*.zip"))
    if zips:
        return zips[0]
    return None


# Parse screener output. Lines look like:
#   [HIGH] unsanitized superglobal             includes/admin/ajax.php:486
#        $data = json_decode(stripslashes($_POST['data']), true);
FINDING_RE = re.compile(
    r"^\s*\[(HIGH|MEDIUM|LOW)\]\s+(.+?)\s{2,}(\S+):(\d+)\s*$"
)
SUMMARY_RE = re.compile(r"^SCREENER_SUMMARY\t(\d+)\t(\d+)\t(\d+)\t(\S+)")


def parse_screener_output(text):
    findings = []
    summary = None
    for line in text.splitlines():
        m = FINDING_RE.match(line)
        if m:
            sev, cat, file_, lineno = m.groups()
            findings.append({
                "sev": sev,
                "category": cat.strip(),
                "file": file_,
                "line": int(lineno),
            })
            continue
        m = SUMMARY_RE.match(line)
        if m:
            summary = {
                "high": int(m.group(1)),
                "medium": int(m.group(2)),
                "low": int(m.group(3)),
                "verdict": m.group(4),
            }
    return findings, summary


def run_screener(target):
    """Return (findings, summary, runtime_seconds, error_or_None)."""
    t0 = time.time()
    try:
        # screener emits ANSI; pass --include-vendored=0 (default) and capture all
        proc = subprocess.run(
            [str(screener), str(target)],
            capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        return [], None, time.time() - t0, "timeout"
    raw = proc.stdout + proc.stderr
    # strip ANSI
    raw = re.sub(r"\x1B\[[0-9;]*[a-zA-Z]", "", raw)
    findings, summary = parse_screener_output(raw)
    return findings, summary, time.time() - t0, None


# ---- main loop --------------------------------------------------------------

results = {
    "baseline_date": time.strftime("%Y-%m-%d"),
    "screener_path": str(screener),
    "screener_sha256": subprocess.run(
        ["sha256sum", str(screener)], capture_output=True, text=True
    ).stdout.split()[0][:12],
    "yield": [],
    "clean": [],
    "killed": [],
}


def scan_and_score_yield(entry):
    slug = entry["slug"]
    target = resolve_source(slug)
    if target is None:
        return {"slug": slug, "error": "source-not-found"}
    findings, summary, runtime, err = run_screener(target)
    if err:
        return {"slug": slug, "error": err}

    # File-level recall: any HIGH/MEDIUM emitted in any expected sink file?
    expected_files = set(entry.get("expected_sink_files") or [])
    expected_categories = set(entry.get("expected_screener_categories") or [])

    flagged_files = {f["file"] for f in findings}
    # File-level match: an expected sink file matches a screener-flagged file if
    # either is a suffix of the other. Screener strips TARGET_DIR; expected
    # paths are relative to plugin root. Both should align but be defensive.
    def matches(expected, flagged):
        return expected == flagged or expected.endswith("/" + flagged) or flagged.endswith("/" + expected)

    matched_expected = [
        ef for ef in expected_files
        if any(matches(ef, ff) for ff in flagged_files)
    ]
    file_recall = "hit" if matched_expected else "miss"

    # Category-level recall: did any finding's category match expected and land in expected file?
    cat_recall = "n/a"
    if expected_categories:
        cat_hit = False
        for f in findings:
            in_expected_file = any(matches(ef, f["file"]) for ef in expected_files)
            if in_expected_file and f["category"] in expected_categories:
                cat_hit = True
                break
        cat_recall = "hit" if cat_hit else "miss"

    # Highs landing in any expected sink file (and which categories produced them)
    tp_categories = {}
    highs_in_sink = 0
    for f in findings:
        if f["sev"] != "HIGH":
            continue
        if any(matches(ef, f["file"]) for ef in expected_files):
            highs_in_sink += 1
            tp_categories[f["category"]] = tp_categories.get(f["category"], 0) + 1

    return {
        "slug": slug,
        "f01": entry.get("f01"),
        "expected_sink_files": list(expected_files),
        "expected_screener_categories": list(expected_categories),
        "current_screener_can_catch": entry.get("current_screener_can_catch"),
        "phase1_target": entry.get("phase1_target"),
        "result": {
            "file_recall": file_recall,
            "category_recall": cat_recall,
            "highs_in_sink_file": highs_in_sink,
            "tp_categories": tp_categories,
            "screener_high_total": summary["high"] if summary else None,
            "screener_med_total": summary["medium"] if summary else None,
            "verdict": summary["verdict"] if summary else None,
            "runtime_s": round(runtime, 1),
        },
    }


def scan_and_score_clean(entry):
    slug = entry["slug"]
    target = resolve_source(slug)
    if target is None:
        return {"slug": slug, "error": "source-not-found"}
    findings, summary, runtime, err = run_screener(target)
    if err:
        return {"slug": slug, "error": err}

    # On clean corpus, every HIGH and MEDIUM is by definition a false positive.
    high_by_cat = {}
    med_by_cat = {}
    for f in findings:
        if f["sev"] == "HIGH":
            high_by_cat[f["category"]] = high_by_cat.get(f["category"], 0) + 1
        elif f["sev"] == "MEDIUM":
            med_by_cat[f["category"]] = med_by_cat.get(f["category"], 0) + 1

    return {
        "slug": slug,
        "audit_date": entry.get("audit"),
        "result": {
            "screener_high_total": summary["high"] if summary else None,
            "screener_med_total": summary["medium"] if summary else None,
            "verdict": summary["verdict"] if summary else None,
            "high_by_category": high_by_cat,
            "med_by_category": med_by_cat,
            "runtime_s": round(runtime, 1),
        },
    }


print(f"Running screener over yield corpus ({len(corpus['yield'])} plugins)...", file=sys.stderr)
for entry in corpus["yield"]:
    print(f"  -> {entry['slug']}", file=sys.stderr)
    results["yield"].append(scan_and_score_yield(entry))

print(f"Running screener over clean corpus ({len(corpus['clean'])} plugins)...", file=sys.stderr)
for entry in corpus["clean"]:
    print(f"  -> {entry['slug']}", file=sys.stderr)
    results["clean"].append(scan_and_score_clean(entry))

print(f"Running screener over killed corpus ({len(corpus['killed'])} plugins)...", file=sys.stderr)
for entry in corpus["killed"]:
    print(f"  -> {entry['slug']}", file=sys.stderr)
    results["killed"].append(scan_and_score_clean(entry))

# ---- summary ----------------------------------------------------------------

yield_total = sum(1 for r in results["yield"] if "error" not in r)
yield_file_hits = sum(1 for r in results["yield"] if r.get("result", {}).get("file_recall") == "hit")
yield_cat_eligible = sum(1 for r in results["yield"] if r.get("result", {}).get("category_recall") in ("hit","miss"))
yield_cat_hits = sum(1 for r in results["yield"] if r.get("result", {}).get("category_recall") == "hit")

clean_total = sum(1 for r in results["clean"] if "error" not in r)
clean_fp_total = sum((r.get("result", {}).get("screener_high_total") or 0) for r in results["clean"])
clean_med_fp_total = sum((r.get("result", {}).get("screener_med_total") or 0) for r in results["clean"])

# Aggregate FP categories on clean corpus — tells us which rules over-fire
fp_categories = {}
for r in results["clean"]:
    for cat, n in (r.get("result", {}).get("high_by_category") or {}).items():
        fp_categories[cat] = fp_categories.get(cat, 0) + n

results["summary"] = {
    "yield_corpus_size": yield_total,
    "clean_corpus_size": clean_total,
    "sink_file_recall": f"{yield_file_hits}/{yield_total}",
    "sink_file_recall_pct": round(100 * yield_file_hits / yield_total, 1) if yield_total else None,
    "sink_category_recall": f"{yield_cat_hits}/{yield_cat_eligible}" if yield_cat_eligible else "n/a",
    "clean_fp_high_total": clean_fp_total,
    "clean_fp_high_per_plugin_avg": round(clean_fp_total / clean_total, 1) if clean_total else None,
    "clean_fp_medium_total": clean_med_fp_total,
    "top_fp_categories": sorted(fp_categories.items(), key=lambda kv: -kv[1])[:10],
}

json.dump(results, open(args.out, "w"), indent=2)
print(f"\nBaseline written: {args.out}", file=sys.stderr)
print(f"Sink-file recall: {results['summary']['sink_file_recall']} ({results['summary']['sink_file_recall_pct']}%)")
print(f"Sink-category recall: {results['summary']['sink_category_recall']}")
print(f"Clean-corpus FP HIGHs (total): {clean_fp_total}  (avg {results['summary']['clean_fp_high_per_plugin_avg']}/plugin)")
print(f"Clean-corpus FP MEDIUMs (total): {clean_med_fp_total}")
print("\nTop FP categories on clean corpus:")
for cat, n in results["summary"]["top_fp_categories"]:
    print(f"  {n:4d}  {cat}")
