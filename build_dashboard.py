#!/usr/bin/env python3
"""Embed VulnRadar findings into the dashboard HTML.

Usage:
    python build_dashboard.py findings.json vulnradar-dashboard.html [--out new.html]

Replaces the JSON inside <script type="application/json" id="vr-data"> ... </script>
in the dashboard file (in place unless --out is given). Validates the findings first.
"""
import argparse, json, re, sys
from datetime import date

REQUIRED = ["id", "title", "category", "source", "ref", "component", "layer",
            "severity", "stage", "verdict", "status", "detected"]
ALLOWED = {
    "layer": {"Base", "Project"},
    "severity": {"Critical", "High", "Medium", "Low"},
    "stage": {"Matched", "Assessed", "Fix proposed", "Closed"},
    "verdict": {"Pending", "Verified", "Not applicable", "Needs investigation"},
    "status": {"Open", "Fix in review", "Closed", "Not applicable"},
}
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def validate(doc):
    errors, seen = [], set()
    for i, f in enumerate(doc.get("findings", [])):
        tag = f.get("id", f"row {i}")
        for k in REQUIRED:
            if f.get(k) in (None, ""):
                errors.append(f"{tag}: missing {k}")
        for k, allowed in ALLOWED.items():
            if f.get(k) and f[k] not in allowed:
                errors.append(f"{tag}: {k}={f[k]!r} not in {sorted(allowed)}")
        for k in ("detected", "closed"):
            if f.get(k) and not DATE.match(f[k]):
                errors.append(f"{tag}: {k} must be YYYY-MM-DD")
        if f.get("status") == "Closed" and not f.get("closed"):
            errors.append(f"{tag}: status Closed needs a closed date")
        if tag in seen:
            errors.append(f"{tag}: duplicate id")
        seen.add(tag)
    return errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("findings")
    ap.add_argument("dashboard")
    ap.add_argument("--out")
    a = ap.parse_args()

    with open(a.findings, encoding="utf-8") as fh:
        doc = json.load(fh)
    if isinstance(doc, list):
        doc = {"findings": doc}
    doc.setdefault("project", "LessorPortal")
    doc.setdefault("asOf", date.today().isoformat())

    errs = validate(doc)
    if errs:
        print("Findings file has problems:\n  " + "\n  ".join(errs), file=sys.stderr)
        sys.exit(1)

    with open(a.dashboard, encoding="utf-8") as fh:
        html = fh.read()
    payload = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    pat = re.compile(r'(<script type="application/json" id="vr-data">)(.*?)(</script>)', re.S)
    if not pat.search(html):
        sys.exit("Dashboard file has no vr-data block.")
    html = pat.sub(lambda m: m.group(1) + payload + m.group(3), html, count=1)

    out = a.out or a.dashboard
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(html)
    n = len(doc["findings"])
    print(f"Embedded {n} findings (as of {doc['asOf']}) into {out}")


if __name__ == "__main__":
    main()
