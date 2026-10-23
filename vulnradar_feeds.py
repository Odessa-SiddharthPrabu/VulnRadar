#!/usr/bin/env python3
"""VulnRadar feeds: build a component inventory from the repo and check it against
public vulnerability databases. Writes feeds.json for vulnradar_scan.py.

Usage:
  python vulnradar_feeds.py --root D:\\DefectInt\\Odessa.Framework \
      --csproj Lw.WebPortal\\Lw.WebPortal.csproj --lock package-lock.json \
      --scripts-dir Lw.WebPortal\\Scripts [--scripts-list names.txt] --out feeds.json

Sources (official only; a source that cannot be reached is recorded, never substituted):
  * GitHub Advisory Database via the npm audit bulk endpoint (registry.npmjs.org)
  * OSV.dev batch API (NuGet + npm)            api.osv.dev
  * NuGet vulnerability resource                api.nuget.org
  * CISA Known Exploited Vulnerabilities (KEV)  www.cisa.gov
"""
import argparse, datetime as dt, json, os, re, urllib.request

# Client-side libraries: file-name / header pattern -> npm package name used by the advisory databases.
JS_LIBS = [
    (r"^jquery-(\d+\.\d+\.\d+)\.js$", "jquery"),
    (r"^jquery-ui-(\d+\.\d+\.\d+)\.js$", "jquery-ui"),
    (r"^jquery\.signalR-(\d+\.\d+\.\d+)(\.min)?\.js$", "signalr"),
    (r"^modernizr-(\d+\.\d+\.\d+)\.js$", "modernizr"),
    (r"^jquery\.jstz-(\d+\.\d+\.\d+)(\.min)?\.js$", "jstz"),
]
JS_HEADERS = [  # file, regex over the first 2 KB, npm name
    ("underscore.js", r"Underscore\.js (\d+\.\d+\.\d+)", "underscore"),
    ("js.cookie.js", r"js-cookie v(\d+\.\d+\.\d+)", "js-cookie"),
]
UNMAPPED_JS = [  # libraries with a version but no npm package the advisory databases track under that name
    (r"^jquery\.blockUI-(\d+\.\d+)\.js$", "jQuery blockUI"),
    (r"^jquery\.maskedinput-(\d+\.\d+)(\.min)?\.js$", "jQuery Masked Input"),
]
NUGET_TO_NPM = {  # NuGet packages that ship a JavaScript library
    "jquery": "jquery", "jquery.validation": "jquery-validation", "bootstrap": "bootstrap",
    "microsoft.jquery.unobtrusive.validation": "jquery-validation-unobtrusive", "modernizr": "modernizr", "respond": "respond.js",
}

def post_json(url, body, timeout=40):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.load(r)

def probe(url, timeout=20):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=timeout) as r:
            return r.status, None
    except Exception as e:
        return None, str(e)[:160]

def inventory(a):
    comps = []
    root = a.root
    names = []
    if a.scripts_list and os.path.exists(a.scripts_list):
        names = [l.strip() for l in open(a.scripts_list, encoding="utf-8") if l.strip()]
    elif a.scripts_dir and os.path.isdir(os.path.join(root, a.scripts_dir)):
        names = os.listdir(os.path.join(root, a.scripts_dir))
    sd = (a.scripts_dir or "").replace("\\", "/")
    for n in names:
        for pat, pkg in JS_LIBS:
            m = re.match(pat, n)
            if m:
                comps.append({"name": pkg, "version": m.group(1), "ecosystem": "npm", "file": f"{sd}/{n}", "evidence": "file name"})
        for pat, label in UNMAPPED_JS:
            m = re.match(pat, n)
            if m:
                comps.append({"name": label, "version": m.group(1), "ecosystem": "none", "file": f"{sd}/{n}", "evidence": "file name"})
    for fname, pat, pkg in JS_HEADERS:
        p = os.path.join(root, a.scripts_dir or "", fname)
        if os.path.exists(p):
            m = re.search(pat, open(p, encoding="utf-8-sig", errors="replace").read(2048))
            if m:
                comps.append({"name": pkg, "version": m.group(1), "ecosystem": "npm", "file": f"{sd}/{fname}", "evidence": "file header"})
    jq = os.path.join(root, a.scripts_dir or "", "jquery.jqGrid.src.js")
    if os.path.exists(jq):
        m = re.search(r"jqGrid\s+(\d+\.\d+\.\d+)", open(jq, encoding="utf-8-sig", errors="replace").read(2048))
        if m:
            comps.append({"name": "jqGrid (Trirand)", "version": m.group(1), "ecosystem": "none", "file": f"{sd}/jquery.jqGrid.src.js", "evidence": "file header"})
    for proj in a.csproj or []:
        p = os.path.join(root, proj)
        if not os.path.exists(p):
            continue
        txt = open(p, encoding="utf-8-sig", errors="replace").read()
        seen = set()
        for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"\s+[Vv]ersion="([^"]+)"', txt):
            name, ver = m.group(1), m.group(2)
            if (name.lower(), ver) in seen:
                continue
            seen.add((name.lower(), ver))
            comps.append({"name": name, "version": ver, "ecosystem": "NuGet", "file": proj.replace("\\", "/"), "evidence": "PackageReference"})
            if name.lower() in NUGET_TO_NPM:
                comps.append({"name": NUGET_TO_NPM[name.lower()], "version": ver, "ecosystem": "npm", "file": proj.replace("\\", "/"),
                              "evidence": f"JavaScript shipped in NuGet package {name}"})
    if a.lock and os.path.exists(os.path.join(root, a.lock)):
        lock = json.load(open(os.path.join(root, a.lock), encoding="utf-8"))
        for k, v in (lock.get("packages") or {}).items():
            if k.startswith("node_modules/") and v.get("version"):
                comps.append({"name": k.split("node_modules/")[-1], "version": v["version"], "ecosystem": "npm",
                              "file": a.lock.replace("\\", "/"), "evidence": "package-lock (dev tooling)" if v.get("dev") else "package-lock"})
    return comps

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--csproj", nargs="*")
    ap.add_argument("--lock")
    ap.add_argument("--scripts-dir")
    ap.add_argument("--scripts-list")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    comps = inventory(a)
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    sources = []

    # 1) GitHub Advisory Database via npm audit bulk endpoint
    npm = {}
    for c in comps:
        if c["ecosystem"] == "npm":
            npm.setdefault(c["name"], set()).add(c["version"])
    try:
        status, res = post_json("https://registry.npmjs.org/-/npm/v1/security/advisories/bulk", {k: sorted(v) for k, v in npm.items()})
        for c in comps:
            if c["ecosystem"] == "npm":
                c["checked"] = "GitHub Advisory Database"
                c["advisories"] = [{"id": x["url"].rsplit("/", 1)[-1], "url": x["url"], "title": x["title"], "severity": x["severity"],
                                    "range": x["vulnerable_versions"], "cwe": x.get("cwe", []), "cvss": (x.get("cvss") or {}).get("score")}
                                   for x in res.get(c["name"], []) if version_in(c["version"], x["vulnerable_versions"])]
        sources.append({"name": "GitHub Advisory Database (npm audit endpoint)", "url": "registry.npmjs.org/-/npm/v1/security/advisories/bulk",
                        "status": "ok", "checked": sum(len(v) for v in npm.values()), "at": now})
    except Exception as e:
        sources.append({"name": "GitHub Advisory Database (npm audit endpoint)", "url": "registry.npmjs.org", "status": "blocked: " + str(e)[:120], "at": now})

    # 2) Sources that also cover NuGet, CVE details and exploitation status
    for name, url in [("OSV.dev (NuGet + npm)", "https://api.osv.dev/v1/querybatch"),
                      ("NuGet vulnerability resource", "https://api.nuget.org/v3/vulnerabilities/index.json"),
                      ("CISA Known Exploited Vulnerabilities", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
                      ("NIST NVD", "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1")]:
        if "osv" in url:
            try:
                q = [{"package": {"name": c["name"], "ecosystem": c["ecosystem"]}, "version": c["version"]} for c in comps if c["ecosystem"] in ("NuGet", "npm")]
                _, res = post_json(url, {"queries": q})
                for c, r in zip([c for c in comps if c["ecosystem"] in ("NuGet", "npm")], res.get("results", [])):
                    ids = [v["id"] for v in r.get("vulns", [])]
                    if ids:
                        c.setdefault("osv", ids)
                    if c["ecosystem"] == "NuGet":
                        c["checked"] = "OSV.dev"
                sources.append({"name": name, "url": url, "status": "ok", "at": now})
            except Exception as e:
                sources.append({"name": name, "url": url, "status": "blocked: " + str(e)[:120], "at": now})
            continue
        code, err = probe(url)
        sources.append({"name": name, "url": url, "status": "reachable (not yet used)" if code else "blocked: " + (err or ""), "at": now})

    for c in comps:
        c.setdefault("checked", "not checked")
        c.setdefault("advisories", [])
    json.dump({"checkedAt": now, "sources": sources, "components": comps}, open(a.out, "w", encoding="utf-8"), indent=1)
    hit = [c for c in comps if c["advisories"]]
    print(f"{len(comps)} components; {len(hit)} with advisories; sources: " + "; ".join(f'{s["name"]}={s["status"][:20]}' for s in sources))

def _v(s):
    return tuple(int(x) for x in re.findall(r"\d+", s)[:4]) + (0,) * (4 - len(re.findall(r"\d+", s)[:4]))

def version_in(ver, rng):
    """Evaluate an npm-style range such as '>=1.0.3 <3.5.0' or '<1.13.3 || >=2.0.0 <2.1.0'."""
    v = _v(ver)
    for alt in rng.split("||"):
        ok = True
        for op, num in re.findall(r"(>=|<=|>|<|=)?\s*(\d[\w.\-]*)", alt.strip()):
            n = _v(num)
            ok &= {">=": v >= n, "<=": v <= n, ">": v > n, "<": v < n}.get(op, v == n)
        if ok and alt.strip():
            return True
    return False

if __name__ == "__main__":
    main()
