# VulnRadar

VulnRadar checks Odessa source code before the vendor VAPT. It compares the code with two sources:

- **Your own history:** every VAPT and pentest finding logged in Jira (odessainc.atlassian.net).
- **Global data:**
  - public vulnerability advisories for the libraries the code uses;
  - the OWASP Top 10:2025 and MITRE CWE Top 25 weakness lists.

Each finding is tied to a file, line numbers and evidence, then triaged by Claude. The results feed a standalone SonarQube-style report. The vendor VAPT stays in place as the safety net.

> **Confidential.** `findings.json` and the dashboard contain source code (passwords masked) and the locations of open vulnerabilities. Share this folder only inside the development and security team, through internal channels.

---

## 0. Project home

All VulnRadar work lives in one folder, by default **`D:\VulnRadar`**. Every run updates the same files in place; nothing is created elsewhere.

- If your copy lives somewhere else, give its path as `output:` in the prompt.
- Each scan **adds to** the existing report:
  - files scanned in this run are re-checked;
  - files from earlier runs keep their findings, IDs and triage.
- Use `fresh: yes` (prompt) or `--fresh` (CLI) only to start the report over.
- When several people use VulnRadar, keep one master copy (a team Git repository or a shared network folder). Pull before a scan and push after it, so `findings.json` and `triage.json` do not drift apart.

---

## 1. What is in this folder

| File | Purpose |
|---|---|
| `skill/SKILL.md` | The VulnRadar skill for Claude: the instructions Claude follows when you use the `/vulnradar` prompt. |
| `vulnradar-skill.zip` | The same skill packaged for upload into Claude. |
| `vulnradar_feeds.py` | Builds the component inventory (NuGet, npm, vendor JavaScript) and checks it against the public advisory databases. Writes `feeds.json`. |
| `vulnradar_scan.py` | Scans every line of the selected files, joins the Jira history and the advisories, and writes `findings.json`. |
| `vulnradar_rules.json` | Rule catalog: what each rule detects, why it is an issue, how to fix it, noncompliant and compliant examples, CWE/OWASP and references. |
| `triage.json` | Reviewer decisions: ID, severity, verdict, status, notes, chosen Jira keys, manual findings and token usage. Re-runs keep these. |
| `jira_vapt.json` | Export of the Jira VAPT, pentest and security tickets. |
| `feeds.json` | Inventory and advisory results from the last feed run. |
| `findings.json` | Combined result of all runs; the dashboard reads this. |
| `build_dashboard.py` | Validates `findings.json` and embeds it into the dashboard. |
| `vulnradar-dashboard.html` | The report. It works offline; double-click to open it in any browser. |
| `scripts_listing.txt` | File names of `Lw.WebPortal\Scripts`, used to find library versions when that folder is not copied. |

---

## 2. Setting up a new user

### Who needs what

| User | Needs |
|---|---|
| **Viewer:** just reads the report | Only `vulnradar-dashboard.html`. No install, no login. |
| **Script user:** runs scans without Claude | This folder and Python 3.9 or later. See section 5. |
| **Claude user:** runs scans with the `/vulnradar` prompt | This folder, plus steps 1–5 below. |

### Steps for a Claude user

1. **Install the skill.** In Claude, add a custom skill and upload `vulnradar-skill.zip` from this folder. Alternatively, a Claude admin can add it once for the whole organization. After installing, the skill appears as **vulnradar**.
2. **Connect Atlassian** in Claude, so the skill can read the Jira VAPT history. You need access to the same Jira projects (FRWK, BNP01, CO and others).
3. **Link your laptop** in the Claude desktop app and connect two folders: your copy of the Odessa repository and your copy of this VulnRadar folder.
4. **Network access.** The session can always reach the GitHub Advisory Database through `registry.npmjs.org`. To check NuGet packages and exploited vulnerabilities as well, ask your organization admin to allow these domains in claude.ai under **Organization settings > Capabilities**:

   | Domain | Used for |
   |---|---|
   | `api.osv.dev` | OSV advisories for NuGet and npm |
   | `api.nuget.org` | NuGet vulnerability data |
   | `www.cisa.gov` | CISA Known Exploited Vulnerabilities |
   | `services.nvd.nist.gov` | NIST NVD CVE details and CVSS |

   Running `vulnradar_feeds.py` directly on your laptop uses your own network, so it can reach these sources even when a Claude session cannot.
5. **Try it** with the single-file prompt in section 4.1.

---

## 3. Prompt syntax

Send a block like this as your message. Lines you leave out take the default.

```yaml
/vulnradar
repo:        D:\DefectInt\Odessa.Framework   # repo root on your laptop
scope:                                        # files or folders, relative to repo, or "all"
  - Lw.WebPortal\Controllers\ProxyController.cs
mode:        scan       # see the table below
rules:                  # check-rule only: rule keys
record:      no         # check-rule only: yes = add the results to the report
jira:        default    # default | a JQL filter
feeds:       all        # all | npm only | none
inventory:   default    # default | extra .csproj / package-lock.json / Scripts folders
severity:    all        # all | Critical | High | Medium | Low (minimum to report)
tokenLimit:  50%        # stop when this share of the session token budget is used
output:      D:\VulnRadar   # your VulnRadar folder
fresh:       no         # yes = start a new report instead of adding to it
```

### Modes

| Mode | What it does | Changes the report? |
|---|---|---|
| `scan` | Scans the scope and adds the findings to the report | Yes |
| `check-rule` | Checks whether specific rules apply to the scope and answers in chat | Only with `record: yes` |
| `check-advisory <id>` | Checks whether a CVE or GHSA advisory affects any library in the repo | Yes, if it applies |
| `explain VR-0NN` | Explains a finding: where it is, why it matters, how to fix it | No |
| `fix VR-0NN` | Proposes a code fix with tests; asks before any branch, commit or PR | Status only |
| `close VR-0NN` | Closes a finding after the fix is approved | Yes |
| `refresh` | Rebuilds the dashboard after you edit `triage.json` | Yes |
| `list-rules` | Lists every rule with key, name, type and severity | No |

### Parameters

| Parameter | Default if omitted |
|---|---|
| `repo` | Claude asks |
| `scope` | Claude asks (not needed for `explain`, `refresh`, `list-rules`, `check-advisory`) |
| `mode` | `scan` |
| `rules` | Claude asks when the mode is `check-rule` |
| `record` | `no` |
| `jira` | VAPT, PENTEST and Security tickets |
| `feeds` | `all` (blocked sources are reported, never worked around) |
| `inventory` | `Lw.WebPortal\Lw.WebPortal.csproj`, root `package-lock.json`, `Lw.WebPortal\Scripts` |
| `severity` | All severities |
| `tokenLimit` | 50% |
| `output` | `D:\VulnRadar` |
| `fresh` | `no` |

---

## 4. Prompt cookbook

Copy the prompt that matches what you want to do and change the paths.

### 4.1 Scan a single file

```yaml
/vulnradar
repo:   D:\DefectInt\Odessa.Framework
scope:
  - Lw.WebPortal\Controllers\CommentFormController.cs
```

### 4.2 Scan several files

```yaml
/vulnradar
repo:   D:\DefectInt\Odessa.Framework
scope:
  - Lw.WebPortal\Controllers\NotificationController.cs
  - Lw.WebPortal\Controllers\UsageTrackingController.cs
  - Lw.WebPortal\Controllers\CrossSiteController.cs
```

### 4.3 Scan a folder

```yaml
/vulnradar
repo:        D:\DefectInt\Odessa.Framework
scope:
  - Lw.WebPortal\Controllers
tokenLimit:  30%
```

Files are copied 50 per call, so a large folder takes several rounds. The token limit stops the run safely if it grows too large.

### 4.4 Scan the whole repository

```yaml
/vulnradar
repo:        D:\DefectInt\Odessa.Framework
scope:       all
tokenLimit:  50%
```

This is the most expensive run. Scanning folder by folder (4.3) gives you results sooner.

### 4.5 Check whether one rule applies to a file

Use this to answer "does this file have the CSRF problem?" without changing the report.

```yaml
/vulnradar
repo:   D:\DefectInt\Odessa.Framework
mode:   check-rule
rules:
  - VR-RULE-CSRF
scope:
  - Lw.WebPortal\Controllers\DocumentHeaderFormController.cs
```

Claude answers per file: whether the rule applies, the line, the code and the reason.

### 4.6 Check several rules across several files

```yaml
/vulnradar
repo:   D:\DefectInt\Odessa.Framework
mode:   check-rule
rules:
  - VR-RULE-GET-STATE
  - VR-RULE-OPEN-REDIRECT
  - VR-RULE-HTML-RAW
scope:
  - Lw.WebPortal\Controllers\DirectLinkController.cs
  - Lw.WebPortal\Controllers\EmbeddedFormController.cs
```

### 4.7 Check a rule and keep the results in the report

```yaml
/vulnradar
repo:   D:\DefectInt\Odessa.Framework
mode:   check-rule
rules:
  - VR-RULE-SQL-CONCAT
scope:
  - Lw.WebPortal\Controllers\AutoActionEntitySelectSQLPreviewController.cs
record: yes
```

With `record: yes`, Claude also runs a full scan of the scope and adds the findings to the report.

### 4.8 See which rules exist

```yaml
/vulnradar
mode: list-rules
```

The **Rules** tab in the dashboard shows the same list with full descriptions.

### 4.9 Check whether a new advisory affects us

```yaml
/vulnradar
repo: D:\DefectInt\Odessa.Framework
mode: check-advisory GHSA-qjx8-664m-686j
```

A CVE ID works too (`mode: check-advisory CVE-2024-21907`). Claude says which library version matches, where it is declared and how it is used.

### 4.10 Explain a finding

```yaml
/vulnradar
mode: explain VR-033
```

### 4.11 Propose a fix

```yaml
/vulnradar
repo: D:\DefectInt\Odessa.Framework
mode: fix VR-011
```

Claude proposes the code change and the tests (MSTest + NSubstitute, and Playwright where the issue is reachable over HTTP). It asks before creating a branch, commit, PR or Jira ticket, and never merges.

### 4.12 Re-scan a file after a fix

```yaml
/vulnradar
repo:   D:\DefectInt\Odessa.Framework
scope:
  - Lw.WebPortal\Web.config
```

Findings that no longer appear are listed as "resolved by rescan" in the summary.

### 4.13 Close a finding after the fix is approved

```yaml
/vulnradar
repo: D:\DefectInt\Odessa.Framework
mode: close VR-011
```

### 4.14 Rebuild the dashboard after editing triage

```yaml
/vulnradar
mode: refresh
```

### 4.15 Report only High and Critical

```yaml
/vulnradar
repo:     D:\DefectInt\Odessa.Framework
scope:
  - Lw.WebPortal\Controllers
severity: High
```

### 4.16 Use a narrower Jira history

```yaml
/vulnradar
repo:  D:\DefectInt\Odessa.Framework
scope:
  - Lw.WebPortal\Controllers\LoginController.cs
jira:  project = FRWK AND labels in (VAPT, SFIVAPT) ORDER BY created DESC
```

### 4.17 Skip the online advisory check

```yaml
/vulnradar
repo:  D:\DefectInt\Odessa.Framework
scope:
  - Lw.WebPortal\Controllers\ProxyController.cs
feeds: none
```

### 4.18 Start a new report

```yaml
/vulnradar
repo:  D:\DefectInt\Odessa.Framework
scope:
  - Lw.WebPortal\Controllers
fresh: yes
```

This replaces the current findings, so commit or back up `findings.json` and `triage.json` first.

### 4.19 Use a VulnRadar folder in another location

```yaml
/vulnradar
repo:   C:\src\Odessa.Framework
scope:
  - Lw.WebPortal\Controllers\ProxyController.cs
output: \\fileserver\security\VulnRadar
```

---

## 5. Running the scripts yourself

The scripts use only the Python 3.9+ standard library. They run on Windows or in a pipeline. Run them from the VulnRadar folder.

### Step 1: global feeds

```powershell
python vulnradar_feeds.py --root D:\DefectInt\Odessa.Framework `
  --csproj Lw.WebPortal\Lw.WebPortal.csproj `
  --lock package-lock.json `
  --scripts-dir Lw.WebPortal\Scripts `
  --out feeds.json
```

| Argument | Meaning |
|---|---|
| `--root` | Repo root |
| `--csproj` | One or more project files to read `PackageReference` entries from |
| `--lock` | npm `package-lock.json` relative to the root |
| `--scripts-dir` | Folder of vendor JavaScript files; versions are read from file names and headers |
| `--scripts-list` | Optional text file of script names, when the folder is not available locally |
| `--out` | Output file (`feeds.json`) |

### Step 2: scan

```powershell
python vulnradar_scan.py --root D:\DefectInt\Odessa.Framework `
  --files Lw.WebPortal\BaseLoginController.cs Lw.WebPortal\Web.config `
  --jira jira_vapt.json --feeds feeds.json --triage triage.json --out findings.json
```

Rule check only, written to a separate file so the report is not changed:

```powershell
python vulnradar_scan.py --root D:\DefectInt\Odessa.Framework `
  --files Lw.WebPortal\Controllers\ProxyController.cs `
  --jira jira_vapt.json --feeds feeds.json --triage triage.json `
  --only-rules VR-RULE-CSRF,VR-RULE-GET-STATE --fresh --out check.json
```

| Argument | Meaning |
|---|---|
| `--root` | Repo root |
| `--files` | Files to scan. Omit it to scan every `.cs`, `.cshtml` and `.config` file, excluding `bin`, `obj` and `node_modules`. |
| `--jira` | Jira export (`jira_vapt.json`). Claude refreshes it through the Atlassian connector. |
| `--feeds` | Output of step 1 |
| `--triage` | Reviewer decisions to keep between runs |
| `--out` | Output file (`findings.json`, or a separate file for a rule check) |
| `--only-rules` | Comma-separated rule keys to run; use with `--fresh` and a separate `--out` |
| `--fresh` | Start a new report. Without it, the run adds to the existing `--out` file. |
| `--rules` | Rule catalog (default `vulnradar_rules.json` next to the script) |
| `--project` | Name shown on the dashboard (default `Odessa.Framework`) |

The scripts find patterns. The AI review (logic issues, verdicts and notes) happens when Claude runs the scan; when you run the scripts alone, new hits stay at verdict **Pending** until they are triaged.

### Step 3: dashboard

```powershell
python build_dashboard.py findings.json vulnradar-dashboard.html
```

Then open `vulnradar-dashboard.html`. **Load findings file** opens any other `findings.json`, such as a `check.json`, without rebuilding.

---

## 6. Reading the report

The dashboard is laid out like a SonarQube project report, with five tabs.

| Tab | What it shows |
|---|---|
| **Overview** | Security rating A–E on the SonarQube scale (A none; B Low; C Medium; D High; E Critical worst open vulnerability). Below it: counts of vulnerabilities, hotspots, critical and high, ruled-out hits, lines scanned, rules run, open Jira VAPT issues and new advisory findings (select any count to see those issues). Then every scanned file with its counts, and the run details: data sources (Used or Blocked) and token usage. |
| **Issues** | One entry per affected line, grouped by file, with filters for status, type, severity, rule and file. Select an issue to see:<br>• **Where is the issue?** The code around the line, with the line highlighted.<br>• **Why is this an issue?** The rule's explanation.<br>• **Why VulnRadar reports it here.** The triage reasoning for this code and the verdict.<br>• **How can I fix it?** Guidance with noncompliant and compliant examples.<br>• **More information.** CWE and OWASP references, advisory links and the matching Jira VAPT tickets. |
| **Code** | Each scanned file in a code viewer with line numbers. Affected lines are marked by severity, with the issue shown under the line; **Why and how to fix** expands the full explanation. Secrets are masked as `********`. |
| **Rules** | Every rule: key, type, default severity, origin, CWE and OWASP tags, and how many files it checked. Expand a rule for the description, fix guidance, examples, references and its findings. |
| **Security posture** | OWASP Top 10:2025 coverage, CWE Top 25 coverage, Jira VAPT history per class, and the component inventory with the advisory database each library was checked against. |

### Issue types

| Type | Meaning |
|---|---|
| **Vulnerability** | Confirmed from the code, the configuration or the component version (verdict Verified). |
| **Security Hotspot** | Needs a person to confirm because it depends on code outside the scan; the triage note says exactly what to check (verdict Needs investigation). |
| **Ruled out** | A rule hit that was reviewed and does not hold; kept for traceability (verdict Not applicable). |

**NEW** marks issues from public advisories that no Jira ticket names yet.

---

## 7. Triage (`triage.json`)

Each finding has a stable fingerprint. Its entry holds:

| Field | Values |
|---|---|
| `id` | `VR-001` … (kept across runs) |
| `severity` | `Critical`, `High`, `Medium`, `Low` |
| `verdict` | `Verified`, `Needs investigation` or `Not applicable` (see Issue types) |
| `status` | `Open`, `Fix in review`, `Closed`, `Not applicable` |
| `stage` | `Matched`, `Assessed`, `Fix proposed`, `Closed` |
| `jiraRefs` | Jira keys to show for the finding, open ones first |
| `notes` | Reasoning and the recommended fix |
| `group` | Merges hits that share one root cause |

To close a finding after its fix is approved, use `mode: close VR-0NN`, or set `status` to `Closed` and `closed` to the date and run `mode: refresh`.

---

## 8. Rules VulnRadar applies

- **Real data only.** There are no sample or estimated findings. Every Jira key comes from Jira, every advisory from an advisory database, and every code finding from a line in the repo.
- **CVSS** is shown only when an advisory supplies it. Code findings are rated from impact and reachability, with the reason in the notes.
- **Blocked sources** are shown as Blocked on the dashboard and are never replaced with mirrors or guesses.
- **Assembly versions** in `bindingRedirect` entries are not package versions. Advisory matches use the `PackageReference` or package-lock version.
- **Base config.** Findings in the framework's base `Web.config` can be changed by environment transforms; confirm them on a deployed site.
- **Scope of the tool.** VulnRadar finds known patterns, logged VAPT classes and published advisories. It does not replace the vendor VAPT for business-logic flaws.
