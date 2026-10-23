#!/usr/bin/env python3
"""VulnRadar scanner: repo files + Jira VAPT history + public advisories -> findings.json.

Usage:
  python vulnradar_scan.py --root D:\\DefectInt\\Odessa.Framework \
      [--files Lw.WebPortal\\Web.config Lw.WebPortal\\BaseLoginController.cs ...] \
      --jira jira_vapt.json --feeds feeds.json --triage triage.json --out findings.json

* Every line of every selected file is checked against:
    - rules for the vulnerability classes the organisation has logged in Jira (VAPT history), and
    - proactive rules for OWASP Top 10:2025 / CWE Top 25 classes, including ones the vendor has not reported yet.
* --feeds (from vulnradar_feeds.py) turns public advisories that match the repo's components into findings.
* --triage keeps reviewer verdicts, notes, IDs and manual (AI review) findings between runs.
* Standard library only; runs on Windows or Linux.
"""
import argparse, datetime as dt, hashlib, json, os, re

CLOSED = {"done", "closed", "released", "completed", "resolved", "duplicate", "rejected",
          "cancelled", "release", "promote merge", "verification"}

OWASP_2025 = [
    ("A01", "Broken Access Control"), ("A02", "Security Misconfiguration"), ("A03", "Software Supply Chain Failures"),
    ("A04", "Cryptographic Failures"), ("A05", "Injection"), ("A06", "Insecure Design"), ("A07", "Authentication Failures"),
    ("A08", "Software or Data Integrity Failures"), ("A09", "Security Logging and Alerting Failures"),
    ("A10", "Mishandling of Exceptional Conditions"),
]
# MITRE CWE Top 25 (2024). Memory-safety entries do not apply to managed .NET / browser JavaScript.
CWE_TOP25 = [
    (1, "CWE-79", "Cross-site scripting"), (2, "CWE-787", "Out-of-bounds write"), (3, "CWE-89", "SQL injection"),
    (4, "CWE-352", "Cross-site request forgery"), (5, "CWE-22", "Path traversal"), (6, "CWE-125", "Out-of-bounds read"),
    (7, "CWE-78", "OS command injection"), (8, "CWE-416", "Use after free"), (9, "CWE-862", "Missing authorization"),
    (10, "CWE-434", "Unrestricted file upload"), (11, "CWE-94", "Code injection"), (12, "CWE-20", "Improper input validation"),
    (13, "CWE-77", "Command injection"), (14, "CWE-287", "Improper authentication"), (15, "CWE-269", "Improper privilege management"),
    (16, "CWE-502", "Deserialization of untrusted data"), (17, "CWE-200", "Exposure of sensitive information"),
    (18, "CWE-863", "Incorrect authorization"), (19, "CWE-918", "Server-side request forgery"),
    (20, "CWE-119", "Memory buffer errors"), (21, "CWE-476", "NULL pointer dereference"), (22, "CWE-798", "Hard-coded credentials"),
    (23, "CWE-190", "Integer overflow"), (24, "CWE-400", "Uncontrolled resource consumption"),
    (25, "CWE-306", "Missing authentication for critical function"),
]
NOT_MANAGED = {"CWE-787", "CWE-125", "CWE-416", "CWE-119", "CWE-476", "CWE-190"}

# Vulnerability classes matched against Jira summaries (org VAPT history) -> OWASP 2025 category.
CLASSES = [
    ("HTTP method tampering (POST to GET)", "A02", r"post to get|method conversion|arbitrary methods?|privilege escalation on get|http method tampering"),
    ("Cross-site request forgery", "A01", r"csrf|cross-site request forgery|antiforgery"),
    ("User enumeration", "A07", r"enumerat|discloses whether an account|password oracle"),
    ("Rate limiting / lockout", "A10", r"rate limit|brute force|lockout|flooding|spamming|dos attack"),
    ("Security headers", "A02", r"header|hsts|\bcsp\b|content security policy|x-frame"),
    ("Information disclosure / errors", "A10", r"server-side details|version disclosure|banner|information disclosure|server information|verbose|error handling|stack trace|server error|debug tools|elmah|tracer|dns resolution|ip address exposure"),
    ("Cookie / session management", "A07", r"cookie|session|concurrent login|otp|tfa|mfa bypass|login expiry"),
    ("Sensitive data / credentials exposure", "A04", r"plain ?text|cleartext|credential|password in|sensitive data|pii|data masking|appsettings|basic authentication"),
    ("Broken access control / IDOR", "A01", r"access control|idor|authori[sz]ation|insecure direct|privilege|forced browsing|functional level"),
    ("Injection (XSS / HTML / SQL / CSV)", "A05", r"xss|cross-site scripting|html injection|hyperlink|link manipulation|text injection|sql injection|inj_0|csv injection|open redirect|host header"),
    ("File upload / EXIF", "A06", r"upload|exif"),
    ("Outdated components", "A03", r"outdated|vulnerable (javascript|application|jquery)|vulnerable/|known vulnerab|jquery version|tinymce|vulnerable components?|supply chain"),
    ("TLS / transport", "A04", r"ssl|tls|cipher|unencrypted|lucky13|wildcard"),
    ("Input validation", "A10", r"input validation|improper input|un-sanitized|special characters|negative amount|business logic"),
    ("Logging and alerting", "A09", r"logging|alerting|logs should"),
    ("Integrity (SRI / deserialization)", "A08", r"\bsri\b|subresource|deserial|integrity"),
]
CLASS_OWASP = {c: o for c, o, _ in CLASSES}
NOISE = r"waf url review|rdc|rdp|whitelist|white-list|server is|servers are|deployment|db (back|refresh|restor|upgrade|changes)|restore|public url|environment setup|env(ironment)? for|setup|vm |new env|access to|site creation|webconfig changes|backmerge|back merge|merge|kt\)|support$|release for|monitoring|elastic server|cost optim"

# rule -> (title, category, [CWEs], OWASP 2025, VAPT class, proactive?)
RULES = {
    "VR-RULE-GET-STATE": ("State-changing action accepts GET", "Code pattern", ["CWE-650"], "A02", "HTTP method tampering (POST to GET)", False),
    "VR-RULE-CSRF": ("POST action without anti-forgery validation", "Code pattern", ["CWE-352"], "A01", "Cross-site request forgery", False),
    "VR-RULE-PRELOGIN-LOOKUP": ("Pre-login lookup reveals account data", "Code pattern", ["CWE-204", "CWE-306"], "A07", "User enumeration", False),
    "VR-RULE-RESET-ENUM": ("Password reset reveals account state", "Code pattern", ["CWE-204"], "A07", "User enumeration", False),
    "VR-RULE-REQUEST-SQL": ("SQL text or connection string taken from the request", "Code pattern", ["CWE-89", "CWE-918"], "A05", "Injection (XSS / HTML / SQL / CSV)", False),
    "VR-RULE-SECRET-DISCLOSURE": ("Connection details returned to the caller", "Code pattern", ["CWE-200", "CWE-522"], "A04", "Sensitive data / credentials exposure", False),
    "VR-RULE-EXCEPTION-MESSAGE": ("Exception message returned to the user", "Code pattern", ["CWE-209", "CWE-200"], "A10", "Information disclosure / errors", False),
    "VR-RULE-TEST-ENDPOINT": ("Test automation API exposed in the portal", "Code pattern", ["CWE-489", "CWE-306"], "A02", "Broken access control / IDOR", False),
    "VR-RULE-OTP-BRUTEFORCE": ("OTP verification not throttled", "Code pattern", ["CWE-307"], "A07", "Rate limiting / lockout", False),
    "VR-RULE-SECURITY-EVENT-LOG": ("Security event not written to an audit log", "Code pattern", ["CWE-778"], "A09", "Logging and alerting", False),
    "VR-RULE-OTP-DESTINATION": ("OTP destination taken from the model", "Code pattern", ["CWE-287", "CWE-639"], "A07", "Cookie / session management", False),
    "VR-RULE-OPEN-PROXY": ("Proxy forwards arbitrary paths to a backend", "Code pattern", ["CWE-441", "CWE-918"], "A01", "Broken access control / IDOR", False),
    "VR-RULE-PUBLIC-NONACTION": ("Public helper on a base controller exposed as an action", "Code pattern", ["CWE-749"], "A01", "Broken access control / IDOR", True),
    "VR-RULE-COOKIE-AUTHCTX": ("Authentication context read from a cookie", "Code pattern", ["CWE-565", "CWE-502", "CWE-287"], "A07", "Broken access control / IDOR", False),
    "VR-RULE-CUSTOMERRORS-OFF": ("Detailed error pages enabled", "Configuration", ["CWE-209", "CWE-200"], "A10", "Information disclosure / errors", False),
    "VR-RULE-DEBUG-TRUE": ("Debug compilation enabled", "Configuration", ["CWE-11"], "A02", "Information disclosure / errors", False),
    "VR-RULE-ELMAH-REMOTE": ("ELMAH error log reachable remotely", "Configuration", ["CWE-215", "CWE-200"], "A02", "Information disclosure / errors", False),
    "VR-RULE-NO-HSTS": ("HSTS header not configured", "Configuration", ["CWE-523"], "A02", "Security headers", False),
    "VR-RULE-NO-CSP": ("Content-Security-Policy header not configured", "Configuration", ["CWE-1021"], "A02", "Security headers", False),
    "VR-RULE-COOKIE-SECURE": ("Cookies not forced to Secure", "Configuration", ["CWE-614"], "A02", "Cookie / session management", False),
    "VR-RULE-PLAINTEXT-PASSWORD": ("Plain-text credential in config", "Configuration", ["CWE-260", "CWE-798"], "A07", "Sensitive data / credentials exposure", False),
    "VR-RULE-SESSION-TIMEOUT": ("Long session idle timeout", "Configuration", ["CWE-613"], "A07", "Cookie / session management", False),
    "VR-RULE-REQUEST-LIMIT": ("Very large request size limit", "Configuration", ["CWE-770", "CWE-400"], "A02", "File upload / EXIF", False),
    "VR-RULE-HTTP-ENDPOINT": ("Service endpoints over plain HTTP", "Configuration", ["CWE-319"], "A04", "TLS / transport", False),
    # Proactive rules: global classes, including ones not yet reported in Jira
    "VR-RULE-SQL-CONCAT": ("SQL built by string concatenation", "Code pattern", ["CWE-89"], "A05", "Injection (XSS / HTML / SQL / CSV)", True),
    "VR-RULE-HTML-RAW": ("Unencoded output with Html.Raw", "Code pattern", ["CWE-79"], "A05", "Injection (XSS / HTML / SQL / CSV)", True),
    "VR-RULE-OPEN-REDIRECT": ("Redirect to a request-supplied URL", "Code pattern", ["CWE-601"], "A01", "Injection (XSS / HTML / SQL / CSV)", True),
    "VR-RULE-PATH-TRAVERSAL": ("File path built from request input", "Code pattern", ["CWE-22"], "A01", "Broken access control / IDOR", True),
    "VR-RULE-SSRF": ("Outbound request to a request-supplied URL", "Code pattern", ["CWE-918"], "A01", "Broken access control / IDOR", True),
    "VR-RULE-UNSAFE-DESERIALIZE": ("Unsafe deserialisation settings", "Code pattern", ["CWE-502"], "A08", "Integrity (SRI / deserialization)", True),
    "VR-RULE-PROCESS-START": ("Process started with variable arguments", "Code pattern", ["CWE-78"], "A05", "Injection (XSS / HTML / SQL / CSV)", True),
    "VR-RULE-WEAK-CRYPTO": ("Weak hash, cipher or TLS setting", "Code pattern", ["CWE-327"], "A04", "TLS / transport", True),
    "VR-RULE-CERT-BYPASS": ("TLS certificate validation disabled", "Code pattern", ["CWE-295"], "A04", "TLS / transport", True),
    "VR-RULE-HARDCODED-SECRET": ("Hard-coded secret in code", "Code pattern", ["CWE-798"], "A07", "Sensitive data / credentials exposure", True),
    "VR-RULE-ALLOW-ANONYMOUS": ("Action open to anonymous users", "Code pattern", ["CWE-306", "CWE-862"], "A01", "Broken access control / IDOR", True),
}
CS_RULES = ["VR-RULE-PUBLIC-NONACTION", "VR-RULE-GET-STATE", "VR-RULE-CSRF", "VR-RULE-PRELOGIN-LOOKUP", "VR-RULE-COOKIE-AUTHCTX", "VR-RULE-SQL-CONCAT",
            "VR-RULE-HTML-RAW", "VR-RULE-OPEN-REDIRECT", "VR-RULE-PATH-TRAVERSAL", "VR-RULE-SSRF", "VR-RULE-UNSAFE-DESERIALIZE",
            "VR-RULE-PROCESS-START", "VR-RULE-WEAK-CRYPTO", "VR-RULE-CERT-BYPASS", "VR-RULE-HARDCODED-SECRET", "VR-RULE-ALLOW-ANONYMOUS"]
CONFIG_RULES = ["VR-RULE-CUSTOMERRORS-OFF", "VR-RULE-DEBUG-TRUE", "VR-RULE-ELMAH-REMOTE", "VR-RULE-NO-HSTS", "VR-RULE-NO-CSP",
                "VR-RULE-COOKIE-SECURE", "VR-RULE-PLAINTEXT-PASSWORD", "VR-RULE-SESSION-TIMEOUT", "VR-RULE-REQUEST-LIMIT", "VR-RULE-HTTP-ENDPOINT"]

CS_ACTION = re.compile(r"^\s*public\s+(?:virtual\s+|override\s+|sealed\s+|async\s+)*(?:ActionResult|IActionResult|JsonResult|void|Task<\w+>)\s+(\w+)\s*\(([^)]*)\)")
STATE_VERB = re.compile(r"^(Update|Set|Save|Delete|Remove|Change|Reset|Add|Create|Logon|Login|Submit|Approve|Clear|Abort|Shrink|Store|Restore|Compress|Rename|Post|Port|Generate|Upload|Execute|Verify|Authenticate|Register|Send|Import|Run|Process|Abandon)(?=[A-Z_]|$)")
LINE_RULES = [  # (rule, regex on a code line) applied to .cs and .cshtml
    ("VR-RULE-SQL-CONCAT", r'"\s*(SELECT|INSERT|UPDATE|DELETE|EXEC)\b[^"]*"\s*\+|\$"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|EXEC)\b[^"]*\{'),
    ("VR-RULE-HTML-RAW", r"\bHtml\.Raw\("),
    ("VR-RULE-PATH-TRAVERSAL", r"\b(Path\.Combine|File\.(Read|Open|Write)\w*)\([^)]*\b(Request|fileName|filePath|path)\b"),
    ("VR-RULE-SSRF", r"\b(GetAsync|GetStringAsync|DownloadString|WebRequest\.Create)\([^)]*\b(url|uri|Request)\b"),
    ("VR-RULE-UNSAFE-DESERIALIZE", r"TypeNameHandling\.(All|Auto|Objects|Arrays)|\bBinaryFormatter\b|\bNetDataContractSerializer\b|\bLosFormatter\b"),
    ("VR-RULE-PROCESS-START", r"\bProcess\.Start\(\s*[a-z_]\w*"),
    ("VR-RULE-WEAK-CRYPTO", r"\b(MD5|SHA1|DES|TripleDES|RC2)\.Create\(|SecurityProtocolType\.(Ssl3|Tls\b|Tls11)"),
    ("VR-RULE-CERT-BYPASS", r"ServerCertificateValidationCallback\s*[+]?=.*=>\s*true"),
    ("VR-RULE-HARDCODED-SECRET", r'\b(password|pwd|secret|apikey|api_key|clientsecret)\s*=\s*"[^"{}\s]{4,}"'),
    ("VR-RULE-ALLOW-ANONYMOUS", r"\[AllowAnonymous\]"),
]

def attrs_above(lines, i):
    out, j = [], i - 1
    while j >= 0 and (lines[j].strip().startswith("[") or lines[j].strip().startswith("#") or not lines[j].strip()):
        if lines[j].strip().startswith("["):
            out.append(lines[j].strip())
        j -= 1
    return " ".join(out)

def scan_lines(lines):
    hits = []
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith("//") or s.startswith("*") or s.startswith("/*"):
            continue
        for rule, pat in LINE_RULES:
            if re.search(pat, ln, re.I if rule in ("VR-RULE-HARDCODED-SECRET",) else 0):
                hits.append((rule, i + 1, RULES[rule][0]))
    text = "\n".join(lines)
    for i, ln in enumerate(lines):
        if re.search(r"\bRedirect\(\s*(returnUrl|url|redirectUrl|Request)", ln) and "IsLocalUrl" not in text:
            hits.append(("VR-RULE-OPEN-REDIRECT", i + 1, "Redirect to a request-supplied URL without Url.IsLocalUrl"))
    return hits

def scan_cs(rel, lines):
    hits = scan_lines(lines)
    is_ctrl = rel.lower().endswith("controller.cs")
    is_login = "login" in os.path.basename(rel).lower()
    if is_ctrl:
        for i, ln in enumerate(lines):
            m = CS_ACTION.match(ln)
            if not m:
                continue
            name, params = m.group(1), m.group(2)
            a = attrs_above(lines, i)
            if name in ("OnActionExecuting", "Index") or "NonAction" in a:
                continue
            if not re.search(r"\[(Http(Post|Get|Put|Delete|Patch)|AcceptVerbs)", a) and STATE_VERB.match(name):
                hits.append(("VR-RULE-GET-STATE", i + 1, f"{name}() has no HTTP verb attribute, so it also accepts GET; restrict it to [HttpPost] if it changes data, preferences or session state."))
            if "HttpPost" in a and "ValidateAntiForgeryToken" not in a:
                hits.append(("VR-RULE-CSRF", i + 1, f"[HttpPost] {name}() has no [ValidateAntiForgeryToken]; add it, or confirm a global anti-forgery filter covers this action."))
            if is_login and re.search(r"string\s+(loginName|userName|username)\b", params):
                hits.append(("VR-RULE-PRELOGIN-LOOKUP", i + 1, f"Pre-login action {name}({params.strip()}) answers per login name without authentication or throttling; return one uniform response."))
    text = "\n".join(lines)
    if is_ctrl and re.search(r"\babstract\s+class\s+\w*Controller\b", text):
        for i, ln in enumerate(lines):
            m = re.match(r"^\s*public\s+(?:virtual\s+|override\s+|new\s+)*(?!static\b|abstract\b|class\b|const\b)([\w.\[\]?]+(?:<[^>()]*>)?)\s+(\w+)\s*\(", ln)
            if not m or m.group(1) in ("ActionResult", "IActionResult", "JsonResult", "PartialViewResult", "ViewResult"):
                continue
            if "NonAction" in attrs_above(lines, i) or re.search(r"\boverride\b", ln):
                continue  # overrides of framework methods (OnActionExecuting, Dispose, ...) are not actions
            hits.append(("VR-RULE-PUBLIC-NONACTION", i + 1, f"{m.group(2)}() is public on a base controller, so every derived controller exposes it as an action; mark it [NonAction] or make it protected."))
    if re.search(r"Cookies\.GetCookie\(", text) and re.search(r"Jsonizer\.Create<\w*Authentication\w*>", text):
        i = next(k for k, l in enumerate(lines) if re.search(r"Jsonizer\.Create<\w*Authentication\w*>", l))
        hits.append(("VR-RULE-COOKIE-AUTHCTX", i + 1, "The ExtLoginDetails request cookie is deserialised into the authentication context that decides whether the password is checked; confirm the cookie is encrypted and signed."))
    return hits

def scan_config(rel, lines):
    hits, text = [], "\n".join(lines)
    nocomment = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    def line_of(pat):
        for k, l in enumerate(lines):
            if re.search(pat, l, re.I) and "<!--" not in l:
                return k + 1
        return 1
    if re.search(r'customErrors\s+mode="Off"', nocomment, re.I):
        hits.append(("VR-RULE-CUSTOMERRORS-OFF", line_of(r'customErrors\s+mode="Off"'),
                     'Set customErrors mode to "RemoteOnly" or "On"; "Off" returns stack traces and version details to remote users.'))
    if re.search(r'compilation[^>]*debug="true"', nocomment, re.I):
        hits.append(("VR-RULE-DEBUG-TRUE", line_of(r'compilation[^>]*debug="true"'), 'Set compilation debug="false" in the shipped configuration.'))
    if re.search(r'allowRemoteAccess="(1|true|yes)"', nocomment, re.I):
        hits.append(("VR-RULE-ELMAH-REMOTE", line_of(r'allowRemoteAccess='), 'Set allowRemoteAccess="0"; the ELMAH log (cookies, form data) is readable from any client.'))
        for k, l in enumerate(lines):
            if 'path="elmah.axd"' in l and "<!--" not in l:
                hits.append(("VR-RULE-ELMAH-REMOTE", k + 1, "elmah.axd is mapped for GET/POST/HEAD with no authorisation rule in this file."))
    if "customHeaders" in nocomment:
        if "Strict-Transport-Security" not in nocomment:
            k = next((k for k, l in enumerate(lines) if "Strict-Transport-Security" in l), None)
            hits.append(("VR-RULE-NO-HSTS", (k + 1) if k is not None else line_of(r"<customHeaders>"),
                         "Strict-Transport-Security is commented out; HTTPS responses are sent without HSTS." if k is not None
                         else "Add a Strict-Transport-Security header to customHeaders."))
        if "Content-Security-Policy" not in nocomment:
            hits.append(("VR-RULE-NO-CSP", line_of(r"<customHeaders>"), "customHeaders defines no Content-Security-Policy; confirm whether the header is added in code."))
    m = re.search(r"<httpCookies[^>]*>", nocomment)
    if m and 'requireSSL="true"' not in m.group(0):
        hits.append(("VR-RULE-COOKIE-SECURE", line_of(r"<httpCookies"), 'Add requireSSL="true" and sameSite to httpCookies; cookies can currently travel over plain HTTP.'))
    for k, l in enumerate(lines):
        if "<!--" in l:
            continue
        pm = re.search(r'\bpassword="([^"]+)"', l, re.I)
        if pm and not re.match(r"^(\[.*\]|#\{.*\}|\$\(.*\)|__.*__|b)$", pm.group(1)):
            hits.append(("VR-RULE-PLAINTEXT-PASSWORD", k + 1, "Move this password to Key Vault or environment configuration; it is committed in plain text."))
    m = re.search(r'<sessionState[^>]*timeout="(\d+)"', nocomment)
    if m and int(m.group(1)) > 30:
        hits.append(("VR-RULE-SESSION-TIMEOUT", line_of(r"<sessionState"), f"Reduce the session idle timeout; {m.group(1)} minutes keeps unattended sessions usable."))
    m = re.search(r'maxAllowedContentLength="(\d+)"', nocomment)
    if m and int(m.group(1)) > 104857600:
        hits.append(("VR-RULE-REQUEST-LIMIT", line_of(r"maxAllowedContentLength"), f"Lower maxAllowedContentLength ({int(m.group(1)):,} bytes) to the largest upload the business needs."))
    for k, l in enumerate(lines):
        if re.search(r'(address|<value>)\s*=?\s*"?http://', l) and "<!--" not in l:
            host = re.search(r'http://([^/:"<]+)', l)
            hits.append(("VR-RULE-HTTP-ENDPOINT", k + 1, f"Use HTTPS for this endpoint; traffic to {host.group(1) if host else 'it'} is unencrypted."))
    return hits

SECRET = [(re.compile(r'(\bpassword\s*=\s*")[^"]*(")', re.I), r"\1********\2"),
          (re.compile(r'(\b(password|pwd)\s*=\s*)[^;"\s]+', re.I), r"\1********")]

def mask(text):
    for pat, rp in SECRET:
        text = pat.sub(rp, text)
    return text

def classify(summary):
    s = summary.lower()
    return [name for name, _, pat in CLASSES if re.search(pat, s)]

def load_jira(path):
    if not path or not os.path.exists(path):
        return 0, [], {}
    issues = json.load(open(path, encoding="utf-8"))
    vapt, by_class = [], {}
    for it in issues:
        s = it.get("summary") or ""
        if re.search(NOISE, s.lower()):
            continue
        cls = classify(s)
        if not cls:
            continue
        closed = (it.get("status") or "").lower() in CLOSED
        rec = {"key": it["key"], "summary": s.strip(), "status": it.get("status"), "created": it.get("created", "")[:10],
               "open": not closed, "classes": cls}
        vapt.append(rec)
        for c in cls:
            by_class.setdefault(c, []).append(rec)
    return len(issues), vapt, by_class

def fingerprint(rule, rel, extra=""):
    return hashlib.sha1(f"{rule}|{rel.replace(os.sep, '/').lower()}|{extra}".encode()).hexdigest()[:12]

def sev_from_cvss(c, label):
    if c:
        return "Critical" if c >= 9 else "High" if c >= 7 else "Medium" if c >= 4 else "Low"
    return {"critical": "Critical", "high": "High", "moderate": "Medium", "low": "Low"}.get(label, "Medium")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--files", nargs="*")
    ap.add_argument("--jira")
    ap.add_argument("--feeds")
    ap.add_argument("--triage")
    ap.add_argument("--out", required=True)
    ap.add_argument("--project", default="Odessa.Framework")
    ap.add_argument("--only-rules", help="Comma-separated rule keys: run only these rules (use with --fresh and a separate --out for a rule check)")
    ap.add_argument("--fresh", action="store_true", help="Start a new report instead of adding to the existing --out file")
    ap.add_argument("--rules", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnradar_rules.json"))
    a = ap.parse_args()
    catalog = json.load(open(a.rules, encoding="utf-8")) if os.path.exists(a.rules) else {}
    only = {r.strip() for r in a.only_rules.split(",")} if a.only_rules else None
    code_src = {}  # file -> masked source lines shown in the code viewer

    files = a.files or [os.path.relpath(os.path.join(d, f), a.root) for d, _, fs in os.walk(a.root)
                        if not re.search(r"[\\/](bin|obj|node_modules|\.git|\.vs)([\\/]|$)", d) for f in fs
                        if re.search(r"\.(cs|cshtml|config)$", f, re.I)]
    triage = json.load(open(a.triage, encoding="utf-8")) if a.triage and os.path.exists(a.triage) else {"findings": {}, "manual": []}
    issues_read, vapt, by_class = load_jira(a.jira)
    feeds = json.load(open(a.feeds, encoding="utf-8")) if a.feeds and os.path.exists(a.feeds) else {"sources": [], "components": []}
    today = dt.date.today().isoformat()

    raw, scope, rules_run = [], [], {}
    for rel in files:
        p = os.path.join(a.root, rel)
        lines = open(p, encoding="utf-8-sig", errors="replace").read().splitlines()
        low = rel.lower()
        if low.endswith(".cs"):
            hits, ran = scan_cs(rel, lines), CS_RULES
        elif low.endswith(".cshtml"):
            hits, ran = scan_lines(lines), [r for r, _ in LINE_RULES] + ["VR-RULE-OPEN-REDIRECT"]
        elif low.endswith(".config"):
            hits, ran = scan_config(rel, lines), CONFIG_RULES
        else:
            hits, ran = [], []
        if only:
            hits, ran = [h for h in hits if h[0] in only], [r for r in ran if r in only]
        relp = rel.replace("\\", "/")
        code_src[relp] = [mask(l) for l in lines]
        rule_hits = {r: 0 for r in ran}
        for h in hits:
            rule_hits[h[0]] = rule_hits.get(h[0], 0) + 1
        scope.append({"file": relp, "lines": len(lines), "rules": len(ran), "hits": len(hits), "ruleHits": rule_hits, "scanned": today})
        for r in ran:
            rules_run.setdefault(r, {"files": 0, "hits": 0})
            rules_run[r]["files"] += 1
        for rule, line, detail in hits:
            rules_run[rule]["hits"] += 1
            sym = re.sub(r"\W.*", "", detail) if rule in ("VR-RULE-GET-STATE", "VR-RULE-CSRF", "VR-RULE-PRELOGIN-LOOKUP") else ""
            raw.append({"fp": fingerprint(rule, rel, sym), "rule": rule, "file": relp, "line": line,
                        "evidence": mask(lines[line - 1].strip())[:240], "detail": detail})
    for m in triage.get("manual", []):
        if m["file"] not in code_src or (only and m["rule"] not in only):
            continue  # manual finding outside this run's scope or rule selection
        ev = m.get("evidence") or code_src[m["file"]][m["line"] - 1].strip()
        raw.append({"fp": m["fp"], "rule": m["rule"], "file": m["file"], "line": m["line"], "evidence": mask(ev)[:240], "detail": m.get("detail", ""), "manual": m})
        sc = next(x for x in scope if x["file"] == m["file"])
        sc["ruleHits"][m["rule"]] = sc["ruleHits"].get(m["rule"], 0) + 1

    grouped = {}
    for h in raw:
        t = triage["findings"].get(h["fp"], {})
        key = t.get("group") or h["fp"]
        g = grouped.setdefault(key, {"hits": [], "triage": triage["findings"].get(key, t)})
        g["hits"].append(h)

    out = []
    def jira_for(cls, t):
        refs = sorted(by_class.get(cls, []), key=lambda r: (r["open"], r["created"]), reverse=True)
        keys = t["jiraRefs"] if "jiraRefs" in t else [r["key"] for r in refs if r["open"]][:4]
        res = [next(({"key": r["key"], "status": r["status"], "summary": r["summary"], "open": r["open"]} for r in vapt if r["key"] == k),
                    {"key": k, "status": "", "summary": "", "open": True}) for k in keys]
        return refs, res

    for key, g in grouped.items():
        h0, t = g["hits"][0], g["triage"]
        man = h0.get("manual") or {}
        rule = h0["rule"]
        title, cat, cwes, owasp, cls, proactive = RULES.get(rule, (man.get("title", rule), man.get("category", "Code pattern"),
                                                                     man.get("cwe", []), man.get("owasp", ""), man.get("vaptClass", ""), False))
        cwes = [cwes] if isinstance(cwes, str) else list(cwes)
        refs, jira_refs = jira_for(cls, t)
        out.append({
            "id": t.get("id") or "", "fp": key, "rule": rule,
            "title": t.get("title") or title, "category": cat, "source": "AI review" if man else ("Global rule (proactive)" if proactive else "Jira VAPT class"),
            "ref": ", ".join(cwes), "cwes": cwes, "owasp": owasp, "vaptClass": cls,
            "component": h0["file"], "file": h0["file"], "lines": sorted({h["line"] for h in g["hits"]}),
            "evidence": [f'{h["line"]}: {h["evidence"]}' for h in sorted(g["hits"], key=lambda x: x["line"])],
            "locations": [{"file": h["file"], "line": h["line"], "message": h["detail"]} for h in sorted(g["hits"], key=lambda x: x["line"])],
            "layer": t.get("layer", "Base"), "severity": t.get("severity", "Medium"), "cvss": None, "kev": False,
            "stage": t.get("stage", "Matched"), "verdict": t.get("verdict", "Pending"), "status": t.get("status", "Open"),
            "detected": t.get("detected", today), "closed": t.get("closed", ""),
            "jira": ", ".join(r["key"] for r in jira_refs), "jiraRefs": jira_refs, "pr": t.get("pr", ""),
            "notes": t.get("notes", "; ".join(h["detail"] for h in g["hits"])),
            "orgHistory": {"total": len(refs), "open": sum(r["open"] for r in refs)}, "advisories": [],
        })

    # Dependency findings from public advisories (one finding per component version + file)
    for c in feeds.get("components", []):
        if not c.get("advisories"):
            continue
        fp = fingerprint("VR-DEP", c["file"], f'{c["name"]}@{c["version"]}')
        t = triage["findings"].get(fp, {})
        top = max(c["advisories"], key=lambda x: x.get("cvss") or 0)
        refs, jira_refs = jira_for("Outdated components", t)
        cwes = sorted({w for x in c["advisories"] for w in x.get("cwe", [])})
        dep_path = os.path.join(a.root, c["file"])
        loc_line = 1
        if os.path.exists(dep_path):
            dl = open(dep_path, encoding="utf-8-sig", errors="replace").read().splitlines()
            code_src.setdefault(c["file"], [mask(l) for l in dl])
            key_pat = f'"node_modules/{c["name"]}": {{' if c["file"].endswith("package-lock.json") else c["version"]
            loc_line = next((i + 1 for i, l in enumerate(dl) if key_pat in l), 1)
            if c["file"].endswith("package-lock.json"):
                loc_line = next((i + 1 for i in range(loc_line - 1, min(loc_line + 4, len(dl))) if '"version"' in dl[i]), loc_line)
        out.append({
            "id": t.get("id") or "", "fp": fp, "rule": "VR-DEP",
            "title": t.get("title") or f'{c["name"]} {c["version"]}: {top["title"]}', "category": "Dependency CVE",
            "source": "GitHub Advisory Database", "ref": ", ".join(x["id"] for x in c["advisories"]), "cwes": cwes, "owasp": "A03",
            "vaptClass": "Outdated components", "component": f'{c["name"]} {c["version"]}', "file": c["file"], "lines": [loc_line],
            "locations": [{"file": c["file"], "line": loc_line, "message": f'{c["name"]} {c["version"]} is inside the affected range "{x["range"]}" of {x["id"]}: {x["title"]}.'} for x in c["advisories"]],
            "evidence": [f'{c["file"]}: {c["name"]} {c["version"]} ({c["evidence"]})'] + [f'{x["id"]} affects {x["range"]}' for x in c["advisories"]],
            "layer": t.get("layer", "Base"), "severity": t.get("severity", sev_from_cvss(top.get("cvss"), top.get("severity"))),
            "cvss": top.get("cvss") or None, "kev": False,
            "stage": t.get("stage", "Matched"), "verdict": t.get("verdict", "Verified"), "status": t.get("status", "Open"),
            "detected": t.get("detected", today), "closed": t.get("closed", ""),
            "jira": ", ".join(r["key"] for r in jira_refs), "jiraRefs": jira_refs, "pr": t.get("pr", ""),
            "notes": t.get("notes", ""), "orgHistory": {"total": len(refs), "open": sum(r["open"] for r in refs)},
            "advisories": c["advisories"], "newToOrg": True,
        })

    for f in out:
        base = catalog.get(f["rule"], {}).get("type", "Vulnerability")
        f["type"] = "Vulnerability" if f["verdict"] == "Verified" else "Security Hotspot" if f["verdict"] == "Needs investigation" else base

    # Add to the existing report: keep files scanned in earlier runs that are not re-scanned now
    if not a.fresh and os.path.exists(a.out):
        prev = json.load(open(a.out, encoding="utf-8"))
        current = {x["file"] for x in scope}
        kept = [x for x in prev.get("scope", {}).get("detail", []) if x["file"] not in current]
        kept_files = {x["file"] for x in kept}
        scope.extend(kept)
        for fpath in kept_files:
            if fpath in prev.get("sources_code", {}):
                code_src[fpath] = prev["sources_code"][fpath]
        for f in prev.get("findings", []):
            if f.get("rule") == "VR-DEP" or f.get("file") not in kept_files:
                continue
            t = triage["findings"].get(f["fp"], {})
            for k in ("title", "severity", "stage", "verdict", "status", "notes", "closed", "pr", "layer"):
                if k in t:
                    f[k] = t[k]
            if "jiraRefs" in t:
                _, f["jiraRefs"] = jira_for(f["vaptClass"], t)
                f["jira"] = ", ".join(r["key"] for r in f["jiraRefs"])
            base = catalog.get(f["rule"], {}).get("type", "Vulnerability")
            f["type"] = "Vulnerability" if f["verdict"] == "Verified" else "Security Hotspot" if f["verdict"] == "Needs investigation" else base
            out.append(f)
    rules_run = {}
    for x in scope:
        for r, h in x.get("ruleHits", {}).items():
            rules_run.setdefault(r, {"files": 0, "hits": 0})
            rules_run[r]["files"] += 1
            rules_run[r]["hits"] += h

    # Stable IDs: triage IDs first, then the next free number
    used = {f["id"] for f in out if f["id"]}
    n = 0
    for f in out:
        if not f["id"]:
            while f"VR-{n + 1:03d}" in used:
                n += 1
            n += 1
            f["id"] = f"VR-{n:03d}"; used.add(f["id"])

    for s in scope:
        fs = [f for f in out if f["file"] == s["file"]]
        s["findings"] = len(fs); s["open"] = sum(f["status"] == "Open" for f in fs)
        s["verified"] = sum(f["verdict"] == "Verified" for f in fs)

    vapt_classes = [{"vaptClass": c, "owasp": CLASS_OWASP.get(c, ""), "total": len(rs), "open": sum(r["open"] for r in rs),
                     "inCode": sum(1 for f in out if f["vaptClass"] == c)} for c, rs in by_class.items()]
    vapt_classes.sort(key=lambda x: -x["total"])
    years = {}
    for r in vapt:
        y = r["created"][:4]
        years.setdefault(y, {"year": y, "total": 0, "open": 0})
        years[y]["total"] += 1; years[y]["open"] += r["open"]

    owasp = []
    for code, name in OWASP_2025:
        jr = {r["key"]: r for c in by_class for r in by_class[c] if CLASS_OWASP.get(c) == code}
        rs = [r for r, v in RULES.items() if v[3] == code]
        owasp.append({"code": code, "name": name, "jiraTotal": len(jr), "jiraOpen": sum(r["open"] for r in jr.values()),
                      "rules": len(rs) + (1 if code == "A03" else 0),
                      "rulesRun": sum(1 for r in rs if r in rules_run) + (1 if code == "A03" and feeds.get("components") else 0),
                      "openInCode": sum(1 for f in out if f["owasp"] == code and f["status"] == "Open")})
    cwe_cov = []
    jira_cwe = {}
    for r, v in RULES.items():
        for w in v[2]:
            jira_cwe.setdefault(w, set()).add(v[4])
    for rank, cwe, name in CWE_TOP25:
        rs = [r for r, v in RULES.items() if cwe in v[2]]
        dep = sum(1 for f in out if f["rule"] == "VR-DEP" and cwe in f["cwes"])
        cwe_cov.append({"rank": rank, "cwe": cwe, "name": name, "applies": cwe not in NOT_MANAGED,
                        "rules": rs, "ran": any(r in rules_run for r in rs),
                        "openInCode": sum(1 for f in out if cwe in f["cwes"] and f["status"] == "Open"), "viaDependencies": dep})

    comps = feeds.get("components", [])
    inventory = {"files": sorted({c["file"] for c in comps}), "components": len(comps),
                 "checked": sum(1 for c in comps if c.get("checked") not in (None, "not checked")),
                 "withAdvisories": sum(1 for c in comps if c.get("advisories")),
                 "byEcosystem": {e: sum(1 for c in comps if c["ecosystem"] == e) for e in sorted({c["ecosystem"] for c in comps})},
                 "list": [{k: c.get(k) for k in ("name", "version", "ecosystem", "file", "evidence", "checked")} | {"advisories": len(c.get("advisories", []))}
                          for c in comps if not (c["ecosystem"] == "npm" and "package-lock" in c["evidence"] and not c.get("advisories"))]}

    sources = [{"name": "Jira (odessainc.atlassian.net)", "status": "ok", "detail": f"{issues_read} tickets read, {len(vapt)} VAPT findings"}]
    sources += [{"name": s["name"], "status": "ok" if s["status"] == "ok" else "blocked", "detail": s["status"] if s["status"] != "ok" else f'{s.get("checked", "")} component versions checked'}
                for s in feeds.get("sources", [])]
    doc = {"project": a.project, "asOf": today, "sample": False,
           "scope": {"files": [s["file"] for s in scope], "lines": sum(s["lines"] for s in scope), "detail": scope},
           "rulesRun": rules_run, "sources_code": code_src,
           "rules": {k: dict(v, cwe=RULES.get(k, (None, None, []))[2] if k in RULES else [], owasp=RULES[k][3] if k in RULES else "A03",
                             origin=("Global (proactive)" if RULES[k][5] else "Jira VAPT class") if k in RULES else "Global advisories",
                             filesChecked=rules_run.get(k, {}).get("files", 0), hits=rules_run.get(k, {}).get("hits", 0),
                             openFindings=sum(1 for f in out if f["rule"] == k and f["status"] == "Open"))
                     for k, v in catalog.items()}, "sources": sources, "feeds": triage.get("feeds", {}), "run": triage.get("run", {}),
           "inventory": inventory,
           "global": {"owasp": owasp, "cweTop25": cwe_cov},
           "jira": {"issuesRead": issues_read, "vaptFindings": len(vapt), "open": sum(r["open"] for r in vapt),
                    "byClass": vapt_classes, "byYear": sorted(years.values(), key=lambda x: x["year"])},
           "findings": sorted(out, key=lambda f: f["id"])}
    json.dump(doc, open(a.out, "w", encoding="utf-8"), indent=1)
    print(f"This run scanned {len(files)} file(s). Report now covers {len(scope)} files / {doc['scope']['lines']} lines -> {len(out)} findings "
          f"({sum(f['rule'] == 'VR-DEP' for f in out)} from advisories); Jira VAPT findings: {len(vapt)}")

if __name__ == "__main__":
    main()
