"""Plain-language summary of a vulnerability from its CVSS vector and weakness type (CWE)."""

CWE_NAMES = {
    "CWE-20": "improper input validation",
    "CWE-22": "path traversal: reading or writing files outside the allowed folder",
    "CWE-77": "command injection",
    "CWE-78": "OS command injection",
    "CWE-79": "cross-site scripting (XSS)",
    "CWE-89": "SQL injection: access to the database",
    "CWE-94": "code injection",
    "CWE-95": "code injection (eval)",
    "CWE-119": "buffer overflow (memory corruption)",
    "CWE-120": "buffer overflow",
    "CWE-121": "stack-based buffer overflow",
    "CWE-122": "heap-based buffer overflow",
    "CWE-125": "out-of-bounds read",
    "CWE-190": "integer overflow",
    "CWE-200": "sensitive information disclosure",
    "CWE-269": "improper privilege management (privilege escalation)",
    "CWE-284": "improper access control",
    "CWE-285": "improper authorization",
    "CWE-287": "authentication bypass",
    "CWE-288": "authentication bypass via alternate path",
    "CWE-290": "authentication bypass by spoofing",
    "CWE-306": "missing authentication for a critical function",
    "CWE-352": "cross-site request forgery (CSRF)",
    "CWE-362": "race condition",
    "CWE-400": "uncontrolled resource consumption (denial of service)",
    "CWE-416": "use-after-free",
    "CWE-434": "unrestricted dangerous file upload",
    "CWE-476": "NULL pointer dereference",
    "CWE-502": "unsafe deserialization",
    "CWE-522": "weakly protected credentials",
    "CWE-601": "open redirect",
    "CWE-611": "XML external entity (XXE)",
    "CWE-639": "access to other users' data via a modified ID (IDOR)",
    "CWE-693": "protection mechanism bypass",
    "CWE-732": "incorrect permissions on a resource",
    "CWE-787": "out-of-bounds write",
    "CWE-798": "hard-coded passwords or keys",
    "CWE-843": "type confusion",
    "CWE-862": "missing authorization check",
    "CWE-863": "incorrect authorization check",
    "CWE-918": "server-side request forgery (SSRF)",
    "CWE-1321": "prototype pollution",
}

AV_LONG = {
    "N": "remotely over the network, including the internet",
    "A": "from the same local network",
    "L": "only with access to the system itself",
    "P": "only with physical access to the device",
}
AV_SHORT = {"N": "Remote", "A": "Adjacent network", "L": "Local", "P": "Physical access"}
PR_LONG = {
    "N": "no login required",
    "L": "a regular user account is required",
    "H": "admin privileges are required",
}
PR_SHORT = {"N": "no login", "L": "login needed", "H": "admin needed"}
UI_LONG = {
    "N": "the victim does not need to do anything",
    "R": "the victim must do something: open a file, link or page",
    "P": "the victim must do something: open a file or page",
    "A": "the victim must take an action prompted by the attacker",
}


def parse_vector(vector):
    parts = (vector or "").split("/")
    return dict(p.split(":", 1) for p in parts[1:] if ":" in p)


def explain(vector, cwe=None):
    d = parse_vector(vector)
    how = [x for x in (AV_LONG.get(d.get("AV")), PR_LONG.get(d.get("PR")), UI_LONG.get(d.get("UI"))) if x]

    c = d.get("C") or d.get("VC")
    i = d.get("I") or d.get("VI")
    a = d.get("A") or d.get("VA")
    impact = []
    if c == "H" and i == "H" and a == "H":
        impact.append("full system takeover: data theft, tampering, shutdown")
    else:
        if c == "H":
            impact.append("data theft")
        elif c == "L":
            impact.append("partial data leak")
        if i == "H":
            impact.append("data tampering or code injection")
        elif i == "L":
            impact.append("partial data tampering")
        if a == "H":
            impact.append("denial of service (crash or hang)")
        elif a == "L":
            impact.append("degraded performance")
    if d.get("S") == "C" or "H" in (d.get("SC"), d.get("SI"), d.get("SA")):
        impact.append("can affect other systems beyond the vulnerable one")

    short = []
    if d.get("AV") in AV_SHORT:
        s = AV_SHORT[d["AV"]]
        if d.get("PR") in PR_SHORT:
            s += ", " + PR_SHORT[d["PR"]]
        if d.get("UI") not in (None, "N"):
            s += ", user interaction"
        short.append(s)
    if impact:
        short.append(impact[0].split(":")[0])

    return {
        "kind": CWE_NAMES.get(cwe or ""),
        "how": how,
        "impact": impact,
        "short": " → ".join(short),
    }
