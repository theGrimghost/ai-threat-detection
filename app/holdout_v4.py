"""Holdout v4 (FROZEN 2026-10-14): honest generalization test. Do NOT add these
instances to gen_dataset.py or rules.py. Uses DIFFERENT vectors than training NOVEL."""
from app.engine import Engine
from app.holdout_eval import run

BENIGN = [
    "/login?next=%2Faccount%2Fbilling",
    "/search?q=best+laptop+under+500000+naira",
    "/shop?cat=phones&sort=newest&page=2",
    "/blog/how-to-secure-ssh-keys-2026",
    "/api/v1/users/2041/orders?status=delivered",
    "/redirect?url=https://www.jumia.com.ng/laptops",
    "/search?q=C%2B%2B+vector+tutorial",
    "/images/team%20photo%202026.jpg",
    "/wp-content/uploads/2026/09/banner.png",
    "/api/search?q=database+selection+committee",
    "/docs/deploy#rollback",
    "/static/css/main.a3f1c9.css",
    "/profile/edit?tab=security&saved=1",
    "/search?q=what%27s+on+the+menu+today",
    "/api/items?page=2&limit=20",
    "/files/report_2026_final.pdf",
    "/search?q=order+by+price+low+to+high",
    "/settings?section=notifications&lang=en",
    "/favicon.ico",
    "/healthz",
]

ATTACKS = [
    # SSTI - different vectors than training
    "/page?name={{config.items()}}",
    "/view?tpl=${7*'7'}",
    "/render?x=#{7*7}",
    # Command injection - different vectors
    "/ping?host=127.0.0.1%7Cwhoami",
    "/exec?cmd=$(id)",
    "/shell?c=hello%60id%60",
    # LDAP - different vectors
    "/users?filter=(|(uid=*)(cn=*))",
    "/auth?dn=cn%3D*%2Cdc%3Dexample%2Cdc%3Dcom",
    # CRLF - different vectors
    "/redir?to=a%0d%0aLocation%3A+http%3A%2F%2Fevil.example%2F",
    "/log?msg=test%250d%250aInjected%3A+yes",
    # Obfuscated classics (case/comment/double-encode - must be caught by ML)
    "/search?q=1%2527%2FUNION%2F%2A%2A%2FSELECT%2Bnull--",
    "/item?id=9+AnD+substring(%40%40version%2C1%2C1)%3D5",
    "/c?x=%3Csvg%2Fonload%3Dalert(1)%3E",
    "/download?f=%252e%252e%2Fetc%2Fshadow",
    "/fetch?url=http://0x7f.0x0.0x0.0x1/admin",
    "/api/orders?x[$ne]=1",
    "/.git%2FHEAD",
    "/backup.sql",
    "/wp-login.php",
    "/server-status",
]

if __name__ == "__main__":
    e = Engine()
    fp = run(e, BENIGN, "BENIGN v4 (want: ok)")
    tp = run(e, ATTACKS, "ATTACKS v4 (want: ALERT)")
    print(f"\nfalse positives: {fp}/{len(BENIGN)}   detected: {tp}/{len(ATTACKS)}")
