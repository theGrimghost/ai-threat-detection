import math
import re
from collections import Counter
from urllib.parse import unquote_plus

SQL_KW = re.compile(r"(?i)\b(select|union|insert|update|delete|drop|sleep|benchmark|where|from|having|waitfor|exec|cast|concat|substring|version)\b")
XSS_KW = re.compile(r"(?i)(script|javascript|onerror|onload|onfocus|ontoggle|onpageshow|<svg|<img|<iframe)")
TOOL_UA = re.compile(r"(?i)(curl|sqlmap|nikto|wget|python-requests|hydra|nmap|gobuster|masscan|zgrab|dirbuster)")
SENSITIVE = re.compile(r"(?i)(\.env|\.git|wp-login|wp-admin|wp-content|phpmyadmin|cgi-bin|actuator|\.php|passwd|boot\.ini|etc/|credentials|xmlrpc|backup|server-status|solr|vendor/|\.ds_store|web-inf|jmx-console|heapdump|struts|id_rsa|dump\.sql)")
NOSQL = re.compile(r"(?i)(\[\$\w+\]|\$(ne|gt|gte|lt|lte|regex|where|in|nin|or|and)\b)")

FEATURES = [
    "path_len", "query_len", "num_params", "max_param_len",
    "special_ratio", "digit_ratio", "upper_ratio", "entropy",
    "pct_count", "double_enc", "dotdot", "quotes", "angles",
    "sql_kw", "xss_kw", "sql_comment", "sensitive_path",
    "is_post", "depth", "ua_len", "ua_tool", "ua_empty",
    "nosql_op", "scheme_in_query", "proto_rel", "at_sign", "enc_ratio", "semicolon",
    "tpl_braces", "cmd_seq", "ldap_ind", "crlf_seq", "shell_var", "null_byte",
    "recon_admin", "recon_dot", "recon_backup", "static_asset",
    "body_len", "body_susp",
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in Counter(s).values())


def extract(record: dict) -> list[float]:
    raw = record.get("path", "") or ""
    ua = record.get("ua", "") or ""
    method = record.get("method", "GET") or "GET"
    body = record.get("body", "") or ""
    dec = unquote_plus(unquote_plus(raw))
    bdec = unquote_plus(unquote_plus(body)) if body else ""
    combined = f"{dec} {bdec}" if bdec else dec
    raw_low = raw.lower()
    path_part, _, query = raw.partition("?")
    n = max(len(dec), 1)
    values = [p.partition("=")[2] for p in query.split("&")] if query else []
    vals = {
        "path_len": len(path_part),
        "query_len": len(query),
        "num_params": len(values),
        "max_param_len": max((len(v) for v in values), default=0),
        "special_ratio": sum(1 for c in dec if not c.isalnum() and c not in "/.") / n,
        "digit_ratio": sum(c.isdigit() for c in dec) / n,
        "upper_ratio": sum(c.isupper() for c in dec) / n,
        "entropy": _entropy(dec),
        "pct_count": raw.count("%"),
        "double_enc": int("%25" in raw),
        "dotdot": dec.count(".."),
        "quotes": dec.count("'") + dec.count('"'),
        "angles": dec.count("<") + dec.count(">"),
        "sql_kw": len(SQL_KW.findall(combined)),
        "xss_kw": len(XSS_KW.findall(combined)),
        "sql_comment": combined.count("--") + combined.count("/*") + combined.count("#"),
        "sensitive_path": int(bool(SENSITIVE.search(dec))),
        "is_post": int(method.upper() == "POST"),
        "depth": path_part.count("/"),
        "ua_len": len(ua),
        "ua_tool": int(bool(TOOL_UA.search(ua))),
        "ua_empty": int(ua in ("", "-")),
        "nosql_op": len(NOSQL.findall(combined)),
        "scheme_in_query": dec.partition("?")[2].count("://"),
        "proto_rel": int(bool(re.search(r"=\s*//", dec))),
        "at_sign": dec.count("@"),
        "enc_ratio": raw.count("%") / max(len(raw), 1),
        "semicolon": dec.count(";"),
        "tpl_braces": dec.count("{{") + dec.count("}}") + dec.count("${") + dec.count("#{"),
        "cmd_seq": len(re.findall(r"\|\||&&|\|\s*\w+|`[^`]*`|\$\([^)]*\)|;\s*(cat|ls|id|whoami|sleep|ping|nc|wget|curl)\b", dec, flags=re.IGNORECASE)) + dec.count("|") * 0.5 + dec.count("`") * 0.5 + len(re.findall(r"[|;&`]\s*(id|whoami|cat|ls|pwd|uname|nc|bash|sh|powershell|cmd)\b", dec, flags=re.IGNORECASE)) * 2.0,
        "ldap_ind": len(re.findall(r"\(\s*[|&!]|\(uid\s*=|\(cn\s*=|\(\w+=\*|uid\s*=\s*\*", dec, flags=re.IGNORECASE)) + (1.0 if dec.count("*") >= 2 and "(" in dec else 0.0),
        "crlf_seq": dec.count("\r") + dec.count("\n") + raw_low.count("%0d") + raw_low.count("%0a") + len(re.findall(r"(?i)set-cookie\s*:", dec)) * 0.5,
        "shell_var": dec.count("${") + dec.count("$(") + dec.count("#{"),
        "null_byte": dec.count("\x00") + raw_low.count("%00"),
        "recon_admin": int(bool(re.search(r"(?i)(wp-(login|admin)|phpmyadmin|pma|adminer|actuator|solr/admin|jmx-console|web-console|manager/html|server-status|xmlrpc|cgi-bin|vendor/|struts|heapdump)", dec))),
        "recon_dot": int(bool(re.search(r"/\.(git|svn|hg|env|aws|ssh|ds_store)(/|\?|$)", dec, flags=re.IGNORECASE))),
        "recon_backup": int(bool(re.search(r"(?i)(\.(bak|old|orig|swp|sql)(\?|$)|backup|dump\.sql|id_rsa|database\.(sql|zip))", dec))),
        "static_asset": int(bool(re.search(r"(?i)(\.(css|js|png|jpg|jpeg|ico|pdf|woff2?)(\?|#|$)|/static/|/images/|/wp-content/uploads/|favicon\.ico)", dec))),
        "body_len": float(len(body)),
        "body_susp": float(len(SQL_KW.findall(bdec)) + len(XSS_KW.findall(bdec)) + len(NOSQL.findall(bdec)) + bdec.count("{{") + bdec.count("}}") + bdec.count(";") * 0.5 + bdec.count("|") * 0.5),
    }
    return [float(vals[f]) for f in FEATURES]
