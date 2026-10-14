import re
from urllib.parse import unquote_plus

RULES = {
    "sqli": [
        r"(?i)\bunion\b.+\bselect\b",
        r"(?i)\b(or|and)\b\s+\d+\s*=\s*\d+",
        r"(?i)'\s*(or|and)\s+'?\w",
        r"(?i)'\s*(--|#)",
        r"(?i)\bsleep\s*\(",
        r"(?i)information_schema",
    ],
    "xss": [
        r"(?i)<script",
        r"(?i)\bon(error|load|click|mouseover)\s*=",
        r"(?i)javascript:",
    ],
    "path_traversal": [
        r"\.\./",
        r"(?i)/etc/(passwd|shadow)",
        r"(?i)\\windows\\",
    ],
    "ssrf": [
        r"(?i)[?&](url|uri|dest|redirect|next|target)=https?://"
        r"(127\.|localhost|0\.0\.0\.0|169\.254\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)",
        r"(?i)(file|gopher)://",
    ],
    "log4shell": [
        r"(?i)\$\{jndi:",
        r"(?i)\$\{\$\{",
    ],
}
RULES["sqli"] += [
    r"(?i)@@version",
    r"(?i)\b(pg_sleep|benchmark)\s*\(",
    r"(?i)\bwaitfor\s+delay\b",
    r"(?i);\s*(drop|shutdown|insert|update|delete)\b",
    r"(?i)\border\s+by\s+\d+",
]
RULES["ssrf"] += [
    r"(?i)[?&]\w+=https?://(\[|\d{8,10}(?=[/&\s]|$))",
]
RULES.update({
    "nosql_injection": [
        r"(?i)\[\$(ne|gt|gte|lt|lte|regex|where|in|nin|or|and|exists)\]",
    ],
    "open_redirect": [
        r"(?i)[?&](url|uri|next|redirect|redirect_uri|return|returnto|goto|target|dest|continue)=(https?:)?//[^&/]*@",
        r"(?i)[?&](url|uri|next|redirect|redirect_uri|return|returnto|goto|continue)=//[^/\s]",
    ],
    "recon": [
        r"(?i)/\.(git|svn|hg|env|ds_store|aws|ssh)(/|\s|\?|$)",
        r"(?i)/(wp-(admin|login\.php|includes|content/plugins)|xmlrpc\.php|phpmyadmin|pma|adminer)",
        r"(?i)/(jenkins|manager/html|jmx-console|web-console|solr/admin|actuator|server-status|server-info)",
        r"(?i)/(WEB-INF|META-INF)/",
        r"(?i)/(backup|dump|db|database)\.(sql|zip|tar|gz|bak)\b",
        r"(?i)\.(bak|old|orig|swp)(\?|\s|$)",
    ],
    "ssti": [
        r"\{\{.+?\}\}",
        r"\$\{.+\}",
        r"#\{.+?\}",
    ],
    "cmdi": [
        r"[|;&`]\s*(id|whoami|cat|ls|pwd|uname)\b",
        r"\$\(.+?\)",
        r"`[^`]+`",
    ],
})
COMPILED = {k: [re.compile(p) for p in v] for k, v in RULES.items()}


def _normalize(s: str) -> str:
    # decode twice to catch double-encoded payloads
    return unquote_plus(unquote_plus(s))


def detect(record: dict) -> list[str]:
    """Return the rule categories that match a parsed log record (path+body+ua)."""
    text = _normalize(f'{record.get("path", "")} {record.get("body", "")} {record.get("ua", "")}')
    return [cat for cat, pats in COMPILED.items() if any(p.search(text) for p in pats)]
