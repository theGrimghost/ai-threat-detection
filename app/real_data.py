"""Real-data ingestion: CSIC-2010 / ECML-style HTTP requests + SecLists payload lists.

Expected layout (drop files here, no code change needed):
  data/real/normalTrafficTraining.txt      CSIC normal (label 0)
  data/real/anomalousTrafficTraining.txt  CSIC attacks (label 1)
  data/real/*Test.txt                      same, auto-picked as test-only
  data/real/payloads/*.txt                one payload per line (SecLists style)

CSIC format is plain HTTP:
  METHOD URL PROTOCOL
  Header: value
  ...
  <blank>
  [body]

Usage:
  python -m app.real_data --out data/real.csv   # converts whatever is present
Train mixes it automatically if data/real.csv exists:
  python -m app.gen_dataset   # writes synthetic
  python -m app.train         # mixes synthetic + real if present
"""
import csv
import glob
import os
import re
import sys

from app.features import FEATURES, extract
from app.rules import detect

REQ_SPLIT = re.compile(r"\n\s*\n")


def parse_csic_file(path):
    """Parse a CSIC-style raw HTTP file into (method, url, ua, body) tuples."""
    with open(path, encoding="latin-1") as f:
        text = f.read()
    out = []
    # CSIC files separate requests by lines starting with METHOD; be lenient.
    chunks = re.split(r"(?m)^(?=GET |POST |PUT |DELETE |HEAD |OPTIONS )", text)
    for ch in chunks:
        ch = ch.strip()
        if not ch:
            continue
        lines = ch.splitlines()
        m = re.match(r"(\S+)\s+(\S+)(?:\s+\S+)?", lines[0])
        if not m:
            continue
        method, url = m.group(1).upper(), m.group(2)
        ua, body, blank = "-", "", False
        for ln in lines[1:]:
            if not ln.strip():
                blank = True
                continue
            if not blank and ":" in ln:
                k, _, v = ln.partition(":")
                if k.strip().lower() == "user-agent":
                    ua = v.strip() or "-"
            elif blank:
                body += ln + "\n"
        out.append((method, url, ua, body.strip()))
    return out


def rows_from_requests(reqs, label, category):
    rows = []
    for method, url, ua, body in reqs:
        rec = {"path": url, "ua": ua, "method": method, "body": body}
        row = {"label": label, "category": category, "rules_flag": int(bool(detect(rec))),
               "path": url, "ua": ua, "body": body}
        row.update(zip(FEATURES, extract(rec)))
        rows.append(row)
    return rows


def main(out="data/real.csv"):
    reqs = []
    for pat, label, cat in (("data/real/normal*.txt", 0, "benign"),
                            ("data/real/anomal*.txt", 1, "real-attack"),
                            ("data/real/*Test*.txt", None, None)):
        for fp in glob.glob(pat):
            is_test = "Test" in os.path.basename(fp)
            lab = label
            if lab is None:  # test files: guess by name
                lab = 0 if "normal" in fp.lower() else 1
                cat = "benign" if lab == 0 else "real-attack"
            parsed = parse_csic_file(fp)
            print(f"{fp}: {len(parsed)} requests (label={lab}{' TEST-ONLY' if is_test else ''})")
            for r in rows_from_requests(parsed, lab, cat):
                r["split"] = "test" if is_test else "train"
                reqs.append(r)
    for fp in glob.glob("data/real/payloads/*.txt"):
        with open(fp, encoding="latin-1", errors="replace") as f:
            lines = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        print(f"{fp}: {len(lines)} payloads")
        for p in lines:
            url = p if p.startswith("/") else f"/search?q={p}"
            for r in rows_from_requests([("GET", url, "sqlmap/1.8", "")], 1, "real-attack"):
                r["split"] = "train"
                reqs.append(r)
    if not reqs:
        print("no real data found. To plug CSIC-2010:")
        print("  mkdir -p data/real && cp normalTrafficTraining.txt anomalousTrafficTraining.txt data/real/")
        print("  python -m app.real_data --out data/real.csv")
        return
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as f:
        wr = csv.DictWriter(f, fieldnames=list(reqs[0].keys()))
        wr.writeheader()
        wr.writerows(reqs)
    print(f"wrote {len(reqs)} real rows -> {out}")


if __name__ == "__main__":
    main(sys.argv[2] if len(sys.argv) > 2 and sys.argv[1] == "--out" else "data/real.csv")
