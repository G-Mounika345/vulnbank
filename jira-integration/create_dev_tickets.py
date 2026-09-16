#!/usr/bin/env python3
"""
Create the 27 grouped dependency-remediation tickets (one per vulnerable
component, rolling up every CVE/finding for that component) in the new
DEV Jira project - separate from the security team's KAN board.

Source data: ../grouped_tickets.json (built from vulnbank_vulnerability_triage.csv,
which itself was built from dependency-check-report.html + snyk-report.html).

Usage:
    python create_dev_tickets.py --dry-run
    python create_dev_tickets.py --apply

Only stdlib is used (urllib) - no pip install needed.
"""
import argparse
import base64
import json
import os
import sys
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(HERE, ".env")
TICKETS_PATH = os.path.join(HERE, "grouped_tickets.json")
DEV_PROJECT_KEY = "DEV"


def load_env(path):
    env = {}
    if not os.path.exists(path):
        return env
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    return env


def text(s):
    return {"type": "text", "text": s}


def paragraph(s):
    return {"type": "paragraph", "content": [text(s)]}


def heading(s, level=2):
    return {"type": "heading", "attrs": {"level": level}, "content": [text(s)]}


def bullet_list(items):
    return {
        "type": "bulletList",
        "content": [
            {"type": "listItem", "content": [paragraph(i)]} for i in items
        ],
    }


def table_cell(s, header=False):
    return {
        "type": "tableHeader" if header else "tableCell",
        "attrs": {},
        "content": [paragraph(s)],
    }


def table_row(cells, header=False):
    return {"type": "tableRow", "content": [table_cell(c, header=header) for c in cells]}


def findings_table(csv_lines):
    """csv_lines: list of '|'-delimited rows parsed out of the wiki-style
    table baked into the ticket's Description field (||h1||h2||... then |c1|c2|...)."""
    rows = []
    header_done = False
    for line in csv_lines:
        line = line.strip()
        if not line.startswith("|"):
            continue
        is_header = line.startswith("||")
        cells = [c for c in line.strip("|").split("||" if is_header else "|") if c != ""]
        if is_header and not header_done:
            rows.append(table_row(cells, header=True))
            header_done = True
        elif not is_header:
            rows.append(table_row(cells, header=False))
    return {"type": "table", "attrs": {"isNumberColumnEnabled": False, "layout": "default"}, "content": rows}


def build_adf(ticket):
    desc_lines = ticket["Description"].split("\n")

    summary_lines = []
    table_lines = []
    note_lines = []
    section = None
    for line in desc_lines:
        if line.startswith("h2. Summary"):
            section = "summary"
            continue
        if line.startswith("h2. Findings"):
            section = "table"
            continue
        if line.startswith("h2. Notes"):
            section = "notes"
            continue
        if section == "summary" and line.strip():
            summary_lines.append(line.strip())
        elif section == "table" and line.strip():
            table_lines.append(line.strip())
        elif section == "notes" and line.strip().startswith("*"):
            note_lines.append(line.strip().lstrip("* ").strip())

    content = [heading("Summary")]
    for s in summary_lines:
        content.append(paragraph(s.replace("*", "")))
    content.append(heading("Findings"))
    content.append(findings_table(table_lines))
    content.append(heading("Notes"))
    content.append(bullet_list(note_lines))

    return {"type": "doc", "version": 1, "content": content}


def jira_request(base_url, auth_header, method, path, payload=None):
    url = f"{base_url}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Basic {auth_header}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, {"raw": body}


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true")
    group.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    env = {**os.environ, **load_env(ENV_PATH)}
    base_url = env.get("JIRA_BASE_URL", "").rstrip("/")
    email = env.get("JIRA_EMAIL", "")
    token = env.get("JIRA_API_TOKEN", "")

    tickets = json.load(open(TICKETS_PATH, encoding="utf-8"))
    print(f"{'DRY RUN' if args.dry_run else 'CREATING'} {len(tickets)} issues "
          f"in project {DEV_PROJECT_KEY} at {base_url}\n")

    auth_header = base64.b64encode(f"{email}:{token}".encode()).decode() if args.apply else ""
    created, failed = [], []

    for t in tickets:
        fields = {
            "project": {"key": DEV_PROJECT_KEY},
            "summary": t["Summary"],
            "issuetype": {"name": t["Issue Type"]},
            "priority": {"name": t["Priority"]},
            "labels": [l.strip() for l in t["Labels"].split(",")],
            "description": build_adf(t),
        }
        if args.dry_run:
            print(f"--- {t['Summary']} ---")
            print(f"  priority={t['Priority']}  labels={fields['labels']}  findings={t['Finding Count']}")
        else:
            status, resp = jira_request(base_url, auth_header, "POST", "/rest/api/3/issue", {"fields": fields})
            if status == 201:
                print(f"Created {resp['key']}: {t['Summary']}")
                created.append(resp["key"])
            else:
                print(f"FAILED ({status}) for '{t['Summary']}': {resp}", file=sys.stderr)
                failed.append(t["Summary"])

    if not args.dry_run:
        print(f"\nDone. Created: {len(created)}  Failed: {len(failed)}")


if __name__ == "__main__":
    main()
