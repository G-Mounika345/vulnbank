#!/usr/bin/env python3
"""
Create one Jira issue per OWASP Top 10:2021 finding from the VulnBank
security review, using the Jira Cloud REST API v3.

Setup:
    1. cp .env.example .env
    2. Fill in .env with your real Jira base URL, email, API token, project key.
    3. Preview what would be created (no network writes):
           python create_jira_tickets.py --dry-run
    4. Actually create the tickets:
           python create_jira_tickets.py --apply

Only stdlib is used (urllib) - no pip install needed.
"""
import argparse
import base64
import json
import os
import sys
import urllib.request
import urllib.error

ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")


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


def adf(*paragraphs):
    """Build a minimal Atlassian Document Format body from plain-text paragraphs."""
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": p}]}
            for p in paragraphs
        ],
    }


# The 10 findings, matching vulnbank/README.md's OWASP Top 10:2021 vulnerability
# map, cross-checked by actually running the app and hitting each endpoint.
FINDINGS = [
    dict(
        label="owasp-a01",
        priority="Highest",
        summary="[A01] Broken Access Control - IDOR on account & admin endpoints",
        details=[
            "GET /account/{id} returns any account (balance included) with no check "
            "that the caller owns it. Confirmed: logged in as alice, GET /account/3 "
            "returned admin's ACC-9000 balance of 999999.99.",
            "GET /accounts dumps every customer's account/balance with no auth.",
            "POST /account/{id}/balance lets anyone overwrite any account's balance directly.",
            "Files: AccountController.java (viewAccount, allAccounts, setBalance).",
            "Fix: derive the acting user from the verified session/JWT, filter queries "
            "by ownerId, and remove the raw balance-write endpoint or gate it behind "
            "the transfer flow.",
        ],
    ),
    dict(
        label="owasp-a02",
        priority="High",
        summary="[A02] Cryptographic Failures - MD5 passwords, hardcoded JWT secret, insecure cookie",
        details=[
            "Passwords are hashed with unsalted MD5 (AuthController.md5, data.sql).",
            "JWT signing secret is hardcoded in JwtUtil.java and application.properties "
            "(vulnbank-super-secret-key-123) and tokens never expire.",
            "VULNBANK_TOKEN cookie is set with no HttpOnly/Secure/SameSite - confirmed "
            "via curl -i on POST /login.",
            "Fix: bcrypt/argon2 for passwords, load the JWT secret from a vaulted env "
            "var with real entropy, set exp claim, mark cookie HttpOnly+Secure+SameSite=Strict.",
        ],
    ),
    dict(
        label="owasp-a03",
        priority="Highest",
        summary="[A03] Injection - reflected & stored XSS on /search and /messages",
        details=[
            "GET /search?q=<script>alert(1)</script> reflects the payload unescaped "
            "into the page - confirmed via curl, <script> tag returned verbatim.",
            "POST /messages stores content as-is and renders it unescaped to every "
            "viewer on GET /messages (stored XSS).",
            "Note: the /login/debug endpoint is documented as SQL-injectable but in "
            "the current build it delegates to UserRepository.rawLogin(), which is "
            "parameterized (?1/?2) - the concatenated `sql` string in AuthController "
            "is dead code and the admin' -- bypass does NOT work as written. Flagging "
            "as a doc/code mismatch to fix alongside the real XSS fixes.",
            "Fix: Thymeleaf th:text (escaped) instead of unescaped [[${...}]]; either "
            "wire the debug endpoint to demonstrate real parameterized-vs-raw SQL or "
            "remove the misleading dead code.",
        ],
    ),
    dict(
        label="owasp-a04",
        priority="High",
        summary="[A04] Insecure Design - unbounded transfers, unrestricted file upload",
        details=[
            "POST /transfer has no per-transaction cap, no re-auth, allows negative "
            "balances, and doesn't verify the caller owns fromId.",
            "POST /profile/upload-picture has no file-type/size/extension checks and "
            "takes the client-supplied filename verbatim (traversal-on-write risk).",
            "Fix: add transaction limits + step-up auth for transfers; allow-list "
            "extensions/MIME types, cap upload size, and generate server-side filenames.",
        ],
    ),
    dict(
        label="owasp-a05",
        priority="High",
        summary="[A05] Security Misconfiguration - CSRF/CORS, open actuator/H2, XXE",
        details=[
            "CSRF protection is globally disabled and CORS allows any origin with "
            "credentials (SecurityConfig).",
            "All actuator endpoints are exposed including /env with show-values=ALWAYS "
            "- confirmed via curl, full env dump returned with no auth.",
            "/h2-console is reachable with no auth - confirmed (HTTP 302 redirect to login).",
            "POST /profile/import parses attacker XML with external entities enabled - "
            "confirmed by reading C:\\Windows\\win.ini back through an XXE payload.",
            "Fix: re-enable CSRF, restrict CORS origins, lock actuator to authenticated "
            "internal access only, disable H2 console outside dev, and set "
            "disallow-doctype-decl=true on the XML parser.",
        ],
    ),
    dict(
        label="owasp-a06",
        priority="Medium",
        summary="[A06] Vulnerable & Outdated Components - Spring Boot 2.7.5, jjwt 0.9.1",
        details=[
            "pom.xml intentionally pins spring-boot-starter-parent 2.7.5 (EOL) and "
            "jjwt 0.9.1, both with known CVEs.",
            "Fix: run `mvn versions:display-dependency-updates` or an SCA tool (OWASP "
            "Dependency-Check/Snyk) and upgrade to current supported versions.",
        ],
    ),
    dict(
        label="owasp-a07",
        priority="High",
        summary="[A07] Identification & Authentication Failures - no lockout, weak defaults, non-expiring tokens",
        details=[
            "No account lockout or rate limiting on /login - brute-forceable.",
            "Seed credentials are weak (admin/admin) and JWTs never expire (JwtUtil, "
            "no setExpiration call).",
            "Fix: add lockout/rate limiting (e.g. Spring Security + bucket4j), enforce "
            "a strong password policy, add a short JWT exp with refresh.",
        ],
    ),
    dict(
        label="owasp-a08",
        priority="Medium",
        summary="[A08] Software & Data Integrity Failures - unvalidated XML import",
        details=[
            "POST /profile/import trusts client-supplied XML structure/content with "
            "no schema validation or integrity check, compounding the A05 XXE issue.",
            "Fix: validate against a strict schema, reject DOCTYPE entirely, and treat "
            "any imported profile data as untrusted input end-to-end.",
        ],
    ),
    dict(
        label="owasp-a09",
        priority="Medium",
        summary="[A09] Security Logging & Monitoring Failures - no audit trail on admin actions",
        details=[
            "AdminController never logs failed 'auth' attempts (wrong key) or "
            "successful admin data dumps - confirmed no distinguishing log output "
            "when hitting /admin/users with and without the correct key.",
            "Fix: log every admin access attempt (success/failure) with actor, "
            "endpoint, and outcome; alert on repeated failures.",
        ],
    ),
    dict(
        label="owasp-a10",
        priority="Highest",
        summary="[A10] SSRF - /currency/rate fetches any server-supplied URL",
        details=[
            "GET /currency/rate?source=<url> fetches whatever URL is supplied with "
            "no allow-list and no blocking of internal/private ranges - confirmed by "
            "pointing it at the app's own /actuator/env and getting the env dump back.",
            "Fix: allow-list only known-good currency-provider hosts, block "
            "RFC1918/link-local/metadata ranges, and disable redirects on the outbound "
            "connection.",
        ],
    ),
]


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
        return e.code, {"raw": body}


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true", help="Preview payloads, no network calls")
    group.add_argument("--apply", action="store_true", help="Actually create the issues in Jira")
    args = parser.parse_args()

    env = {**os.environ, **load_env(ENV_PATH)}
    base_url = env.get("JIRA_BASE_URL", "").rstrip("/")
    email = env.get("JIRA_EMAIL", "")
    token = env.get("JIRA_API_TOKEN", "")
    project_key = env.get("JIRA_PROJECT_KEY", "")
    issue_type = env.get("JIRA_ISSUE_TYPE", "Bug")

    missing = [k for k, v in {
        "JIRA_BASE_URL": base_url, "JIRA_EMAIL": email,
        "JIRA_API_TOKEN": token, "JIRA_PROJECT_KEY": project_key,
    }.items() if not v]
    if args.apply and missing:
        print(f"Missing required .env values: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    auth_header = base64.b64encode(f"{email}:{token}".encode()).decode() if args.apply else ""

    print(f"{'DRY RUN' if args.dry_run else 'CREATING'} {len(FINDINGS)} issues "
          f"in project {project_key or '<unset>'} at {base_url or '<unset>'}\n")

    for finding in FINDINGS:
        fields = {
            "project": {"key": project_key},
            "summary": finding["summary"],
            "issuetype": {"name": issue_type},
            "labels": [finding["label"], "vulnbank-owasp-lab"],
            "description": adf(*finding["details"]),
        }
        if finding.get("priority"):
            fields["priority"] = {"name": finding["priority"]}

        if args.dry_run:
            print(f"--- {finding['summary']} ---")
            print(f"  label: {finding['label']}  priority: {finding.get('priority')}")
            for d in finding["details"]:
                print(f"    - {d}")
            print()
        else:
            status, resp = jira_request(base_url, auth_header, "POST", "/rest/api/3/issue",
                                         {"fields": fields})
            if status == 201:
                print(f"Created {resp['key']}: {finding['summary']}")
            else:
                print(f"FAILED ({status}) for '{finding['summary']}': {resp}", file=sys.stderr)


if __name__ == "__main__":
    main()
