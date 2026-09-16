# VulnBank -> Jira integration

Creates one Jira issue per OWASP Top 10:2021 finding from the VulnBank
security review (REST API v3, Jira Cloud). Pure stdlib Python — no `pip
install` needed.

## Setup

1. In Jira: create (or pick) a project. Note its **project key** (e.g. `VULNBANK`).
2. Generate an API token: https://id.atlassian.com/manage-profile/security/api-tokens
3. Copy the env template and fill it in:
   ```
   cp .env.example .env
   ```
   Edit `.env` with your `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`,
   `JIRA_PROJECT_KEY`. `.env` is gitignored — never commit it.

## Preview (no network calls, no Jira changes)

```
python create_jira_tickets.py --dry-run
```

## Create the tickets for real

```
python create_jira_tickets.py --apply
```

Prints the created issue key (e.g. `VULNBANK-1`) per finding, or the Jira
error body if a field doesn't match your project's scheme (most commonly:
`issuetype` name, or `priority` names — adjust `JIRA_ISSUE_TYPE` in `.env`
or edit the `priority` values in `create_jira_tickets.py` to match what
your project actually offers).

## What gets created

10 issues, one per OWASP category (A01–A10), each labeled `owasp-a0N` +
`vulnbank-owasp-lab`, with severity set via `priority`, and a description
listing the specific endpoint(s)/file(s), what was confirmed by actually
exercising the running app, and a suggested fix.

## Suggested Jira board/dashboard setup

- **Project type:** Team-managed Kanban (fixed backlog, no sprints needed).
- **Board columns:** To Do → In Progress → In Review → Done.
- **Grouping:** create an Epic "OWASP Top 10:2021 Remediation" and manually
  link these 10 issues under it (the script intentionally doesn't attempt
  parent-linking, since the field differs between team-managed and
  company-managed projects — link once in the UI after creation, or extend
  the script for your project type).
- **Dashboard gadgets** (Jira → Dashboards → Create):
  - *Filter Results*: open issues sorted by Priority.
  - *Pie Chart*: issue count grouped by `owasp-a0x` label — shows which
    category has the most open work.
  - *Two-Dimensional Filter Statistics*: Priority × Status — spot stalled
    criticals fast.
  - *Created vs. Resolved*: remediation burn-down over time.
