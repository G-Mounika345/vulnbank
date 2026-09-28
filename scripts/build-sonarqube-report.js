#!/usr/bin/env node
// Builds an industry-standard-style standalone HTML SAST report from
// SonarQube's issues + rules API responses (already fetched to JSON files).
// Usage: node build-sonarqube-report.js <issues.json> <rules.json> <measures.json> <projectKey> <sonarUrl> <out.html>
const fs = require('fs');

const [, , issuesPath, rulesPath, measuresPath, projectKey, sonarUrl, outPath] = process.argv;
const issuesData = JSON.parse(fs.readFileSync(issuesPath, 'utf8'));
const rulesArr = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
const measuresData = JSON.parse(fs.readFileSync(measuresPath, 'utf8'));

const ruleNames = {};
rulesArr.forEach(r => { ruleNames[r.rule.key] = r.rule.name; });

const SEV_MAP = { BLOCKER: 'Critical', CRITICAL: 'Critical', MAJOR: 'High', MINOR: 'Medium', INFO: 'Low' };
const SEV_COLOR = { Critical: '#7c1d1d', High: '#c0392b', Medium: '#d97706', Low: '#6b7280' };
const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };

function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

const findings = issuesData.issues.map(i => ({
  sev: SEV_MAP[i.severity] || 'Low',
  type: i.type,
  rule: i.rule,
  ruleName: ruleNames[i.rule] || i.rule,
  file: i.component.split(':').slice(1).join(':'),
  line: i.line || '-',
  message: i.message,
  effort: i.debt || i.effort || 'n/a',
  tags: i.tags || []
})).sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);

const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
findings.forEach(f => counts[f.sev]++);
const total = findings.length;

const measures = {};
(measuresData.component.measures || []).forEach(m => { measures[m.metric] = m.value; });

function statCard(label, count, color) {
  return `<div class="stat"><div class="stat-num" style="color:${color}">${count}</div><div class="stat-label">${label}</div></div>`;
}

function typeBadge(type) {
  const map = { VULNERABILITY: '#7c1d1d', BUG: '#c0392b', CODE_SMELL: '#6b7280', SECURITY_HOTSPOT: '#d97706' };
  return `<span class="type-badge" style="background:${(map[type] || '#6b7280')}1a;color:${map[type] || '#6b7280'}">${type.replace('_', ' ')}</span>`;
}

function findingRow(f, idx) {
  return `
  <div class="finding" id="f${idx}">
    <div class="finding-head">
      <span class="badge" style="background:${SEV_COLOR[f.sev]}1a;color:${SEV_COLOR[f.sev]}">${f.sev}</span>
      ${typeBadge(f.type)}
      <span class="finding-title">${esc(f.ruleName)}</span>
      <span class="finding-loc">${esc(f.file)}:${f.line}</span>
    </div>
    <div class="finding-body">
      <p class="msg">${esc(f.message)}</p>
      <div class="meta-row">
        <span class="tag muted">Rule: ${esc(f.rule)}</span>
        <span class="tag muted">Estimated effort: ${esc(f.effort)}</span>
        ${f.tags.map(t => `<span class="tag">${esc(t)}</span>`).join('')}
      </div>
    </div>
  </div>`;
}

const timestamp = new Date().toUTCString();

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnBank - SAST Report (SonarQube)</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system,Segoe UI,Roboto,Arial,sans-serif; background:#f5f6f8; color:#1f2937; margin:0; padding:0; }
  .wrap { max-width: 960px; margin: 0 auto; padding: 32px 20px; }
  .header { background:linear-gradient(135deg,#0b1f3a,#13294b); color:#fff; padding:28px 32px; border-radius:12px 12px 0 0; }
  .header .kicker { font-size:12px; letter-spacing:.12em; text-transform:uppercase; color:#7fa8ff; font-weight:700; }
  .header h1 { margin:6px 0 0; font-size:24px; }
  .header .sub { color:#9fb3d1; font-size:13px; margin-top:8px; }
  .header a { color:#7fa8ff; }
  .panel { background:#fff; border:1px solid #e6e9ee; border-top:none; border-radius:0 0 12px 12px; padding:28px 32px; }
  .stats { display:flex; gap:12px; margin-bottom:16px; }
  .stat { flex:1; border:1px solid #e6e9ee; border-radius:8px; padding:18px; text-align:center; }
  .stat-num { font-size:32px; font-weight:700; line-height:1; }
  .stat-label { font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:#6b7280; margin-top:6px; }
  .metrics { display:flex; gap:12px; margin-bottom:24px; font-size:12px; color:#374151; }
  .metrics span { background:#f1f3f6; padding:6px 12px; border-radius:6px; }
  h2.section { font-size:13px; text-transform:uppercase; letter-spacing:.05em; color:#111827; border-bottom:2px solid #13294b; padding-bottom:6px; margin:28px 0 14px; }
  .summary-table { width:100%; border-collapse:collapse; font-size:13px; margin-bottom:8px; }
  .summary-table th { text-align:left; background:#f1f3f6; padding:8px 10px; font-size:11px; text-transform:uppercase; color:#6b7280; }
  .summary-table td { padding:8px 10px; border-bottom:1px solid #eef0f3; }
  .summary-table a { color:#13294b; text-decoration:none; font-weight:600; }
  .finding { border:1px solid #e6e9ee; border-radius:8px; margin-bottom:14px; overflow:hidden; }
  .finding-head { display:flex; align-items:center; gap:8px; padding:12px 16px; background:#f8f9fb; border-bottom:1px solid #eef0f3; flex-wrap:wrap; }
  .badge, .type-badge { padding:3px 10px; border-radius:10px; font-size:11px; font-weight:700; text-transform:uppercase; }
  .finding-title { font-weight:700; font-size:14px; }
  .finding-loc { margin-left:auto; font-family:Consolas,monospace; font-size:12px; color:#6b7280; }
  .finding-body { padding:14px 16px; }
  .msg { font-size:13px; margin:0 0 10px; color:#374151; }
  .tag { display:inline-block; background:#eef2ff; color:#3730a3; font-size:11px; padding:3px 8px; border-radius:4px; margin:0 6px 6px 0; }
  .tag.muted { background:#f3f4f6; color:#6b7280; }
  .footer { text-align:center; color:#9ca3af; font-size:11px; margin-top:20px; }
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="kicker">Static Application Security Testing</div>
    <h1>VulnBank &mdash; SAST Report (SonarQube)</h1>
    <div class="sub">Generated ${timestamp} &middot; Project: ${esc(projectKey)} &middot; <a href="${esc(sonarUrl)}/dashboard?id=${esc(projectKey)}">View live dashboard &rarr;</a></div>
  </div>
  <div class="panel">
    <div class="stats">
      ${statCard('Critical', counts.Critical, SEV_COLOR.Critical)}
      ${statCard('High', counts.High, SEV_COLOR.High)}
      ${statCard('Medium', counts.Medium, SEV_COLOR.Medium)}
      ${statCard('Low', counts.Low, SEV_COLOR.Low)}
      <div class="stat"><div class="stat-num">${total}</div><div class="stat-label">Total Issues</div></div>
    </div>
    <div class="metrics">
      <span>Lines of code: <b>${esc(measures.ncloc || '?')}</b></span>
      <span>Vulnerabilities: <b>${esc(measures.vulnerabilities || '0')}</b></span>
      <span>Bugs: <b>${esc(measures.bugs || '0')}</b></span>
      <span>Code Smells: <b>${esc(measures.code_smells || '0')}</b></span>
      <span>Security Hotspots: <b>${esc(measures.security_hotspots || '0')}</b></span>
    </div>

    <h2 class="section">Executive Summary</h2>
    <table class="summary-table">
      <tr><th>Severity</th><th>Type</th><th>Rule</th><th>Location</th></tr>
      ${findings.map((f, i) => `<tr><td><span style="color:${SEV_COLOR[f.sev]};font-weight:700;">${f.sev}</span></td><td>${f.type.replace('_',' ')}</td><td><a href="#f${i}">${esc(f.ruleName)}</a></td><td style="font-family:Consolas,monospace;font-size:12px;">${esc(f.file)}:${f.line}</td></tr>`).join('')}
    </table>

    <h2 class="section">Detailed Findings</h2>
    ${findings.map((f, i) => findingRow(f, i)).join('')}
  </div>
  <div class="footer">Automated SAST scan &middot; SonarQube Community Edition &middot; VulnBank</div>
</div>
</body>
</html>`;

fs.writeFileSync(outPath, html);
console.log(`SonarQube HTML report written to ${outPath} (${total} issues: ${counts.Critical} Critical, ${counts.High} High, ${counts.Medium} Medium, ${counts.Low} Low)`);
