#!/usr/bin/env node
// Builds an industry-standard-style standalone HTML SAST report from a
// Semgrep JSON results file. Usage:
//   node build-semgrep-report.js <semgrep-results.json> <source-root> <out.html>
const fs = require('fs');
const path = require('path');

const [, , resultsPath, srcRoot, outPath] = process.argv;
const data = JSON.parse(fs.readFileSync(resultsPath, 'utf8'));
const results = data.results || [];

const SEV_MAP = { ERROR: 'High', WARNING: 'Medium', INFO: 'Low' };
const SEV_COLOR = { High: '#c0392b', Medium: '#d97706', Low: '#6b7280' };
const SEV_ORDER = { High: 0, Medium: 1, Low: 2 };

function snippet(filePath, startLine, endLine) {
  try {
    const full = path.join(srcRoot, filePath);
    const lines = fs.readFileSync(full, 'utf8').split('\n');
    const from = Math.max(1, startLine - 2);
    const to = Math.min(lines.length, endLine + 2);
    const out = [];
    for (let i = from; i <= to; i++) {
      const marker = (i >= startLine && i <= endLine) ? '>' : ' ';
      out.push(`${marker} ${String(i).padStart(4)} | ${lines[i - 1] ?? ''}`);
    }
    return out.join('\n');
  } catch (e) {
    return '(source unavailable)';
  }
}

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

const findings = results.map(r => {
  const sev = SEV_MAP[r.extra.severity] || 'Low';
  const meta = r.extra.metadata || {};
  return {
    id: r.check_id,
    sev,
    file: r.path,
    startLine: r.start.line,
    endLine: r.end.line,
    message: r.extra.message,
    cwe: (meta.cwe || []).join('; '),
    owasp: (meta.owasp || []).join(', '),
    vulnClass: (meta.vulnerability_class || []).join(', '),
    confidence: meta.confidence || 'n/a',
    likelihood: meta.likelihood || 'n/a',
    impact: meta.impact || 'n/a',
    references: meta.references || [],
    code: snippet(r.path, r.start.line, r.end.line)
  };
}).sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);

const counts = { High: 0, Medium: 0, Low: 0 };
findings.forEach(f => counts[f.sev]++);
const total = findings.length;

function statCard(label, count, color) {
  return `<div class="stat"><div class="stat-num" style="color:${color}">${count}</div><div class="stat-label">${label}</div></div>`;
}

function findingCard(f, idx) {
  return `
  <div class="finding" id="f${idx}">
    <div class="finding-head">
      <span class="badge" style="background:${SEV_COLOR[f.sev]}1a;color:${SEV_COLOR[f.sev]}">${f.sev}</span>
      <span class="finding-title">${esc(f.vulnClass || f.id)}</span>
      <span class="finding-loc">${esc(f.file)}:${f.startLine}</span>
    </div>
    <div class="finding-body">
      <p class="msg">${esc(f.message)}</p>
      <div class="meta-row">
        ${f.cwe ? `<span class="tag">${esc(f.cwe)}</span>` : ''}
        ${f.owasp ? `<span class="tag">${esc(f.owasp)}</span>` : ''}
        <span class="tag muted">Confidence: ${esc(f.confidence)}</span>
        <span class="tag muted">Likelihood: ${esc(f.likelihood)}</span>
        <span class="tag muted">Impact: ${esc(f.impact)}</span>
      </div>
      <pre class="code">${esc(f.code)}</pre>
      <div class="rule-id">Rule: <code>${esc(f.id)}</code></div>
      ${f.references.length ? `<div class="refs">Ref: ${f.references.map(r => `<a href="${esc(r)}">${esc(r)}</a>`).join(', ')}</div>` : ''}
    </div>
  </div>`;
}

const timestamp = new Date().toUTCString();

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnBank - SAST Report (Semgrep)</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system,Segoe UI,Roboto,Arial,sans-serif; background:#f5f6f8; color:#1f2937; margin:0; padding:0; }
  .wrap { max-width: 960px; margin: 0 auto; padding: 32px 20px; }
  .header { background:linear-gradient(135deg,#0b1f3a,#13294b); color:#fff; padding:28px 32px; border-radius:12px 12px 0 0; }
  .header .kicker { font-size:12px; letter-spacing:.12em; text-transform:uppercase; color:#7fa8ff; font-weight:700; }
  .header h1 { margin:6px 0 0; font-size:24px; }
  .header .sub { color:#9fb3d1; font-size:13px; margin-top:8px; }
  .panel { background:#fff; border:1px solid #e6e9ee; border-top:none; border-radius:0 0 12px 12px; padding:28px 32px; }
  .stats { display:flex; gap:12px; margin-bottom:24px; }
  .stat { flex:1; border:1px solid #e6e9ee; border-radius:8px; padding:18px; text-align:center; }
  .stat-num { font-size:32px; font-weight:700; line-height:1; }
  .stat-label { font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:#6b7280; margin-top:6px; }
  h2.section { font-size:13px; text-transform:uppercase; letter-spacing:.05em; color:#111827; border-bottom:2px solid #13294b; padding-bottom:6px; margin:28px 0 14px; }
  .summary-table { width:100%; border-collapse:collapse; font-size:13px; margin-bottom:8px; }
  .summary-table th { text-align:left; background:#f1f3f6; padding:8px 10px; font-size:11px; text-transform:uppercase; color:#6b7280; }
  .summary-table td { padding:8px 10px; border-bottom:1px solid #eef0f3; }
  .summary-table a { color:#13294b; text-decoration:none; font-weight:600; }
  .finding { border:1px solid #e6e9ee; border-radius:8px; margin-bottom:16px; overflow:hidden; }
  .finding-head { display:flex; align-items:center; gap:10px; padding:12px 16px; background:#f8f9fb; border-bottom:1px solid #eef0f3; flex-wrap:wrap; }
  .badge { padding:3px 10px; border-radius:10px; font-size:11px; font-weight:700; text-transform:uppercase; }
  .finding-title { font-weight:700; font-size:14px; }
  .finding-loc { margin-left:auto; font-family:Consolas,monospace; font-size:12px; color:#6b7280; }
  .finding-body { padding:16px; }
  .msg { font-size:13px; margin:0 0 12px; color:#374151; }
  .meta-row { margin-bottom:12px; }
  .tag { display:inline-block; background:#eef2ff; color:#3730a3; font-size:11px; padding:3px 8px; border-radius:4px; margin:0 6px 6px 0; }
  .tag.muted { background:#f3f4f6; color:#6b7280; }
  .code { background:#0d1117; color:#c9d1d9; font-family:Consolas,monospace; font-size:12px; padding:12px; border-radius:6px; overflow-x:auto; white-space:pre; }
  .rule-id { font-size:11px; color:#6b7280; margin-top:10px; }
  .rule-id code { background:#f3f4f6; padding:1px 6px; border-radius:4px; }
  .refs { font-size:11px; margin-top:6px; }
  .refs a { color:#4c4cff; }
  .footer { text-align:center; color:#9ca3af; font-size:11px; margin-top:20px; }
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="kicker">Static Application Security Testing</div>
    <h1>VulnBank &mdash; SAST Report (Semgrep)</h1>
    <div class="sub">Generated ${timestamp} &middot; Rulesets: owasp-top-ten, security-audit, java</div>
  </div>
  <div class="panel">
    <div class="stats">
      ${statCard('High', counts.High, SEV_COLOR.High)}
      ${statCard('Medium', counts.Medium, SEV_COLOR.Medium)}
      ${statCard('Low', counts.Low, SEV_COLOR.Low)}
      <div class="stat"><div class="stat-num">${total}</div><div class="stat-label">Total Findings</div></div>
    </div>

    <h2 class="section">Executive Summary</h2>
    <table class="summary-table">
      <tr><th>Severity</th><th>Vulnerability Class</th><th>Location</th></tr>
      ${findings.map((f, i) => `<tr><td><span style="color:${SEV_COLOR[f.sev]};font-weight:700;">${f.sev}</span></td><td><a href="#f${i}">${esc(f.vulnClass || f.id)}</a></td><td style="font-family:Consolas,monospace;font-size:12px;">${esc(f.file)}:${f.startLine}</td></tr>`).join('')}
    </table>

    <h2 class="section">Detailed Findings</h2>
    ${findings.map((f, i) => findingCard(f, i)).join('')}
  </div>
  <div class="footer">Automated SAST scan &middot; Semgrep OSS &middot; VulnBank</div>
</div>
</body>
</html>`;

fs.writeFileSync(outPath, html);
console.log(`Semgrep HTML report written to ${outPath} (${total} findings: ${counts.High} High, ${counts.Medium} Medium, ${counts.Low} Low)`);
