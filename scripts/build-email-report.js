#!/usr/bin/env node
// Builds a dashboard-style HTML email summarizing SCA findings for the
// current Jenkins build. Table-based layout for email-client compatibility
// (no flexbox/grid - Outlook and friends don't render those reliably).
const fs = require('fs');

const [, , dcPath, snykPath, outPath, buildUrl, buildNumber, buildResult] = process.argv;

function readJsonSafe(path) {
  try {
    return JSON.parse(fs.readFileSync(path, 'utf8'));
  } catch (e) {
    return null;
  }
}

const SEV_COLORS = {
  critical: '#c0392b',
  high: '#e67e22',
  medium: '#d4ac0d',
  low: '#7f8c8d'
};

function dcFindings(dc) {
  if (!dc || !dc.dependencies) return [];
  const out = [];
  dc.dependencies.forEach(dep => {
    (dep.vulnerabilities || []).forEach(v => {
      let sev = (v.severity || '').toLowerCase();
      const score = v.cvssv3 ? v.cvssv3.baseScore : (v.cvssv2 ? v.cvssv2.score : null);
      if (!['critical', 'high', 'medium', 'low'].includes(sev)) {
        sev = score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
      }
      out.push({ pkg: dep.fileName, id: v.name, score, sev });
    });
  });
  return out;
}

function snykFindings(snyk) {
  if (!snyk || !snyk.vulnerabilities) return [];
  const seen = new Set();
  const out = [];
  snyk.vulnerabilities.forEach(v => {
    const cve = v.identifiers && v.identifiers.CVE ? v.identifiers.CVE[0] : v.id;
    const key = v.packageName + '@' + v.version + '|' + cve;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ pkg: `${v.packageName}@${v.version}`, id: cve, score: v.cvssScore, sev: v.severity });
  });
  return out;
}

function countBySeverity(list) {
  const c = { critical: 0, high: 0, medium: 0, low: 0 };
  list.forEach(v => { if (c[v.sev] !== undefined) c[v.sev]++; });
  return c;
}

const dc = readJsonSafe(dcPath);
const snyk = readJsonSafe(snykPath);
const dcAll = dcFindings(dc);
const snykAll = snykFindings(snyk);
const dcCounts = countBySeverity(dcAll);
const snykCounts = countBySeverity(snykAll);
const totals = {
  critical: dcCounts.critical + snykCounts.critical,
  high: dcCounts.high + snykCounts.high,
  medium: dcCounts.medium + snykCounts.medium,
  low: dcCounts.low + snykCounts.low
};
const grandTotal = totals.critical + totals.high + totals.medium + totals.low;
const dcCritList = dcAll.filter(v => v.sev === 'critical');
const snykCritList = snykAll.filter(v => v.sev === 'critical');

function statCard(label, count, color) {
  return `
  <td width="25%" style="padding:4px;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid #e6e9ee;border-radius:8px;">
      <tr><td style="padding:16px 8px;text-align:center;">
        <div style="font-size:28px;font-weight:700;color:${color};line-height:1;">${count}</div>
        <div style="font-size:11px;letter-spacing:.05em;color:#6b7280;text-transform:uppercase;margin-top:6px;">${label}</div>
      </td></tr>
    </table>
  </td>`;
}

function severityBar(t) {
  const total = Math.max(grandTotal, 1);
  const segs = ['critical', 'high', 'medium', 'low']
    .filter(s => t[s] > 0)
    .map(s => `<td width="${Math.round((t[s] / total) * 100)}%" style="background:${SEV_COLORS[s]};height:10px;font-size:0;line-height:0;">&nbsp;</td>`)
    .join('');
  return `<table width="100%" cellpadding="0" cellspacing="0" style="border-radius:5px;overflow:hidden;"><tr>${segs || '<td style="background:#e6e9ee;height:10px;">&nbsp;</td>'}</tr></table>`;
}

function sevBadge(sev) {
  const c = SEV_COLORS[sev] || '#7f8c8d';
  return `<span style="display:inline-block;padding:2px 8px;border-radius:10px;background:${c}1a;color:${c};font-size:11px;font-weight:700;text-transform:uppercase;">${sev || 'n/a'}</span>`;
}

function findingsTable(list) {
  if (!list.length) {
    return `<table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e6e9ee;border-radius:8px;"><tr><td style="padding:16px;color:#6b7280;font-size:13px;text-align:center;">No critical findings</td></tr></table>`;
  }
  const rows = list.map((v, i) => `
    <tr style="background:${i % 2 === 0 ? '#ffffff' : '#f8f9fb'};">
      <td style="padding:8px 12px;font-family:Consolas,monospace;font-size:12px;color:#1f2937;border-bottom:1px solid #eef0f3;">${v.pkg}</td>
      <td style="padding:8px 12px;font-family:Consolas,monospace;font-size:12px;color:#1f2937;border-bottom:1px solid #eef0f3;">${v.id}</td>
      <td style="padding:8px 12px;text-align:center;font-weight:700;color:${SEV_COLORS.critical};border-bottom:1px solid #eef0f3;">${v.score ?? '-'}</td>
    </tr>`).join('');
  return `
  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e6e9ee;border-radius:8px;overflow:hidden;border-collapse:collapse;">
    <tr style="background:#f1f3f6;">
      <th align="left" style="padding:8px 12px;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#6b7280;">Package</th>
      <th align="left" style="padding:8px 12px;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#6b7280;">CVE / ID</th>
      <th style="padding:8px 12px;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#6b7280;">CVSS</th>
    </tr>
    ${rows}
  </table>`;
}

function sourceCard(name, counts, total, logo) {
  return `
  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e6e9ee;border-radius:8px;margin-bottom:12px;">
    <tr>
      <td style="padding:14px 16px;">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td style="font-size:13px;font-weight:700;color:#111827;">${logo} ${name}</td>
            <td align="right" style="font-size:13px;color:#6b7280;">${total} findings</td>
          </tr>
        </table>
        <div style="margin-top:8px;">${severityBar(counts)}</div>
        <table cellpadding="0" cellspacing="0" style="margin-top:8px;">
          <tr>
            <td style="font-size:11px;color:${SEV_COLORS.critical};font-weight:700;padding-right:14px;">${counts.critical} Critical</td>
            <td style="font-size:11px;color:${SEV_COLORS.high};font-weight:700;padding-right:14px;">${counts.high} High</td>
            <td style="font-size:11px;color:${SEV_COLORS.medium};font-weight:700;padding-right:14px;">${counts.medium} Medium</td>
            <td style="font-size:11px;color:${SEV_COLORS.low};font-weight:700;">${counts.low} Low</td>
          </tr>
        </table>
      </td>
    </tr>
  </table>`;
}

const resultColor = buildResult === 'SUCCESS' ? '#16a34a' : (buildResult === 'UNSTABLE' ? '#d97706' : '#dc2626');
const resultBg = buildResult === 'SUCCESS' ? '#dcfce7' : (buildResult === 'UNSTABLE' ? '#fef3c7' : '#fee2e2');
const timestamp = new Date().toUTCString();

const html = `
<div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:700px;margin:0 auto;background:#f5f6f8;padding:24px 16px;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td>

      <!-- Header -->
      <table width="100%" cellpadding="0" cellspacing="0" style="background:linear-gradient(135deg,#0b1f3a,#13294b);border-radius:12px 12px 0 0;">
        <tr>
          <td style="padding:24px 28px;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td>
                  <div style="font-size:12px;letter-spacing:.12em;color:#7fa8ff;text-transform:uppercase;font-weight:700;">Application Security</div>
                  <div style="font-size:22px;color:#ffffff;font-weight:700;margin-top:4px;">VulnBank &mdash; SCA Risk Report</div>
                </td>
                <td align="right" style="vertical-align:top;">
                  <span style="display:inline-block;padding:6px 14px;border-radius:20px;background:${resultBg};color:${resultColor};font-size:12px;font-weight:700;">${buildResult}</span>
                </td>
              </tr>
            </table>
            <div style="color:#9fb3d1;font-size:12px;margin-top:10px;">Build #${buildNumber} &middot; ${timestamp}</div>
          </td>
        </tr>
      </table>

      <!-- Body -->
      <table width="100%" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid #e6e9ee;border-top:none;border-radius:0 0 12px 12px;">
        <tr><td style="padding:24px 28px;">

          <!-- Stat cards -->
          <table width="100%" cellpadding="0" cellspacing="0"><tr>
            ${statCard('Critical', totals.critical, SEV_COLORS.critical)}
            ${statCard('High', totals.high, SEV_COLORS.high)}
            ${statCard('Medium', totals.medium, SEV_COLORS.medium)}
            ${statCard('Low', totals.low, SEV_COLORS.low)}
          </tr></table>

          <div style="margin:20px 0 24px;">
            <div style="font-size:12px;color:#6b7280;margin-bottom:6px;">Overall severity distribution &middot; ${grandTotal} total findings</div>
            ${severityBar(totals)}
          </div>

          <!-- Per-source breakdown -->
          <div style="font-size:13px;font-weight:700;color:#111827;text-transform:uppercase;letter-spacing:.04em;margin-bottom:10px;">Findings by source</div>
          ${sourceCard('OWASP Dependency-Check', dcCounts, dcAll.length, '&#128737;')}
          ${sourceCard('Snyk', snykCounts, snykAll.length, '&#9889;')}

          <!-- Critical tables -->
          <div style="font-size:13px;font-weight:700;color:#111827;text-transform:uppercase;letter-spacing:.04em;margin:20px 0 10px;">Critical &mdash; Dependency-Check</div>
          ${findingsTable(dcCritList)}

          <div style="font-size:13px;font-weight:700;color:#111827;text-transform:uppercase;letter-spacing:.04em;margin:20px 0 10px;">Critical &mdash; Snyk</div>
          ${findingsTable(snykCritList)}

          <!-- CTAs -->
          <table cellpadding="0" cellspacing="0" style="margin-top:24px;">
            <tr>
              <td style="padding-right:10px;">
                <a href="${buildUrl}" style="display:inline-block;background:#13294b;color:#ffffff;text-decoration:none;padding:11px 18px;border-radius:6px;font-size:13px;font-weight:600;">View Jenkins Build &rarr;</a>
              </td>
              <td>
                <a href="https://app.snyk.io" style="display:inline-block;background:#4c4cff;color:#ffffff;text-decoration:none;padding:11px 18px;border-radius:6px;font-size:13px;font-weight:600;">Open Snyk Dashboard &rarr;</a>
              </td>
            </tr>
          </table>

        </td></tr>
      </table>

      <div style="text-align:center;color:#9ca3af;font-size:11px;margin-top:16px;">
        Automated SCA scan &middot; VulnBank Jenkins Pipeline &middot; Dependency-Check + Snyk
      </div>

    </td></tr>
  </table>
</div>
`;

fs.writeFileSync(outPath, html);
console.log(`Email body written to ${outPath} (totals: C${totals.critical} H${totals.high} M${totals.medium} L${totals.low})`);
