#!/usr/bin/env node
// Builds an HTML email body summarizing critical findings from the two SCA
// reports for the current Jenkins build. Reads paths from argv, writes HTML
// to stdout-adjacent file so the Jenkinsfile can attach it via readFile().
const fs = require('fs');

const [, , dcPath, snykPath, outPath, buildUrl, buildNumber, buildResult] = process.argv;

function readJsonSafe(path) {
  try {
    return JSON.parse(fs.readFileSync(path, 'utf8'));
  } catch (e) {
    return null;
  }
}

function dcCriticals(dc) {
  if (!dc || !dc.dependencies) return [];
  const out = [];
  dc.dependencies.forEach(dep => {
    (dep.vulnerabilities || []).forEach(v => {
      const sev = (v.severity || '').toUpperCase();
      const score = v.cvssv3 ? v.cvssv3.baseScore : (v.cvssv2 ? v.cvssv2.score : null);
      if (sev === 'CRITICAL' || (score && score >= 9.0)) {
        out.push({ pkg: dep.fileName, id: v.name, score });
      }
    });
  });
  return out;
}

function snykCriticals(snyk) {
  if (!snyk || !snyk.vulnerabilities) return [];
  const seen = new Set();
  const out = [];
  snyk.vulnerabilities.forEach(v => {
    if (v.severity !== 'critical') return;
    const cve = v.identifiers && v.identifiers.CVE ? v.identifiers.CVE[0] : v.id;
    const key = v.packageName + '@' + v.version + '|' + cve;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ pkg: `${v.packageName}@${v.version}`, id: cve, score: v.cvssScore });
  });
  return out;
}

const dc = readJsonSafe(dcPath);
const snyk = readJsonSafe(snykPath);
const dcCrit = dcCriticals(dc);
const snykCrit = snykCriticals(snyk);

function rows(list) {
  if (!list.length) return '<tr><td colspan="3" style="padding:8px;color:#666;">None found</td></tr>';
  return list.map(v => `
    <tr>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;font-family:monospace;">${v.pkg}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;font-family:monospace;">${v.id}</td>
      <td style="padding:6px 10px;border-bottom:1px solid #eee;text-align:center;font-weight:bold;color:#c0392b;">${v.score ?? '-'}</td>
    </tr>`).join('');
}

const resultColor = buildResult === 'SUCCESS' ? '#2e7d32' : (buildResult === 'UNSTABLE' ? '#e6a700' : '#c0392b');

const html = `
<div style="font-family:Segoe UI,Arial,sans-serif;max-width:680px;margin:0 auto;color:#222;">
  <div style="background:#0b2545;padding:20px 24px;border-radius:8px 8px 0 0;">
    <h1 style="color:#fff;margin:0;font-size:20px;">VulnBank &mdash; SCA Scan Report</h1>
    <p style="color:#b8c7e0;margin:6px 0 0;font-size:13px;">Build #${buildNumber} &middot; Result:
      <span style="color:${resultColor};font-weight:bold;">${buildResult}</span>
    </p>
  </div>
  <div style="border:1px solid #e0e0e0;border-top:none;padding:20px 24px;border-radius:0 0 8px 8px;">
    <p style="font-size:14px;">Dependency-Check found <b>${dcCrit.length}</b> critical CVEs.
       Snyk found <b>${snykCrit.length}</b> critical CVEs.</p>

    <h3 style="font-size:15px;border-bottom:2px solid #0b2545;padding-bottom:4px;">Dependency-Check &mdash; Critical</h3>
    <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:20px;">
      <tr style="background:#f4f6f9;"><th style="padding:6px 10px;text-align:left;">Package</th><th style="padding:6px 10px;text-align:left;">CVE</th><th style="padding:6px 10px;">CVSS</th></tr>
      ${rows(dcCrit)}
    </table>

    <h3 style="font-size:15px;border-bottom:2px solid #0b2545;padding-bottom:4px;">Snyk &mdash; Critical</h3>
    <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:20px;">
      <tr style="background:#f4f6f9;"><th style="padding:6px 10px;text-align:left;">Package</th><th style="padding:6px 10px;text-align:left;">CVE</th><th style="padding:6px 10px;">CVSS</th></tr>
      ${rows(snykCrit)}
    </table>

    <div style="margin-top:20px;">
      <a href="${buildUrl}" style="display:inline-block;background:#0b2545;color:#fff;text-decoration:none;padding:10px 16px;border-radius:6px;font-size:13px;margin-right:10px;">View Jenkins Build</a>
      <a href="https://app.snyk.io" style="display:inline-block;background:#4c4cff;color:#fff;text-decoration:none;padding:10px 16px;border-radius:6px;font-size:13px;">Open Snyk Dashboard</a>
    </div>
  </div>
</div>
`;

fs.writeFileSync(outPath, html);
console.log(`Email body written to ${outPath} (${dcCrit.length} DC criticals, ${snykCrit.length} Snyk criticals)`);
