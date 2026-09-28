#!/usr/bin/env node
// Fetches issues + rule metadata + measures for a SonarQube project via its
// REST API and writes them to JSON files, ready for build-sonarqube-report.js.
// Usage: node fetch-sonarqube-data.js <hostUrl> <token> <projectKey> <outDir>
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

const [, , hostUrl, token, projectKey, outDir] = process.argv;
const client = hostUrl.startsWith('https') ? https : http;
const auth = Buffer.from(`${token}:`).toString('base64');

function get(apiPath) {
  return new Promise((resolve, reject) => {
    const url = new URL(hostUrl + apiPath);
    const req = client.request(url, {
      headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
    }, res => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function main() {
  fs.mkdirSync(outDir, { recursive: true });

  const issuesRes = await get(`/api/issues/search?componentKeys=${encodeURIComponent(projectKey)}&ps=100`);
  if (issuesRes.status !== 200) {
    console.error('Failed to fetch issues:', issuesRes.status, issuesRes.body.slice(0, 300));
    process.exit(1);
  }
  fs.writeFileSync(path.join(outDir, 'sonarqube-issues-raw.json'), issuesRes.body);
  const issuesJson = JSON.parse(issuesRes.body);

  const ruleKeys = [...new Set(issuesJson.issues.map(i => i.rule))];
  const rules = [];
  for (const key of ruleKeys) {
    const r = await get(`/api/rules/show?key=${encodeURIComponent(key)}`);
    if (r.status === 200) rules.push(JSON.parse(r.body));
  }
  fs.writeFileSync(path.join(outDir, 'sonarqube-rules-raw.json'), JSON.stringify(rules));

  const measuresRes = await get(`/api/measures/component?component=${encodeURIComponent(projectKey)}&metricKeys=bugs,vulnerabilities,code_smells,security_hotspots,ncloc`);
  fs.writeFileSync(path.join(outDir, 'sonarqube-measures-raw.json'), measuresRes.body);

  console.log(`Fetched ${issuesJson.issues.length} issues, ${rules.length} rule definitions for '${projectKey}'.`);
}

main().catch(e => { console.error(e); process.exit(1); });
