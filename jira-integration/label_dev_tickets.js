#!/usr/bin/env node
// Adds dependency-classification labels (direct/transitive, scope, via-<parent>)
// onto the 27 existing DEV-board issues. Matches grouped_tickets.json entries
// to DEV-1..DEV-27 by array order (confirmed identical order against Jira).
const https = require('https');
const fs = require('fs');
const path = require('path');

const HERE = __dirname;
const env = {};
fs.readFileSync(path.join(HERE, '.env'), 'utf8').split('\n').forEach(l => {
  if (!l.trim() || l.trim().startsWith('#') || !l.includes('=')) return;
  const [k, ...rest] = l.split('=');
  env[k.trim()] = rest.join('=').trim();
});

const DEV_PROJECT_KEY = 'DEV';
const auth = Buffer.from(`${env.JIRA_EMAIL}:${env.JIRA_API_TOKEN}`).toString('base64');
const baseUrl = new URL(env.JIRA_BASE_URL);

function jiraRequest(method, apiPath, payload) {
  return new Promise((resolve, reject) => {
    const data = payload ? JSON.stringify(payload) : null;
    const req = https.request({
      hostname: baseUrl.hostname,
      path: apiPath,
      method,
      headers: {
        'Authorization': `Basic ${auth}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      }
    }, res => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

const NEW_LABEL_PREFIXES = ['direct-dependency', 'transitive-dependency', 'scope-', 'via-'];

async function main() {
  const apply = process.argv.includes('--apply');
  const tickets = JSON.parse(fs.readFileSync(path.join(HERE, 'grouped_tickets.json'), 'utf8'));

  // Confirm order against Jira before touching anything.
  const jql = encodeURIComponent(`project = ${DEV_PROJECT_KEY} ORDER BY created ASC`);
  const { status, body } = await jiraRequest('GET', `/rest/api/3/search/jql?jql=${jql}&fields=summary,labels&maxResults=100`);
  if (status !== 200) {
    console.error('Failed to list DEV issues:', status, body.slice(0, 300));
    process.exit(1);
  }
  const issues = JSON.parse(body).issues;
  if (issues.length !== tickets.length) {
    console.error(`Mismatch: ${issues.length} Jira issues vs ${tickets.length} local tickets - aborting.`);
    process.exit(1);
  }

  for (let i = 0; i < tickets.length; i++) {
    const issue = issues[i];
    const ticket = tickets[i];
    if (!issue.fields.summary.includes(ticket.Component)) {
      console.error(`Order mismatch at index ${i}: Jira="${issue.fields.summary}" vs local Component="${ticket.Component}" - aborting.`);
      process.exit(1);
    }
    const newLabels = ticket.Labels.split(',').map(s => s.trim())
      .filter(l => NEW_LABEL_PREFIXES.some(p => l.startsWith(p)));
    const existing = new Set(issue.fields.labels || []);
    const toAdd = newLabels.filter(l => !existing.has(l));

    if (!toAdd.length) {
      console.log(`${issue.key} (${ticket.Component}): already up to date`);
      continue;
    }

    console.log(`${issue.key} (${ticket.Component}): ${apply ? 'adding' : 'would add'} [${toAdd.join(', ')}]`);
    if (apply) {
      const update = { update: { labels: toAdd.map(l => ({ add: l })) } };
      const res = await jiraRequest('PUT', `/rest/api/3/issue/${issue.key}`, update);
      if (res.status !== 204) {
        console.error(`  FAILED (${res.status}): ${res.body.slice(0, 300)}`);
      }
    }
  }
  console.log(apply ? '\nDone.' : '\nDry run only - pass --apply to actually update Jira.');
}

main().catch(e => { console.error(e); process.exit(1); });
