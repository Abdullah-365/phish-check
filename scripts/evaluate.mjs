#!/usr/bin/env node
/**
 * Measures the engine against labelled email corpora.
 *
 *   node scripts/evaluate.mjs --phish <dir> [--phish <dir>] --ham <dir> [--ham <dir>] [--out report.json]
 *
 * Every file in a directory is treated as one raw email. Corpora are untrusted data:
 * they are only read and parsed here, never executed or opened in another program.
 */
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { analyzeEmail } from "../packages/engine/src/index.ts";

const args = process.argv.slice(2);
const dirs = { phish: [], ham: [] };
let out = null;
let noProvider = false;
for (let i = 0; i < args.length; i++) {
  const flag = args[i];
  if (flag === "--no-provider") {
    noProvider = true;
    continue;
  }
  const value = args[++i];
  if (value === undefined || value.startsWith("--")) {
    console.error(`${flag} needs a value.\nUsage: node scripts/evaluate.mjs --phish <dir> --ham <dir> [--out report.json] [--no-provider]`);
    process.exit(1);
  }
  if (flag === "--phish") dirs.phish.push(value);
  else if (flag === "--ham") dirs.ham.push(value);
  else if (flag === "--out") out = value;
  else throw new Error(`Unknown flag ${flag}`);
}

/**
 * Removes the verdicts a mail provider already stamped on the email (spam scores,
 * Microsoft's spoof check), so the numbers show what the engine finds on its own.
 */
function stripProviderVerdicts(raw) {
  const text = raw.toString("latin1");
  const split = text.search(/\r?\n\r?\n/);
  if (split < 0) return raw;
  const head = text
    .slice(0, split)
    .replace(/^(x-ms-exchange-organization-scl|x-ms-exchange-organization-pcl|x-forefront-antispam-report|x-microsoft-antispam|x-spam-[\w-]+|x-rspamd-[\w-]+|x-barracuda-spam-[\w-]+|x-proofpoint-spam-[\w-]+)[ \t]*:.*(\r?\n[ \t].*)*/gim, "X-Removed: provider verdict")
    .replace(/;?\s*compauth=\w+(\s+reason=\d+)?/gi, "");
  return Buffer.from(head + text.slice(split), "latin1");
}

function files(dir) {
  return readdirSync(dir)
    .map((name) => join(dir, name))
    .filter((path) => statSync(path).isFile());
}

async function run(label, paths) {
  const result = { label, total: 0, errors: 0, verdicts: { phishing: 0, suspicious: 0, "no-red-flags": 0 }, rules: {}, items: [] };
  for (const path of paths) {
    result.total++;
    let raw;
    try {
      raw = readFileSync(path);
      if (noProvider) raw = stripProviderVerdicts(raw);
    } catch {
      result.errors++;
      continue;
    }
    try {
      const a = await analyzeEmail(raw);
      result.verdicts[a.verdict]++;
      for (const rule of new Set(a.findings.map((f) => f.rule))) result.rules[rule] = (result.rules[rule] ?? 0) + 1;
      result.items.push({
        file: path.split(/[\\/]/).slice(-2).join("/"),
        verdict: a.verdict,
        score: a.score,
        rules: a.findings.map((f) => f.rule),
        from: a.sender ? `${a.sender.name} <${a.sender.address}>` : null,
        subject: a.subject,
      });
    } catch (err) {
      result.errors++;
      result.items.push({ file: path, error: String(err?.message ?? err) });
    }
  }
  return result;
}

const pct = (n, d) => (d ? `${((100 * n) / d).toFixed(1)}%` : "n/a");

const report = {};
for (const [label, list] of Object.entries(dirs)) {
  if (!list.length) continue;
  const started = performance.now();
  report[label] = await run(label, list.flatMap(files));
  report[label].ms = Math.round(performance.now() - started);
}

for (const r of Object.values(report)) {
  const v = r.verdicts;
  const judged = r.total - r.errors;
  console.log(`\n== ${r.label}: ${r.total} emails (${r.errors} unreadable), ${r.ms} ms`);
  console.log(`   phishing ${v.phishing} (${pct(v.phishing, judged)})  suspicious ${v.suspicious} (${pct(v.suspicious, judged)})  no red flags ${v["no-red-flags"]} (${pct(v["no-red-flags"], judged)})`);
  const top = Object.entries(r.rules).sort((a, b) => b[1] - a[1]).slice(0, 14);
  console.log(`   rules: ${top.map(([k, n]) => `${k} ${n}`).join(", ")}`);
}
// An email the engine can't analyse gets no verdict, so for phishing it counts as missed:
// a phish that breaks the analyser has slipped past it.
if (report.phish) {
  const p = report.phish.verdicts;
  const n = report.phish.total;
  console.log(`\nDetection (phishing or suspicious): ${pct(p.phishing + p.suspicious, n)}   Caught as "Likely phishing": ${pct(p.phishing, n)}${report.phish.errors ? `   (${report.phish.errors} unreadable, counted as missed)` : ""}`);
}
if (report.ham) {
  const h = report.ham.verdicts;
  const n = report.ham.total;
  console.log(`False positives on legitimate mail: suspicious or worse ${pct(h.phishing + h.suspicious, n)}, "Likely phishing" ${pct(h.phishing, n)}${report.ham.errors ? `   (${report.ham.errors} unreadable)` : ""}`);
}
if (out) writeFileSync(out, JSON.stringify(report, null, 2));
