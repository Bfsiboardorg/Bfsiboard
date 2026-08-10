#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { scan, RULES } = require("../lib/scanner");
const { loadConfig, DEFAULT_CONFIG } = require("../lib/config");
const pkg = require("../package.json");

const args = process.argv.slice(2);

function usage() {
  console.log(`bfsiboard v${pkg.version} — PII & credential scanner for the BFSI sector

Usage:
  bfsiboard scan [path]            Scan a directory for exposed PII and secrets
  bfsiboard rules                  List detection rules
  bfsiboard init                   Write a sample bfsiboard.config.json
  bfsiboard --version              Print version

Options:
  --config <file>      Use a specific config file
  --json               Emit full JSON report to stdout
  --fail-on <sev>      Exit 1 if findings at this severity or above (default: high)
  --no-fail            Always exit 0
  --output <file>      Write findings JSON to file (default: bfsiboard-findings.json)
  --no-write           Do not write the findings file
  --exclude <pattern>  Extra exclude pattern (comma separated, e.g. .git,node_modules)
  --include <text>     Only scan paths containing this substring (repeatable/comma)
  --max-findings <n>   Cap the number of findings (default: 1000)
`);
}

function parseFlags(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--config":
      case "--fail-on":
      case "--output":
      case "--exclude":
      case "--include":
      case "--max-findings":
        flags[a.slice(2)] = argv[++i];
        break;
      case "--json":
      case "--no-fail":
      case "--no-write":
        flags[a.slice(2)] = true;
        break;
      case "--version":
      case "-v":
        flags.version = true;
        break;
      case "--help":
      case "-h":
        flags.help = true;
        break;
      default:
        if (a.startsWith("--")) flags[a.slice(2)] = true;
        else positional.push(a);
    }
  }
  return { flags, positional };
}

function writeSampleConfig() {
  const sample = JSON.stringify(DEFAULT_CONFIG, null, 2);
  const file = "bfsiboard.config.json";
  if (fs.existsSync(file)) {
    console.error(`Already exists: ${file}`);
    process.exit(1);
  }
  fs.writeFileSync(file, sample + "\n");
  console.log(`Wrote ${file}`);
}

async function runScan(positional, flags) {
  const cwd = process.cwd();
  const { config } = loadConfig(cwd, flags.config);

  const scanPath = positional[0] || config.scan.paths[0] || ".";
  const excludes = [
    ...(config.scan.exclude || []),
    ...(flags.exclude ? flags.exclude.split(",").map((s) => s.trim()).filter(Boolean) : []),
  ];
  const include = flags.include
    ? flags.include.split(",").map((s) => s.trim()).filter(Boolean)
    : config.scan.include || [];

  const maxFindings = flags["max-findings"]
    ? parseInt(flags["max-findings"], 10)
    : config.scan.maxFindings || 1000;

  console.error(`Scanning ${path.resolve(scanPath)} ...`);

  const result = await scan(scanPath, { excludes, include, maxFindings });

  const failOn = flags["fail-on"] || config.report.failOn || "high";
  const order = { high: 0, medium: 1, low: 2 };
  const failing = result.findings.filter((f) => order[f.severity] <= order[failOn]).length;

  if (flags.json) {
    process.stdout.write(JSON.stringify({ version: pkg.version, ...result }, null, 2) + "\n");
  } else {
    console.log("");
    console.log(`Scanned ${result.filesScanned} files in ${result.durationMs}ms`);
    console.log(`  High:   ${result.summary.high}`);
    console.log(`  Medium: ${result.summary.medium}`);
    console.log(`  Low:    ${result.summary.low}`);
    console.log(`  Total:  ${result.summary.total}`);
    console.log("");
    for (const f of result.findings.slice(0, 50)) {
      const line = String(f.line);
      console.log(`  [${f.severity.toUpperCase()}] ${f.name} — ${f.file}:${line} — ${f.match}`);
    }
    if (result.truncated) console.log("  (truncated)");
  }

  if (!flags["no-write"]) {
    const outFile = flags.output || config.report.output || "bfsiboard-findings.json";
    fs.writeFileSync(outFile, JSON.stringify({ version: pkg.version, ...result }, null, 2) + "\n");
    console.error(`Wrote ${outFile}`);
  }

  if (!flags["no-fail"] && failing > 0) {
    console.error(`FAIL: ${failing} finding(s) at '${failOn}' or above.`);
    process.exit(1);
  }
  process.exit(0);
}

async function main() {
  const { flags, positional } = parseFlags(args);
  if (flags.help) return usage();
  if (flags.version) {
    console.log(pkg.version);
    return;
  }

  const command = positional[0];
  if (command === "init") return writeSampleConfig();
  if (command === "rules") {
    for (const r of RULES) console.log(`${r.severity.padEnd(6)} ${r.id.padEnd(24)} ${r.name}`);
    return;
  }
  if (command === "scan" || command === undefined) {
    const rest = command === "scan" ? positional.slice(1) : positional;
    return runScan(rest, flags);
  }

  console.error(`Unknown command: ${command}`);
  usage();
  process.exit(2);
}

main().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
