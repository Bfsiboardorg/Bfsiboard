"use strict";

const fs = require("fs");
const path = require("path");

const DEFAULT_CONFIG = {
  scan: {
    paths: ["./"],
    exclude: [],
    include: [],
    maxFindings: 1000,
  },
  report: {
    failOn: "high",
    output: "bfsiboard-findings.json",
  },
};

function findConfig(cwd, explicit) {
  if (explicit) {
    return fs.existsSync(explicit) ? explicit : null;
  }
  const candidates = ["bfsiboard.config.json", "bfsiboard.json", ".bfsiboard.json"];
  for (const c of candidates) {
    const p = path.join(cwd, c);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function loadConfig(cwd, explicit) {
  const file = findConfig(cwd, explicit);
  if (!file) return { config: JSON.parse(JSON.stringify(DEFAULT_CONFIG)), path: null };
  try {
    const raw = fs.readFileSync(file, "utf8");
    const parsed = JSON.parse(raw);
    const merged = {
      scan: { ...DEFAULT_CONFIG.scan, ...(parsed.scan || {}) },
      report: { ...DEFAULT_CONFIG.report, ...(parsed.report || {}) },
    };
    return { config: merged, path: file };
  } catch (err) {
    throw new Error(`Failed to parse config file ${file}: ${err.message}`);
  }
}

module.exports = { loadConfig, DEFAULT_CONFIG };
