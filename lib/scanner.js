"use strict";

const fs = require("fs");
const path = require("path");
const { RULES } = require("./rules");

const DEFAULT_EXCLUDES = [
  ".git",
  "node_modules",
  "dist",
  "build",
  ".next",
  ".venv",
  "vendor",
  ".cache",
  ".idea",
  ".vscode",
  ".terraform",
  "coverage",
];

const SKIP_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".zip", ".gz", ".tar", ".7z", ".rar",
  ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".o", ".a",
  ".woff", ".woff2", ".ttf", ".otf", ".eot",
  ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav",
]);

const MAX_FILE_BYTES = 1024 * 1024;

function isBinary(buf) {
  const head = buf.subarray(0, 8192);
  for (let i = 0; i < head.length; i++) {
    if (head[i] === 0) return true;
  }
  return false;
}

function isExcluded(relPath, excludes) {
  const parts = relPath.split("/");
  for (const ex of excludes) {
    if (ex.startsWith("*.")) {
      if (relPath.endsWith(ex.slice(1))) return true;
      continue;
    }
    if (ex.includes("/") || ex.includes("\\")) {
      const pattern = ex.replace(/\\/g, "/").replace(/\*\*/g, "__DOUBLE__").replace(/\*/g, "[^/]*").replace("__DOUBLE__", ".*");
      try {
        if (new RegExp(`^${pattern}$`).test(relPath)) return true;
      } catch {
        /* ignore bad pattern */
      }
      continue;
    }
    if (parts.includes(ex)) return true;
  }
  return false;
}

function luhnValid(digits) {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function countLines(content, index) {
  let n = 1;
  const upto = Math.min(index, content.length);
  for (let i = 0; i < upto; i++) {
    if (content.charCodeAt(i) === 10) n++;
  }
  return n;
}

function defaultMask(value) {
  if (!value) return value;
  const clean = value.replace(/[\r\n]+/g, " ").trim();
  if (clean.length <= 8) return "***";
  return clean.slice(0, 4) + "..." + clean.slice(-4);
}

function maskMatch(matchText, rule, match) {
  if (rule.id === "connection-string") {
    return matchText.replace(/:\/\/[^@\s]*@/, "://***:***@");
  }
  if (rule.id === "private-key") {
    return "-----BEGIN PRIVATE KEY----- (content masked)";
  }
  if (rule.id === "email") {
    return matchText.replace(/^(.{1,3})[^@]*@/, "$1***@");
  }
  if (typeof rule.secretGroup === "number" && match.indices && match.indices[rule.secretGroup]) {
    const [s, e] = match.indices[rule.secretGroup];
    const secret = matchText.slice(s, e);
    const masked = defaultMask(secret);
    return matchText.slice(0, s) + masked + matchText.slice(e);
  }
  return defaultMask(matchText);
}

function compileRules() {
  return RULES.map((rule) => {
    let flags = rule.regex.flags;
    if (!flags.includes("g")) flags += "g";
    if (!flags.includes("d")) flags += "d";
    return { ...rule, compiled: new RegExp(rule.regex.source, flags) };
  });
}

async function walkFiles(root, opts) {
  const files = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = await fs.promises.readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const abs = path.join(dir, entry.name);
      const rel = path.relative(opts.root, abs).replace(/\\/g, "/");
      if (isExcluded(rel, opts.excludes)) continue;
      if (entry.isDirectory()) {
        stack.push(abs);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (SKIP_EXTENSIONS.has(ext)) continue;
        if (opts.include && opts.include.length && !opts.include.some((i) => rel.includes(i))) continue;
        files.push(abs);
      }
    }
  }
  return files;
}

async function scan(root, opts = {}) {
  const start = Date.now();
  const excludes = opts.excludes && opts.excludes.length ? opts.excludes : DEFAULT_EXCLUDES;
  const rules = compileRules();
  const maxFindings = opts.maxFindings || 1000;
  const findings = [];
  const seen = new Set();
  let filesScanned = 0;

  const rootAbs = path.resolve(root || ".");
  const files = await walkFiles(rootAbs, { root: rootAbs, excludes, include: opts.include });

  for (const file of files) {
    let stat;
    try {
      stat = await fs.promises.stat(file);
    } catch {
      continue;
    }
    if (stat.size > (opts.maxFileBytes || MAX_FILE_BYTES)) continue;
    let buf;
    try {
      buf = await fs.promises.readFile(file);
    } catch {
      continue;
    }
    if (isBinary(buf)) continue;
    filesScanned++;

    const content = buf.toString("utf8");
    const rel = path.relative(rootAbs, file).replace(/\\/g, "/");

    for (const rule of rules) {
      rule.compiled.lastIndex = 0;
      let m;
      while ((m = rule.compiled.exec(content)) !== null) {
        if (m[0].length === 0) {
          rule.compiled.lastIndex++;
          continue;
        }
        if (rule.id === "credit-card") {
          const digits = m[0].replace(/[^0-9]/g, "");
          if (digits.length < 13 || digits.length > 19 || !luhnValid(digits)) {
            rule.compiled.lastIndex = m.index + 1;
            continue;
          }
        }
        if (rule.id === "email") {
          let s = m.index;
          while (s > 0 && /[A-Za-z0-9._%+-]/.test(content[s - 1])) s--;
          if (s > 0 && (content[s - 1] === ":" || content[s - 1] === "/")) {
            rule.compiled.lastIndex = m.index + 1;
            continue;
          }
        }
        if (rule.id === "aadhaar") {
          const digits = m[0].replace(/[^0-9]/g, "");
          if (!/^[2-9]\d{11}$/.test(digits)) {
            rule.compiled.lastIndex = m.index + 1;
            continue;
          }
        }
        const line = countLines(content, m.index);
        const masked = maskMatch(m[0], rule, m);
        const dedupKey = `${rule.id}|${rel}|${line}|${masked}`;
        if (seen.has(dedupKey)) {
          rule.compiled.lastIndex = m.index + 1;
          continue;
        }
        seen.add(dedupKey);
        findings.push({
          rule: rule.id,
          name: rule.name,
          severity: rule.severity,
          type: rule.type,
          file: rel,
          line,
          match: masked,
        });
        if (findings.length >= maxFindings) break;
      }
      if (findings.length >= maxFindings) break;
    }
    if (findings.length >= maxFindings) break;
  }

  const bySeverity = { high: 0, medium: 0, low: 0 };
  const byType = { secret: 0, pii: 0 };
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byType[f.type] = (byType[f.type] || 0) + 1;
  }

  const order = { high: 0, medium: 1, low: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file) || a.line - b.line);

  return {
    findings,
    summary: { ...bySeverity, total: findings.length, ...byType },
    filesScanned,
    durationMs: Date.now() - start,
    truncated: findings.length >= maxFindings,
    scannedAt: new Date().toISOString(),
  };
}

module.exports = { scan, RULES, DEFAULT_EXCLUDES, luhnValid };
