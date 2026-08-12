#!/usr/bin/env node
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const { scan } = require("../lib/scanner");
const pkg = require("../package.json");

const PORT = parseInt(process.env.BFSIBOARD_PORT || "8080", 10);
const SCAN_PATH = process.env.BFSIBOARD_SCAN_PATH || process.cwd();
const SCAN_INTERVAL = parseInt(process.env.BFSIBOARD_SCAN_INTERVAL || "900", 10);
const PUBLIC_DIR = path.join(__dirname, "public");
const FEEDS = (process.env.BFSIBOARD_FEEDS || [
  "https://www.fca.org.uk/news/rss.xml",
  "https://www.sec.gov/news/pressreleases.rss",
  "https://www.federalreserve.gov/feeds/press_all.xml",
  "https://www.finra.org/rss.xml",
  "https://www.bankofengland.co.uk/rss/news",
  "https://blog.pcisecuritystandards.org/blog/rss.xml",
  "https://www.cisa.gov/cybersecurity-advisories/all.xml",
  "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
].join(",")).split(",").map((s) => s.trim()).filter(Boolean);
const FEED_TTL = parseInt(process.env.BFSIBOARD_FEED_TTL || "1800", 10);
const FEED_TIMEOUT_MS = parseInt(process.env.BFSIBOARD_FEED_TIMEOUT || "10000", 10);
const FEED_MAX_ITEMS = parseInt(process.env.BFSIBOARD_FEED_LIMIT || "60", 10);

const state = {
  status: "idle",
  lastScan: null,
  nextScan: null,
  durationMs: 0,
  error: null,
  result: { findings: [], summary: { high: 0, medium: 0, low: 0, total: 0, secret: 0, pii: 0 }, filesScanned: 0 },
};

const feedState = { items: [], fetchedAt: null, errors: [] };

function stripTags(s) {
  return String(s)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#0?39;/gi, "'")
    .replace(/&#x27;/gi, "'")
    .replace(/\s+/g, " ")
    .trim();
}

function feedField(block, tag) {
  const safe = tag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`<${safe}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${safe}>`, "i");
  const m = block.match(re);
  return m ? stripTags(m[1]) : "";
}

function parseFeed(xml, source) {
  const items = [];
  const re = /<(item|entry)(?:\s[^>]*)?>([\s\S]*?)<\/\1>/gi;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const block = m[2];
    let link = feedField(block, "link");
    if (!link) {
      const a = block.match(/<link[^>]*href=["']([^"']+)["']/i);
      link = a ? stripTags(a[1]) : "";
    }
    const title = feedField(block, "title") || "Untitled";
    const dateRaw =
      feedField(block, "pubDate") ||
      feedField(block, "published") ||
      feedField(block, "updated") ||
      feedField(block, "dc:date");
    const published = dateRaw ? Date.parse(dateRaw) : NaN;
    if (!link || !title) continue;
    items.push({
      title,
      link,
      source,
      published: Number.isFinite(published) ? published : 0,
      date: Number.isFinite(published) ? new Date(published).toISOString() : null,
    });
  }
  return items;
}

async function fetchFeed(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FEED_TIMEOUT_MS);
  try {
    const r = await fetch(url, {
      signal: ctrl.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "BFSIboard/0.1 (self-hosted dashboard; https://bfsiboard.org)",
        "Accept": "application/rss+xml, application/atom+xml, text/xml, application/xml, */*",
      },
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const xml = await r.text();
    return parseFeed(xml, url);
  } finally {
    clearTimeout(timer);
  }
}

async function refreshFeeds() {
  if (!FEEDS.length) return;
  const results = await Promise.allSettled(FEEDS.map(fetchFeed));
  const errors = [];
  const all = [];
  results.forEach((res, i) => {
    if (res.status === "fulfilled") all.push(...res.value);
    else errors.push({ url: FEEDS[i], error: res.reason ? res.reason.message : "fetch failed" });
  });
  all.sort((a, b) => (b.published || 0) - (a.published || 0));
  feedState.items = all.slice(0, FEED_MAX_ITEMS);
  feedState.errors = errors;
  feedState.fetchedAt = new Date().toISOString();
  if (errors.length) {
    console.error(`[bfsiboard] feed errors: ${errors.map((e) => `${e.url} (${e.error})`).join("; ")}`);
  }
}

async function runScan() {
  if (state.status === "scanning") return;
  state.status = "scanning";
  state.error = null;
  try {
    console.log(`[bfsiboard] scanning ${SCAN_PATH}`);
    const result = await scan(SCAN_PATH);
    state.result = result;
    state.lastScan = result.scannedAt;
    state.durationMs = result.durationMs;
    state.nextScan = new Date(Date.now() + SCAN_INTERVAL * 1000).toISOString();
    console.log(
      `[bfsiboard] done: ${result.filesScanned} files, ${result.summary.total} findings (high=${result.summary.high})`
    );
    state.status = "ok";
  } catch (err) {
    state.status = "error";
    state.error = err.message;
    state.nextScan = new Date(Date.now() + SCAN_INTERVAL * 1000).toISOString();
    console.error(`[bfsiboard] scan failed: ${err.message}`);
  }
}

function sendJson(res, code, data) {
  const body = JSON.stringify(data);
  res.writeHead(code, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'",
  });
  res.end(body);
}

function statusPayload() {
  return {
    version: pkg.version,
    status: state.status,
    scanPath: SCAN_PATH,
    scanInterval: SCAN_INTERVAL,
    lastScan: state.lastScan,
    nextScan: state.nextScan,
    durationMs: state.durationMs,
    error: state.error,
    summary: state.result.summary,
    filesScanned: state.result.filesScanned,
  };
}

function findingsPayload(reqUrl) {
  const url = new URL(reqUrl, `http://localhost:${PORT}`);
  const severity = url.searchParams.get("severity");
  const type = url.searchParams.get("type");
  const limit = parseInt(url.searchParams.get("limit") || "200", 10);
  let list = state.result.findings;
  if (severity) list = list.filter((f) => f.severity === severity);
  if (type) list = list.filter((f) => f.type === type);
  const capped = list.slice(0, Math.min(limit, 2000));
  return { count: list.length, truncated: list.length > capped.length || !!state.result.truncated, findings: capped };
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

function serveStatic(res, pathname) {
  const rel = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const file = path.resolve(PUBLIC_DIR, rel);
  if (!file.startsWith(PUBLIC_DIR + path.sep) && file !== PUBLIC_DIR) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    return res.end("Forbidden");
  }
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      return res.end("Not found");
    }
    const ext = path.extname(file).toLowerCase();
    res.writeHead(200, {
      "Content-Type": MIME[ext] || "application/octet-stream",
      "Cache-Control": "no-cache",
    });
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = url.pathname;

  if (req.method === "GET" && pathname === "/api/status") {
    return sendJson(res, 200, statusPayload());
  }
  if (req.method === "GET" && pathname === "/api/findings") {
    return sendJson(res, 200, findingsPayload(req.url));
  }
  if (req.method === "GET" && pathname === "/api/feeds") {
    return sendJson(res, 200, feedState);
  }
  if (req.method === "POST" && pathname === "/api/scan") {
    runScan().then(() => sendJson(res, 202, { accepted: true }));
    return;
  }
  if (pathname === "/api/config" || pathname === "/api/health") {
    return sendJson(res, 200, { version: pkg.version, status: state.status });
  }
  return serveStatic(res, pathname);
});

runScan().then(() => {
  server.listen(PORT, () => {
    console.log(`[bfsiboard] dashboard: http://localhost:${PORT}`);
    console.log(`[bfsiboard] scanning every ${SCAN_INTERVAL}s: ${SCAN_PATH}`);
    console.log(`[bfsiboard] press release feeds: ${FEEDS.length} source(s), refreshed every ${FEED_TTL}s`);
  });
});

setInterval(runScan, SCAN_INTERVAL * 1000);

refreshFeeds().catch((err) => console.error(`[bfsiboard] feed refresh failed: ${err.message}`));
setInterval(() => {
  refreshFeeds().catch((err) => console.error(`[bfsiboard] feed refresh failed: ${err.message}`));
}, FEED_TTL * 1000);

function shutdown(signal) {
  console.log(`[bfsiboard] ${signal} received, shutting down`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
