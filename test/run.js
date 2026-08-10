"use strict";

const assert = require("assert");
const path = require("path");
const { scan } = require("../lib/scanner");

async function main() {
  const result = await scan(path.join(__dirname, "..", "sample"));
  const { findings, summary } = result;

  assert(summary.total >= 10, `expected >=10 findings, got ${summary.total}`);
  assert(summary.high >= 8, `expected >=8 high findings, got ${summary.high}`);

  const rulesHit = new Set(findings.map((f) => f.rule));
  for (const expected of ["aws-access-key", "aws-secret-key", "github-token", "stripe-live-key", "connection-string", "aadhaar", "pan-india", "email", "phone-india", "credit-card"]) {
    assert(rulesHit.has(expected), `rule ${expected} did not fire`);
  }

  const cc = findings.find((f) => f.rule === "credit-card");
  assert(cc, "valid test card (Luhn) not detected");

  const leakedSecrets = [
    "AKIA__FAKE_AWS_KEY__",
    "__AWS_FAKE_SECRET_KEY__",
    "ghp__FAKE_GITHUB_PAT__",
    "sk_test__FAKE_STRIPE_KEY__",
    "FAKE_DB_PASS",
    "2345 6789 0123",
    "4111 1111 1111 1111",
  ];
  const allText = JSON.stringify(findings);
  for (const secret of leakedSecrets) {
    assert(!allText.includes(secret), `secret leaked unmasked: ${secret}`);
  }

  const masked = findings.find((f) => f.rule === "github-token");
  assert(masked.match.includes("..."), "expected a masked match string");
  assert(!/\bghp_[A-Za-z0-9]{36}\b/.test(masked.match), "full token visible in masked output");

  console.log("PASS");
  console.log(JSON.stringify({ total: summary.total, high: summary.high, filesScanned: result.filesScanned, durationMs: result.durationMs }));
}

main().catch((err) => {
  console.error("FAIL:", err.message);
  process.exit(1);
});
