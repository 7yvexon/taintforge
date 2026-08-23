import assert from "node:assert/strict";
import test from "node:test";
import { analyzeSource } from "../src/analyzer.mjs";
import { fixtures } from "../src/fixtures.mjs";

const fixture = (id) => fixtures.find((candidate) => candidate.id === id);

test("maps all intended Node gateway flows", () => {
  const result = analyzeSource(fixture("node-gateway"));
  const rules = result.findings.map((finding) => finding.ruleId);

  assert.deepEqual(rules, ["TF-SSRF-001", "TF-SQLI-001", "TF-CMD-001", "TF-PATH-001", "TF-XSS-001"]);
  assert.equal(result.summary.critical, 3);
  assert.equal(result.summary.high, 2);
});

test("maps vulnerable Python flows", () => {
  const result = analyzeSource(fixture("python-worker"));
  const rules = result.findings.map((finding) => finding.ruleId);

  assert.deepEqual(rules, ["TF-SSRF-001", "TF-SQLI-001", "TF-CMD-001", "TF-PATH-001"]);
  assert.equal(result.summary.findings, 4);
});

test("does not flag an allowlisted and parameterized service", () => {
  const result = analyzeSource(fixture("safe-service"));

  assert.equal(result.summary.findings, 0);
  assert.equal(result.summary.riskScore, 0);
});

test("preserves an explainable path for an indirect flow", () => {
  const result = analyzeSource({
    fileName: "flow.js",
    language: "javascript",
    code: `const input = req.query.url;\nconst target = input;\nawait fetch(target);`
  });

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].source.reference, "req.query.url");
  assert.equal(result.findings[0].flow.length, 3);
});
