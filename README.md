# TaintForge

> Trace the flow. Forge the fix.

TaintForge is a local-first, explainable static-analysis workspace for visualizing attacker-controlled data as it travels from a source to a dangerous sink.

It is intentionally built as a defender tool. Paste or import source code, run a local scan, then inspect the exact source-to-sink path, severity, confidence, and a remediation direction.

## Why it exists

Most security tools stop at “a vulnerability may exist.” TaintForge makes the reasoning visible:

```text
HTTP request input → propagated variable → dangerous API → actionable remediation
```

That makes it useful for learning, code review demos, secure-coding workshops, and early security feedback in a project.

## What it detects today

| Rule | Risk | Example sink |
| --- | --- | --- |
| `TF-SSRF-001` | Server-side request forgery | `fetch`, `axios`, `requests.get` |
| `TF-SQLI-001` | SQL injection | `query`, `execute`, `raw` |
| `TF-CMD-001` | Command injection | `exec`, `spawn`, `subprocess.run` |
| `TF-PATH-001` | Path traversal | `sendFile`, `readFile`, `open` |
| `TF-XSS-001` | Cross-site scripting | `innerHTML`, `dangerouslySetInnerHTML` |

The current engine follows common JavaScript/TypeScript and Python request-input patterns, simple variable propagation, direct network/database/command/filesystem/HTML sinks, host allowlists, and parameterized SQL usage.

## Experience

- Dark local security workspace with an integrated source editor
- Deliberately vulnerable Node.js and Python fixtures
- Hardened reference fixture that produces no findings
- Risk score, critical finding count, scanned line count, and flow count
- Severity filters and clickable finding queue
- Source → transform → sink flow visualizer
- Confidence, explanation, and remediation for every finding
- File import for `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.py`, and `.html`
- No third-party dependencies and no outbound source-code upload

## Run locally

```bash
git clone https://github.com/7yvexon/taintforge.git
cd taintforge
npm start
```

Then open [http://127.0.0.1:4173](http://127.0.0.1:4173).

For live reload while building:

```bash
npm run dev
```

## API

### Health check

```text
GET /api/health
```

### Analyze code

```text
POST /api/analyze
Content-Type: application/json
```

```json
{
  "fileName": "gateway.js",
  "language": "javascript",
  "code": "const target = req.query.url;\nawait fetch(target);"
}
```

Example response shape:

```json
{
  "summary": {
    "lines": 2,
    "findings": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0,
    "riskScore": 77
  },
  "findings": [
    {
      "ruleId": "TF-SSRF-001",
      "category": "SSRF",
      "severity": "critical",
      "source": {
        "reference": "req.query.url"
      },
      "sink": {
        "label": "Network client"
      }
    }
  ]
}
```

## Architecture

```text
Browser editor
    ↓
Local POST /api/analyze
    ↓
Heuristic taint engine
    ↓
Structured findings
    ↓
Flow graph, risk score, and remediation UI
```

The runtime binds to `127.0.0.1` only. Source code is sent exclusively to the local Node.js process and is not persisted by TaintForge.

## Project layout

```text
public/
  app.js              Dashboard interaction and rendering
  index.html          Workspace UI
  styles.css          Visual system and responsive layout
src/
  analyzer.mjs        Rule definitions and taint-flow analysis
  fixtures.mjs        Vulnerable and hardened demo sources
test/
  analyzer.test.mjs   Engine coverage
server.mjs            Local HTTP API and static-file server
```

## Test

```bash
npm test
```

The test suite verifies detection of the five supported flow types, Python coverage, indirect propagation, and suppression of the hardened fixture’s allowlisted and parameterized paths.

## Scope and limitations

TaintForge `0.1.0` is a deliberately lightweight heuristic analyzer, not a substitute for manual security review or a mature language-aware SAST engine. It does not execute analyzed code, scan hosts, or attempt exploitation. Use it only on code you own or are authorized to assess.

## Roadmap

- AST-backed language parsers
- Multi-file project graph and import tracing
- Custom rule packs
- SARIF export for code-scanning pipelines
- GitHub Actions integration
- Baseline comparisons and issue triage

## License

MIT
