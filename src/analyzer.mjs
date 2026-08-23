const severityWeight = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1
};

const ruleDefinitions = [
  {
    id: "TF-SSRF-001",
    category: "SSRF",
    title: "Untrusted URL reaches a network client",
    severity: "critical",
    confidence: 94,
    sinkPattern: /\b(?:fetch|axios\.(?:get|post|request)|got|requests\.(?:get|post)|http\.(?:get|request)|https\.(?:get|request))\s*\(/i,
    sinkLabel: "Network client",
    why: "User-controlled data can make the server request internal or otherwise unintended resources.",
    remediation: "Parse the URL, enforce an explicit hostname allowlist, and block private or loopback addresses."
  },
  {
    id: "TF-SQLI-001",
    category: "SQL injection",
    title: "Untrusted data reaches a SQL execution sink",
    severity: "critical",
    confidence: 96,
    sinkPattern: /\b(?:db\.)?(?:query|execute|executeQuery|raw)\s*\(/i,
    sinkLabel: "SQL execution",
    why: "String-built SQL can let an attacker alter the query structure or extract data.",
    remediation: "Use parameterized queries or a query builder. Never concatenate request data into SQL strings."
  },
  {
    id: "TF-CMD-001",
    category: "Command injection",
    title: "Untrusted data reaches a command execution sink",
    severity: "critical",
    confidence: 95,
    sinkPattern: /\b(?:exec|execSync|spawn|spawnSync|system|popen|subprocess\.(?:run|call|Popen)|os\.system)\s*\(/i,
    sinkLabel: "Command execution",
    why: "User-controlled text can change the command that the host operating system executes.",
    remediation: "Avoid shell execution. Pass a fixed executable and a structured argument array, then validate each value."
  },
  {
    id: "TF-PATH-001",
    category: "Path traversal",
    title: "Untrusted data reaches a filesystem path sink",
    severity: "high",
    confidence: 91,
    sinkPattern: /\b(?:sendFile|readFile|readFileSync|writeFile|writeFileSync|open|createReadStream|unlink|remove)\s*\(/i,
    sinkLabel: "Filesystem access",
    why: "An attacker may use traversal sequences to access files outside the intended directory.",
    remediation: "Resolve paths against a fixed base directory, reject traversal segments, and verify the resolved path stays inside the base."
  },
  {
    id: "TF-XSS-001",
    category: "Cross-site scripting",
    title: "Untrusted markup reaches an HTML rendering sink",
    severity: "high",
    confidence: 90,
    sinkPattern: /\b(?:innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML|render_template_string)\b/i,
    sinkLabel: "HTML rendering",
    why: "Rendering attacker-controlled markup can execute scripts in another user's browser.",
    remediation: "Use safe DOM APIs such as textContent, or sanitize HTML with a well-maintained allowlist sanitizer."
  }
];

const sourcePatterns = [
  {
    pattern: /\breq\.(?:query|body|params)\.([A-Za-z_$][\w$]*)/g,
    label: "HTTP request input"
  },
  {
    pattern: /\brequest\.(?:args|form|values|json)\.get\(\s*["']([^"']+)["']\s*\)/g,
    label: "HTTP request input"
  },
  {
    pattern: /\brequest\.json\.get\(\s*["']([^"']+)["']\s*\)/g,
    label: "HTTP request input"
  }
];

const normalizeLine = (line) => line.replace(/\s+/g, " ").trim();

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const getDirectSource = (line, lineNumber) => {
  for (const definition of sourcePatterns) {
    definition.pattern.lastIndex = 0;
    const match = definition.pattern.exec(line);

    if (match) {
      return {
        label: definition.label,
        reference: match[0],
        line: lineNumber,
        snippet: normalizeLine(line)
      };
    }
  }

  return null;
};

const extractAssignment = (line) => {
  const match = line.match(/^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*;?\s*$/);

  if (!match) {
    return null;
  }

  return {
    variable: match[1],
    expression: match[2]
  };
};

const findReferencedTaint = (line, taints) => {
  const candidates = [];

  for (const [variable, taint] of taints.entries()) {
    const pattern = new RegExp(`\\b${escapeRegex(variable)}\\b`);

    if (pattern.test(line)) {
      candidates.push({ variable, taint });
    }
  }

  candidates.sort((left, right) => right.taint.source.line - left.taint.source.line);
  return candidates[0] ?? null;
};

const isLikelySanitized = (line) => /(escape|sanitize|validate|allowlist|whitelist|parameterized|prepared)/i.test(line);

const isParameterizedQuery = (line) => {
  const hasPlaceholder = /(?:\$\d+|\?\s*["')\],])/.test(line);
  const hasArguments = /,\s*(?:\[|\()/.test(line);
  return hasPlaceholder && hasArguments;
};

const isRuleSuppressed = (rule, line, referenced, safeVariables) => {
  if (rule.category === "SQL injection" && isParameterizedQuery(line)) {
    return true;
  }

  return Boolean(referenced && safeVariables.has(referenced.variable));
};

const makeFlow = (source, variable, history, rule, sinkLine, sinkSnippet) => {
  const flow = [
    {
      kind: "source",
      label: source.label,
      detail: source.reference,
      line: source.line,
      snippet: source.snippet
    }
  ];

  if (variable) {
    flow.push({
      kind: "transform",
      label: "Propagated value",
      detail: variable,
      line: history?.line ?? source.line,
      snippet: history?.snippet ?? source.snippet
    });
  }

  flow.push({
    kind: "sink",
    label: rule.sinkLabel,
    detail: rule.category,
    line: sinkLine,
    snippet: sinkSnippet
  });

  return flow;
};

const makeFinding = ({ rule, source, referenced, line, lineNumber }) => {
  const sinkSnippet = normalizeLine(line);
  const variable = referenced?.variable ?? null;
  const history = referenced?.taint.history.at(-1);

  return {
    id: `${rule.id}-${lineNumber}-${source.line}`,
    ruleId: rule.id,
    category: rule.category,
    title: rule.title,
    severity: rule.severity,
    confidence: isLikelySanitized(line) ? Math.max(rule.confidence - 35, 45) : rule.confidence,
    line: lineNumber,
    source,
    sink: {
      label: rule.sinkLabel,
      line: lineNumber,
      snippet: sinkSnippet
    },
    flow: makeFlow(source, variable, history, rule, lineNumber, sinkSnippet),
    why: rule.why,
    remediation: rule.remediation
  };
};

const scoreFindings = (findings) => {
  if (findings.length === 0) {
    return 0;
  }

  const weightedTotal = findings.reduce((total, finding) => total + severityWeight[finding.severity], 0);
  return Math.min(99, Math.round((weightedTotal / Math.max(findings.length, 1)) * 18 + findings.length * 5));
};

export const analyzeSource = ({ code, language = "javascript", fileName = "untitled" }) => {
  if (typeof code !== "string") {
    throw new TypeError("code must be a string");
  }

  const lines = code.replace(/\r\n/g, "\n").split("\n");
  const taints = new Map();
  const safeVariables = new Set();
  const findings = [];
  const observed = new Set();

  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    const directSource = getDirectSource(line, lineNumber);
    const assignment = extractAssignment(line);
    const allowlistMatch = line.match(/(?:allowlist|allowedHosts|whitelist|trustedHosts)\.has\(\s*([A-Za-z_$][\w$]*)/i);

    if (allowlistMatch) {
      safeVariables.add(allowlistMatch[1]);
    }

    if (assignment) {
      const assignmentSource = getDirectSource(assignment.expression, lineNumber);
      const referenced = findReferencedTaint(assignment.expression, taints);

      if (assignmentSource) {
        taints.set(assignment.variable, {
          source: assignmentSource,
          history: [{ line: lineNumber, snippet: normalizeLine(line) }]
        });
      } else if (referenced && !isLikelySanitized(assignment.expression)) {
        taints.set(assignment.variable, {
          source: referenced.taint.source,
          history: [...referenced.taint.history, { line: lineNumber, snippet: normalizeLine(line) }]
        });
      } else if (!referenced) {
        taints.delete(assignment.variable);
      }
    }

    const referenced = findReferencedTaint(line, taints);
    const source = directSource ?? referenced?.taint.source;

    if (!source || isLikelySanitized(line)) {
      return;
    }

    for (const rule of ruleDefinitions) {
      if (!rule.sinkPattern.test(line)) {
        continue;
      }

      const finding = makeFinding({ rule, source, referenced, line, lineNumber });
      const key = `${finding.ruleId}:${finding.line}:${finding.source.line}`;

      if (!observed.has(key) && !isRuleSuppressed(rule, line, referenced, safeVariables)) {
        observed.add(key);
        findings.push(finding);
      }
    }
  });

  findings.sort((left, right) => {
    const severityDifference = severityWeight[right.severity] - severityWeight[left.severity];
    return severityDifference || left.line - right.line;
  });

  const severity = Object.fromEntries(Object.keys(severityWeight).map((key) => [key, 0]));
  findings.forEach((finding) => {
    severity[finding.severity] += 1;
  });

  return {
    fileName,
    language,
    engine: {
      name: "TaintForge heuristic engine",
      version: "0.1.0",
      mode: "Local analysis"
    },
    summary: {
      lines: lines.length,
      findings: findings.length,
      critical: severity.critical,
      high: severity.high,
      medium: severity.medium,
      low: severity.low,
      riskScore: scoreFindings(findings)
    },
    findings,
    analyzedAt: new Date().toISOString()
  };
};

export const rules = ruleDefinitions.map(({ sinkPattern, ...rule }) => rule);
