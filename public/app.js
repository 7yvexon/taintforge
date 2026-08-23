const state = {
  fixtures: [],
  activeFixture: null,
  analysis: null,
  selectedFinding: null,
  filter: "all",
  fileName: "gateway.js",
  language: "javascript"
};

const elements = {
  currentFile: document.querySelector("#currentFile"),
  scanStatus: document.querySelector("#scanStatus"),
  scanWindowText: document.querySelector("#scanWindowText"),
  sampleSelect: document.querySelector("#sampleSelect"),
  fileInput: document.querySelector("#fileInput"),
  scanButton: document.querySelector("#scanButton"),
  refreshButton: document.querySelector("#refreshButton"),
  editor: document.querySelector("#editor"),
  lineNumbers: document.querySelector("#lineNumbers"),
  editorInfo: document.querySelector("#editorInfo"),
  editorPath: document.querySelector("#editorPath"),
  languageBadge: document.querySelector("#languageBadge"),
  dropZone: document.querySelector("#dropZone"),
  riskMetric: document.querySelector("#riskMetric"),
  riskLabel: document.querySelector("#riskLabel"),
  riskTrack: document.querySelector("#riskTrack"),
  flowMetric: document.querySelector("#flowMetric"),
  criticalMetric: document.querySelector("#criticalMetric"),
  linesMetric: document.querySelector("#linesMetric"),
  engineMetric: document.querySelector("#engineMetric"),
  findingCount: document.querySelector("#findingCount"),
  findingsList: document.querySelector("#findingsList"),
  filterRow: document.querySelector("#filterRow"),
  findingTemplate: document.querySelector("#findingTemplate"),
  flowTitle: document.querySelector("#flowTitle"),
  flowGraph: document.querySelector("#flowGraph"),
  confidenceValue: document.querySelector("#confidenceValue"),
  inspectionRule: document.querySelector("#inspectionRule"),
  inspectionSeverity: document.querySelector("#inspectionSeverity"),
  inspectionTitle: document.querySelector("#inspectionTitle"),
  inspectionWhy: document.querySelector("#inspectionWhy"),
  inspectionFix: document.querySelector("#inspectionFix"),
  jumpButton: document.querySelector("#jumpButton"),
  rulesButton: document.querySelector("#rulesButton")
};

const languageForFile = (fileName) => {
  const extension = fileName.split(".").pop()?.toLowerCase();

  if (["py"].includes(extension)) return "python";
  if (["ts", "tsx"].includes(extension)) return "typescript";
  if (["html", "htm"].includes(extension)) return "html";
  return "javascript";
};

const titleCase = (value) => value.replace(/\b\w/g, (character) => character.toUpperCase());

const formatRisk = (score) => {
  if (score >= 80) return "critical exposure";
  if (score >= 55) return "high exposure";
  if (score > 0) return "review advised";
  return "no tainted paths";
};

const updateLineNumbers = () => {
  const lineCount = elements.editor.value.split("\n").length;
  elements.lineNumbers.textContent = Array.from({ length: lineCount }, (_, index) => String(index + 1).padStart(2, " ")).join("\n");
  elements.editorInfo.textContent = `${lineCount} lines · ${elements.editor.value.length.toLocaleString()} chars`;
};

const syncScroll = () => {
  elements.lineNumbers.scrollTop = elements.editor.scrollTop;
};

const setSource = ({ code, fileName, language, fixtureId = null }) => {
  state.fileName = fileName;
  state.language = language;
  state.activeFixture = fixtureId;
  elements.editor.value = code;
  elements.currentFile.textContent = fileName;
  elements.editorPath.textContent = fixtureId ? `fixtures/${fileName}` : `import/${fileName}`;
  elements.languageBadge.textContent = language.toUpperCase();
  updateLineNumbers();
};

const renderMetrics = (analysis) => {
  const { summary, engine } = analysis;
  elements.riskMetric.textContent = String(summary.riskScore).padStart(2, "0");
  elements.riskLabel.textContent = formatRisk(summary.riskScore);
  elements.riskTrack.style.width = `${Math.max(summary.riskScore, 3)}%`;
  elements.flowMetric.textContent = String(summary.findings).padStart(2, "0");
  elements.criticalMetric.textContent = String(summary.critical).padStart(2, "0");
  elements.linesMetric.textContent = String(summary.lines).padStart(2, "0");
  elements.engineMetric.textContent = `${engine.name} · ${engine.version}`;
};

const setStatus = (status, message) => {
  elements.scanStatus.textContent = status;
  elements.scanWindowText.textContent = message;
  document.body.dataset.scanState = status.toLowerCase();
};

const getVisibleFindings = () => {
  const findings = state.analysis?.findings ?? [];
  return state.filter === "all" ? findings : findings.filter((finding) => finding.severity === state.filter);
};

const renderFindings = () => {
  const findings = getVisibleFindings();
  elements.findingsList.replaceChildren();
  elements.findingCount.textContent = String(findings.length).padStart(2, "0");

  if (findings.length === 0) {
    const isClear = Boolean(state.analysis?.findings.length);
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.innerHTML = isClear
      ? "<span class=\"empty-mark clear\">✓</span><strong>No signals in this filter</strong><p>Try another severity or inspect the hardened fixture.</p>"
      : "<span class=\"empty-mark\">⌁</span><strong>Engine standing by</strong><p>Run a scan to surface tainted data flows.</p>";
    elements.findingsList.append(empty);
    return;
  }

  findings.forEach((finding, index) => {
    const card = elements.findingTemplate.content.firstElementChild.cloneNode(true);
    card.dataset.findingId = finding.id;
    card.style.setProperty("--delay", `${index * 45}ms`);
    card.classList.toggle("selected", state.selectedFinding?.id === finding.id);
    card.querySelector(".finding-category").textContent = finding.category.toUpperCase();
    card.querySelector(".finding-line").textContent = `LN ${finding.line}`;
    card.querySelector(".finding-title").textContent = finding.title;
    card.querySelector(".finding-route").textContent = `${finding.source.reference}  →  ${finding.sink.label}`;
    const severity = card.querySelector(".severity");
    severity.textContent = finding.severity.toUpperCase();
    severity.classList.add(finding.severity);
    card.addEventListener("click", () => selectFinding(finding.id));
    elements.findingsList.append(card);
  });
};

const flowNodeMarkup = (step, index) => {
  const glyph = step.kind === "source" ? "↓" : step.kind === "sink" ? "×" : "↔";
  return `
    <div class="flow-step ${step.kind}" style="--step:${index}">
      <div class="flow-node-icon">${glyph}</div>
      <div><span>${step.kind.toUpperCase()}</span><strong>${step.label}</strong><small>${step.detail}</small></div>
      <div class="flow-line">LN ${step.line}</div>
    </div>`;
};

const renderInspection = () => {
  const finding = state.selectedFinding;

  if (!finding) {
    elements.flowTitle.textContent = "Select a finding to inspect the flow";
    elements.confidenceValue.textContent = "--";
    elements.flowGraph.innerHTML = "<div class=\"graph-empty\"><span>◌</span><p>Source → transform → sink</p></div>";
    elements.inspectionRule.textContent = "NO SIGNAL";
    elements.inspectionSeverity.textContent = "READY";
    elements.inspectionSeverity.className = "severity quiet";
    elements.inspectionTitle.textContent = "No finding selected";
    elements.inspectionWhy.textContent = "TaintForge will explain why a detected flow matters and how to break it safely.";
    elements.inspectionFix.textContent = "Load a fixture and run analysis to inspect a remediation path.";
    elements.jumpButton.disabled = true;
    return;
  }

  elements.flowTitle.textContent = `${finding.category} path · ${finding.ruleId}`;
  elements.confidenceValue.textContent = `${finding.confidence}%`;
  elements.flowGraph.innerHTML = finding.flow.map(flowNodeMarkup).join("");
  elements.inspectionRule.textContent = finding.ruleId;
  elements.inspectionSeverity.textContent = finding.severity.toUpperCase();
  elements.inspectionSeverity.className = `severity ${finding.severity}`;
  elements.inspectionTitle.textContent = finding.title;
  elements.inspectionWhy.textContent = finding.why;
  elements.inspectionFix.textContent = finding.remediation;
  elements.jumpButton.disabled = false;
};

const jumpToLine = () => {
  const finding = state.selectedFinding;
  if (!finding) return;
  const lines = elements.editor.value.split("\n");
  const before = lines.slice(0, Math.max(finding.line - 1, 0)).join("\n").length;
  const targetLine = lines[finding.line - 1] ?? "";
  elements.editor.focus();
  elements.editor.setSelectionRange(before, before + targetLine.length);
  const lineHeight = Number.parseFloat(getComputedStyle(elements.editor).lineHeight) || 22;
  elements.editor.scrollTop = Math.max(0, (finding.line - 4) * lineHeight);
  syncScroll();
};

const selectFinding = (findingId) => {
  state.selectedFinding = state.analysis?.findings.find((finding) => finding.id === findingId) ?? null;
  renderFindings();
  renderInspection();
};

const runAnalysis = async () => {
  const code = elements.editor.value.trim();

  if (!code) {
    setStatus("EMPTY", "Add source code before starting analysis.");
    return;
  }

  setStatus("SCANNING", "Tracing source-to-sink paths through local code.");
  elements.scanButton.disabled = true;
  elements.scanButton.innerHTML = "<span class=\"button-spark\">◌</span> TRACING FLOW";

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: elements.editor.value,
        fileName: state.fileName,
        language: state.language
      })
    });
    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload.error ?? "Analysis failed");
    }

    state.analysis = payload;
    state.selectedFinding = payload.findings[0] ?? null;
    renderMetrics(payload);
    renderFindings();
    renderInspection();
    setStatus(payload.findings.length ? "SIGNALS FOUND" : "CLEAN", payload.findings.length ? `${payload.findings.length} data-flow signal${payload.findings.length === 1 ? "" : "s"} mapped in ${payload.summary.lines} lines.` : "No tracked tainted path reached an active sink.");
  } catch (error) {
    state.analysis = null;
    state.selectedFinding = null;
    renderFindings();
    renderInspection();
    setStatus("ERROR", error instanceof Error ? error.message : "Analysis failed.");
  } finally {
    elements.scanButton.disabled = false;
    elements.scanButton.innerHTML = "<span class=\"button-spark\">✦</span> RUN ANALYSIS <kbd>⌘↵</kbd>";
  }
};

const loadFixture = async (fixtureId) => {
  const response = await fetch(`/api/fixtures/${encodeURIComponent(fixtureId)}`);
  const fixture = await response.json();
  setSource({ ...fixture, fixtureId: fixture.id });
  setStatus("READY", fixture.description);
  state.analysis = null;
  state.selectedFinding = null;
  renderFindings();
  renderInspection();
};

const handleFile = async (file) => {
  if (!file) return;
  const code = await file.text();
  setSource({
    code,
    fileName: file.name,
    language: languageForFile(file.name)
  });
  state.analysis = null;
  state.selectedFinding = null;
  renderFindings();
  renderInspection();
  setStatus("FILE LOADED", `${file.name} is staged for local analysis.`);
};

const setupEvents = () => {
  elements.sampleSelect.addEventListener("change", (event) => loadFixture(event.target.value));
  elements.fileInput.addEventListener("change", (event) => handleFile(event.target.files?.[0]));
  elements.scanButton.addEventListener("click", runAnalysis);
  elements.refreshButton.addEventListener("click", runAnalysis);
  elements.jumpButton.addEventListener("click", jumpToLine);
  elements.editor.addEventListener("input", updateLineNumbers);
  elements.editor.addEventListener("scroll", syncScroll);
  elements.rulesButton.addEventListener("click", () => document.querySelector("#rules").scrollIntoView({ behavior: "smooth", block: "center" }));
  elements.filterRow.addEventListener("click", (event) => {
    const button = event.target.closest(".filter");
    if (!button) return;
    state.filter = button.dataset.filter;
    elements.filterRow.querySelectorAll(".filter").forEach((item) => item.classList.toggle("active", item === button));
    renderFindings();
  });
  elements.dropZone.addEventListener("dragover", (event) => {
    event.preventDefault();
    elements.dropZone.classList.add("dragging");
  });
  elements.dropZone.addEventListener("dragleave", () => elements.dropZone.classList.remove("dragging"));
  elements.dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    elements.dropZone.classList.remove("dragging");
    handleFile(event.dataTransfer.files?.[0]);
  });
  window.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
      event.preventDefault();
      runAnalysis();
    }
  });
};

const bootstrap = async () => {
  try {
    const response = await fetch("/api/fixtures");
    state.fixtures = await response.json();
    state.fixtures.forEach((fixture) => {
      const option = document.createElement("option");
      option.value = fixture.id;
      option.textContent = fixture.name;
      elements.sampleSelect.append(option);
    });
    await loadFixture(state.fixtures[0].id);
    setupEvents();
    await runAnalysis();
  } catch {
    setStatus("OFFLINE", "Unable to reach the local analysis engine.");
  }
};

bootstrap();
