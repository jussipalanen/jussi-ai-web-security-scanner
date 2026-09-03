"use strict";

// Findings echo content controlled by the scanned site (header values, URLs).
// Everything below therefore builds DOM nodes and assigns textContent; nothing
// is ever passed to innerHTML. A scanner that could be XSSed by the site it
// scans would be an embarrassing way to lose.

const SEVERITY_ORDER = ["high", "medium", "low", "info"];

const form = document.getElementById("scan-form");
const input = document.getElementById("url");
const submit = document.getElementById("submit");
const statusLine = document.getElementById("status");
const errorBox = document.getElementById("error");
const summary = document.getElementById("summary");
const results = document.getElementById("results");
const notesList = document.getElementById("notes");

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/**
 * The API returns two error shapes: our own handler sends `detail` as a string,
 * while request-model errors from Pydantic send an array of error objects.
 */
function errorMessages(payload, fallback) {
  const detail = payload && payload.detail;
  if (typeof detail === "string") return [detail];
  if (Array.isArray(detail)) {
    return detail.map((e) => {
      const where = Array.isArray(e.loc) ? e.loc.join(".") : "";
      return where ? `${where}: ${e.msg}` : e.msg;
    });
  }
  return [fallback];
}

function showError(heading, messages) {
  clear(errorBox);
  errorBox.appendChild(el("h2", null, heading));
  const list = el("ul");
  messages.forEach((m) => list.appendChild(el("li", null, m)));
  errorBox.appendChild(list);
  errorBox.hidden = false;
}

function renderSummary(data) {
  document.getElementById("final-url").textContent = data.final_url;
  document.getElementById("status-code").textContent = String(data.status_code);
  document.getElementById("duration").textContent = `${Math.round(data.duration_ms)} ms`;

  const counts = document.getElementById("counts");
  clear(counts);
  SEVERITY_ORDER.forEach((sev) => {
    const li = el("li");
    li.appendChild(el("span", "n", String(data.counts[sev] ?? 0)));
    li.appendChild(document.createTextNode(` ${sev}`));
    counts.appendChild(li);
  });

  clear(notesList);
  (data.notes || []).forEach((n) => notesList.appendChild(el("li", null, n)));
  notesList.hidden = (data.notes || []).length === 0;

  summary.hidden = false;
}

function renderFinding(finding) {
  const card = el("div", `finding ${finding.severity}`);

  const heading = el("h3");
  heading.appendChild(el("span", `badge ${finding.severity}`, finding.severity));
  heading.appendChild(document.createTextNode(finding.title));
  card.appendChild(heading);
  card.appendChild(el("p", "check-id", `${finding.check_id} · confidence: ${finding.confidence}`));

  if (finding.description) card.appendChild(el("p", null, finding.description));

  if (finding.remediation && finding.remediation !== "No action needed.") {
    const fix = el("p", "fix");
    fix.appendChild(el("strong", null, "How to fix"));
    fix.appendChild(document.createTextNode(finding.remediation));
    card.appendChild(fix);
  }

  const evidence = finding.evidence || {};
  if (Object.keys(evidence).length) {
    const details = el("details", "evidence");
    details.appendChild(el("summary", null, "Evidence"));
    const pre = el("pre");
    pre.textContent = Object.entries(evidence)
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n");
    details.appendChild(pre);
    card.appendChild(details);
  }
  return card;
}

function renderResults(data) {
  clear(results);
  const sorted = [...data.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
  if (!sorted.length) {
    results.appendChild(el("p", null, "No findings were produced."));
    return;
  }
  sorted.forEach((f) => results.appendChild(renderFinding(f)));
}

async function runScan(url) {
  if (!url) return;

  submit.disabled = true;
  errorBox.hidden = true;
  summary.hidden = true;
  clear(results);
  statusLine.textContent = `Scanning ${url}…`;
  statusLine.hidden = false;

  try {
    const response = await fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    let payload = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }

    if (!response.ok) {
      const heading =
        response.status === 422
          ? "Target rejected"
          : response.status === 502
            ? "Target could not be reached"
            : `Request failed (HTTP ${response.status})`;
      showError(heading, errorMessages(payload, `HTTP ${response.status}`));
      return;
    }

    renderSummary(payload);
    renderResults(payload);
  } catch (err) {
    showError("Could not reach the scanner API", [String(err)]);
  } finally {
    statusLine.hidden = true;
    submit.disabled = false;
  }
}

/** The ?url= value currently in the address bar, or "". */
function urlFromLocation() {
  return (new URLSearchParams(window.location.search).get("url") || "").trim();
}

/**
 * Reflect the scanned target in the address bar so the result can be shared,
 * bookmarked or reloaded. URLSearchParams encodes the value, and it is never
 * written back into the document.
 */
function pushLocation(url) {
  const params = new URLSearchParams(window.location.search);
  params.set("url", url);
  const next = `${window.location.pathname}?${params.toString()}`;
  if (next !== window.location.pathname + window.location.search) {
    window.history.pushState({ url }, "", next);
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const url = input.value.trim();
  if (!url) return;
  pushLocation(url);
  runScan(url);
});

// Back and forward should move between scans rather than leaving the page.
window.addEventListener("popstate", () => {
  const url = urlFromLocation();
  input.value = url;
  if (url) {
    runScan(url);
  } else {
    errorBox.hidden = true;
    summary.hidden = true;
    clear(results);
  }
});

// ?url=<target> prefills the field and scans immediately, so a scan can be
// linked to. The value is only ever read as text and sent to /scan, which
// validates it like any other request; nothing here trusts it.
(function scanFromQueryString() {
  const url = urlFromLocation();
  if (!url) return;
  input.value = url;
  runScan(url);
})();
