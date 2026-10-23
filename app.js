/**
 * app.js — UI wiring and rendering
 * IBM BharatCares · Phishing Email Analyzer
 *
 * Depends on: rules.js, analyzer.js (loaded before this file)
 */

// ── DOM references ─────────────────────────────────────────────────
const elEmail       = document.getElementById("input-email");
const elAttachments = document.getElementById("input-attachments");
const btnAnalyze    = document.getElementById("btn-analyze");
const btnClear      = document.getElementById("btn-clear");
const btnDemo       = document.getElementById("btn-demo");
const btnCopyIOC    = document.getElementById("btn-copy-ioc");

const elEmptyState      = document.getElementById("empty-state");
const elResultsContent  = document.getElementById("results-content");

// Summary card elements
const elScoreValue  = document.getElementById("score-value");
const elScoreBar    = document.getElementById("score-bar");
const elScoreLevel  = document.getElementById("score-level");
const elCardScore   = document.getElementById("card-score");

const elStatSender  = document.getElementById("stat-sender");
const elDetailSender= document.getElementById("detail-sender");
const elStatLinks   = document.getElementById("stat-links");
const elDetailLinks = document.getElementById("detail-links");
const elStatAttach  = document.getElementById("stat-attach");
const elDetailAttach= document.getElementById("detail-attach");
const elStatIOC     = document.getElementById("stat-ioc");
const elDetailIOC   = document.getElementById("detail-ioc");

// Section blocks
const elFindingsList      = document.getElementById("findings-list");
const elSenderDetailBlock = document.getElementById("sender-detail-block");
const elLinksBlock        = document.getElementById("links-block");
const elAttachmentsBlock  = document.getElementById("attachments-block");
const elIocBlock          = document.getElementById("ioc-block");

// Demo picker state
let demoIndex = 0;

// ── Helpers ────────────────────────────────────────────────────────

/** Safely escape text for insertion as HTML text content */
function esc(text) {
  const div = document.createElement("div");
  div.textContent = String(text);
  return div.innerHTML;
}

function severityBadge(severity) {
  const map = { high: "badge-high", medium: "badge-medium", low: "badge-low", info: "badge-info" };
  const cls = map[severity] || "badge-info";
  return `<span class="finding-badge ${cls}">${esc(severity)}</span>`;
}

function statusPill(value) {
  if (!value) return `<span class="status-pill status-neutral">—</span>`;
  const v = value.toLowerCase();
  if (v === "pass")                         return `<span class="status-pill status-pass">PASS</span>`;
  if (v === "fail" || v === "softfail")     return `<span class="status-pill status-fail">${esc(value.toUpperCase())}</span>`;
  if (v === "none" || v === "neutral")      return `<span class="status-pill status-neutral">${esc(value.toUpperCase())}</span>`;
  return `<span class="status-pill status-warn">${esc(value.toUpperCase())}</span>`;
}

function urlSeverityBadge(flags) {
  if (!flags || flags.length === 0) return `<span class="finding-badge badge-info">clean</span>`;
  const top = flags.reduce((a, b) => {
    const order = { high: 3, medium: 2, low: 1 };
    return (order[a.severity] || 0) >= (order[b.severity] || 0) ? a : b;
  });
  return severityBadge(top.severity);
}

// ── Show / hide results ────────────────────────────────────────────

function showResults() {
  elEmptyState.classList.add("hidden");
  elResultsContent.classList.remove("hidden");
}

function showEmpty() {
  elEmptyState.classList.remove("hidden");
  elResultsContent.classList.add("hidden");
}

// ── Render functions ───────────────────────────────────────────────

function renderScore(score, level) {
  elScoreValue.textContent = score;
  elScoreBar.style.width   = score + "%";
  elScoreLevel.textContent = level + " Risk";

  const levelClass = "level-" + level.toLowerCase();
  elCardScore.className = "card card-score " + levelClass;
}

function renderSummaryCards(result) {
  // Sender
  const senderOk = result.triggered.some(r =>
    r.category === "Sender Spoofing" || r.category === "Header Analysis"
  );
  elStatSender.textContent  = senderOk ? "⚠ Issues Found" : "✓ No Issues";
  elStatSender.style.color  = senderOk ? "var(--danger)" : "var(--success)";
  elDetailSender.textContent = result.email.senderEmail || "—";

  // Links
  elStatLinks.textContent   = result.suspiciousURLCount;
  elStatLinks.style.color   = result.suspiciousURLCount > 0 ? "var(--warning)" : "var(--success)";
  elDetailLinks.textContent = result.urls.length + " total link(s) found";

  // Attachments
  elStatAttach.textContent  = result.riskyAttachCount;
  elStatAttach.style.color  = result.riskyAttachCount > 0 ? "var(--danger)" : "var(--success)";
  elDetailAttach.textContent = result.attachments.length + " file(s) listed";

  // IOCs
  elStatIOC.textContent     = result.iocCount;
  elStatIOC.style.color     = result.iocCount > 0 ? "var(--accent)" : "var(--text-muted)";
  elDetailIOC.textContent   = "unique indicators";
}

function renderFindings(triggered) {
  if (triggered.length === 0) {
    elFindingsList.innerHTML =
      `<div class="no-findings">✓ No suspicious indicators were found by the rule engine. The email appears low-risk based on the available content.</div>`;
    return;
  }

  // Sort by weight descending
  const sorted = [...triggered].sort((a, b) => b.weight - a.weight);

  elFindingsList.innerHTML = sorted.map(rule => `
    <div class="finding-item">
      ${severityBadge(rule.severity)}
      <div class="finding-content">
        <div class="finding-title">${esc(rule.title)}</div>
        <div class="finding-desc">${esc(rule.description)}</div>
        <div class="finding-weight">Category: ${esc(rule.category)} · Score contribution: +${rule.weight} pts</div>
      </div>
    </div>
  `).join("");
}

function renderSenderDetail(email, auth) {
  let html = "";

  html += `<div class="auth-row"><span class="auth-label">From (raw)</span><span class="auth-value">${esc(email.sender || "—")}</span></div>`;
  html += `<div class="auth-row"><span class="auth-label">Display Name</span><span class="auth-value">${esc(email.displayName || "—")}</span></div>`;
  html += `<div class="auth-row"><span class="auth-label">Sender Address</span><span class="auth-value">${esc(email.senderEmail || "—")}</span></div>`;
  html += `<div class="auth-row"><span class="auth-label">Reply-To</span><span class="auth-value">${esc(email.replyTo || "—")}</span></div>`;
  html += `<div class="auth-row"><span class="auth-label">To</span><span class="auth-value">${esc(email.to || "—")}</span></div>`;

  if (auth) {
    html += `<div class="auth-row"><span class="auth-label">SPF</span><span class="auth-value">${statusPill(auth.spf)}</span></div>`;
    html += `<div class="auth-row"><span class="auth-label">DKIM</span><span class="auth-value">${statusPill(auth.dkim)}</span></div>`;
    html += `<div class="auth-row"><span class="auth-label">DMARC</span><span class="auth-value">${statusPill(auth.dmarc)}</span></div>`;
  } else {
    html += `<div class="auth-row"><span class="auth-label">Authentication</span>
      <span class="auth-value" style="color:var(--text-muted);font-style:italic;">
        Authentication status unavailable — no authentication headers were found in the pasted text.
      </span></div>`;
  }

  elSenderDetailBlock.innerHTML = html;
}

function renderLinks(classifiedURLs) {
  if (classifiedURLs.length === 0) {
    elLinksBlock.innerHTML = `<div class="no-findings">No URLs were found in the email body.</div>`;
    return;
  }

  elLinksBlock.innerHTML = classifiedURLs.map(({ url, flags }) => {
    const flagHtml = flags.length > 0
      ? flags.map(f => `<span class="finding-badge ${
          f.severity === "high" ? "badge-high" : f.severity === "medium" ? "badge-medium" : "badge-low"
        }">${esc(f.label)}</span>`).join(" ")
      : `<span class="finding-badge badge-info">no flags</span>`;

    return `
      <div class="url-item">
        <div class="url-text">${esc(url)}</div>
        <div class="url-flag">${flagHtml}</div>
      </div>`;
  }).join("");
}

function renderAttachments(attachments) {
  if (attachments.length === 0) {
    elAttachmentsBlock.innerHTML = `<div class="no-findings">No attachments were provided for analysis.</div>`;
    return;
  }

  const sevIcon = { high: "🔴", medium: "🟡", low: "🟢", info: "⚪" };

  elAttachmentsBlock.innerHTML = attachments.map(a => `
    <div class="attach-item">
      <span>${sevIcon[a.severity] || "⚪"}</span>
      <span class="attach-name">${esc(a.filename)}</span>
      ${severityBadge(a.severity)}
      <span style="font-size:12px;color:var(--text-muted);">${esc(a.reason)}</span>
    </div>
  `).join("");
}

function renderIOCs(iocs) {
  const cats = [
    { key: "emailAddrs", label: "Email Addresses", items: iocs.emailAddrs },
    { key: "urls",       label: "URLs",            items: iocs.urls       },
    { key: "domains",    label: "Domains",         items: iocs.domains    },
    { key: "ips",        label: "IPv4 Addresses",  items: iocs.ips        },
    { key: "hashes",     label: "File Hashes",     items: iocs.hashes     },
  ];

  const nonEmpty = cats.filter(c => c.items.length > 0);

  if (nonEmpty.length === 0) {
    elIocBlock.innerHTML = `<p class="ioc-empty" style="padding:12px 0;">No IOCs were extracted from the email content.</p>`;
    return;
  }

  elIocBlock.innerHTML = nonEmpty.map(cat => `
    <div class="ioc-category">
      <div class="ioc-cat-title">${esc(cat.label)} (${cat.items.length})</div>
      <ul class="ioc-list">
        ${cat.items.map(v => `<li class="ioc-entry">${esc(v)}</li>`).join("")}
      </ul>
    </div>
  `).join("");
}

// ── Main render ────────────────────────────────────────────────────

function renderResult(result) {
  if (result.error) {
    elEmptyState.classList.remove("hidden");
    elResultsContent.classList.add("hidden");
    elEmptyState.innerHTML = `
      <div class="empty-icon">⚠</div>
      <p style="color:var(--danger);">${esc(result.error)}</p>`;
    return;
  }

  showResults();
  renderScore(result.score, result.level);
  renderSummaryCards(result);
  renderFindings(result.triggered);
  renderSenderDetail(result.email, result.auth);
  renderLinks(result.urls);
  renderAttachments(result.attachments);
  renderIOCs(result.iocs);

  // Scroll results panel into view on mobile
  if (window.innerWidth < 900) {
    document.getElementById("results-panel").scrollIntoView({ behavior: "smooth" });
  }
}

// ── Button handlers ────────────────────────────────────────────────

btnAnalyze.addEventListener("click", () => {
  const rawText        = elEmail.value;
  const attachmentText = elAttachments.value;
  const result         = analyze(rawText, attachmentText);
  renderResult(result);
});

btnClear.addEventListener("click", () => {
  elEmail.value       = "";
  elAttachments.value = "";
  // Reset empty state
  elEmptyState.innerHTML = `
    <div class="empty-icon">🔎</div>
    <p>Paste an email on the left and click <strong>Analyze Email</strong> to see the results here.</p>
    <p class="muted">No data is sent anywhere — all analysis runs in your browser.</p>`;
  showEmpty();
});

btnDemo.addEventListener("click", () => {
  const demo = DEMO_EMAILS[demoIndex % DEMO_EMAILS.length];
  elEmail.value       = demo.raw;
  elAttachments.value = demo.attachments;
  demoIndex++;

  // Auto-run analysis
  const result = analyze(demo.raw, demo.attachments);
  renderResult(result);

  btnDemo.textContent = `Load Demo (${(demoIndex % DEMO_EMAILS.length) + 1}/${DEMO_EMAILS.length})`;
});

btnCopyIOC.addEventListener("click", () => {
  // Gather IOC text from the rendered list
  const entries = document.querySelectorAll(".ioc-entry");
  if (entries.length === 0) {
    btnCopyIOC.textContent = "⚠ Nothing to copy";
    setTimeout(() => { btnCopyIOC.textContent = "📋 Copy IOCs"; }, 1500);
    return;
  }
  const text = Array.from(entries).map(el => el.textContent.trim()).join("\n");
  navigator.clipboard.writeText(text).then(() => {
    btnCopyIOC.textContent = "✓ Copied!";
    setTimeout(() => { btnCopyIOC.textContent = "📋 Copy IOCs"; }, 1500);
  }).catch(() => {
    // Fallback for browsers without clipboard API
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    btnCopyIOC.textContent = "✓ Copied!";
    setTimeout(() => { btnCopyIOC.textContent = "📋 Copy IOCs"; }, 1500);
  });
});

// Allow Ctrl+Enter in the email textarea to trigger analysis
elEmail.addEventListener("keydown", e => {
  if (e.ctrlKey && e.key === "Enter") {
    btnAnalyze.click();
  }
});

// Initialise demo button label
btnDemo.textContent = `Load Demo (1/${DEMO_EMAILS.length})`;
