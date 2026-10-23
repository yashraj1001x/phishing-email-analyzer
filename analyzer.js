/**
 * analyzer.js — Core analysis engine
 * IBM BharatCares · Phishing Email Analyzer
 *
 * Depends on: rules.js (must be loaded first)
 */

// ── Email parser ───────────────────────────────────────────────────

/**
 * Parse raw pasted text into a structured email object.
 * We split on the first blank line to separate headers from body,
 * then extract well-known header fields by name.
 */
function parseEmail(rawText, attachmentText) {
  const raw = rawText || "";

  // Split headers from body on the first blank line
  const blankLineIdx = raw.search(/\r?\n\r?\n/);
  let headerSection = "";
  let bodySection   = raw;

  if (blankLineIdx !== -1) {
    headerSection = raw.slice(0, blankLineIdx);
    bodySection   = raw.slice(blankLineIdx).trim();
  }

  // Extract individual header fields (case-insensitive)
  function getHeader(name) {
    const re = new RegExp(`^${name}\\s*:\\s*(.+)`, "im");
    const m  = raw.match(re);
    return m ? m[1].trim() : "";
  }

  const rawFrom    = getHeader("from");
  const subject    = getHeader("subject");
  const to         = getHeader("to");
  const replyTo    = getHeader("reply-to");

  // Parse display name and email address from From field
  // Formats: "Display Name <email@domain.com>" or "email@domain.com"
  let displayName  = "";
  let senderEmail  = "";

  const angleMatch = rawFrom.match(/^(.*?)<([^>]+)>\s*$/);
  if (angleMatch) {
    displayName  = angleMatch[1].trim().replace(/^["']|["']$/g, "");
    senderEmail  = angleMatch[2].trim();
  } else {
    // Plain address
    senderEmail  = rawFrom.replace(/["']/g, "").trim();
  }

  // Attachments
  const attachmentLines = (attachmentText || "")
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(Boolean);

  return {
    raw,
    headers:      headerSection,
    sender:       rawFrom,
    displayName,
    senderEmail,
    to,
    replyTo,
    subject,
    body:         bodySection,
    attachments:  attachmentLines,
  };
}

// ── URL extractor ──────────────────────────────────────────────────

function extractURLs(text) {
  const re = /https?:\/\/[^\s<>"')\]]+/gi;
  const raw = text.match(re) || [];
  // Deduplicate
  return [...new Set(raw.map(u => u.replace(/[.,;:!?]+$/, "")))];
}

// ── IOC extractor ─────────────────────────────────────────────────

function extractIOCs(email) {
  const all = email.raw;

  // Email addresses
  const emailRe = /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g;
  const emailAddrs = [...new Set(all.match(emailRe) || [])];

  // URLs
  const urls = extractURLs(all);

  // Domains (extracted from URLs)
  const domainRe = /https?:\/\/([a-zA-Z0-9.\-]+)/gi;
  const domains = [];
  let dm;
  const seen = new Set();
  while ((dm = domainRe.exec(all)) !== null) {
    const d = dm[1].toLowerCase();
    if (!seen.has(d)) { seen.add(d); domains.push(d); }
  }

  // IPv4 addresses
  const ipRe = /\b(\d{1,3}\.){3}\d{1,3}\b/g;
  const ips = [...new Set(all.match(ipRe) || [])];

  // Hex hashes: 32 (MD5), 40 (SHA-1), 64 (SHA-256) character runs
  const hashRe = /\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b/g;
  const hashes = [...new Set(all.match(hashRe) || [])];

  return { emailAddrs, urls, domains, ips, hashes };
}

// ── URL classifier ─────────────────────────────────────────────────

const URL_FLAGS = [
  {
    label: "IP-based host",
    severity: "high",
    test: url => /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(url),
  },
  {
    label: "Suspicious TLD",
    severity: "high",
    test: url => /\.(xyz|tk|ml|ga|cf|gq|top|click|link|pw|cc|su|buzz|loan|win|download|zip|review|work|party|shop|online|site|website|space|live|stream)\b/i.test(url),
  },
  {
    label: "URL shortener",
    severity: "medium",
    test: url => /https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|shorturl\.at|rb\.gy|cutt\.ly|tiny\.cc|short\.link|clck\.ru)\//i.test(url),
  },
  {
    label: "Free hosting",
    severity: "medium",
    test: url => /\.(weebly\.com|wixsite\.com|blogspot\.com|000webhostapp\.com|freehostia\.com|netlify\.app|vercel\.app|github\.io|glitch\.me)\b/i.test(url),
  },
  {
    label: "Non-HTTPS",
    severity: "low",
    test: url => /^http:\/\//i.test(url),
  },
];

function classifyURL(url) {
  const flags = URL_FLAGS.filter(f => f.test(url));
  return flags; // empty array = no specific flags
}

// ── Attachment classifier ──────────────────────────────────────────

const ATTACH_RISK = {
  high:   /\.(exe|vbs|bat|cmd|scr|pif|jar|hta|wsf|lnk|ps1|msi)\b/i,
  medium: /\.(js|iso|img|docm|xlsm|pptm|one|pub)\b/i,
  low:    /\.(zip|rar|7z|doc|xls|xlt|ppt|odt|ods)\b/i,
};

function classifyAttachment(filename) {
  if (ATTACH_RISK.high.test(filename))   return { severity: "high",   reason: "Known malware delivery extension" };
  if (ATTACH_RISK.medium.test(filename)) return { severity: "medium", reason: "Macro-enabled or container file — can execute code" };
  if (ATTACH_RISK.low.test(filename))    return { severity: "low",    reason: "Common file type — generally safe, but verify the sender" };
  return { severity: "info", reason: "No known risk associated with this extension" };
}

// ── Authentication header parser ───────────────────────────────────

function parseAuthHeaders(headers) {
  if (!headers || !headers.trim()) return null;

  const result = {
    spf:   null,
    dkim:  null,
    dmarc: null,
    raw:   headers,
  };

  const spfM  = headers.match(/spf=(pass|fail|softfail|neutral|none|permerror|temperror)/i);
  const dkimM = headers.match(/dkim=(pass|fail|none)/i);
  const dmarcM = headers.match(/dmarc=(pass|fail|none)/i);

  if (spfM)   result.spf   = spfM[1].toLowerCase();
  if (dkimM)  result.dkim  = dkimM[1].toLowerCase();
  if (dmarcM) result.dmarc = dmarcM[1].toLowerCase();

  // Only return non-null if we found at least one auth header keyword
  const hasAny = /authentication-results|received-spf|dkim-signature/i.test(headers);
  return hasAny ? result : null;
}

// ── Main analysis function ─────────────────────────────────────────

/**
 * analyze(rawText, attachmentText)
 * Returns a complete result object consumed by app.js for rendering.
 */
function analyze(rawText, attachmentText) {
  if (!rawText || !rawText.trim()) {
    return { error: "No email content provided. Please paste an email to analyze." };
  }

  const email     = parseEmail(rawText, attachmentText);
  const auth      = parseAuthHeaders(email.headers);
  const urls      = extractURLs(email.body);
  const iocs      = extractIOCs(email);

  // ── Run all rules ──────────────────────────────────────────────
  const triggered = [];
  let rawScore    = 0;
  const seen      = new Set(); // prevent double-counting same id

  for (const rule of RULES) {
    if (seen.has(rule.id)) continue;
    let hit = false;
    try { hit = rule.check(email); } catch (_) { /* skip broken rule */ }
    if (hit) {
      triggered.push(rule);
      rawScore += rule.weight;
      seen.add(rule.id);
    }
  }

  // Clamp score to 0–100
  const score = Math.min(100, rawScore);

  // Risk level
  let level;
  if      (score >= 75) level = "Critical";
  else if (score >= 50) level = "High";
  else if (score >= 25) level = "Medium";
  else                  level = "Low";

  // ── Classify each URL ──────────────────────────────────────────
  const classifiedURLs = urls.map(url => ({
    url,
    flags: classifyURL(url),
  }));

  const suspiciousURLCount = classifiedURLs.filter(u => u.flags.length > 0).length;

  // ── Classify attachments ───────────────────────────────────────
  const classifiedAttachments = email.attachments.map(f => ({
    filename: f,
    ...classifyAttachment(f),
  }));

  const riskyAttachCount = classifiedAttachments.filter(a => a.severity === "high" || a.severity === "medium").length;

  // ── IOC counts ────────────────────────────────────────────────
  const iocCount = iocs.emailAddrs.length + iocs.urls.length + iocs.ips.length + iocs.hashes.length;

  return {
    error: null,
    score,
    level,
    triggered,
    email,
    auth,
    urls: classifiedURLs,
    suspiciousURLCount,
    attachments: classifiedAttachments,
    riskyAttachCount,
    iocs,
    iocCount,
  };
}

// ── Demo emails ────────────────────────────────────────────────────

const DEMO_EMAILS = [
  {
    label: "Demo 1 — Classic PayPal Phish",
    attachments: "invoice_details.exe\nreceipt.docm",
    raw: `From: PayPal Support <noreply@paypa1-secure.xyz>
To: victim@example.com
Subject: URGENT: Your PayPal Account Has Been SUSPENDED - Verify NOW!!!
Date: Mon, 01 Jan 2024 10:00:00 +0000
Authentication-Results: mx.example.com;
   spf=fail (sender IP is 185.220.101.45) smtp.mailfrom=paypa1-secure.xyz;
   dkim=fail header.d=paypa1-secure.xyz;
   dmarc=fail action=none header.from=paypa1-secure.xyz

Dear Customer,

We have detected unusual activity on your PayPal account. Your account has been SUSPENDED immediately until you verify your identity.

ACTION REQUIRED: You must act now or your account will be permanently deleted within 24 hours.

Click the link below to verify your account and restore access:
http://paypa1-secure.xyz/verify/account?token=ab12cd34ef56

If you do not confirm your account, we will be forced to take LEGAL ACTION.

Please provide your full name, credit card number, account number, and PIN number to verify your identity.

Regards,
PayPal Security Team

This is an automated message. Do not reply.`,
  },
  {
    label: "Demo 2 — Lottery Scam",
    attachments: "",
    raw: `From: UK National Lottery <lottery@win-notification.tk>
To: lucky.winner@example.com
Subject: CONGRATULATIONS!!! You Have WON £850,000 in the UK Lottery!!!
Date: Tue, 02 Jan 2024 09:00:00 +0000

Dear Beneficiary,

Congratulations! You are selected as our LUCKY WINNER in this year's UK National Lottery draw. You have won the sum of £850,000 (EIGHT HUNDRED AND FIFTY THOUSAND POUNDS).

To claim your prize reward, kindly revert with the following:
- Your full name
- Your date of birth
- Your social security number
- Your bank account and routing number

Send to our claims agent via: http://bit.ly/claim-lotto-prize or visit http://192.168.100.5/claim

This is a limited time offer. You must act immediately within 48 hours or the prize will expire.

Best Regards,
Mr. James Smith
UK Lottery Claims Department`,
  },
  {
    label: "Demo 3 — Legitimate-looking IT Alert (Lower Risk)",
    attachments: "security-report.pdf",
    raw: `From: IT Security Team <security@company-internal.com>
To: employee@company-internal.com
Subject: Monthly Security Report - January 2024
Date: Wed, 03 Jan 2024 08:00:00 +0000
Authentication-Results: mx.company-internal.com;
   spf=pass smtp.mailfrom=company-internal.com;
   dkim=pass header.d=company-internal.com;
   dmarc=pass

Hello John,

Please find attached the monthly security report for January 2024.

This month we observed 12 blocked phishing attempts and 3 malware detections.
The full report is attached as a PDF for your review.

For any questions please contact the IT Security team at security@company-internal.com.

Best regards,
IT Security Team
Company Inc.`,
  },
];
