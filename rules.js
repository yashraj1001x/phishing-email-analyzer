/**
 * rules.js — Rule definitions for the Phishing Email Analyzer
 * IBM BharatCares · Cybersecurity Project
 *
 * Each rule has:
 *   id          : unique string
 *   category    : grouping label
 *   title       : short finding title
 *   description : plain-English explanation for the user
 *   weight      : points (0–35) added to the risk score when triggered
 *   severity    : 'high' | 'medium' | 'low' | 'info'
 *   check(e)    : function(emailObject) → boolean
 *
 * emailObject shape:
 *   { raw, headers, sender, displayName, senderEmail,
 *     subject, body, attachments[] }
 */

// ── Keyword helpers ────────────────────────────────────────────────

const URGENCY_WORDS = [
  "urgent", "immediately", "act now", "limited time", "expire",
  "suspended", "verify now", "confirm immediately", "last chance",
  "your account will be", "account has been", "within 24 hours",
  "within 48 hours", "respond immediately", "action required",
  "important notice", "final warning", "last reminder", "must act",
  "account suspended", "access restricted", "security alert",
];

const REWARD_WORDS = [
  "you have won", "you've won", "congratulations", "winner",
  "prize", "reward", "free gift", "claim your", "you are selected",
  "lucky winner", "jackpot", "lottery", "unclaimed funds",
  "inheritance", "million dollars", "beneficiary",
];

const THREAT_WORDS = [
  "lawsuit", "legal action", "arrested", "police", "criminal",
  "penalty", "fined", "debt collection", "irs", "tax refund",
  "overdue payment", "court order", "warrant", "prosecuted",
  "deactivated", "blocked your account",
];

const CREDENTIAL_WORDS = [
  "verify your account", "confirm your password", "update your details",
  "login to confirm", "sign in to verify", "enter your credentials",
  "validate your email", "re-enter your", "banking details",
  "social security", "credit card number", "account number",
  "pin number", "provide your password", "confirm your email",
  "click here to verify", "click here to confirm",
  "click the link below to", "verify your identity",
];

const GENERIC_GREETINGS = [
  "dear customer", "dear user", "dear account holder",
  "dear valued member", "hello user", "dear sir/madam",
  "dear client", "to whom it may concern", "dear friend",
  "dear beneficiary",
];

const MISSPELLINGS = [
  "kindly revert", "do the needful", "we has detected",
  "your account is been", "you account", "recieve",
  "assocciated", "verfy", "accoont", "securty", "passward",
  "informaton", "acount", "updaet",
];

const SENSITIVE_REQUEST_WORDS = [
  "mother's maiden name", "date of birth", "ssn",
  "social security number", "passport number", "driver license",
  "bank account", "routing number", "wire transfer",
  "western union", "moneygram", "gift card", "itunes card",
  "google play card",
];

// ── Regex patterns ─────────────────────────────────────────────────

// NOTE: No /g flag on patterns used only with .test() — global regexes
// maintain lastIndex state and silently fail on repeated calls.
const RE_SUSPICIOUS_TLD = /https?:\/\/[^\s<>"]*\.(xyz|tk|ml|ga|cf|gq|top|click|link|pw|cc|su|buzz|loan|win|download|zip|review|work|party|shop|online|site|website|space|live|stream)\b/i;
const RE_IP_URL          = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i;
const RE_SHORTENED       = /https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|shorturl\.at|rb\.gy|cutt\.ly|tiny\.cc|short\.link|clck\.ru|t\.me)\//i;
const RE_ATTACH_RISKY    = /\.(exe|vbs|bat|cmd|scr|pif|jar|js|ps1|msi|hta|wsf|lnk|iso|img|docm|xlsm|pptm|xls|doc|odt|ods|pub|one)\b/i;
const RE_HTML_FORM       = /<\s*form\b/i;
const RE_FREE_HOSTING    = /https?:\/\/[^\s<>"]*\.(weebly\.com|wixsite\.com|blogspot\.com|000webhostapp\.com|freehostia\.com|x10host\.com|netlify\.app|vercel\.app|github\.io|glitch\.me)\b/i;
const RE_HTTP_ONLY       = /\bhttp:\/\//i;

// Lookalike brand substitutions
const LOOKALIKE_PAIRS = [
  ["paypa1", "paypal"], ["paypai", "paypal"], ["paypa|", "paypal"],
  ["arnazon", "amazon"], ["amaz0n", "amazon"], ["amazan", "amazon"],
  ["g00gle", "google"], ["gogle", "google"],
  ["micros0ft", "microsoft"], ["rniicrosoft", "microsoft"],
  ["appl3", "apple"], ["appie", "apple"],
  ["netfl1x", "netflix"], ["faceb00k", "facebook"],
  ["linkedln", "linkedin"], ["twittter", "twitter"],
  ["citibaank", "citibank"], ["wellsfarg0", "wellsfargo"],
];

// Known brand names — used for display-name vs domain mismatch
const KNOWN_BRANDS = [
  "paypal", "amazon", "google", "microsoft", "apple", "netflix",
  "facebook", "instagram", "twitter", "bank", "chase", "citibank",
  "hdfc", "icici", "sbi", "axis", "barclays", "hsbc", "linkedin",
  "dropbox", "docusign", "intuit", "wellsfargo",
];

// ── Helper functions ───────────────────────────────────────────────

function containsAny(text, words) {
  const t = text.toLowerCase();
  return words.some(w => t.includes(w));
}

// ── Rules array ────────────────────────────────────────────────────

const RULES = [
  // ── Social Engineering
  {
    id: "urgency_language",
    category: "Social Engineering",
    title: "Urgency language detected",
    description: "The email uses pressure words like 'act now', 'immediately', 'suspended', or 'within 24 hours' to push the recipient into acting without thinking. This is one of the most common phishing tactics.",
    weight: 18,
    severity: "high",
    check(e) { return containsAny(e.subject + " " + e.body, URGENCY_WORDS); }
  },
  {
    id: "reward_language",
    category: "Social Engineering",
    title: "Reward or prize language",
    description: "The email promises unexpected prizes, rewards, winnings, or inheritances. Legitimate organisations rarely send unsolicited prize notifications by email.",
    weight: 18,
    severity: "high",
    check(e) { return containsAny(e.subject + " " + e.body, REWARD_WORDS); }
  },
  {
    id: "threat_language",
    category: "Social Engineering",
    title: "Threat or intimidation language",
    description: "The email threatens legal action, fines, arrest, or account deactivation. Phishers use fear to override the recipient's caution.",
    weight: 18,
    severity: "high",
    check(e) { return containsAny(e.subject + " " + e.body, THREAT_WORDS); }
  },
  {
    id: "generic_greeting",
    category: "Social Engineering",
    title: "Generic, impersonal greeting",
    description: "The email uses a vague greeting such as 'Dear Customer' or 'Dear User' instead of addressing the recipient by name. Legitimate services usually address users by their real name.",
    weight: 8,
    severity: "low",
    check(e) { return containsAny(e.body, GENERIC_GREETINGS); }
  },
  {
    id: "excessive_caps",
    category: "Social Engineering",
    title: "Excessive capitalisation or exclamation marks",
    description: "The email uses many ALL-CAPS words or multiple exclamation marks (!! !!!). This is a classic alarm tactic designed to create panic.",
    weight: 8,
    severity: "low",
    check(e) {
      const capWords = (e.subject + " " + e.body).match(/\b[A-Z]{4,}\b/g) || [];
      const exclMatches = (e.subject + " " + e.body).match(/!{2,}/g) || [];
      return capWords.length >= 4 || exclMatches.length >= 3;
    }
  },
  {
    id: "sensitive_info_request",
    category: "Social Engineering",
    title: "Request for sensitive personal information",
    description: "The email asks for highly sensitive data such as SSN, passport number, gift card codes, or wire transfer details. No legitimate service asks for these via email.",
    weight: 28,
    severity: "high",
    check(e) { return containsAny(e.body, SENSITIVE_REQUEST_WORDS); }
  },

  // ── Credential Harvesting
  {
    id: "credential_request",
    category: "Credential Harvesting",
    title: "Request to enter or verify credentials",
    description: "The email asks the recipient to click a link and enter their password, account details, or login information. This is the defining characteristic of a phishing email.",
    weight: 25,
    severity: "high",
    check(e) { return containsAny(e.body, CREDENTIAL_WORDS); }
  },
  {
    id: "html_form",
    category: "Credential Harvesting",
    title: "HTML <form> tag in email body",
    description: "The email body contains an HTML form. Embedding forms in emails is highly unusual for legitimate senders and may be used to steal credentials directly inside the message.",
    weight: 25,
    severity: "high",
    check(e) { return RE_HTML_FORM.test(e.body); }
  },

  // ── Suspicious URLs
  {
    id: "ip_based_url",
    category: "Suspicious URLs",
    title: "IP-address-based link",
    description: "One or more links use a raw IP address (e.g. http://192.168.1.1/login) instead of a domain name. Legitimate services always use proper domain names.",
    weight: 30,
    severity: "high",
    check(e) { return RE_IP_URL.test(e.body); }
  },
  {
    id: "suspicious_tld",
    category: "Suspicious URLs",
    title: "Link with suspicious or unusual domain extension",
    description: "One or more links point to domains ending in .xyz, .tk, .ml, .top, .click, or similar low-credibility extensions that are commonly used in phishing campaigns.",
    weight: 22,
    severity: "high",
    check(e) { return RE_SUSPICIOUS_TLD.test(e.body); }
  },
  {
    id: "shortened_url",
    category: "Suspicious URLs",
    title: "URL shortener detected",
    description: "The email contains shortened URLs (e.g. bit.ly, tinyurl.com). Shorteners hide the real destination and are frequently abused in phishing campaigns.",
    weight: 18,
    severity: "medium",
    check(e) { return RE_SHORTENED.test(e.body); }
  },
  {
    id: "free_hosting",
    category: "Suspicious URLs",
    title: "Link to a free website hosting platform",
    description: "The email links to a free hosting platform (Weebly, Wix, Blogspot, Netlify, etc.). Attackers often create fake brand pages on these platforms because registration is free and instant.",
    weight: 15,
    severity: "medium",
    check(e) { return RE_FREE_HOSTING.test(e.body); }
  },
  {
    id: "many_urls",
    category: "Suspicious URLs",
    title: "Unusually high number of links",
    description: "The email contains five or more URLs. While not always malicious, a high link density combined with other indicators is a common phishing pattern.",
    weight: 10,
    severity: "low",
    check(e) {
      const urls = e.body.match(/https?:\/\/[^\s<>"')\]]+/gi) || [];
      return urls.length >= 5;
    }
  },
  {
    id: "http_only",
    category: "Suspicious URLs",
    title: "Non-HTTPS (unencrypted) links",
    description: "The email contains plain http:// links. Legitimate login or payment pages always use HTTPS. Unencrypted links may expose data entered by the user.",
    weight: 8,
    severity: "low",
    check(e) { return RE_HTTP_ONLY.test(e.body); }
  },

  // ── Sender Spoofing
  {
    id: "sender_domain_mismatch",
    category: "Sender Spoofing",
    title: "Sender display name does not match email domain",
    description: "The sender's display name claims to be from a well-known brand (e.g. 'PayPal Support'), but the actual email domain does not belong to that brand. This is called display-name spoofing.",
    weight: 30,
    severity: "high",
    check(e) {
      if (!e.displayName || !e.senderEmail) return false;
      const name = e.displayName.toLowerCase();
      const domain = e.senderEmail.split("@")[1] || "";
      return KNOWN_BRANDS.some(brand =>
        name.includes(brand) && !domain.toLowerCase().includes(brand)
      );
    }
  },
  {
    id: "lookalike_brand",
    category: "Sender Spoofing",
    title: "Lookalike brand name (character substitution)",
    description: "The sender address or email body contains a brand name with character substitutions designed to look real at a glance (e.g. 'Paypa1' for 'PayPal', 'Amaz0n' for 'Amazon').",
    weight: 30,
    severity: "high",
    check(e) {
      const combined = (e.sender + " " + e.body).toLowerCase();
      return LOOKALIKE_PAIRS.some(([fake]) => combined.includes(fake.toLowerCase()));
    }
  },
  {
    id: "suspicious_sender_domain",
    category: "Sender Spoofing",
    title: "Suspicious or unusual sender domain",
    description: "The sender's email domain does not look like a legitimate corporate domain. Examples: random strings, domains with many hyphens, or free email providers masquerading as official senders.",
    weight: 15,
    severity: "medium",
    check(e) {
      if (!e.senderEmail) return false;
      const domain = (e.senderEmail.split("@")[1] || "").toLowerCase();
      // Flag if domain has 3+ hyphens, is a free provider but claims to be a business,
      // or has a suspicious TLD
      const hasLongHyphens = (domain.match(/-/g) || []).length >= 3;
      const suspTLD = /\.(xyz|tk|ml|ga|cf|gq|top|click|pw|cc|su)\s*$/.test(domain);
      return hasLongHyphens || suspTLD;
    }
  },

  // ── Header Analysis
  {
    id: "spf_fail",
    category: "Header Analysis",
    title: "SPF authentication failure in headers",
    description: "The pasted email headers show that the SPF check failed or returned 'softfail'. SPF failure means the email was sent from a server not authorised by the domain owner — a strong indicator of spoofing.",
    weight: 35,
    severity: "high",
    check(e) {
      if (!e.headers) return false;
      return /spf=(fail|softfail|none)/i.test(e.headers);
    }
  },
  {
    id: "dkim_fail",
    category: "Header Analysis",
    title: "DKIM signature failure in headers",
    description: "The pasted email headers show that DKIM signature verification failed or is absent. DKIM failure means the email content may have been altered or the sender domain is spoofed.",
    weight: 30,
    severity: "high",
    check(e) {
      if (!e.headers) return false;
      return /dkim=(fail|none)/i.test(e.headers);
    }
  },
  {
    id: "dmarc_fail",
    category: "Header Analysis",
    title: "DMARC policy failure in headers",
    description: "The pasted email headers show that DMARC policy evaluation failed. DMARC failure confirms the email did not pass sender authentication, which is a strong phishing signal.",
    weight: 30,
    severity: "high",
    check(e) {
      if (!e.headers) return false;
      return /dmarc=(fail|none)/i.test(e.headers);
    }
  },

  // ── Malicious Payload
  {
    id: "risky_attachment",
    category: "Malicious Payload",
    title: "Potentially dangerous attachment type",
    description: "One or more attachment filenames have extensions commonly used to deliver malware: .exe, .vbs, .bat, .js, .hta, .scr, .ps1, or macro-enabled Office files (.docm, .xlsm). Never open such files from untrusted senders.",
    weight: 30,
    severity: "high",
    check(e) {
      return e.attachments.some(f => RE_ATTACH_RISKY.test(f));
    }
  },

  // ── Content Quality
  {
    id: "spelling_errors",
    category: "Content Quality",
    title: "Suspicious phrasing or spelling errors",
    description: "The email contains unusual phrasing or spelling mistakes commonly seen in phishing emails sent from non-native speakers or automated tools (e.g. 'kindly revert', 'do the needful', 'recieve').",
    weight: 8,
    severity: "low",
    check(e) { return containsAny(e.body, MISSPELLINGS); }
  },
];

// Export for use in analyzer.js
// (No ES modules needed — both scripts are loaded in the same page)
