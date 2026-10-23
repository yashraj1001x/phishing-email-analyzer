# Project Report

## Phishing Email Analyzer

**Project Title:** Phishing Email Analyzer  
**Organisation:** IBM BharatCares  
**Domain:** Cybersecurity  
**Technology:** HTML5, CSS3, Vanilla JavaScript  
**Type:** Client-side web application (runs in browser, no server required)

---

## 1. Abstract

Phishing is a form of cyber attack in which a criminal sends a fake email designed to look like it came from a trusted organisation. The goal is to trick the recipient into clicking a dangerous link, entering their password, or downloading malware. Phishing attacks are responsible for a large percentage of data breaches worldwide, and they are growing in number every year.

This project presents a **Phishing Email Analyzer** — a web application that allows a user to paste the text of any email and receive an immediate, detailed analysis of how suspicious it is. The application uses 22 rule-based checks across six categories: social engineering language, credential harvesting indicators, suspicious URLs, sender spoofing, email authentication results, and dangerous attachment types. Each check has a defined weight. The weights are added together to produce a transparent risk score from 0 to 100, which maps to a risk level of Low, Medium, High, or Critical. The application extracts Indicators of Compromise (IOCs) and explains every finding in plain language.

The entire application runs locally inside the browser. No email content is sent anywhere. No API keys or installations are required. The tool is a rule-based prototype and is not powered by a trained AI or machine learning model.

---

## 2. Introduction

### 2.1 Background

The Internet is an essential part of modern life, and email is one of its most widely used communication channels. Unfortunately, this also makes email one of the most common attack vectors for cybercriminals. According to publicly available cybersecurity research, more than 90% of cyberattacks begin with a phishing email.

A phishing email typically impersonates a trusted entity such as a bank, payment service, or government department. It uses psychological manipulation — urgency, fear, or the promise of a reward — to make the recipient act quickly without thinking. The email usually contains a link to a fake website that collects login credentials, or an attachment that installs malware.

### 2.2 Motivation

Existing phishing detection tools are either built into email clients (where they work silently in the background) or are complex enterprise products. There is no simple, free tool that a student, small business owner, or non-technical user can open in a browser, paste a suspicious email into, and get a clear explanation of what looks wrong and why.

### 2.3 Project Context

This project was developed as part of the IBM BharatCares initiative, which supports students in building practical technology skills for real-world problems. The goal was to build a working, useful, and honest cybersecurity application within a short timeframe using only basic web technologies.

---

## 3. Problem Definition

### The problem being solved:
> Most people cannot easily tell whether an email is a phishing attempt. There is no simple, offline, free tool that analyses email content and explains suspicious indicators in plain language.

### Specific challenges addressed:
- Users do not know which parts of an email to check (headers, sender domain, links, language).
- Even when they notice something odd, they do not know how serious it is.
- Existing tools either require installation, API keys, server access, or they provide only a verdict without an explanation.

### Scope of this project:
- Text-based analysis of pasted email content only.
- No live network checks, no file execution, no AI models.
- Works on any modern computer with a browser, even without internet.

---

## 4. Objectives

1. **Build a functional web application** that analyses pasted email content for phishing indicators.
2. **Implement 22 rule-based checks** covering six phishing indicator categories.
3. **Produce a transparent, explainable risk score** — not a black-box verdict.
4. **Detect sender spoofing** through display-name vs domain comparison and lookalike character checks.
5. **Interpret authentication headers** (SPF, DKIM, DMARC) only when they are actually present in the pasted text.
6. **Extract and display IOCs** (email addresses, URLs, IPs, file hashes) for further investigation.
7. **Analyse attachment filenames** for known dangerous file extensions.
8. **Design a professional UI** that is approachable for a non-technical user.
9. **Ensure privacy** by keeping all processing local, sending nothing to any external service.

---

## 5. System Design and Workflow

### 5.1 Architecture

The application has a single-page architecture with no backend server. Three JavaScript files work together:

```
┌───────────────────────────────────────────────────────────┐
│                        index.html                         │
│          (Layout, UI elements, loads scripts)             │
└──────────────────────────┬────────────────────────────────┘
                           │ loads in order
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
      rules.js        analyzer.js        app.js
   (Rule definitions) (Analysis engine) (UI / events)
```

- **[`rules.js`](static/js/rules.js)** — Contains all rule objects, keyword lists, and regex patterns. A rule is a plain JavaScript object with an `id`, `category`, `title`, `description`, `weight`, `severity`, and a `check(email)` function that returns `true` or `false`.
- **[`analyzer.js`](static/js/analyzer.js)** — Contains the email parser, URL extractor, IOC extractor, URL classifier, attachment classifier, authentication header parser, and the main `analyze()` function. Also holds the 3 demo emails.
- **[`app.js`](static/js/app.js)** — Handles all button events and translates the result object from `analyzer.js` into HTML rendered on screen.

### 5.2 Workflow Diagram

```
User Input (pasted email text + optional filenames)
            │
            ▼
      parseEmail()
      ├── Split on first blank line → headers / body
      ├── Extract: From, To, Subject, Reply-To
      └── Parse From into displayName + senderEmail
            │
            ▼
      parseAuthHeaders()
      └── Looks for SPF/DKIM/DMARC only if auth header keywords present
            │
            ▼
      Run 22 RULES  (loop over RULES array)
      └── For each rule: call check(email)
          If true → add rule.weight to rawScore, record finding
            │
            ▼
      score = min(rawScore, 100)
      level = Critical / High / Medium / Low
            │
            ├── extractURLs()  → classifyURL() per URL
            ├── classifyAttachment() per filename
            └── extractIOCs() → emails, URLs, domains, IPs, hashes
                        │
                        ▼
                  renderResult()
                  ├── Score card + risk meter
                  ├── Summary cards (sender, links, attachments, IOCs)
                  ├── Findings list (sorted by weight, with explanations)
                  ├── Sender & authentication detail
                  ├── Link table with flags
                  ├── Attachment table with severity
                  └── IOC sections with Copy button
```

---

## 6. Methodology

### 6.1 Rule-Based Approach

The application uses a **rule-based expert system** — a set of human-defined rules that encode expert knowledge about what phishing emails look like. This approach was chosen because:

- It is fully transparent (every decision is explainable).
- It does not require a large dataset of labelled emails to train.
- It can be built and understood by a student without machine learning expertise.
- It runs instantly, with no computation overhead.

### 6.2 Rule Categories and Rationale

**Social Engineering (5 rules):** Phishing emails manipulate human psychology. Rules check for urgency/pressure language, reward promises, threats of legal action, generic greetings (a sign the sender doesn't know the recipient), and excessive capitalisation.

**Credential Harvesting (2 rules):** Rules check for explicit requests to enter passwords or account details, and for the presence of HTML `<form>` tags embedded in email bodies.

**Suspicious URLs (6 rules):** Rules check each URL in the body for: raw IP address as host, suspicious domain extensions (TLDs), known URL shortener services, free hosting platforms, and unencrypted HTTP.

**Sender Spoofing (3 rules):** Rules compare the sender's display name against the actual email domain, check for lookalike brand name substitutions (e.g. `paypa1` for `paypal`), and flag domains with structural anomalies.

**Header Analysis (3 rules):** Rules read SPF, DKIM, and DMARC results from the pasted headers. These are standard email authentication mechanisms. A failure means the email server was not authorised to send on behalf of the stated domain.

**Malicious Payload (1 rule):** Checks attachment filenames against a list of extensions associated with malware delivery.

### 6.3 Scoring Design

Weights were assigned based on how strongly each indicator is associated with phishing in well-known cybersecurity literature and publicly available phishing datasets:

- Indicators that are almost never seen in legitimate email (IP-based URL, SPF fail + domain mismatch) receive the highest weights (30–35 pts).
- Common indicators that can also appear in legitimate email (generic greeting, HTTP link) receive lower weights (8–10 pts).
- Multiple low-weight indicators combine to raise the score, which is the intended design — a single HTTP link should not flag an email as critical.

### 6.4 IOC Extraction

IOCs (Indicators of Compromise) are technical artefacts that a security analyst would use in further investigation. The application extracts these using regular expressions:

- **Email addresses** — standard RFC-5322-like pattern.
- **URLs** — all `http://` and `https://` links.
- **Domains** — extracted from URL hostnames.
- **IPv4 addresses** — standard dotted-quad pattern.
- **File hashes** — 32-character (MD5), 40-character (SHA-1), and 64-character (SHA-256) hexadecimal strings.

---

## 7. Implementation Details

### 7.1 Email Parsing

The email is split at the first blank line, following the RFC 2822 standard that separates email headers from the body. Individual header fields are extracted using case-insensitive regular expressions. The `From:` field is parsed to separate the display name from the actual email address using angle-bracket notation.

### 7.2 Authentication Header Parsing

The parser searches for the keywords `authentication-results`, `received-spf`, or `dkim-signature` to determine whether authentication headers are present at all. If they are present, it extracts the `spf=`, `dkim=`, and `dmarc=` values. If no authentication headers are found, the result is `null` and the UI displays "Authentication status unavailable" — it never invents a pass or fail result.

### 7.3 Regex Safety

All regular expressions used in `.test()` calls are defined without the global (`/g`) flag. This is an important correctness detail: JavaScript global regexes maintain internal state (`lastIndex`) between calls on the same regex object, which would cause them to silently return `false` on every second analysis. Non-global regexes do not have this problem. Regex patterns used with `.match()` (which needs all occurrences) are created with fresh inline literals each time.

### 7.4 XSS Prevention

The application treats all pasted email content as untrusted plain text. A helper function `esc()` in [`app.js`](static/js/app.js) converts every string to a DOM text node before inserting it as HTML (`div.textContent = value; return div.innerHTML`). This means any HTML or JavaScript embedded in the pasted email is displayed as text characters, not executed.

### 7.5 Technologies Used

| Component | Technology |
|---|---|
| Structure | HTML5 semantic elements |
| Styling | CSS3 custom properties (variables), CSS Grid, Flexbox |
| Logic | Vanilla JavaScript ES6+ (const/let, arrow functions, template literals, Set, spread operator) |
| Clipboard | Web Clipboard API with `execCommand` fallback |
| Storage | None in current version |

No libraries (no jQuery, no Bootstrap, no React). No build tools (no npm, no webpack). No server.

---

## 8. Testing and Results

Testing was performed manually by loading each demo email and verifying that the correct rules were triggered and the correct score was produced.

### Test Case 1 — Demo 1: PayPal Phish

| Input feature | Expected rule triggered |
|---|---|
| `noreply@paypa1-secure.xyz` | Lookalike brand, Sender domain mismatch |
| `spf=fail`, `dkim=fail`, `dmarc=fail` | SPF fail, DKIM fail, DMARC fail |
| Subject: "URGENT ... SUSPENDED" | Urgency language, Excessive caps |
| Body: "verify your account", "credit card number" | Credential request, Sensitive info |
| `http://paypa1-secure.xyz/...` (non-HTTPS) | Suspicious TLD, HTTP-only |
| `invoice_details.exe`, `receipt.docm` | Risky attachment |

**Observed result:** Score > 75 · Risk level: Critical ✓

### Test Case 2 — Demo 2: Lottery Scam

| Input feature | Expected rule triggered |
|---|---|
| `lottery@win-notification.tk` | Suspicious sender domain, Suspicious TLD |
| Body: "You have won", "Lucky Winner" | Reward language |
| Body: "legal action", "debt collection" | Threat language |
| `http://bit.ly/...`, `http://192.168.100.5/...` | URL shortener, IP-based URL |
| Body: "bank account", "routing number" | Sensitive info request |
| Body: "Dear Beneficiary" | Generic greeting |
| Body: "within 48 hours" | Urgency language |

**Observed result:** Score > 75 · Risk level: Critical ✓

### Test Case 3 — Demo 3: Legitimate IT Email

| Input feature | Expected behaviour |
|---|---|
| `spf=pass`, `dkim=pass`, `dmarc=pass` | No auth failures triggered |
| Personalised greeting ("Hello John") | Generic greeting rule NOT triggered |
| No URLs in body | No URL rules triggered |
| `.pdf` attachment | No risky attachment rule triggered |
| No urgency / credential words | No social engineering rules triggered |

**Observed result:** Score < 25 · Risk level: Low ✓

### Test Case 4 — Empty Input

**Input:** Click Analyze with empty text area  
**Observed result:** Error message displayed, results panel remains hidden ✓

### Test Case 5 — No Headers Provided

**Input:** Paste only an email body (no headers)  
**Observed result:** Authentication section shows "Authentication status unavailable". URL and keyword rules still execute on the body text ✓

---

## 9. Limitations

### 9.1 False Positives
A legitimate email may trigger rules and receive a medium risk score. For example, a marketing newsletter with many links and urgency language ("Last chance — offer expires today!") could score in the medium range even though it is not malicious. Users are advised to read the individual findings and use their own judgement.

### 9.2 False Negatives
A sophisticated phishing email that uses a clean, newly registered domain, avoids all keyword patterns, and has valid SPF/DKIM records will score very low. Rule-based systems cannot detect threats they have no rules for.

### 9.3 Header Parsing
The parser handles standard Gmail and Outlook copy-pasted headers correctly. Unusual or proprietary header formats, folded headers (multi-line values), and encoded header values (Base64 or quoted-printable) may not parse correctly.

### 9.4 Language
All keyword rules are in English. Phishing emails in Hindi, Tamil, Telugu, or other Indian languages will not trigger the keyword rules, though URL and sender-based rules will still apply.

### 9.5 No File Content Analysis
Attachment analysis is limited to filename extensions. A file named `report.pdf` that actually contains malware will not be detected. A file named `document.exe` that is harmless will still be flagged because of its extension.

### 9.6 No Network Checks
The application cannot verify whether a URL is actually malicious. It can only flag URLs that match structural patterns associated with phishing. A clean-looking URL to a freshly created phishing site will not be flagged.

---

## 10. Future Scope

### 10.1 Short-Term (1–3 months)
- Add analysis history saved to browser `localStorage`.
- Add a one-click export of the full report as a text file.
- Expand keyword rules to cover Hindi and regional Indian language phishing patterns.

### 10.2 Medium-Term (3–12 months)
- Add support for uploading `.eml` (standard email file) and `.msg` (Outlook) formats so users do not need to copy-paste.
- Integrate an optional VirusTotal URL lookup (user provides their own free API key; opt-in only).
- Add a rule-effectiveness feedback mechanism — users can mark a result as incorrect, which feeds into rule refinement.

### 10.3 Long-Term
- Train a supervised machine learning classifier on a labelled phishing email dataset (such as the SpamAssassin or Enron datasets) as a second analysis layer alongside the rule engine.
- Build a browser extension version that analyses incoming emails directly in Gmail or Outlook Web.
- Add multi-language NLP support.

---

## 11. Conclusion

The Phishing Email Analyzer successfully meets all project objectives. It is a working, functional web application that:

- Analyses pasted email content using 22 transparent, rule-based checks.
- Produces an explainable risk score from 0 to 100.
- Detects sender spoofing, suspicious links, dangerous attachments, and authentication failures.
- Extracts Indicators of Compromise for further investigation.
- Operates entirely in the browser without any server, API key, or internet connection.
- Respects user privacy — no data leaves the device.

The project demonstrates the application of cybersecurity concepts (phishing anatomy, email authentication protocols, IOC analysis) in a practical, accessible software tool. It is honest about what it is — a rule-based prototype — and does not claim capabilities it does not have.

The most important technical lesson from this project is that useful security tools do not need to be complex. A small number of well-chosen, well-explained rules, presented in a clean interface, can give a non-technical user genuine and actionable insight into whether an email is safe.

---

*Submitted as part of IBM BharatCares Cybersecurity Project.*  
*All analysis is performed locally. No email content is transmitted to any external service.*  
*This is a rule-based prototype, not a trained AI model.*
