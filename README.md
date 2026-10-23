# 🛡 Phishing Email Analyzer

**IBM BharatCares Cybersecurity Project**  
A local, rule-based web application that helps users identify phishing emails by analysing their content, links, attachments, and authentication headers — entirely inside the browser, with no server, no API keys, and no internet connection required.

---

## Problem Statement

Phishing emails are one of the most common and damaging cyber threats. They trick users into clicking malicious links, revealing passwords, or downloading malware — often by pretending to be from trusted organisations. Most people cannot easily tell the difference between a real email from their bank and a fake one designed to steal their credentials.

There is no simple, free, offline tool that a non-technical user can open and use immediately to check whether an email looks suspicious. This project addresses that gap.

---

## Objectives

1. Build a working web application that performs phishing analysis locally in the browser.
2. Detect common phishing indicators using a transparent, rule-based approach.
3. Explain every finding in plain language so a non-technical user can understand it.
4. Extract Indicators of Compromise (IOCs) such as email addresses, URLs, IPs, and file hashes.
5. Provide a risk score with a clear breakdown — not a black-box AI verdict.
6. Run without any installation, server, API key, or internet connection.

---

## Proposed Solution

The application accepts pasted email text (headers, subject, and body) and optionally a list of attachment filenames. It then runs **22 rule-based checks** across six categories:

| Category | What is checked |
|---|---|
| Social Engineering | Urgency words, reward promises, threats, generic greetings, ALL-CAPS |
| Credential Harvesting | Requests for passwords / account details, HTML forms in email |
| Suspicious URLs | IP-based links, suspicious TLDs, URL shorteners, free hosting platforms |
| Sender Spoofing | Display-name vs domain mismatch, lookalike brand names |
| Header Analysis | SPF, DKIM, DMARC results from pasted headers |
| Malicious Payload | Risky attachment file extensions |

Each triggered rule adds weighted points to a **risk score (0–100)**, capped at 100. The score maps to a risk level: **Low / Medium / High / Critical**.

> ⚠ This is a **rule-based prototype**. It is not a trained AI or machine learning model. Results are indicative and should be verified by a security professional.

---

## Features

### Feature 1 — Email Input
- Large text area for pasting the full email (headers + body).
- Separate field for typing attachment filenames (one per line).
- **Load Demo** button that cycles through 3 pre-loaded fictional phishing examples.
- **Ctrl + Enter** shortcut to run analysis from the keyboard.

### Feature 2 — Sender Spoofing Detector
- Parses the `From:` header into display name and actual email address.
- Flags when the display name claims to be a known brand (PayPal, Amazon, HDFC, etc.) but the email domain does not match.
- Detects lookalike character substitutions (e.g. `paypa1`, `amaz0n`, `micros0ft`).
- Checks for suspicious sender domains (too many hyphens, unusual TLDs).
- Reads SPF, DKIM, and DMARC results **only if authentication headers are present** in the pasted text. If they are absent, displays "Authentication status unavailable" rather than inventing a result.

### Feature 3 — Link and Attachment Scanner
- Extracts all `http://` and `https://` URLs from the email body.
- Flags each URL for: IP-based host, suspicious TLD, URL shortener, free hosting platform, and unencrypted HTTP.
- Analyses attachment filenames for risky extensions: `.exe`, `.vbs`, `.bat`, `.cmd`, `.scr`, `.pif`, `.jar`, `.hta`, `.wsf`, `.lnk`, `.ps1`, `.msi` (High risk) and `.js`, `.iso`, `.docm`, `.xlsm`, `.pptm`, `.one` (Medium risk).
- Never opens, executes, or uploads any file or link.

### Feature 4 — IOC Extraction
- Extracts and deduplicates: email addresses, URLs, domains, IPv4 addresses, and hex file hashes (MD5/SHA-1/SHA-256).
- Displays each category in a separate section.
- **Copy IOCs** button copies all extracted values to the clipboard.

### Feature 5 — Phishing Risk Score
- Weighted score from 0 to 100, built from 22 rules.
- Each rule contributes its own points only once (no double-counting).
- Score is capped at 100.
- Risk levels: **Low** (0–24) · **Medium** (25–49) · **High** (50–74) · **Critical** (75–100).
- Every triggered rule is listed with its category, plain-English explanation, and exact point contribution.

---

## Technologies Used

| Technology | Purpose |
|---|---|
| HTML5 | App structure and layout |
| CSS3 (custom, no framework) | Dark-navy cybersecurity dashboard theme |
| Vanilla JavaScript (ES6+) | Email parsing, rule engine, UI rendering |
| Browser localStorage | (available for future history feature) |
| Browser Clipboard API | Copy IOCs button |

No external libraries, no npm, no build tools, no server, no database.

---

## System Requirements

| Requirement | Minimum |
|---|---|
| Operating System | Windows 10 / 11, macOS 10.15+, or any modern Linux |
| Browser | Chrome 90+, Edge 90+, or Firefox 90+ |
| Internet connection | **Not required** for any core feature |
| Disk space | < 100 KB (all files combined) |
| RAM | Any modern computer |
| Installation | None |

---

## Project File Structure

```
phishing-email-analyzer/
│
├── index.html              ← Main application page (open this to run the app)
│
├── static/
│   ├── css/
│   │   └── style.css       ← Full dark-navy dashboard stylesheet
│   └── js/
│       ├── rules.js        ← 22 rule definitions, keyword lists, regex patterns
│       ├── analyzer.js     ← Email parser, IOC extractor, URL/attachment classifiers
│       └── app.js          ← Button handlers and DOM rendering
│
├── README.md               ← This file
└── PROJECT_REPORT.md       ← Detailed project report
```

---

## Installation and Execution (Windows 11)

**No installation required.**

1. Download or copy the project folder to your computer.
2. Open **File Explorer** and navigate to the project folder.
3. Double-click `index.html`.
4. The application opens in your default browser immediately.

**Recommended browsers:** Google Chrome or Microsoft Edge.

> If your browser shows a blank page, right-click `index.html` → **Open with** → **Google Chrome** or **Microsoft Edge**.

---

## Application Workflow

```
User pastes email text
        │
        ▼
[parseEmail()] ── splits headers from body, extracts From/To/Subject/Reply-To
        │
        ▼
[parseAuthHeaders()] ── reads SPF/DKIM/DMARC only if auth headers are present
        │
        ▼
[RULES loop] ── each of 22 rules runs check() on the email object
        │            triggered rules add their weight to rawScore
        ▼
score = min(rawScore, 100) ── capped at 100
        │
        ▼
[extractURLs()] ── finds all http/https links in the body
[classifyURL()] ── flags each link for specific risks
        │
        ▼
[classifyAttachment()] ── checks each filename extension
        │
        ▼
[extractIOCs()] ── pulls email addresses, URLs, IPs, hashes
        │
        ▼
[renderResult()] ── builds the dashboard: score card, findings,
                    sender detail, links, attachments, IOCs
```

---

## How the Risk Score Is Calculated

The risk score is **purely additive and rule-based**. It is not produced by a machine learning model.

Each rule has a fixed weight based on how strongly that indicator is associated with phishing:

| Weight range | Examples |
|---|---|
| 30–35 pts | IP-based URL, sender domain mismatch, lookalike brand, SPF fail, DMARC fail |
| 25–28 pts | Credential request, HTML form, sensitive info request |
| 18–22 pts | Urgency language, reward language, threat language, suspicious TLD |
| 8–15 pts | Generic greeting, excessive caps, HTTP-only links, free hosting |

The weights are summed across all triggered rules. The total is then capped at 100.

**Score → Risk Level mapping:**

| Score | Level |
|---|---|
| 0 – 24 | 🟢 Low |
| 25 – 49 | 🟡 Medium |
| 50 – 74 | 🔴 High |
| 75 – 100 | 🔴 Critical |

Every finding that contributed to the score is listed in the Findings section with its exact point contribution, so the score is fully transparent and explainable.

---

## Sample Test Cases and Expected Behaviour

### Test Case 1 — Classic PayPal Phish (Demo 1)
**Input:** Click "Load Demo (1/3)"  
**Key indicators:** Lookalike sender domain (`paypa1-secure.xyz`), SPF=fail, DKIM=fail, DMARC=fail, urgency subject, credential request, `.exe` and `.docm` attachments, IP-based link  
**Expected:** Score ≥ 75 · Level: **Critical** · Multiple High findings

### Test Case 2 — Lottery Scam (Demo 2)
**Input:** Click "Load Demo (2/3)"  
**Key indicators:** Reward language ("You have won"), suspicious TLD (`.tk`), URL shortener (bit.ly), IP-based link, generic greeting ("Dear Beneficiary"), sensitive info request (SSN, bank account), threat language  
**Expected:** Score ≥ 75 · Level: **Critical** · Multiple High findings

### Test Case 3 — Legitimate IT Email (Demo 3)
**Input:** Click "Load Demo (3/3)"  
**Key indicators:** SPF=pass, DKIM=pass, DMARC=pass, no urgency, no credential request, `.pdf` attachment  
**Expected:** Score < 25 · Level: **Low** · No or very few findings

### Test Case 4 — Manual: Empty input
**Input:** Click Analyse Email with empty text area  
**Expected:** Error message "No email content provided" · Results panel stays hidden

### Test Case 5 — Manual: Body-only (no headers)
**Input:** Paste just a suspicious email body without any headers  
**Expected:** Authentication status shows "unavailable" · URL/keyword rules still run on the body text

---

## Limitations

1. **Rule-based only** — The engine uses fixed keyword lists and regex patterns. It will not detect novel or sophisticated phishing techniques that avoid known patterns.
2. **No live threat intelligence** — No connection is made to VirusTotal, Google Safe Browsing, or any threat feed. A URL cannot be confirmed as malicious, only flagged as suspicious.
3. **Header parsing is best-effort** — Standard Gmail/Outlook copy-pasted headers work well. Unusual header formats or folded header lines may not parse correctly.
4. **Attachment filenames only** — File contents are never analysed, opened, or uploaded.
5. **False positives possible** — A legitimate marketing email with many links or urgency language may score medium.
6. **False negatives possible** — A carefully crafted phishing email that avoids all keyword patterns and uses a clean domain will score low.
7. **No persistent storage** — Analysis history is not saved between browser sessions in the current version.
8. **English language** — Keyword rules are written for English-language emails only.

---

## Privacy and Security Considerations

- **All analysis runs locally in the browser.** No email content is ever sent to a server, external API, or third-party service.
- **No URLs are fetched.** The app extracts and displays URLs but never opens or visits them.
- **No files are opened.** Attachment analysis is limited to filename text only.
- **Pasted email content is treated as plain text.** The app never executes any HTML or JavaScript found inside the pasted email.
- **No tracking, no cookies, no analytics.**

---

## Future Enhancements

| Enhancement | Description |
|---|---|
| Analysis history | Save the last 10 analyses to browser localStorage |
| Export report | Download the full analysis as a PDF or formatted text file |
| VirusTotal integration | Optional lookup for URL reputation (requires API key, user opt-in) |
| Multi-language support | Extend keyword rules for Hindi and other languages |
| Email file upload | Accept `.eml` and `.msg` files directly instead of pasting |
| Dark/light mode toggle | User preference for theme |
| Machine learning layer | Train a classifier on a labelled phishing dataset as an optional enhancement |

---

## Conclusion

The Phishing Email Analyzer is a functional, beginner-friendly cybersecurity tool built entirely with HTML, CSS, and vanilla JavaScript. It runs locally without any installation, analyses emails using 22 transparent, rule-based checks, and presents results in a clean professional dashboard. It is an honest prototype — it clearly labels its scoring as rule-based, does not claim AI capabilities it does not have, and does not fabricate results from services it never calls.

---

*IBM BharatCares Cybersecurity Project · Rule-based prototype · Not a trained AI model · Results should be verified by a security professional.*
