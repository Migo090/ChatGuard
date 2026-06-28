# ChatGuard v3.0

> Automated Chat Widget Security Scanner — detects Intercom & Pylon IDOR misconfigurations.

ChatGuard inspects how a site embeds its support-chat widget and flags the missing
**Identity Verification** (`user_hash` HMAC) that lets an attacker read or hijack other
users' conversations. It's a single-page app with **zero dependencies and no build step** —
just static HTML, CSS, and vanilla JS served from any file server.

## Features

- **Scanner** — point it at a target (or the bundled offline demo) to extract the widget
  `app_id`, detect the vendor, and surface A01–A03 findings.
- **Inspector** — drill into a finding: view the crafted proof-of-concept request, tweak
  parameters live, and inspect the raw extracted source.
- **History** — every scan is saved locally; filter past runs and re-open any of them in
  the Inspector.
- **Analytics** — at-a-glance breakdown of findings by severity and vendor.
- **Guide** — built-in explainer of each vulnerability class and how to remediate it.
- **Settings** — tune the request templates (email, user-id type) used in PoCs.
- **Strict CSP, sanitized everywhere** — see the [Security Model](#security-model) below.

## Project Structure

```
chatguard/
├── index.html          ← Application shell + markup (no inline JS, no inline event handlers)
├── css/
│   └── main.css        ← All styles (design tokens, layout, components)
├── js/
│   ├── app.js          ← Core application: utils (escapeHtml, safeUrl, setText),
│   │                     modal, storage, TemplateManager, ScannerEngine,
│   │                     Inspector, Analytics, ReportManager, Navigation
│   └── events.js       ← All DOM event bindings (wired after DOMContentLoaded,
│                         no inline onclick — required for script-src 'self' CSP)
└── demo/
    └── target.html     ← Local demo target — fake Intercom widget (no external calls)
```

> The application logic lives in a single `js/app.js` (self-contained `'use strict'`
> IIFE modules) with DOM wiring isolated in `js/events.js`. This keeps the CSP strict
> (`script-src 'self'`, no inline handlers) while remaining trivial to serve statically.

## Running

Serve from any static file server — the app needs `file://` access to load JS modules:

```bash
# Python 3
python3 -m http.server 8080

# Node
npx serve .

# Then open: http://localhost:8080
```

> **Note:** Opening `index.html` directly via `file://` will block the JS module
> loads due to CORS. Use a local server.

## Demo Scan

Click **Demo** in the Scanner tab. The scanner will analyze `demo/target.html` —
a bundled page with a deliberately misconfigured fake Intercom widget (`app_id: cgdemo01`,
no `user_hash`) that triggers A01 and A02 findings without making any external network calls.

The `app_id` is intentionally an 8-character alphanumeric string so it satisfies the
extractor's validity constraint (`/^[a-zA-Z0-9]{6,10}$/`) and surfaces cleanly in the
Inspector and findings card.

## Security Model

### XSS Prevention
All user-controlled strings are sanitized before entering `innerHTML`:

| Source | Goes into | Protection |
|--------|-----------|------------|
| URL input (`targetUrl`) | Log, history table | `escapeHtml()` |
| `app_id` (extracted from remote JS) | Inspector, findings card | `escapeHtml()` |
| `vendor` (detected from remote source) | History table | `escapeHtml()` |
| Scan log messages (filenames from CDN) | Log area | `escapeHtml()` |
| User settings (email, userIdType) | Templates | `textContent` only |

Functions that touch the DOM:
- `escapeHtml(str)` — HTML-encodes `&`, `<`, `>`, `"`, `'`, `/`
- `safeUrl(str)` — validates only `http:`/`https:` protocols (blocks `javascript:`)
- `setText(el, val)` — always uses `textContent`, never `innerHTML`

### Content-Security-Policy
`index.html` sets a CSP `<meta>` tag:
- `default-src 'self'` — same-origin baseline for anything not otherwise listed
- `script-src 'self'` — no inline scripts, no CDN scripts (all JS is external)
- `style-src 'self' 'unsafe-inline'` — `'unsafe-inline'` is required for the
  dynamic inline styles the UI applies (charts, status colors)
- `img-src 'self' data:` — local images plus `data:` URIs for inline icons
- `connect-src *` — fetch to CORS proxies and Intercom/Pylon APIs allowed
- `frame-src 'self' demo/` — only the local demo target can be framed
- `base-uri 'none'` / `object-src 'none'` — hardening against base-tag and plugin abuse

## Vulnerabilities Covered

| ID  | Vendor   | Endpoint                              | CVSS |
|-----|----------|---------------------------------------|------|
| A01 | Intercom | POST /messenger/web/conversations     | 7.5  |
| A02 | Intercom | POST /messenger/web/conversations     | 7.5  |
| A03 | Pylon    | GET /chatwidget/unreads + /chatwidget/issue | 8.1 |

## Ethics & Scope

ChatGuard is an **educational and authorized-testing tool only**. It exists to help
developers and security reviewers identify *their own* misconfigured chat widgets
(missing Identity Verification / `user_hash` HMAC) before an attacker does.

**Permitted use:**
- Scanning the bundled `demo/target.html` (the default, fully offline demo target).
- Scanning systems you own, or for which you hold **explicit written authorization**
  to test (e.g., a signed penetration-testing engagement or bug-bounty scope).

**Prohibited use:**
- Pointing the scanner at any third-party domain without prior written permission.
- Using extracted identifiers or proof-of-concept requests against live accounts you
  do not own or are not authorized to assess.

Unauthorized scanning or exploitation of systems you do not own may violate computer
misuse laws (e.g., the CFAA and equivalent statutes). The authors accept no liability
for misuse; responsibility for staying within a lawful, authorized scope rests entirely
with the operator. By default, ChatGuard performs **no external network calls** — the
demo scan runs entirely against the local bundled target.
