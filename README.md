# Hunter

Hunter is a local defensive web security scanner with a web UI.  
It crawls same-origin pages/assets, performs passive checks, runs safe active behavioral detection, and provides manual review workflows.

## What It Does

- Live local UI with target URL input and preview pane
- Same-origin crawl (default depth 2)
- Extracts HTML/CSS/JS/JSON/text assets
- Passive findings:
  - leaked secrets/tokens patterns
  - sensitive file exposure probes (`/.env`, `/.aws/credentials`, `/.svn/entries`, `/backup.sql`, `/.git/config`, etc.)
  - missing security headers
  - cookie flag issues
  - sourcemap/debug artifacts
  - mixed content/risky JS sink heuristics
- Optional host-level checks:
  - built-in top-port TCP scan with open-port findings
  - built-in port vulnerability checks (service/version/auth exposure heuristics)
- Safe active detection:
  - endpoint/parameter discovery
  - baseline vs benign edge-case input diffs
  - anomaly findings for status/error/latency/body drift
- Manual review status per finding:
  - `open`, `confirmed`, `false_positive`, `needs_review`
- JSON report persistence in local `data/scans/`

## Security Boundary

Hunter is for authorized defensive testing only.

- No exploit automation
- No brute force
- No destructive attack behavior

## Tech Stack

- React + Vite + Tailwind (frontend)
- Express + TypeScript (backend)
- Server-Sent Events for scan progress updates
- JSON file store for scan history

## Quick Start

1. Install dependencies:

```bash
npm install
```

2. Run both server + client:

```bash
npm run dev
```

3. Open:

`http://localhost:3000`

## Environment

Copy `.env.example` to `.env` and adjust if needed:

- `PORT` (default `8787`)
- `DATA_DIR` (default `./data`)
- `SCAN_MAX_PAGES` (default `50`)
- `SCAN_MAX_ASSETS` (default `300`)
- `REQUEST_TIMEOUT_MS` (default `12000`)
- `PREVIEW_REQUEST_TIMEOUT_MS` (default `12000`)
- `CRAWL_TIMEOUT_MS` (default `300000`)
- `SCAN_TIMEOUT_MS` (default `480000`)
- `SCAN_PROGRESS_EVENT_INTERVAL_MS` (default `500`)
- `ALLOW_INSECURE_TLS` (default `true`, allows self-signed targets)
- `SCANNER_USER_AGENT` (optional browser-like UA override for crawler requests)
- `PREVIEW_USER_AGENT` (optional browser-like UA override for preview proxy requests)
- `SCANNER_COOKIE` (optional, authorized session cookie for scanner fetches)
- `PREVIEW_COOKIE` (optional, authorized session cookie for preview proxy fetches)
- `PORT_SCAN_TOP_PORTS` (default `200`)
- `PORT_SCAN_TIMEOUT_MS` (default `1200`)
- `PORT_SCAN_CONCURRENCY` (default `24`)
- `PORT_SCAN_PORTS` (optional comma-separated TCP ports)
- `PORT_VULN_SCAN_ENABLED` (default `true`)
- `PORT_VULN_MAX_SERVICES` (default `12`)
- `PORT_VULN_TIMEOUT_MS` (default `1800`)
- `PORT_VULN_CONCURRENCY` (default `4`)

## API (Core)

- `POST /api/scans`
- `GET /api/scans`
- `GET /api/scans/:scanId`
- `GET /api/scans/:scanId/events`
- `GET /api/scans/:scanId/files`
- `GET /api/scans/:scanId/files/:fileId/content`
- `GET /api/scans/:scanId/findings`
- `PATCH /api/scans/:scanId/findings/:findingId`
- `GET /api/scans/:scanId/network`
- `GET /api/scans/:scanId/surface`
- `GET /api/scans/:scanId/diffs`
- `POST /api/preview/sessions`
- `DELETE /api/preview/sessions/:sessionId`

## Notes

- The preview pane uses iframe mode, so some sites may block embedding via CSP/X-Frame-Options.
- Targets with anti-bot checkpoints (for example Vercel Security Checkpoint Code 99) are detected explicitly.
- For protected targets, you can paste session cookie directly in the UI `Cookie (optional)` field (no restart needed).
- `https://example.com/` uses a built-in placeholder preview page: "This is an example page."
- Port scanning is fully built-in and does not require an external `nmap` executable.
- Re-scanning the same normalized target URL reuses and updates the same JSON report file instead of creating a new file.
- Scans are constrained by depth and asset/page caps for stability.
