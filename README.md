# Hunter

Hunter is a local defensive web security scanner with a web UI.  
It crawls same-origin pages/assets, performs passive checks, runs safe active behavioral detection, and provides manual review workflows.

## What It Does

- Live local UI with target URL input and preview pane
- Same-origin crawl (default depth 2)
- Extracts HTML/CSS/JS/JSON/text assets
- Passive findings:
  - leaked secrets/tokens patterns
  - missing security headers
  - cookie flag issues
  - sourcemap/debug artifacts
  - mixed content/risky JS sink heuristics
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
- Scans are constrained by depth and asset/page caps for stability.
