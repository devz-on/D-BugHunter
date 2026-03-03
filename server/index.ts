import dotenv from 'dotenv';
import express from 'express';
import path from 'node:path';
import { JsonScanStore } from './store/jsonStore';
import { PreviewSessionManager } from './services/previewSessions';
import { SecurityCheckpoint, detectSecurityCheckpoint } from './services/securityCheckpoint';
import { ScanOrchestrator } from './services/scanOrchestrator';
import { ReviewStatus, ScanStartRequest } from './types';

dotenv.config();

const app = express();
app.use(express.json({ limit: '1mb' }));

const port = Number(process.env.PORT || 8787);
const dataDir = process.env.DATA_DIR || path.join(process.cwd(), 'data');
const previewRequestTimeoutMs = Number(process.env.PREVIEW_REQUEST_TIMEOUT_MS || 12_000);
const allowInsecureTls = process.env.ALLOW_INSECURE_TLS !== 'false';
const PREVIEW_COOKIE = process.env.PREVIEW_COOKIE || process.env.SCANNER_COOKIE || '';
const BROWSER_LIKE_USER_AGENT =
  process.env.PREVIEW_USER_AGENT ||
  process.env.SCANNER_USER_AGENT ||
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36';

const store = new JsonScanStore(dataDir);
const orchestrator = new ScanOrchestrator(store);
const preview = new PreviewSessionManager();

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'hunter-server',
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/preview/proxy', async (req, res) => {
  const targetRaw = String(req.query.target || '');
  const sessionId = String(req.query.sessionId || '');
  if (!targetRaw) {
    res.status(400).send('Missing target query parameter');
    return;
  }

  let targetUrl: URL;
  try {
    targetUrl = new URL(targetRaw);
    if (!['http:', 'https:'].includes(targetUrl.protocol)) {
      throw new Error('Only http/https URLs are supported');
    }
  } catch {
    res.status(400).send('Invalid target URL');
    return;
  }

  if (shouldServeExamplePage(targetUrl)) {
    res.status(200);
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(rewritePreviewHtml(renderExamplePageHtml(targetUrl.toString()), targetUrl.toString()));
    return;
  }

  const sessionCookie = resolvePreviewSessionCookie(preview, sessionId, targetUrl);
  const requestCookie = sessionCookie || PREVIEW_COOKIE;

  try {
    const proxiedResponse = await fetchPreviewResource(
      targetUrl.toString(),
      previewRequestTimeoutMs,
      allowInsecureTls,
      requestCookie,
    );
    const contentType = proxiedResponse.headers.get('content-type') || '';
    const bodyBuffer = Buffer.from(await proxiedResponse.arrayBuffer());
    const finalUrl = proxiedResponse.url || targetUrl.toString();

    res.status(proxiedResponse.status);
    res.setHeader('Cache-Control', 'no-store');

    if (contentType.toLowerCase().includes('text/html')) {
      const html = bodyBuffer.toString('utf8');
      const checkpoint = detectSecurityCheckpoint(contentType, html);
      if (checkpoint) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(renderSecurityCheckpointHtml(finalUrl, checkpoint));
        return;
      }
      const rewritten = rewritePreviewHtml(html, finalUrl);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(rewritten);
      return;
    }

    if (isLikelyCss(contentType, finalUrl)) {
      const css = bodyBuffer.toString('utf8');
      const rewrittenCss = rewriteCssUrls(css, finalUrl);
      res.setHeader('Content-Type', contentType || 'text/css; charset=utf-8');
      res.send(rewrittenCss);
      return;
    }

    if (isLikelyJavaScript(contentType, finalUrl)) {
      const script = bodyBuffer.toString('utf8');
      const rewrittenScript = rewriteJavaScriptImports(script, finalUrl);
      res.setHeader('Content-Type', contentType || 'text/javascript; charset=utf-8');
      res.send(rewrittenScript);
      return;
    }

    if (contentType) {
      res.setHeader('Content-Type', contentType);
    }
    res.send(bodyBuffer);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Proxy request failed';
    res.status(502).send(`Preview proxy failed: ${message}`);
  }
});

app.post('/api/scans', async (req, res) => {
  try {
    const body = req.body as ScanStartRequest;
    if (!body?.targetUrl) {
      res.status(400).json({ error: 'targetUrl is required' });
      return;
    }
    const scan = await orchestrator.startScan(body);
    res.status(202).json({
      scanId: scan.scanId,
      status: scan.status,
      targetUrl: scan.targetUrl,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Failed to start scan';
    res.status(400).json({ error: message });
  }
});

app.get('/api/scans', async (_req, res) => {
  const scans = await orchestrator.listSummaries();
  res.json(scans);
});

app.get('/api/scans/:scanId/events', async (req, res) => {
  const { scanId } = req.params;
  const scan = await orchestrator.getScan(scanId);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const unsubscribe = orchestrator.subscribe(scanId, res);
  const heartbeat = setInterval(() => {
    res.write(': heartbeat\n\n');
  }, 20_000);

  req.on('close', () => {
    clearInterval(heartbeat);
    unsubscribe();
    res.end();
  });
});

app.get('/api/scans/:scanId', async (req, res) => {
  const summary = await orchestrator.getSummary(req.params.scanId);
  if (!summary) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }
  res.json(summary);
});

app.get('/api/scans/:scanId/files', async (req, res) => {
  const scan = await orchestrator.getScan(req.params.scanId);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }
  res.json(
    scan.files.map((file) => ({
      fileId: file.fileId,
      url: file.url,
      kind: file.kind,
      size: file.size,
      discoveredFrom: file.discoveredFrom,
    })),
  );
});

app.get('/api/scans/:scanId/files/:fileId/content', async (req, res) => {
  const scan = await orchestrator.getScan(req.params.scanId);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }
  const file = scan.files.find((candidate) => candidate.fileId === req.params.fileId);
  if (!file) {
    res.status(404).json({ error: 'File not found' });
    return;
  }
  res.json({
    fileId: file.fileId,
    url: file.url,
    kind: file.kind,
    content: file.content,
  });
});

app.get('/api/scans/:scanId/findings', async (req, res) => {
  const scan = await orchestrator.getScan(req.params.scanId);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }
  const type = String(req.query.type || '').trim();
  const severity = String(req.query.severity || '').trim();
  const findings = scan.findings.filter((item) => {
    if (type && item.type !== type) {
      return false;
    }
    if (severity && item.severity !== severity) {
      return false;
    }
    return true;
  });
  res.json(findings);
});

app.patch('/api/scans/:scanId/findings/:findingId', async (req, res) => {
  const requestedStatus = req.body?.reviewStatus as ReviewStatus | undefined;
  const accepted: ReviewStatus[] = ['confirmed', 'false_positive', 'needs_review', 'open'];
  if (!requestedStatus || !accepted.includes(requestedStatus)) {
    res.status(400).json({ error: 'reviewStatus must be one of open/confirmed/false_positive/needs_review' });
    return;
  }
  const updated = await orchestrator.updateReviewStatus(
    req.params.scanId,
    req.params.findingId,
    requestedStatus,
  );
  if (!updated) {
    res.status(404).json({ error: 'Scan or finding not found' });
    return;
  }
  res.json(updated);
});

app.get('/api/scans/:scanId/network', async (req, res) => {
  const scan = await orchestrator.getScan(req.params.scanId);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }
  res.json(scan.requests);
});

app.get('/api/scans/:scanId/surface', async (req, res) => {
  const scan = await orchestrator.getScan(req.params.scanId);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }
  res.json(scan.surface);
});

app.get('/api/scans/:scanId/diffs', async (req, res) => {
  const scan = await orchestrator.getScan(req.params.scanId);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }
  res.json(scan.diffs);
});

app.post('/api/preview/sessions', (req, res) => {
  try {
    const targetUrl = String(req.body?.targetUrl || '');
    const cookie = String(req.body?.cookie || '');
    if (!targetUrl) {
      res.status(400).json({ error: 'targetUrl is required' });
      return;
    }
    const parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      res.status(400).json({ error: 'Only http/https URLs are supported' });
      return;
    }
    const session = preview.create(parsed.toString(), cookie);
    res.status(201).json(session);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid URL';
    res.status(400).json({ error: message });
  }
});

app.delete('/api/preview/sessions/:sessionId', (req, res) => {
  const removed = preview.destroy(req.params.sessionId);
  if (!removed) {
    res.status(404).json({ error: 'Preview session not found' });
    return;
  }
  res.status(204).send();
});

app.listen(port, async () => {
  await store.init();
  console.log(`Hunter server listening on http://localhost:${port}`);
});

async function fetchPreviewResource(
  url: string,
  timeoutMs: number,
  insecureTlsAllowed: boolean,
  requestCookie?: string,
): Promise<Response> {
  let lastError: unknown = null;

  try {
    return await fetchWithTimeout(url, timeoutMs, false, requestCookie);
  } catch (error) {
    lastError = error;
  }

  if (insecureTlsAllowed && isTlsCertificateError(lastError)) {
    try {
      return await fetchWithTimeout(url, timeoutMs, true, requestCookie);
    } catch (error) {
      lastError = error;
    }
  }

  if (isRetryableNetworkError(lastError)) {
    await wait(200);
    try {
      return await fetchWithTimeout(url, timeoutMs, false, requestCookie);
    } catch (error) {
      lastError = error;
    }
  }

  throw new Error(formatFetchError(lastError));
}

async function fetchWithTimeout(
  url: string,
  timeoutMs: number,
  insecureTls: boolean,
  requestCookie?: string,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const previousTlsMode = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  if (insecureTls) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  }

  try {
    return await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      headers: {
        'User-Agent': BROWSER_LIKE_USER_AGENT,
        ...(requestCookie ? { Cookie: requestCookie } : {}),
        Accept:
          'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache',
        Pragma: 'no-cache',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        Connection: 'keep-alive',
      },
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
    if (insecureTls) {
      if (previousTlsMode === undefined) {
        delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      } else {
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = previousTlsMode;
      }
    }
  }
}

function rewritePreviewHtml(html: string, baseUrl: string): string {
  let rewritten = html;

  rewritten = rewritten.replace(
    /\b(href|src|action)\s*=\s*(['"])([^"']*)\2/gi,
    (full, attributeName: string, quote: string, rawValue: string) => {
      const proxiedValue = toProxyUrl(rawValue, baseUrl);
      if (!proxiedValue) {
        return full;
      }
      return `${attributeName}=${quote}${proxiedValue}${quote}`;
    },
  );

  rewritten = rewritten.replace(
    /\bsrcset\s*=\s*(['"])([^"']*)\1/gi,
    (full, quote: string, rawValue: string) => {
      const rewrittenCandidates = rawValue
        .split(',')
        .map((candidate) => candidate.trim())
        .filter(Boolean)
        .map((candidate) => {
          const [urlPart, ...descriptorParts] = candidate.split(/\s+/);
          const proxiedValue = toProxyUrl(urlPart, baseUrl);
          if (!proxiedValue) {
            return candidate;
          }
          return descriptorParts.length > 0
            ? `${proxiedValue} ${descriptorParts.join(' ')}`
            : proxiedValue;
        });
      return `srcset=${quote}${rewrittenCandidates.join(', ')}${quote}`;
    },
  );

  rewritten = rewritten.replace(
    /<script\b([^>]*)type\s*=\s*(['"])module\2([^>]*)>([\s\S]*?)<\/script>/gi,
    (full, preAttrs: string, quote: string, postAttrs: string, inlineBody: string) => {
      const attrs = `${preAttrs || ''}${postAttrs || ''}`;
      if (/\bsrc\s*=/.test(attrs)) {
        return full;
      }
      const rewrittenInline = rewriteJavaScriptImports(inlineBody, baseUrl);
      return `<script${preAttrs}type=${quote}module${quote}${postAttrs}>${rewrittenInline}</script>`;
    },
  );

  if (!rewritten.includes('hunter-preview-url')) {
    const injectedScript = `
<script>
(function () {
  var lastKnownTarget = null;
  function normalizeTarget(rawValue) {
    if (!rawValue) return null;
    try {
      var parsed = new URL(rawValue, window.location.href);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
      parsed.hash = '';
      return parsed.toString();
    } catch (error) {
      return null;
    }
  }
  function readTargetFromLocation() {
    try {
      var params = new URLSearchParams(window.location.search);
      return normalizeTarget(params.get('target'));
    } catch (error) {
      return null;
    }
  }
  function currentTargetUrl() {
    var fromLocation = readTargetFromLocation();
    if (fromLocation) {
      lastKnownTarget = fromLocation;
      return fromLocation;
    }
    return lastKnownTarget;
  }
  function notifyParent() {
    var current = currentTargetUrl();
    if (!current) return;
    try {
      if (window.parent && window.parent !== window) {
        window.parent.postMessage({ type: 'hunter-preview-url', url: current }, '*');
      }
    } catch (error) {}
  }
  var originalPushState = history.pushState;
  history.pushState = function () {
    var result = originalPushState.apply(this, arguments);
    setTimeout(notifyParent, 0);
    return result;
  };
  var originalReplaceState = history.replaceState;
  history.replaceState = function () {
    var result = originalReplaceState.apply(this, arguments);
    setTimeout(notifyParent, 0);
    return result;
  };
  lastKnownTarget = readTargetFromLocation();
  window.addEventListener('load', notifyParent);
  window.addEventListener('hashchange', notifyParent);
  window.addEventListener('popstate', notifyParent);
  document.addEventListener('click', function () { setTimeout(notifyParent, 100); }, true);
  document.addEventListener('submit', function () { setTimeout(notifyParent, 250); }, true);
  notifyParent();
})();
</script>
`.trim();

    if (/<\/body>/i.test(rewritten)) {
      rewritten = rewritten.replace(/<\/body>/i, `${injectedScript}</body>`);
    } else {
      rewritten += injectedScript;
    }
  }

  return rewritten;
}

function toProxyUrl(rawValue: string, baseUrl: string): string | null {
  const trimmed = rawValue.trim();
  if (!trimmed) {
    return null;
  }

  const lowered = trimmed.toLowerCase();
  if (
    lowered.startsWith('#') ||
    lowered.startsWith('javascript:') ||
    lowered.startsWith('data:') ||
    lowered.startsWith('mailto:') ||
    lowered.startsWith('tel:') ||
    lowered.startsWith('blob:')
  ) {
    return null;
  }

  if (trimmed.startsWith('/api/preview/proxy?target=')) {
    return trimmed;
  }

  try {
    const resolved = new URL(trimmed, baseUrl);
    if (!['http:', 'https:'].includes(resolved.protocol)) {
      return null;
    }
    return `/api/preview/proxy?target=${encodeURIComponent(resolved.toString())}`;
  } catch {
    return null;
  }
}

function isLikelyCss(contentType: string, url: string): boolean {
  const lowerType = contentType.toLowerCase();
  if (lowerType.includes('text/css')) {
    return true;
  }
  try {
    const pathname = new URL(url).pathname.toLowerCase();
    return pathname.endsWith('.css');
  } catch {
    return false;
  }
}

function rewriteCssUrls(source: string, baseUrl: string): string {
  let rewritten = source;

  rewritten = rewritten.replace(
    /url\(\s*(['"]?)([^'")]+)\1\s*\)/gi,
    (full, quote: string, rawValue: string) => {
      const proxied = toProxyUrl(rawValue, baseUrl);
      if (!proxied) {
        return full;
      }
      const outputQuote = quote || '"';
      return `url(${outputQuote}${proxied}${outputQuote})`;
    },
  );

  rewritten = rewritten.replace(
    /(@import\s+url\(\s*)(['"]?)([^'")]+)\2(\s*\))/gi,
    (full, prefix: string, quote: string, rawValue: string, suffix: string) => {
      const proxied = toProxyUrl(rawValue, baseUrl);
      if (!proxied) {
        return full;
      }
      const outputQuote = quote || '"';
      return `${prefix}${outputQuote}${proxied}${outputQuote}${suffix}`;
    },
  );

  rewritten = rewritten.replace(
    /(@import\s+)(['"])([^'"]+)\2/gi,
    (full, prefix: string, quote: string, rawValue: string) => {
      const proxied = toProxyUrl(rawValue, baseUrl);
      if (!proxied) {
        return full;
      }
      return `${prefix}${quote}${proxied}${quote}`;
    },
  );

  return rewritten;
}

function isLikelyJavaScript(contentType: string, url: string): boolean {
  const lowerType = contentType.toLowerCase();
  if (
    lowerType.includes('javascript') ||
    lowerType.includes('ecmascript') ||
    lowerType.includes('module')
  ) {
    return true;
  }
  try {
    const pathname = new URL(url).pathname.toLowerCase();
    return pathname.endsWith('.js') || pathname.endsWith('.mjs') || pathname.endsWith('.cjs');
  } catch {
    return false;
  }
}

function rewriteJavaScriptImports(source: string, baseUrl: string): string {
  const rewriteSpecifier = (rawSpecifier: string): string => {
    const proxied = toProxyUrl(rawSpecifier, baseUrl);
    return proxied || rawSpecifier;
  };

  let rewritten = source;

  // import ... from "x" / export ... from "x"
  rewritten = rewritten.replace(
    /(\b(?:import|export)\s+[\s\S]*?\sfrom\s*)(['"])([^'"\n\r]+)\2/g,
    (full, prefix: string, quote: string, specifier: string) =>
      `${prefix}${quote}${rewriteSpecifier(specifier)}${quote}`,
  );

  // import "x"
  rewritten = rewritten.replace(
    /(\bimport\s+)(['"])([^'"\n\r]+)\2/g,
    (full, prefix: string, quote: string, specifier: string) =>
      `${prefix}${quote}${rewriteSpecifier(specifier)}${quote}`,
  );

  // import("x")
  rewritten = rewritten.replace(
    /(\bimport\s*\(\s*)(['"])([^'"\n\r]+)\2(\s*\))/g,
    (full, prefix: string, quote: string, specifier: string, suffix: string) =>
      `${prefix}${quote}${rewriteSpecifier(specifier)}${quote}${suffix}`,
  );

  // new URL("x", import.meta.url)
  rewritten = rewritten.replace(
    /(new\s+URL\(\s*)(['"])([^'"\n\r]+)\2(\s*,\s*import\.meta\.url\s*\))/g,
    (full, prefix: string, quote: string, specifier: string, suffix: string) =>
      `${prefix}${quote}${rewriteSpecifier(specifier)}${quote}${suffix}`,
  );

  return rewritten;
}

function isRetryableNetworkError(error: unknown): boolean {
  const message = formatFetchError(error).toLowerCase();
  return (
    message.includes('timeout') ||
    message.includes('timed out') ||
    message.includes('fetch failed') ||
    message.includes('socket') ||
    message.includes('econnreset') ||
    message.includes('enetunreach') ||
    message.includes('eai_again')
  );
}

function isTlsCertificateError(error: unknown): boolean {
  const message = formatFetchError(error).toLowerCase();
  return (
    message.includes('self-signed certificate') ||
    message.includes('unable to verify the first certificate') ||
    message.includes('self signed certificate in certificate chain') ||
    message.includes('unable_to_get_issuer_cert_locally') ||
    message.includes('certificate has expired') ||
    message.includes('certificate') && message.includes('verify')
  );
}

function formatFetchError(error: unknown): string {
  if (!error) {
    return 'Unknown fetch error';
  }
  if (error instanceof Error) {
    const causeMessage =
      error.cause && typeof error.cause === 'object'
        ? String((error.cause as { message?: string }).message || error.cause)
        : '';
    return causeMessage ? `${error.message} (${causeMessage})` : error.message;
  }
  return String(error);
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function renderSecurityCheckpointHtml(targetUrl: string, checkpoint: SecurityCheckpoint): string {
  const escapedUrl = escapeHtml(targetUrl);
  const escapedSummary = escapeHtml(checkpoint.summary);
  const codeLabel = checkpoint.code ? `Code ${escapeHtml(checkpoint.code)}` : 'Challenge detected';
  const reference = checkpoint.referenceId ? escapeHtml(checkpoint.referenceId) : 'not provided';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Checkpoint Detected</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      background: #0b1020;
      color: #e5e7eb;
    }
    main {
      width: min(780px, 92vw);
      background: #111827;
      border: 1px solid #374151;
      border-radius: 14px;
      padding: 24px;
      box-shadow: 0 16px 50px rgba(0, 0, 0, 0.35);
    }
    h1 {
      margin: 0 0 8px;
      font-size: 28px;
    }
    p {
      margin: 0 0 12px;
      line-height: 1.6;
      color: #d1d5db;
    }
    code {
      display: block;
      margin: 8px 0;
      padding: 8px 10px;
      border-radius: 8px;
      border: 1px solid #4b5563;
      background: #0f172a;
      color: #cbd5e1;
      overflow-wrap: anywhere;
    }
  </style>
</head>
<body>
  <main>
    <h1>Security checkpoint blocked preview</h1>
    <p>${escapedSummary}</p>
    <code>${codeLabel} | ref: ${reference}</code>
    <p>Target: <code>${escapedUrl}</code></p>
    <p>If you are authorized to test this target, open it in a regular browser, complete the challenge, then provide clearance cookie in the UI Cookie field or in local <code>.env</code>:</p>
    <code>SCANNER_COOKIE=...<br>PREVIEW_COOKIE=...</code>
  </main>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function resolvePreviewSessionCookie(
  manager: PreviewSessionManager,
  sessionId: string,
  targetUrl: URL,
): string | undefined {
  const trimmedSessionId = sessionId.trim();
  if (!trimmedSessionId) {
    return undefined;
  }
  const session = manager.get(trimmedSessionId);
  if (!session) {
    return undefined;
  }

  try {
    const sessionTarget = new URL(session.targetUrl);
    if (sessionTarget.hostname.toLowerCase() !== targetUrl.hostname.toLowerCase()) {
      return undefined;
    }
  } catch {
    return undefined;
  }

  return manager.getCookie(trimmedSessionId);
}

function shouldServeExamplePage(targetUrl: URL): boolean {
  const host = targetUrl.hostname.toLowerCase();
  if (host !== 'example.com' && host !== 'www.example.com') {
    return false;
  }
  const pathname = targetUrl.pathname || '/';
  return pathname === '/' || pathname === '/index.html';
}

function renderExamplePageHtml(targetUrl: string): string {
  const escapedTarget = targetUrl.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Example Page</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      background: linear-gradient(160deg, #f1f5f9, #dbeafe);
      color: #111827;
    }
    main {
      width: min(680px, 92vw);
      background: rgba(255, 255, 255, 0.9);
      border: 1px solid #cbd5e1;
      border-radius: 14px;
      padding: 28px;
      box-shadow: 0 18px 45px rgba(15, 23, 42, 0.14);
    }
    h1 {
      margin: 0 0 10px;
      font-size: 30px;
      line-height: 1.2;
    }
    p {
      margin: 0;
      line-height: 1.6;
      color: #374151;
    }
    code {
      display: inline-block;
      margin-top: 10px;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 5px 8px;
      font-size: 13px;
      color: #0f172a;
    }
  </style>
</head>
<body>
  <main>
    <h1>This is an example page.</h1>
    <p>The preview proxy served this placeholder for example.com so you can test the scanner safely.</p>
    <code>${escapedTarget}</code>
  </main>
</body>
</html>`;
}
