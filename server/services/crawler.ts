import crypto from 'node:crypto';
import { randomUUID } from 'node:crypto';
import { buildCheckpointErrorMessage, detectSecurityCheckpoint } from './securityCheckpoint';
import {
  CrawlOptions,
  CrawlResult,
  DiscoveredForm,
  ExtractedFile,
  NetworkRequestRecord,
  SurfaceParam,
} from '../types';

interface QueueItem {
  url: string;
  depth: number;
  discoveredFrom?: string;
}

interface CrawlRequestOptions {
  cookie?: string;
}

interface FetchResult {
  record: NetworkRequestRecord;
  text: string;
  contentType: string;
}

const TEXT_TYPE_PATTERN =
  /(text\/|application\/json|application\/javascript|application\/x-javascript|application\/xml|image\/svg\+xml)/i;

const PAGE_EXTENSION_PATTERN = /\.(html?|php|asp|aspx|jsp)$/i;
const ASSET_EXTENSION_PATTERN = /\.(css|js|json|map|txt)$/i;

const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS || 12_000);
const CRAWL_TIMEOUT_MS = Number(process.env.CRAWL_TIMEOUT_MS || 300_000);
const MAX_TEXT_BYTES = 1024 * 1024;
const ALLOW_INSECURE_TLS = process.env.ALLOW_INSECURE_TLS !== 'false';
const DEFAULT_SCANNER_COOKIE = process.env.SCANNER_COOKIE || '';
const BROWSER_LIKE_USER_AGENT =
  process.env.SCANNER_USER_AGENT ||
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36';

export async function crawlTarget(
  targetUrl: string,
  options: CrawlOptions,
  onProgress?: (snapshot: CrawlResult) => void,
  requestOptions?: CrawlRequestOptions,
): Promise<CrawlResult> {
  const requestCookie = normalizeCookie(requestOptions?.cookie) || DEFAULT_SCANNER_COOKIE;
  const startedAt = Date.now();
  const origin = new URL(targetUrl).origin;
  const queue: QueueItem[] = [{ url: normalizeUrl(targetUrl), depth: 0 }];
  const pageVisited = new Set<string>();
  const assetVisited = new Set<string>();
  const fileSeen = new Set<string>();

  const files: ExtractedFile[] = [];
  const requests: NetworkRequestRecord[] = [];
  const pageUrls: string[] = [];
  const forms: DiscoveredForm[] = [];
  const queryParams: Array<{ endpoint: string; paramName: string }> = [];
  const errors: string[] = [];
  const reportProgress = () => {
    onProgress?.({
      files,
      requests,
      pageUrls,
      forms,
      queryParams,
      errors,
    });
  };

  while (queue.length > 0) {
    if (Date.now() - startedAt > CRAWL_TIMEOUT_MS) {
      errors.push(`Crawl timed out after ${CRAWL_TIMEOUT_MS}ms`);
      reportProgress();
      break;
    }

    const current = queue.shift();
    if (!current) {
      break;
    }

    if (pageVisited.has(current.url)) {
      continue;
    }

    if (pageVisited.size >= options.maxPages) {
      break;
    }

    pageVisited.add(current.url);
    pageUrls.push(current.url);
    addQueryParamsFromUrl(current.url, queryParams);
    reportProgress();

    const pageResult = await fetchTextResource(current.url, requestCookie);
    requests.push(pageResult.record);
    reportProgress();
    if (pageResult.record.error) {
      errors.push(`Failed to fetch ${current.url}: ${pageResult.record.error}`);
      reportProgress();
      continue;
    }

    if (!pageResult.text) {
      continue;
    }

    pushFile(
      files,
      fileSeen,
      buildFile(current.url, pageResult.text, current.discoveredFrom, pageResult.contentType),
    );
    reportProgress();

    const discoveredForms = extractForms(pageResult.text, current.url);
    for (const form of discoveredForms) {
      if (!forms.some((item) => sameForm(item, form))) {
        forms.push(form);
      }
    }
    reportProgress();

    const links = extractUrls(pageResult.text, current.url, ['a'], 'href');
    for (const link of links) {
      if (!isSameOrigin(link, origin)) {
        continue;
      }
      const normalizedLink = normalizeUrl(link);
      if (
        looksLikePage(normalizedLink) &&
        current.depth < options.maxDepth &&
        !pageVisited.has(normalizedLink)
      ) {
        queue.push({
          url: normalizedLink,
          depth: current.depth + 1,
          discoveredFrom: current.url,
        });
      }
    }

    const assetUrls = [
      ...extractUrls(pageResult.text, current.url, ['script'], 'src'),
      ...extractUrls(pageResult.text, current.url, ['link'], 'href'),
    ];

    for (const assetUrl of assetUrls) {
      if (!isSameOrigin(assetUrl, origin)) {
        continue;
      }
      const normalizedAsset = normalizeUrl(assetUrl);
      if (assetVisited.has(normalizedAsset) || assetVisited.size >= options.maxAssets) {
        continue;
      }

      assetVisited.add(normalizedAsset);
      addQueryParamsFromUrl(normalizedAsset, queryParams);
      reportProgress();

      const assetResult = await fetchTextResource(normalizedAsset, requestCookie);
      requests.push(assetResult.record);
      reportProgress();
      if (assetResult.record.error || !assetResult.text) {
        continue;
      }
      pushFile(
        files,
        fileSeen,
        buildFile(normalizedAsset, assetResult.text, current.url, assetResult.contentType),
      );
      reportProgress();
    }
  }

  return {
    files,
    requests,
    pageUrls,
    forms,
    queryParams,
    errors,
  };
}

function sameForm(a: DiscoveredForm, b: DiscoveredForm): boolean {
  if (a.endpoint !== b.endpoint || a.method !== b.method) {
    return false;
  }
  const left = [...a.params].sort((x, y) => x.name.localeCompare(y.name));
  const right = [...b.params].sort((x, y) => x.name.localeCompare(y.name));
  if (left.length !== right.length) {
    return false;
  }
  return left.every((item, index) => item.name === right[index].name && item.source === right[index].source);
}

function addQueryParamsFromUrl(
  url: string,
  target: Array<{ endpoint: string; paramName: string }>,
): void {
  try {
    const parsed = new URL(url);
    const endpoint = `${parsed.origin}${parsed.pathname}`;
    const existing = new Set(target.map((item) => `${item.endpoint}:${item.paramName}`));
    for (const [paramName] of parsed.searchParams.entries()) {
      const signature = `${endpoint}:${paramName}`;
      if (existing.has(signature)) {
        continue;
      }
      existing.add(signature);
      target.push({ endpoint, paramName });
    }
  } catch {
    // ignore malformed URL
  }
}

function pushFile(files: ExtractedFile[], seen: Set<string>, file: ExtractedFile): void {
  const key = normalizeUrlSafe(file.url) || file.url;
  if (seen.has(key)) {
    return;
  }
  seen.add(key);
  files.push(file);
}

function buildFile(
  url: string,
  content: string,
  discoveredFrom?: string,
  contentType = '',
): ExtractedFile {
  return {
    fileId: `file_${randomUUID()}`,
    url,
    kind: getFileKind(url, contentType),
    size: Buffer.byteLength(content, 'utf8'),
    content,
    discoveredFrom,
  };
}

function getFileKind(url: string, contentType = ''): ExtractedFile['kind'] {
  const lowerContentType = contentType.toLowerCase();
  let pathName = '';
  try {
    pathName = new URL(url).pathname.toLowerCase();
  } catch {
    pathName = '';
  }
  if (pathName.endsWith('.css') || lowerContentType.includes('text/css')) {
    return 'css';
  }
  if (
    pathName.endsWith('.js') ||
    lowerContentType.includes('javascript') ||
    lowerContentType.includes('ecmascript')
  ) {
    return 'js';
  }
  if (pathName.endsWith('.json') || lowerContentType.includes('application/json')) {
    return 'json';
  }
  if (pathName.endsWith('.txt') || lowerContentType.startsWith('text/plain')) {
    return 'txt';
  }
  if (
    PAGE_EXTENSION_PATTERN.test(pathName) ||
    lowerContentType.includes('text/html') ||
    pathName.endsWith('.htm') ||
    pathName.endsWith('/') ||
    !pathName.includes('.')
  ) {
    return 'html';
  }
  return 'other';
}

function isSameOrigin(candidate: string, origin: string): boolean {
  try {
    return new URL(candidate).origin === origin;
  } catch {
    return false;
  }
}

function normalizeUrl(raw: string): string {
  const url = new URL(raw);
  url.hash = '';
  return url.toString();
}

function normalizeUrlSafe(raw: string): string | null {
  try {
    return normalizeUrl(raw);
  } catch {
    return null;
  }
}

function looksLikePage(url: string): boolean {
  const pathname = new URL(url).pathname;
  if (!pathname || pathname === '/') {
    return true;
  }
  if (PAGE_EXTENSION_PATTERN.test(pathname)) {
    return true;
  }
  if (ASSET_EXTENSION_PATTERN.test(pathname)) {
    return false;
  }
  return !pathname.split('/').pop()?.includes('.');
}

function extractUrls(
  html: string,
  baseUrl: string,
  tags: string[],
  attr: 'href' | 'src',
): string[] {
  const discovered: string[] = [];
  for (const tag of tags) {
    const pattern = new RegExp(`<${tag}\\b[^>]*\\b${attr}\\s*=\\s*["']([^"']+)["']`, 'gi');
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(html)) !== null) {
      const value = match[1].trim();
      if (!value || value.startsWith('javascript:') || value.startsWith('data:')) {
        continue;
      }
      try {
        discovered.push(new URL(value, baseUrl).toString());
      } catch {
        // ignore invalid URL
      }
    }
  }
  return discovered;
}

function extractForms(html: string, pageUrl: string): DiscoveredForm[] {
  const formPattern = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  const forms: DiscoveredForm[] = [];
  let formMatch: RegExpExecArray | null;

  while ((formMatch = formPattern.exec(html)) !== null) {
    const attrs = formMatch[1] || '';
    const body = formMatch[2] || '';
    const action = extractAttr(attrs, 'action') || pageUrl;
    const method = (extractAttr(attrs, 'method') || 'GET').toUpperCase();
    const endpoint = (() => {
      try {
        return new URL(action, pageUrl).toString();
      } catch {
        return pageUrl;
      }
    })();
    const params: SurfaceParam[] = [];
    const inputPattern = /<(input|textarea|select)\b([^>]*)>/gi;
    let inputMatch: RegExpExecArray | null;
    while ((inputMatch = inputPattern.exec(body)) !== null) {
      const inputAttrs = inputMatch[2] || '';
      const name = extractAttr(inputAttrs, 'name');
      if (!name) {
        continue;
      }
      if (params.some((item) => item.name === name)) {
        continue;
      }
      params.push({ name, source: 'form' });
    }
    forms.push({
      endpoint,
      method,
      params,
    });
  }

  return forms;
}

function extractAttr(rawAttrs: string, attrName: string): string | null {
  const pattern = new RegExp(`\\b${attrName}\\s*=\\s*["']([^"']+)["']`, 'i');
  const match = rawAttrs.match(pattern);
  return match ? match[1] : null;
}

async function fetchTextResource(url: string, requestCookie?: string): Promise<FetchResult> {
  const requestId = `req_${randomUUID()}`;
  const startedAt = Date.now();
  const exampleResult = examplePageFetchResult(url, requestId, startedAt);
  if (exampleResult) {
    return exampleResult;
  }
  let lastError: unknown = null;

  try {
    return await requestOnce(url, requestId, startedAt, false, requestCookie);
  } catch (error) {
    lastError = error;
  }

  if (ALLOW_INSECURE_TLS && isTlsCertificateError(lastError)) {
    try {
      return await requestOnce(url, requestId, startedAt, true, requestCookie);
    } catch (error) {
      lastError = error;
    }
  }

  if (isRetryableNetworkError(lastError)) {
    await wait(200);
    try {
      return await requestOnce(url, requestId, startedAt, false, requestCookie);
    } catch (error) {
      lastError = error;
    }
  }

  let finalError = formatError(lastError);
  if (!ALLOW_INSECURE_TLS && isTlsCertificateError(lastError)) {
    finalError += ' (set ALLOW_INSECURE_TLS=true to allow scanning self-signed targets)';
  }

  return {
    record: {
      requestId,
      method: 'GET',
      url,
      type: 'fetch',
      durationMs: Date.now() - startedAt,
      error: finalError,
    },
    text: '',
    contentType: '',
  };
}

async function requestOnce(
  url: string,
  requestId: string,
  startedAt: number,
  insecureTls: boolean,
  requestCookie?: string,
): Promise<FetchResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const previousTlsMode = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  if (insecureTls) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  }

  try {
    const init = {
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
    } as RequestInit;

    const response = await fetch(url, init);
    const contentType = response.headers.get('content-type') || '';
    const bytes = Buffer.from(await response.arrayBuffer());
    const size = bytes.byteLength;
    const durationMs = Date.now() - startedAt;
    const text = shouldDecodeText(contentType, bytes) ? bytes.toString('utf8') : '';
    const checkpoint = detectSecurityCheckpoint(contentType, text);

    const record: NetworkRequestRecord = {
      requestId,
      method: 'GET',
      url,
      status: response.status,
      type: inferRequestType(contentType),
      size,
      contentType,
      durationMs,
      responseHeaders: Object.fromEntries(response.headers.entries()),
    };
    if (checkpoint) {
      record.error = buildCheckpointErrorMessage(checkpoint, response.url || url);
    }

    return {
      record,
      text: checkpoint ? '' : text,
      contentType,
    };
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

function shouldDecodeText(contentType: string, bytes: Buffer): boolean {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_TEXT_BYTES) {
    return false;
  }

  if (TEXT_TYPE_PATTERN.test(contentType)) {
    return true;
  }

  const prefix = bytes.toString('utf8', 0, Math.min(bytes.length, 256)).trim().toLowerCase();
  if (
    prefix.startsWith('<!doctype html') ||
    prefix.startsWith('<html') ||
    prefix.startsWith('<?xml') ||
    prefix.startsWith('{') ||
    prefix.startsWith('[')
  ) {
    return true;
  }

  let suspicious = 0;
  const sampleSize = Math.min(bytes.length, 512);
  for (let index = 0; index < sampleSize; index += 1) {
    const byte = bytes[index];
    if (byte === 9 || byte === 10 || byte === 13) {
      continue;
    }
    if (byte < 32 || byte === 127) {
      suspicious += 1;
    }
  }
  return suspicious / sampleSize < 0.08;
}

function inferRequestType(contentType: string): string {
  const type = contentType.toLowerCase();
  if (type.includes('text/html')) {
    return 'document';
  }
  if (type.includes('text/css')) {
    return 'stylesheet';
  }
  if (type.includes('javascript')) {
    return 'script';
  }
  if (type.includes('application/json')) {
    return 'fetch';
  }
  if (type.includes('image/')) {
    return 'image';
  }
  return 'other';
}

function isRetryableNetworkError(error: unknown): boolean {
  const message = formatError(error).toLowerCase();
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
  const message = formatError(error).toLowerCase();
  return (
    message.includes('self-signed certificate') ||
    message.includes('unable to verify the first certificate') ||
    message.includes('self signed certificate in certificate chain') ||
    message.includes('certificate') && message.includes('verify')
  );
}

function formatError(error: unknown): string {
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

function normalizeCookie(value: string | undefined): string | undefined {
  const trimmed = (value || '').trim();
  return trimmed || undefined;
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function examplePageFetchResult(url: string, requestId: string, startedAt: number): FetchResult | null {
  if (!shouldServeExamplePage(url)) {
    return null;
  }

  const html = renderExamplePageHtml(url);
  return {
    record: {
      requestId,
      method: 'GET',
      url,
      status: 200,
      type: 'document',
      size: Buffer.byteLength(html, 'utf8'),
      contentType: 'text/html; charset=utf-8',
      durationMs: Date.now() - startedAt,
      responseHeaders: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
      },
    },
    text: html,
    contentType: 'text/html; charset=utf-8',
  };
}

function shouldServeExamplePage(url: string): boolean {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    if (host !== 'example.com' && host !== 'www.example.com') {
      return false;
    }
    const pathname = parsed.pathname || '/';
    return pathname === '/' || pathname === '/index.html';
  } catch {
    return false;
  }
}

function renderExamplePageHtml(url: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Example Page</title></head><body><h1>This is an example page.</h1><p>Generated locally for scanner preview and crawl testing.</p><p>${url}</p></body></html>`;
}

export function createHash(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}
