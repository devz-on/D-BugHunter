import { randomUUID } from 'node:crypto';
import { ExtractedFile, Finding, NetworkRequestRecord } from '../../types';

interface SensitivePathRule {
  path: string;
  ruleId: string;
  title: string;
  severity: Finding['severity'];
  confidence: Finding['confidence'];
  recommendation: string;
  matcher: (body: string, contentType: string) => string | null;
}

interface ProbeResult {
  files: ExtractedFile[];
  requests: NetworkRequestRecord[];
  findings: Finding[];
  errors: string[];
}

interface ProbeOptions {
  cookie?: string;
}

const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS || 12_000);
const ALLOW_INSECURE_TLS = process.env.ALLOW_INSECURE_TLS !== 'false';
const DEFAULT_SCANNER_COOKIE = process.env.SCANNER_COOKIE || '';
const BROWSER_LIKE_USER_AGENT =
  process.env.SCANNER_USER_AGENT ||
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36';

const SENSITIVE_PATH_RULES: SensitivePathRule[] = [
  {
    path: '/.env',
    ruleId: 'EXPOSED_ENV_FILE',
    title: 'Exposed .env File',
    severity: 'critical',
    confidence: 'high',
    recommendation: 'Block public access to .env files and rotate any leaked credentials immediately.',
    matcher: matchEnvFile,
  },
  {
    path: '/.env.local',
    ruleId: 'EXPOSED_ENV_FILE',
    title: 'Exposed .env.local File',
    severity: 'critical',
    confidence: 'high',
    recommendation: 'Block public access to environment files and move secrets to server-side storage.',
    matcher: matchEnvFile,
  },
  {
    path: '/.env.production',
    ruleId: 'EXPOSED_ENV_FILE',
    title: 'Exposed .env.production File',
    severity: 'critical',
    confidence: 'high',
    recommendation: 'Remove .env.production from web root and rotate all potentially exposed credentials.',
    matcher: matchEnvFile,
  },
  {
    path: '/.aws/credentials',
    ruleId: 'EXPOSED_AWS_CREDENTIALS_FILE',
    title: 'Exposed AWS Credentials File',
    severity: 'critical',
    confidence: 'high',
    recommendation: 'Remove public access to AWS credentials files and rotate exposed IAM credentials.',
    matcher: matchAwsCredentialsFile,
  },
  {
    path: '/.aws/config',
    ruleId: 'EXPOSED_AWS_CONFIG_FILE',
    title: 'Exposed AWS Config File',
    severity: 'high',
    confidence: 'medium',
    recommendation: 'Restrict public access to AWS CLI config files and review account/profile leakage.',
    matcher: (body) => {
      if (/\[profile\s+[^\]]+\]/i.test(body) || /\bregion\s*=\s*[a-z]{2}-[a-z]+-\d\b/i.test(body)) {
        return redactSnippet(body);
      }
      return null;
    },
  },
  {
    path: '/.git/config',
    ruleId: 'EXPOSED_GIT_METADATA',
    title: 'Exposed Git Metadata',
    severity: 'high',
    confidence: 'high',
    recommendation: 'Block access to .git directories at the web server level.',
    matcher: (body) => {
      if (/\[(core|remote|branch)\]/i.test(body)) {
        return redactSnippet(body);
      }
      return null;
    },
  },
  {
    path: '/.git/HEAD',
    ruleId: 'EXPOSED_GIT_METADATA',
    title: 'Exposed Git HEAD Reference',
    severity: 'high',
    confidence: 'high',
    recommendation: 'Block access to .git directories and verify repository data is not web-accessible.',
    matcher: (body) => {
      const match = body.match(/\bref:\s*refs\/heads\/[A-Za-z0-9._/-]+\b/i);
      return match ? match[0] : null;
    },
  },
  {
    path: '/.svn/entries',
    ruleId: 'EXPOSED_SVN_METADATA',
    title: 'Exposed SVN Entries Metadata',
    severity: 'high',
    confidence: 'high',
    recommendation: 'Block access to `.svn` metadata directories at the web server level.',
    matcher: matchSvnEntriesFile,
  },
  {
    path: '/.htpasswd',
    ruleId: 'EXPOSED_HTPASSWD',
    title: 'Exposed .htpasswd File',
    severity: 'critical',
    confidence: 'high',
    recommendation: 'Block .htpasswd access and rotate affected credentials.',
    matcher: (body) => {
      if (/^[^:\r\n]+:\$[0-9a-z]+\$/im.test(body) || /^[^:\r\n]+:[^\r\n]{10,}$/im.test(body)) {
        return redactSnippet(body);
      }
      return null;
    },
  },
  {
    path: '/backup.sql',
    ruleId: 'EXPOSED_SQL_BACKUP',
    title: 'Exposed SQL Backup File',
    severity: 'critical',
    confidence: 'high',
    recommendation: 'Block backup files from public access and rotate credentials embedded in dumps.',
    matcher: matchSqlDumpFile,
  },
  {
    path: '/database.sql',
    ruleId: 'EXPOSED_SQL_BACKUP',
    title: 'Exposed SQL Database Dump',
    severity: 'critical',
    confidence: 'high',
    recommendation: 'Move SQL dump files out of web-accessible paths and enforce backup storage controls.',
    matcher: matchSqlDumpFile,
  },
  {
    path: '/db.sql',
    ruleId: 'EXPOSED_SQL_BACKUP',
    title: 'Exposed SQL Database Dump',
    severity: 'critical',
    confidence: 'high',
    recommendation: 'Move SQL dump files out of web-accessible paths and enforce backup storage controls.',
    matcher: matchSqlDumpFile,
  },
  {
    path: '/dump.sql',
    ruleId: 'EXPOSED_SQL_BACKUP',
    title: 'Exposed SQL Dump File',
    severity: 'critical',
    confidence: 'high',
    recommendation: 'Move SQL dump files out of web-accessible paths and enforce backup storage controls.',
    matcher: matchSqlDumpFile,
  },
  {
    path: '/wp-config.php.bak',
    ruleId: 'EXPOSED_PHP_BACKUP_CONFIG',
    title: 'Exposed PHP Backup Config',
    severity: 'critical',
    confidence: 'high',
    recommendation: 'Remove backup config files from public directories and rotate exposed database credentials.',
    matcher: matchPhpConfigBackup,
  },
  {
    path: '/config.php.bak',
    ruleId: 'EXPOSED_PHP_BACKUP_CONFIG',
    title: 'Exposed PHP Backup Config',
    severity: 'critical',
    confidence: 'high',
    recommendation: 'Remove backup config files from public directories and rotate exposed database credentials.',
    matcher: matchPhpConfigBackup,
  },
  {
    path: '/.npmrc',
    ruleId: 'EXPOSED_NPMRC_TOKEN',
    title: 'Exposed .npmrc Token Configuration',
    severity: 'high',
    confidence: 'high',
    recommendation: 'Block access to `.npmrc` and rotate exposed npm registry tokens.',
    matcher: (body) => {
      if (/(_authToken|\/\/[^=\s]+:_authToken)\s*=?\s*[A-Za-z0-9._-]{8,}/i.test(body)) {
        return redactSnippet(body);
      }
      return null;
    },
  },
  {
    path: '/config.json',
    ruleId: 'EXPOSED_CONFIG_FILE',
    title: 'Potentially Sensitive config.json Exposed',
    severity: 'medium',
    confidence: 'medium',
    recommendation: 'Avoid exposing runtime secrets in client-readable configuration files.',
    matcher: (body, contentType) => {
      if (!contentType.toLowerCase().includes('json') && !looksLikeJson(body)) {
        return null;
      }
      if (/\b(api[_-]?key|token|secret|password|private[_-]?key)\b/i.test(body)) {
        return redactSnippet(body);
      }
      return null;
    },
  },
];

export async function probeSensitivePaths(
  targetUrl: string,
  options?: ProbeOptions,
): Promise<ProbeResult> {
  const base = new URL(targetUrl);
  const origin = `${base.protocol}//${base.host}`;
  const requestCookie = normalizeCookie(options?.cookie) || DEFAULT_SCANNER_COOKIE;
  const files: ExtractedFile[] = [];
  const requests: NetworkRequestRecord[] = [];
  const findings: Finding[] = [];
  const errors: string[] = [];

  for (const rule of SENSITIVE_PATH_RULES) {
    const url = `${origin}${rule.path}`;
    const requestId = `req_${randomUUID()}`;
    const startedAt = Date.now();
    let response: Response | null = null;
    let bodyBuffer = Buffer.alloc(0);
    let contentType = '';

    try {
      response = await fetchWithTlsFallback(url, requestCookie);
      contentType = response.headers.get('content-type') || '';
      bodyBuffer = Buffer.from(await response.arrayBuffer());
      requests.push({
        requestId,
        method: 'GET',
        url,
        status: response.status,
        type: inferRequestType(contentType, rule.path),
        size: bodyBuffer.byteLength,
        contentType,
        durationMs: Date.now() - startedAt,
        responseHeaders: Object.fromEntries(response.headers.entries()),
      });
    } catch (error) {
      const message = formatFetchError(error);
      requests.push({
        requestId,
        method: 'GET',
        url,
        type: 'fetch',
        durationMs: Date.now() - startedAt,
        error: message,
      });
      errors.push(`Sensitive path probe failed for ${url}: ${message}`);
      continue;
    }

    if (!response || !response.ok) {
      continue;
    }

    const bodyText = decodeBody(bodyBuffer, contentType);
    if (!bodyText) {
      continue;
    }

    files.push({
      fileId: `file_${randomUUID()}`,
      url,
      kind: fileKindForPath(rule.path, contentType),
      size: bodyBuffer.byteLength,
      content: bodyText,
      discoveredFrom: targetUrl,
    });

    const evidence = rule.matcher(bodyText, contentType);
    if (!evidence) {
      continue;
    }

    findings.push({
      id: '',
      type: 'vuln',
      ruleId: rule.ruleId,
      severity: rule.severity,
      confidence: rule.confidence,
      reviewStatus: 'open',
      title: rule.title,
      description: `${url} appears to be publicly accessible and contains sensitive data patterns.`,
      recommendation: rule.recommendation,
      location: { url },
      evidence,
      createdAt: new Date().toISOString(),
    });
  }

  return { files, requests, findings, errors };
}

async function fetchWithTlsFallback(url: string, requestCookie?: string): Promise<Response> {
  let lastError: unknown = null;
  try {
    return await fetchOnce(url, false, requestCookie);
  } catch (error) {
    lastError = error;
  }

  if (ALLOW_INSECURE_TLS && isTlsCertificateError(lastError)) {
    return await fetchOnce(url, true, requestCookie);
  }

  throw lastError;
}

async function fetchOnce(url: string, insecureTls: boolean, requestCookie?: string): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
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
        Accept: '*/*',
        'Cache-Control': 'no-cache',
        Pragma: 'no-cache',
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

function matchEnvFile(body: string): string | null {
  const envLinePattern = /^[A-Z][A-Z0-9_]{1,64}\s*=\s*.+$/gim;
  const matches = Array.from(body.matchAll(envLinePattern)).map((match) => match[0]);
  if (matches.length === 0) {
    return null;
  }

  const sensitive = matches.find((line) =>
    /\b(password|secret|token|api[_-]?key|private[_-]?key|database_url|connection_string)\b/i.test(line),
  );
  const candidate = sensitive || matches[0];
  return redactEnvLine(candidate);
}

function matchAwsCredentialsFile(body: string): string | null {
  const accessKeyLine = body.match(/\baws_access_key_id\s*=\s*([A-Z0-9]{16,})/i);
  const secretKeyLine = body.match(/\baws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{20,})/i);
  const sessionTokenLine = body.match(/\baws_session_token\s*=\s*([A-Za-z0-9/+=]{20,})/i);
  if (!accessKeyLine && !secretKeyLine && !sessionTokenLine) {
    return null;
  }

  const profile = body.match(/^\s*\[[^\]]+\]\s*$/m)?.[0] || '[default]';
  const parts = [profile];
  if (accessKeyLine) {
    parts.push(redactEnvLine(accessKeyLine[0].replace(/\s*=\s*/, '=')));
  }
  if (secretKeyLine) {
    parts.push(redactEnvLine(secretKeyLine[0].replace(/\s*=\s*/, '=')));
  }
  if (sessionTokenLine) {
    parts.push(redactEnvLine(sessionTokenLine[0].replace(/\s*=\s*/, '=')));
  }
  return parts.join(' | ');
}

function matchSvnEntriesFile(body: string): string | null {
  const hasRevision = /(?:^|\n)\d+(?:\n|$)/m.test(body);
  const hasDirMarker = /(?:^|\n)dir(?:\n|$)/i.test(body);
  const hasRepoMarker = /(svn|repository|revision|entries)/i.test(body);
  if (hasRevision && hasDirMarker && hasRepoMarker) {
    return redactSnippet(body);
  }
  return null;
}

function matchSqlDumpFile(body: string): string | null {
  const sqlPattern =
    /(--\s*(mysql|mariadb|postgresql)\s+dump|\/\*!\d{5}|CREATE\s+TABLE|INSERT\s+INTO|LOCK\s+TABLES|UNLOCK\s+TABLES)/i;
  if (!sqlPattern.test(body)) {
    return null;
  }
  return redactSnippet(body);
}

function matchPhpConfigBackup(body: string): string | null {
  const hasPhpTag = /<\?php/i.test(body);
  const hasConfigSignals =
    /(db_(name|user|password|host)|database|password|username|define\s*\(\s*['"]DB_)/i.test(body);
  if (hasPhpTag && hasConfigSignals) {
    return redactSnippet(body);
  }
  return null;
}

function redactEnvLine(line: string): string {
  const parts = line.split('=');
  if (parts.length < 2) {
    return line;
  }
  const key = parts.shift()?.trim() || 'KEY';
  const value = parts.join('=').trim();
  if (!value) {
    return `${key}=`;
  }
  if (value.length <= 4) {
    return `${key}=***`;
  }
  return `${key}=${value.slice(0, 2)}***${value.slice(-2)}`;
}

function redactSnippet(body: string): string {
  const sanitized = body
    .split(/\r?\n/)
    .slice(0, 3)
    .map((line) => line.trim())
    .filter(Boolean)
    .join(' | ');
  if (!sanitized) {
    return 'Sensitive content exposed';
  }
  return sanitized.length > 180 ? `${sanitized.slice(0, 180)}...` : sanitized;
}

function decodeBody(bytes: Buffer, contentType: string): string {
  if (bytes.byteLength === 0 || bytes.byteLength > 512 * 1024) {
    return '';
  }
  if (contentType.toLowerCase().includes('application/octet-stream')) {
    return '';
  }
  const text = bytes.toString('utf8');
  if (!text.trim()) {
    return '';
  }
  return text;
}

function inferRequestType(contentType: string, path: string): string {
  const lower = contentType.toLowerCase();
  if (lower.includes('json') || path.endsWith('.json')) {
    return 'fetch';
  }
  if (lower.includes('html')) {
    return 'document';
  }
  return 'other';
}

function fileKindForPath(path: string, contentType: string): ExtractedFile['kind'] {
  const lowerType = contentType.toLowerCase();
  if (path.endsWith('.json') || lowerType.includes('json')) {
    return 'json';
  }
  if (path.endsWith('.txt') || lowerType.startsWith('text/plain')) {
    return 'txt';
  }
  if (lowerType.includes('html')) {
    return 'html';
  }
  return 'txt';
}

function isTlsCertificateError(error: unknown): boolean {
  const message = formatFetchError(error).toLowerCase();
  return (
    message.includes('self-signed certificate') ||
    message.includes('unable to verify the first certificate') ||
    message.includes('self signed certificate in certificate chain') ||
    (message.includes('certificate') && message.includes('verify'))
  );
}

function looksLikeJson(value: string): boolean {
  const trimmed = value.trim();
  return trimmed.startsWith('{') || trimmed.startsWith('[');
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

function normalizeCookie(value: string | undefined): string | undefined {
  const trimmed = (value || '').trim();
  return trimmed || undefined;
}
