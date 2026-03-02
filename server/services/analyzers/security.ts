import { Finding, ExtractedFile, NetworkRequestRecord } from '../../types';

const REQUIRED_HEADERS = [
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
];

const DB_ERROR_PATTERN =
  /(sql syntax|database error|odbc|pdoexception|query failed|unterminated string|syntax error near)/i;

export function analyzeHeaders(record: NetworkRequestRecord): Finding[] {
  const findings: Finding[] = [];
  const headers = normalizeHeaders(record.responseHeaders || {});
  if (!record.status || !String(record.status).startsWith('2')) {
    return findings;
  }

  for (const required of REQUIRED_HEADERS) {
    if (headers[required]) {
      continue;
    }
    findings.push({
      id: '',
      type: 'vuln',
      ruleId: 'MISSING_SECURITY_HEADER',
      severity: required === 'content-security-policy' ? 'high' : 'medium',
      confidence: 'high',
      reviewStatus: 'open',
      title: `Missing Security Header: ${required}`,
      description: `Response from ${record.url} is missing ${required}.`,
      recommendation:
        'Add the missing header in your reverse proxy or application response middleware.',
      location: { url: record.url },
      evidence: required,
      createdAt: new Date().toISOString(),
    });
  }

  const acao = headers['access-control-allow-origin'];
  const acac = headers['access-control-allow-credentials'];
  if (acao === '*' && acac === 'true') {
    findings.push({
      id: '',
      type: 'vuln',
      ruleId: 'CORS_WILDCARD_WITH_CREDENTIALS',
      severity: 'high',
      confidence: 'high',
      reviewStatus: 'open',
      title: 'Potentially Unsafe CORS Configuration',
      description: `CORS appears to allow wildcard origin with credentials at ${record.url}.`,
      recommendation:
        'Restrict allowed origins to explicit trusted hosts and avoid wildcard with credentials.',
      location: { url: record.url },
      evidence: 'Access-Control-Allow-Origin=* with Access-Control-Allow-Credentials=true',
      createdAt: new Date().toISOString(),
    });
  }

  const setCookie = headers['set-cookie'];
  if (setCookie) {
    const normalizedCookie = setCookie.toLowerCase();
    if (!normalizedCookie.includes('secure')) {
      findings.push(cookieFlagFinding(record.url, 'Secure'));
    }
    if (!normalizedCookie.includes('httponly')) {
      findings.push(cookieFlagFinding(record.url, 'HttpOnly'));
    }
    if (!normalizedCookie.includes('samesite')) {
      findings.push(cookieFlagFinding(record.url, 'SameSite'));
    }
  }

  return findings;
}

export function analyzeFilePatterns(
  file: ExtractedFile,
  rootProtocol: string,
): Finding[] {
  const findings: Finding[] = [];

  if (
    file.kind === 'js' &&
    /(eval\s*\(|new Function\s*\(|\.innerHTML\s*=)/i.test(file.content)
  ) {
    findings.push({
      id: '',
      type: 'vuln',
      ruleId: 'RISKY_JS_SINKS',
      severity: 'medium',
      confidence: 'medium',
      reviewStatus: 'open',
      title: 'Risky JavaScript Sink Detected',
      description: `${file.url} uses patterns commonly associated with XSS-prone flows.`,
      recommendation: 'Validate and sanitize untrusted input before using dynamic execution or HTML sinks.',
      location: { fileId: file.fileId, url: file.url },
      evidence: extractSnippet(file.content, /(eval\s*\(|new Function\s*\(|\.innerHTML\s*=)/i),
      createdAt: new Date().toISOString(),
    });
  }

  if (/(\/\/# sourceMappingURL=|\/\*# sourceMappingURL=)/i.test(file.content) || file.url.endsWith('.map')) {
    findings.push({
      id: '',
      type: 'vuln',
      ruleId: 'SOURCEMAP_EXPOSED',
      severity: 'low',
      confidence: 'medium',
      reviewStatus: 'open',
      title: 'Potential Source Map Exposure',
      description: `${file.url} appears to expose source map linkage.`,
      recommendation: 'Disable public source maps or restrict access in production.',
      location: { fileId: file.fileId, url: file.url },
      evidence: 'sourceMappingURL directive or .map asset',
      createdAt: new Date().toISOString(),
    });
  }

  if (/\bdebug\b\s*[:=]\s*true|\bstaging\b|\bNODE_ENV\b\s*[:=]\s*["']development["']/i.test(file.content)) {
    findings.push({
      id: '',
      type: 'vuln',
      ruleId: 'DEBUG_ARTIFACT_EXPOSED',
      severity: 'medium',
      confidence: 'medium',
      reviewStatus: 'open',
      title: 'Debug or Staging Artifact Found',
      description: `${file.url} contains tokens that look like debug or staging artifacts.`,
      recommendation: 'Strip debug/staging flags and internal diagnostics from production bundles.',
      location: { fileId: file.fileId, url: file.url },
      evidence: extractSnippet(
        file.content,
        /\bdebug\b\s*[:=]\s*true|\bstaging\b|\bNODE_ENV\b\s*[:=]\s*["']development["']/i,
      ),
      createdAt: new Date().toISOString(),
    });
  }

  if (rootProtocol === 'https:' && /http:\/\//i.test(file.content) && file.kind === 'html') {
    findings.push({
      id: '',
      type: 'vuln',
      ruleId: 'MIXED_CONTENT_REFERENCE',
      severity: 'medium',
      confidence: 'low',
      reviewStatus: 'open',
      title: 'Possible Mixed Content Reference',
      description: `${file.url} includes non-HTTPS resource references.`,
      recommendation: 'Serve all assets and API calls over HTTPS.',
      location: { fileId: file.fileId, url: file.url },
      evidence: extractSnippet(file.content, /http:\/\//i),
      createdAt: new Date().toISOString(),
    });
  }

  const dbErrorMatch = file.content.match(DB_ERROR_PATTERN);
  if (dbErrorMatch) {
    findings.push({
      id: '',
      type: 'vuln',
      ruleId: 'DATABASE_ERROR_DISCLOSURE',
      severity: 'high',
      confidence: 'medium',
      reviewStatus: 'open',
      title: 'Database Error Signature Disclosed',
      description: `${file.url} may expose backend database error details.`,
      recommendation: 'Return generic error responses and suppress raw backend exception text.',
      location: { fileId: file.fileId, url: file.url },
      evidence: dbErrorMatch[0],
      createdAt: new Date().toISOString(),
    });
  }

  return findings;
}

function normalizeHeaders(headers: Record<string, string>): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    normalized[name.toLowerCase()] = value;
  }
  return normalized;
}

function cookieFlagFinding(url: string, flag: string): Finding {
  return {
    id: '',
    type: 'vuln',
    ruleId: 'COOKIE_FLAG_MISSING',
    severity: 'medium',
    confidence: 'high',
    reviewStatus: 'open',
    title: `Cookie Missing ${flag}`,
    description: `${url} sets cookie data without ${flag} protection.`,
    recommendation: `Set ${flag} on security-sensitive cookies.`,
    location: { url },
    evidence: flag,
    createdAt: new Date().toISOString(),
  };
}

function extractSnippet(content: string, pattern: RegExp): string {
  const match = content.match(pattern);
  if (!match) {
    return 'Pattern detected';
  }
  const index = content.indexOf(match[0]);
  const start = Math.max(0, index - 40);
  const end = Math.min(content.length, index + match[0].length + 40);
  return content.slice(start, end).replace(/\s+/g, ' ').trim();
}
