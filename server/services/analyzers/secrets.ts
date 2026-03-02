import { Finding, ExtractedFile } from '../../types';

interface SecretRule {
  ruleId: string;
  title: string;
  severity: Finding['severity'];
  confidence: Finding['confidence'];
  pattern: RegExp;
  recommendation: string;
}

const SECRET_RULES: SecretRule[] = [
  {
    ruleId: 'SECRET_AWS_ACCESS_KEY',
    title: 'Potential AWS Access Key Exposed',
    severity: 'high',
    confidence: 'medium',
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    recommendation: 'Rotate key immediately and use server-side secret management.',
  },
  {
    ruleId: 'SECRET_STRIPE_LIVE',
    title: 'Potential Stripe Live Secret Exposed',
    severity: 'critical',
    confidence: 'high',
    pattern: /\bsk_live_[0-9a-zA-Z]{16,}\b/g,
    recommendation: 'Rotate the Stripe key and ensure client bundles never include live secrets.',
  },
  {
    ruleId: 'SECRET_GITHUB_PAT',
    title: 'Potential GitHub Personal Access Token Exposed',
    severity: 'high',
    confidence: 'high',
    pattern: /\bghp_[0-9A-Za-z]{36}\b/g,
    recommendation: 'Revoke token and move credentials to protected environment configuration.',
  },
  {
    ruleId: 'SECRET_GOOGLE_API_KEY',
    title: 'Potential Google API Key Exposed (Gemini Compatible)',
    severity: 'high',
    confidence: 'high',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    recommendation:
      'Rotate the Google API key, restrict it by API + referrer/IP, and keep it out of client bundles.',
  },
  {
    ruleId: 'SECRET_PRIVATE_KEY_BLOCK',
    title: 'Private Key Block Detected',
    severity: 'critical',
    confidence: 'high',
    pattern: /-----BEGIN (RSA|EC|OPENSSH|DSA|PRIVATE) KEY-----/g,
    recommendation: 'Remove private key material from public content and rotate credentials.',
  },
  {
    ruleId: 'SECRET_GENERIC_ASSIGNMENT',
    title: 'Suspicious Hardcoded Secret Assignment',
    severity: 'medium',
    confidence: 'medium',
    pattern:
      /\b(api[_-]?key|secret|token|access[_-]?key)\b\s*[:=]\s*["'][A-Za-z0-9_\-.]{16,}["']/gi,
    recommendation: 'Replace hardcoded values with environment-based secret injection.',
  },
  {
    ruleId: 'SECRET_JWT_TOKEN',
    title: 'Potential JWT Token Exposed',
    severity: 'medium',
    confidence: 'low',
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b/g,
    recommendation: 'Do not expose bearer tokens in static assets or logs.',
  },
];

export function analyzeSecrets(file: ExtractedFile): Finding[] {
  const findings: Finding[] = [];
  for (const rule of SECRET_RULES) {
    for (const match of file.content.matchAll(rule.pattern)) {
      const matchText = match[0];
      const startIndex = match.index || 0;
      findings.push({
        id: '',
        type: 'secret',
        ruleId: rule.ruleId,
        severity: rule.severity,
        confidence: rule.confidence,
        reviewStatus: 'open',
        title: rule.title,
        description: `Potential secret-like value found in ${file.url}.`,
        recommendation: rule.recommendation,
        location: {
          fileId: file.fileId,
          url: file.url,
          line: lineFromIndex(file.content, startIndex),
        },
        evidence: redactSecret(matchText),
        createdAt: new Date().toISOString(),
      });
    }
  }
  return findings;
}

function lineFromIndex(content: string, index: number): number {
  return content.slice(0, index).split('\n').length;
}

function redactSecret(secret: string): string {
  if (secret.length <= 8) {
    return `${secret.slice(0, 2)}***`;
  }
  return `${secret.slice(0, 4)}***${secret.slice(-3)}`;
}
