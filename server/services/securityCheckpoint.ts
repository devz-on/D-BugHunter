export interface SecurityCheckpoint {
  provider: 'vercel' | 'cloudflare' | 'generic';
  code?: string;
  referenceId?: string;
  summary: string;
}

export function detectSecurityCheckpoint(contentType: string, body: string): SecurityCheckpoint | null {
  if (!body) {
    return null;
  }

  const lowerContentType = contentType.toLowerCase();
  if (!lowerContentType.includes('html') && !lowerContentType.includes('text')) {
    return null;
  }

  const lowerBody = body.toLowerCase();

  const looksLikeVercelCheckpoint =
    lowerBody.includes('vercel security checkpoint') ||
    lowerBody.includes('failed to verify your browser');
  if (looksLikeVercelCheckpoint) {
    const code = matchGroup(body, /\bcode\s*[:#-]?\s*([0-9]{1,4})\b/i);
    const referenceId = matchGroup(body, /\b[a-z]{3,5}\d?::[A-Za-z0-9._-]{8,}\b/i);
    const summary = code
      ? `Vercel Security Checkpoint blocked automated access (Code ${code}).`
      : 'Vercel Security Checkpoint blocked automated access.';
    return { provider: 'vercel', code, referenceId, summary };
  }

  const looksLikeCloudflareChallenge =
    lowerBody.includes('cloudflare') &&
    (lowerBody.includes('checking your browser') ||
      lowerBody.includes('verify you are human') ||
      lowerBody.includes('attention required') ||
      lowerBody.includes('cf-chl'));
  if (looksLikeCloudflareChallenge) {
    return {
      provider: 'cloudflare',
      summary: 'Cloudflare challenge blocked automated access.',
    };
  }

  const looksLikeGenericChallenge =
    lowerBody.includes('verify your browser') ||
    lowerBody.includes('security checkpoint') ||
    lowerBody.includes('captcha');
  if (looksLikeGenericChallenge) {
    return {
      provider: 'generic',
      summary: 'A security challenge blocked automated access.',
    };
  }

  return null;
}

export function buildCheckpointErrorMessage(checkpoint: SecurityCheckpoint, url: string): string {
  const codeText = checkpoint.code ? ` Code ${checkpoint.code}.` : '';
  const referenceText = checkpoint.referenceId ? ` Ref ${checkpoint.referenceId}.` : '';
  return (
    `${checkpoint.summary}${codeText}${referenceText} ` +
    `URL: ${url}. If this target is authorized, solve the challenge in a normal browser then provide cookie via UI (Cookie field) or SCANNER_COOKIE/PREVIEW_COOKIE in .env.`
  );
}

function matchGroup(value: string, pattern: RegExp): string | undefined {
  const match = value.match(pattern);
  if (!match) {
    return undefined;
  }
  return match[1] || match[0];
}
