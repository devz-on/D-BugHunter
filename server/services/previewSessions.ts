import { randomUUID } from 'node:crypto';

export interface PreviewSession {
  sessionId: string;
  targetUrl: string;
  mode: 'iframe';
  createdAt: string;
  note: string;
}

export class PreviewSessionManager {
  private sessions = new Map<string, PreviewSession>();
  private sessionCookies = new Map<string, string>();

  create(targetUrl: string, cookie?: string): PreviewSession {
    const session: PreviewSession = {
      sessionId: `preview_${randomUUID()}`,
      targetUrl,
      mode: 'iframe',
      createdAt: new Date().toISOString(),
      note: 'Direct iframe mode is active. Some sites may block embedding via CSP/X-Frame-Options.',
    };
    this.sessions.set(session.sessionId, session);
    const normalizedCookie = normalizeCookie(cookie);
    if (normalizedCookie) {
      this.sessionCookies.set(session.sessionId, normalizedCookie);
    }
    return session;
  }

  get(sessionId: string): PreviewSession | null {
    return this.sessions.get(sessionId) || null;
  }

  getCookie(sessionId: string): string | undefined {
    return this.sessionCookies.get(sessionId);
  }

  destroy(sessionId: string): boolean {
    this.sessionCookies.delete(sessionId);
    return this.sessions.delete(sessionId);
  }
}

function normalizeCookie(value: string | undefined): string | undefined {
  const trimmed = (value || '').trim();
  return trimmed || undefined;
}
