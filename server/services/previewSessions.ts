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

  create(targetUrl: string): PreviewSession {
    const session: PreviewSession = {
      sessionId: `preview_${randomUUID()}`,
      targetUrl,
      mode: 'iframe',
      createdAt: new Date().toISOString(),
      note: 'Direct iframe mode is active. Some sites may block embedding via CSP/X-Frame-Options.',
    };
    this.sessions.set(session.sessionId, session);
    return session;
  }

  get(sessionId: string): PreviewSession | null {
    return this.sessions.get(sessionId) || null;
  }

  destroy(sessionId: string): boolean {
    return this.sessions.delete(sessionId);
  }
}
