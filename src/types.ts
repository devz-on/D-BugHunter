export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
export type FindingType = 'secret' | 'vuln' | 'anomaly';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'low' | 'medium' | 'high';
export type ReviewStatus = 'open' | 'confirmed' | 'false_positive' | 'needs_review';

export interface ScanProfile {
  passive: boolean;
  activeDetection: boolean;
  manualReview: boolean;
  sensitiveExposureChecks: boolean;
  nmapPortScan: boolean;
}

export interface ScanSummary {
  scanId: string;
  targetUrl: string;
  startedAt: string;
  completedAt?: string;
  status: ScanStatus;
  stats: {
    pages: number;
    assets: number;
    requests: number;
    findings: number;
  };
  errors: string[];
}

export interface FileEntry {
  fileId: string;
  url: string;
  kind: 'html' | 'css' | 'js' | 'json' | 'txt' | 'other';
  size: number;
  discoveredFrom?: string;
}

export interface FileContentResponse {
  fileId: string;
  url: string;
  kind: FileEntry['kind'];
  content: string;
}

export interface Finding {
  id: string;
  type: FindingType;
  ruleId: string;
  severity: Severity;
  confidence: Confidence;
  reviewStatus: ReviewStatus;
  title: string;
  description: string;
  recommendation: string;
  location: {
    url?: string;
    fileId?: string;
    line?: number;
    endpoint?: string;
  };
  evidence: string;
  createdAt: string;
}

export interface NetworkEntry {
  requestId: string;
  method: string;
  url: string;
  status?: number;
  type?: string;
  size?: number;
  contentType?: string;
  durationMs?: number;
  error?: string;
}

export interface SurfaceItem {
  id: string;
  endpoint: string;
  method: string;
  params: Array<{ name: string; source: 'query' | 'form' | 'json' }>;
  riskScore: number;
  signals: string[];
}

export interface ActiveDiff {
  id: string;
  endpoint: string;
  method: string;
  paramName: string;
  mutationLabel: string;
  baseline: {
    status?: number;
    durationMs: number;
    bodyHash: string;
    bodyLength: number;
    errorMarkers: string[];
  };
  observed: {
    status?: number;
    durationMs: number;
    bodyHash: string;
    bodyLength: number;
    errorMarkers: string[];
  };
  signals: string[];
}

export interface PreviewSession {
  sessionId: string;
  targetUrl: string;
  mode: 'iframe';
  createdAt: string;
  note: string;
}
