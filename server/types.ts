export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

export type FindingType = 'secret' | 'vuln' | 'anomaly';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'low' | 'medium' | 'high';
export type ReviewStatus = 'open' | 'confirmed' | 'false_positive' | 'needs_review';

export type FileKind = 'html' | 'css' | 'js' | 'json' | 'txt' | 'other';
export type ParamSource = 'query' | 'form' | 'json';

export interface CrawlOptions {
  maxDepth: number;
  maxPages: number;
  maxAssets: number;
}

export interface ScanProfile {
  passive: boolean;
  activeDetection: boolean;
  manualReview: boolean;
}

export interface ScanStartRequest {
  targetUrl: string;
  crawl?: Partial<CrawlOptions>;
  profile?: Partial<ScanProfile>;
}

export interface ExtractedFile {
  fileId: string;
  url: string;
  kind: FileKind;
  size: number;
  content: string;
  discoveredFrom?: string;
}

export interface NetworkRequestRecord {
  requestId: string;
  method: string;
  url: string;
  status?: number;
  type?: string;
  size?: number;
  contentType?: string;
  durationMs?: number;
  responseHeaders?: Record<string, string>;
  requestHeaders?: Record<string, string>;
  error?: string;
}

export interface FindingLocation {
  url?: string;
  fileId?: string;
  line?: number;
  endpoint?: string;
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
  location: FindingLocation;
  evidence: string;
  createdAt: string;
}

export interface SurfaceParam {
  name: string;
  source: ParamSource;
}

export interface SurfaceItem {
  id: string;
  endpoint: string;
  method: string;
  params: SurfaceParam[];
  riskScore: number;
  signals: string[];
}

export interface Fingerprint {
  status?: number;
  durationMs: number;
  bodyHash: string;
  bodyLength: number;
  errorMarkers: string[];
}

export interface ActiveDiff {
  id: string;
  endpoint: string;
  method: string;
  paramName: string;
  mutationLabel: string;
  baseline: Fingerprint;
  observed: Fingerprint;
  signals: string[];
}

export interface ScanStats {
  pages: number;
  assets: number;
  requests: number;
  findings: number;
}

export interface ScanDocument {
  scanId: string;
  targetUrl: string;
  startedAt: string;
  completedAt?: string;
  status: ScanStatus;
  profile: ScanProfile;
  crawl: CrawlOptions;
  stats: ScanStats;
  files: ExtractedFile[];
  requests: NetworkRequestRecord[];
  findings: Finding[];
  surface: SurfaceItem[];
  diffs: ActiveDiff[];
  errors: string[];
}

export interface ScanSummary {
  scanId: string;
  targetUrl: string;
  startedAt: string;
  completedAt?: string;
  status: ScanStatus;
  stats: ScanStats;
  errors: string[];
}

export interface DiscoveredForm {
  endpoint: string;
  method: string;
  params: SurfaceParam[];
}

export interface CrawlResult {
  files: ExtractedFile[];
  requests: NetworkRequestRecord[];
  pageUrls: string[];
  forms: DiscoveredForm[];
  queryParams: Array<{ endpoint: string; paramName: string }>;
  errors: string[];
}
