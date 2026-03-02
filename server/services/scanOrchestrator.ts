import { randomUUID } from 'node:crypto';
import { Response } from 'express';
import { runActiveDetection, buildSurface } from './analyzers/activeDetection';
import { analyzeFilePatterns, analyzeHeaders } from './analyzers/security';
import { analyzeSecrets } from './analyzers/secrets';
import { crawlTarget } from './crawler';
import { applyReviewStatus, sortSurfaceByRisk } from './reviewAssistant';
import { JsonScanStore } from '../store/jsonStore';
import {
  CrawlOptions,
  Finding,
  ReviewStatus,
  ScanDocument,
  ScanProfile,
  ScanStartRequest,
  ScanSummary,
} from '../types';

const DEFAULT_CRAWL: CrawlOptions = {
  maxDepth: 2,
  maxPages: Number(process.env.SCAN_MAX_PAGES || 50),
  maxAssets: Number(process.env.SCAN_MAX_ASSETS || 300),
};

const TOTAL_SCAN_TIMEOUT_MS = Number(process.env.SCAN_TIMEOUT_MS || 480_000);
const LIVE_CRAWL_EVENT_INTERVAL_MS = Number(process.env.SCAN_PROGRESS_EVENT_INTERVAL_MS || 500);

const DEFAULT_PROFILE: ScanProfile = {
  passive: true,
  activeDetection: true,
  manualReview: true,
};

export class ScanOrchestrator {
  private scans = new Map<string, ScanDocument>();
  private eventClients = new Map<string, Set<Response>>();

  constructor(private readonly store: JsonScanStore) {}

  async startScan(input: ScanStartRequest): Promise<ScanDocument> {
    const targetUrl = normalizeTargetUrl(input.targetUrl);
    const scanId = `scan_${randomUUID()}`;
    const crawl = {
      ...DEFAULT_CRAWL,
      ...(input.crawl || {}),
    };
    const profile = {
      ...DEFAULT_PROFILE,
      ...(input.profile || {}),
    };

    const scan: ScanDocument = {
      scanId,
      targetUrl,
      startedAt: new Date().toISOString(),
      status: 'queued',
      profile,
      crawl,
      stats: {
        pages: 0,
        assets: 0,
        requests: 0,
        findings: 0,
      },
      files: [],
      requests: [],
      findings: [],
      surface: [],
      diffs: [],
      errors: [],
    };

    this.scans.set(scanId, scan);
    await this.store.saveScan(scan);
    this.emit(scanId, 'scan-updated', this.summary(scan));

    void this.executeScan(scanId);

    return scan;
  }

  subscribe(scanId: string, response: Response): () => void {
    if (!this.eventClients.has(scanId)) {
      this.eventClients.set(scanId, new Set<Response>());
    }
    const set = this.eventClients.get(scanId);
    if (!set) {
      return () => undefined;
    }
    set.add(response);

    const snapshot = this.getScanSync(scanId);
    if (snapshot) {
      sendEvent(response, 'snapshot', this.summary(snapshot));
    }

    return () => {
      set.delete(response);
      if (set.size === 0) {
        this.eventClients.delete(scanId);
      }
    };
  }

  async getScan(scanId: string): Promise<ScanDocument | null> {
    const inMemory = this.getScanSync(scanId);
    if (inMemory) {
      await this.recoverStaleScan(inMemory);
      return inMemory;
    }
    const persisted = await this.store.loadScan(scanId);
    if (persisted) {
      await this.recoverStaleScan(persisted);
      this.scans.set(scanId, persisted);
    }
    return persisted;
  }

  async getSummary(scanId: string): Promise<ScanSummary | null> {
    const scan = await this.getScan(scanId);
    return scan ? this.summary(scan) : null;
  }

  async listSummaries(): Promise<ScanSummary[]> {
    const persisted = await this.store.listScans();
    for (const scan of persisted) {
      await this.recoverStaleScan(scan);
      this.scans.set(scan.scanId, scan);
    }
    return persisted.map((scan) => this.summary(scan));
  }

  async updateReviewStatus(
    scanId: string,
    findingId: string,
    reviewStatus: ReviewStatus,
  ): Promise<Finding | null> {
    const scan = await this.getScan(scanId);
    if (!scan) {
      return null;
    }
    const updated = applyReviewStatus(scan.findings, findingId, reviewStatus);
    if (!updated) {
      return null;
    }
    await this.store.saveScan(scan);
    this.emit(scanId, 'scan-updated', this.summary(scan));
    return updated;
  }

  private async executeScan(scanId: string): Promise<void> {
    const scan = this.getScanSync(scanId);
    if (!scan) {
      return;
    }

    scan.status = 'running';
    await this.store.saveScan(scan);
    this.emit(scanId, 'scan-updated', this.summary(scan));
    try {
      await withTimeout(
        this.runScanPipeline(scanId, scan),
        TOTAL_SCAN_TIMEOUT_MS,
        `Scan exceeded ${TOTAL_SCAN_TIMEOUT_MS}ms total timeout`,
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Scan execution failed';
      await this.failScan(scanId, message);
    }
  }

  private async runScanPipeline(scanId: string, scan: ScanDocument): Promise<void> {
    const rootProtocol = new URL(scan.targetUrl).protocol;
    const processedPassiveFileIds = new Set<string>();
    const processedPassiveRequestIds = new Set<string>();
    let lastLiveEmitMs = 0;

    const analyzePassiveIncremental = (
      files: ScanDocument['files'],
      requests: ScanDocument['requests'],
    ) => {
      if (!scan.profile.passive) {
        return;
      }

      for (const file of files) {
        const fileKey = file.fileId || file.url;
        if (processedPassiveFileIds.has(fileKey)) {
          continue;
        }
        processedPassiveFileIds.add(fileKey);
        this.pushFindings(scan, analyzeSecrets(file));
        this.pushFindings(scan, analyzeFilePatterns(file, rootProtocol));
      }

      for (const request of requests) {
        const requestKey =
          request.requestId ||
          `${request.method}:${request.url}:${request.status || ''}:${request.durationMs || ''}`;
        if (processedPassiveRequestIds.has(requestKey)) {
          continue;
        }
        processedPassiveRequestIds.add(requestKey);
        this.pushFindings(scan, analyzeHeaders(request));
      }
    };

    const applyCrawlSnapshot = (forceEmit: boolean, crawlResult: {
      files: ScanDocument['files'];
      requests: ScanDocument['requests'];
      pageUrls: string[];
      errors: string[];
    }) => {
      scan.files = crawlResult.files;
      scan.requests = crawlResult.requests;
      scan.errors = [...crawlResult.errors];
      scan.stats.pages = crawlResult.pageUrls.length;
      scan.stats.assets = crawlResult.files.filter((file) => file.kind !== 'html').length;
      scan.stats.requests = crawlResult.requests.length;
      analyzePassiveIncremental(scan.files, scan.requests);

      const now = Date.now();
      if (forceEmit || now - lastLiveEmitMs >= LIVE_CRAWL_EVENT_INTERVAL_MS) {
        lastLiveEmitMs = now;
        this.emit(scanId, 'scan-updated', this.summary(scan));
      }
    };

    const crawlResult = await crawlTarget(
      scan.targetUrl,
      scan.crawl,
      (snapshot) => applyCrawlSnapshot(false, snapshot),
    );
    applyCrawlSnapshot(true, crawlResult);

    if (scan.profile.passive) {
      // Final full-pass passive analysis after crawl completes to catch any edge-case misses.
      for (const file of crawlResult.files) {
        this.pushFindings(scan, analyzeSecrets(file));
        this.pushFindings(scan, analyzeFilePatterns(file, rootProtocol));
      }
      for (const request of crawlResult.requests) {
        this.pushFindings(scan, analyzeHeaders(request));
      }
    }

    await this.store.saveScan(scan);
    this.emit(scanId, 'scan-updated', this.summary(scan));

    if (scan.profile.activeDetection) {
      scan.surface = sortSurfaceByRisk(
        buildSurface({
          forms: crawlResult.forms.map((form) => ({
            endpoint: form.endpoint,
            method: form.method,
            params: form.params.filter((param) => param.source === 'form') as Array<{
              name: string;
              source: 'form';
            }>,
          })),
          queryParams: crawlResult.queryParams,
        }),
      );

      if (scan.surface.length > 0) {
        const { diffs, findings } = await runActiveDetection(scan.surface);
        scan.diffs = diffs;
        this.pushFindings(scan, findings);
      }

      await this.store.saveScan(scan);
      this.emit(scanId, 'scan-updated', this.summary(scan));
    }

    scan.status = 'completed';
    scan.completedAt = new Date().toISOString();
    scan.stats.findings = scan.findings.length;
    await this.store.saveScan(scan);
    this.emit(scanId, 'scan-completed', this.summary(scan));
  }

  private async failScan(scanId: string, errorMessage: string): Promise<void> {
    const scan = this.getScanSync(scanId);
    if (!scan) {
      return;
    }
    scan.status = 'failed';
    scan.errors.push(errorMessage);
    scan.completedAt = new Date().toISOString();
    await this.store.saveScan(scan);
    this.emit(scanId, 'scan-failed', this.summary(scan));
  }

  private getScanSync(scanId: string): ScanDocument | null {
    return this.scans.get(scanId) || null;
  }

  private emit(scanId: string, event: string, payload: unknown): void {
    const clients = this.eventClients.get(scanId);
    if (!clients || clients.size === 0) {
      return;
    }
    for (const response of clients) {
      sendEvent(response, event, payload);
    }
  }

  private pushFindings(scan: ScanDocument, findings: Finding[]): void {
    for (const finding of findings) {
      const dedupeKey = `${finding.type}:${finding.ruleId}:${finding.location.url || ''}:${finding.location.fileId || ''}:${finding.evidence}`;
      const duplicate = scan.findings.some((item) => {
        const candidate = `${item.type}:${item.ruleId}:${item.location.url || ''}:${item.location.fileId || ''}:${item.evidence}`;
        return candidate === dedupeKey;
      });
      if (duplicate) {
        continue;
      }
      finding.id = `finding_${randomUUID()}`;
      scan.findings.push(finding);
    }
    scan.stats.findings = scan.findings.length;
  }

  private summary(scan: ScanDocument): ScanSummary {
    return {
      scanId: scan.scanId,
      targetUrl: scan.targetUrl,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
      status: scan.status,
      stats: scan.stats,
      errors: scan.errors,
    };
  }

  private async recoverStaleScan(scan: ScanDocument): Promise<void> {
    const isPending = scan.status === 'queued' || scan.status === 'running';
    if (!isPending) {
      return;
    }

    const startedAtMs = Date.parse(scan.startedAt);
    if (Number.isNaN(startedAtMs)) {
      return;
    }
    const staleThresholdMs = TOTAL_SCAN_TIMEOUT_MS * 2;
    if (Date.now() - startedAtMs <= staleThresholdMs) {
      return;
    }

    scan.status = 'failed';
    scan.completedAt = scan.completedAt || new Date().toISOString();
    const staleError = `Scan was marked failed after exceeding stale threshold (${staleThresholdMs}ms)`;
    if (!scan.errors.includes(staleError)) {
      scan.errors.push(staleError);
    }
    await this.store.saveScan(scan);
  }
}

function normalizeTargetUrl(rawUrl: string): string {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only http/https URLs are allowed');
  }
  parsed.hash = '';
  return parsed.toString();
}

function sendEvent(response: Response, event: string, payload: unknown): void {
  response.write(`event: ${event}\n`);
  response.write(`data: ${JSON.stringify(payload)}\n\n`);
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  return await new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(message));
    }, timeoutMs);

    promise
      .then((value) => {
        clearTimeout(timer);
        resolve(value);
      })
      .catch((error) => {
        clearTimeout(timer);
        reject(error);
      });
  });
}
