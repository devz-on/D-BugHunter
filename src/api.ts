import {
  ActiveDiff,
  FileContentResponse,
  FileEntry,
  Finding,
  NetworkEntry,
  PreviewSession,
  ReviewStatus,
  ScanSummary,
  SurfaceItem,
} from './types';

interface StartScanResponse {
  scanId: string;
  status: string;
  targetUrl: string;
}

export async function startScan(targetUrl: string): Promise<StartScanResponse> {
  return request('/api/scans', {
    method: 'POST',
    body: JSON.stringify({
      targetUrl,
      crawl: {
        maxDepth: 2,
        maxPages: 50,
        maxAssets: 300,
      },
      profile: {
        passive: true,
        activeDetection: true,
        manualReview: true,
      },
    }),
  });
}

export async function createPreviewSession(targetUrl: string): Promise<PreviewSession> {
  return request('/api/preview/sessions', {
    method: 'POST',
    body: JSON.stringify({ targetUrl }),
  });
}

export async function getScanSummary(scanId: string): Promise<ScanSummary> {
  return request(`/api/scans/${scanId}`);
}

export async function getFiles(scanId: string): Promise<FileEntry[]> {
  return request(`/api/scans/${scanId}/files`);
}

export async function getFileContent(scanId: string, fileId: string): Promise<FileContentResponse> {
  return request(`/api/scans/${scanId}/files/${fileId}/content`);
}

export async function getFindings(scanId: string): Promise<Finding[]> {
  return request(`/api/scans/${scanId}/findings`);
}

export async function getNetwork(scanId: string): Promise<NetworkEntry[]> {
  return request(`/api/scans/${scanId}/network`);
}

export async function getSurface(scanId: string): Promise<SurfaceItem[]> {
  return request(`/api/scans/${scanId}/surface`);
}

export async function getDiffs(scanId: string): Promise<ActiveDiff[]> {
  return request(`/api/scans/${scanId}/diffs`);
}

export async function updateFindingReviewStatus(
  scanId: string,
  findingId: string,
  reviewStatus: ReviewStatus,
): Promise<Finding> {
  return request(`/api/scans/${scanId}/findings/${findingId}`, {
    method: 'PATCH',
    body: JSON.stringify({ reviewStatus }),
  });
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
  });
  if (!response.ok) {
    let details = '';
    try {
      const errorPayload = await response.json();
      details = errorPayload?.error ? `: ${errorPayload.error}` : '';
    } catch {
      // ignore non-json error payloads
    }
    throw new Error(`Request failed (${response.status})${details}`);
  }
  return (await response.json()) as T;
}
