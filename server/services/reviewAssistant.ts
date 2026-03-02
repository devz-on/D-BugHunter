import { Finding, ReviewStatus, SurfaceItem } from '../types';

export function applyReviewStatus(
  findings: Finding[],
  findingId: string,
  reviewStatus: ReviewStatus,
): Finding | null {
  const finding = findings.find((item) => item.id === findingId);
  if (!finding) {
    return null;
  }
  finding.reviewStatus = reviewStatus;
  return finding;
}

export function sortSurfaceByRisk(surface: SurfaceItem[]): SurfaceItem[] {
  return [...surface].sort((a, b) => b.riskScore - a.riskScore);
}
