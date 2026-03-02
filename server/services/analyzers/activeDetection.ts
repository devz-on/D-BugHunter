import { randomUUID } from 'node:crypto';
import { ActiveDiff, Finding, Fingerprint, SurfaceItem } from '../../types';
import { createHash } from '../crawler';

interface SurfaceInput {
  forms: Array<{ endpoint: string; method: string; params: Array<{ name: string; source: 'form' }> }>;
  queryParams: Array<{ endpoint: string; paramName: string }>;
}

const RISKY_PARAM_NAMES = ['id', 'user', 'query', 'search', 'filter', 'sort', 'email', 'name'];
const ERROR_MARKER_PATTERN =
  /(sql syntax|database error|odbc|pdoexception|stack trace|exception|unterminated string|query failed)/i;

export function buildSurface(input: SurfaceInput): SurfaceItem[] {
  const map = new Map<string, SurfaceItem>();

  for (const form of input.forms) {
    const endpoint = safeEndpoint(form.endpoint);
    const method = normalizeMethod(form.method);
    const key = `${method}:${endpoint}`;
    if (!map.has(key)) {
      map.set(key, {
        id: `surface_${randomUUID()}`,
        endpoint,
        method,
        params: [],
        riskScore: 10,
        signals: [],
      });
    }
    const item = map.get(key);
    if (!item) {
      continue;
    }
    for (const param of form.params) {
      if (!item.params.some((candidate) => candidate.name === param.name)) {
        item.params.push(param);
      }
    }
  }

  for (const query of input.queryParams) {
    const endpoint = safeEndpoint(query.endpoint);
    const key = `GET:${endpoint}`;
    if (!map.has(key)) {
      map.set(key, {
        id: `surface_${randomUUID()}`,
        endpoint,
        method: 'GET',
        params: [],
        riskScore: 10,
        signals: [],
      });
    }
    const item = map.get(key);
    if (!item) {
      continue;
    }
    if (!item.params.some((candidate) => candidate.name === query.paramName)) {
      item.params.push({ name: query.paramName, source: 'query' });
    }
  }

  for (const item of map.values()) {
    const signals: string[] = [];
    let score = 5;
    if (/\/api\/|\/search|\/auth|\/admin/i.test(item.endpoint)) {
      score += 15;
      signals.push('sensitive_path_pattern');
    }
    for (const param of item.params) {
      if (RISKY_PARAM_NAMES.includes(param.name.toLowerCase())) {
        score += 8;
        signals.push(`high_value_param:${param.name}`);
      } else {
        score += 2;
      }
    }
    item.signals = Array.from(new Set(signals));
    item.riskScore = Math.min(100, score);
  }

  return Array.from(map.values()).sort((a, b) => b.riskScore - a.riskScore);
}

export async function runActiveDetection(
  surface: SurfaceItem[],
  maxEndpoints = 30,
): Promise<{ diffs: ActiveDiff[]; findings: Finding[] }> {
  const diffs: ActiveDiff[] = [];
  const findings: Finding[] = [];
  const targetSurface = surface.slice(0, maxEndpoints).filter((item) => item.params.length > 0);

  for (const item of targetSurface) {
    const baselineParams = Object.fromEntries(item.params.map((param) => [param.name, 'hunter_baseline']));
    const baseline = await fingerprintRequest(item.endpoint, item.method, baselineParams);
    const mutations = safeMutations();

    for (const mutation of mutations) {
      const firstParam = item.params[0];
      if (!firstParam) {
        continue;
      }

      const observed = await fingerprintRequest(item.endpoint, item.method, {
        ...baselineParams,
        [firstParam.name]: mutation.value,
      });

      const signals = diffSignals(baseline, observed);
      const diff: ActiveDiff = {
        id: `diff_${randomUUID()}`,
        endpoint: item.endpoint,
        method: item.method,
        paramName: firstParam.name,
        mutationLabel: mutation.label,
        baseline,
        observed,
        signals,
      };
      diffs.push(diff);

      const anomaly = anomalyFindingFromDiff(diff);
      if (anomaly) {
        findings.push(anomaly);
      }
    }
  }

  return { diffs, findings };
}

async function fingerprintRequest(
  endpoint: string,
  method: string,
  params: Record<string, string>,
): Promise<Fingerprint> {
  const started = Date.now();
  try {
    const request = buildRequest(endpoint, method, params);
    const response = await fetch(request.url, request.init);
    const text = await response.text();
    const durationMs = Date.now() - started;
    return {
      status: response.status,
      durationMs,
      bodyHash: createHash(text),
      bodyLength: Buffer.byteLength(text, 'utf8'),
      errorMarkers: extractErrorMarkers(text),
    };
  } catch {
    const durationMs = Date.now() - started;
    return {
      durationMs,
      bodyHash: '',
      bodyLength: 0,
      errorMarkers: [],
    };
  }
}

function buildRequest(endpoint: string, method: string, params: Record<string, string>) {
  const requestMethod = normalizeMethod(method);
  if (requestMethod === 'POST') {
    const body = new URLSearchParams(params);
    return {
      url: endpoint,
      init: {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Hunter/1.1 (+defensive scanner)',
        },
        body: body.toString(),
        signal: AbortSignal.timeout(10_000),
      },
    };
  }

  const url = new URL(endpoint);
  for (const [name, value] of Object.entries(params)) {
    url.searchParams.set(name, value);
  }
  return {
    url: url.toString(),
    init: {
      method: 'GET',
      headers: {
        'User-Agent': 'Hunter/1.1 (+defensive scanner)',
      },
      signal: AbortSignal.timeout(10_000),
    },
  };
}

function diffSignals(baseline: Fingerprint, observed: Fingerprint): string[] {
  const signals: string[] = [];

  if ((baseline.status || 0) < 500 && (observed.status || 0) >= 500) {
    signals.push('status_shift_5xx');
  }

  if (observed.errorMarkers.length > baseline.errorMarkers.length) {
    signals.push('new_error_markers');
  }

  if (baseline.bodyLength > 0) {
    const ratio = observed.bodyLength / baseline.bodyLength;
    if (ratio > 2 || ratio < 0.5) {
      signals.push('response_size_drift');
    }
  }

  if (baseline.durationMs > 0 && observed.durationMs > baseline.durationMs * 3 && observed.durationMs > 1500) {
    signals.push('latency_spike');
  }

  if (baseline.status === observed.status && baseline.bodyHash !== observed.bodyHash) {
    signals.push('response_hash_change');
  }

  return signals;
}

function anomalyFindingFromDiff(diff: ActiveDiff): Finding | null {
  if (diff.signals.length === 0) {
    return null;
  }

  const hasCriticalSignals =
    diff.signals.includes('status_shift_5xx') || diff.signals.includes('new_error_markers');
  const hasMediumSignals = diff.signals.includes('response_size_drift');

  const severity: Finding['severity'] = hasCriticalSignals ? 'high' : hasMediumSignals ? 'medium' : 'low';
  const confidence: Finding['confidence'] = hasCriticalSignals ? 'high' : hasMediumSignals ? 'medium' : 'low';

  return {
    id: '',
    type: 'anomaly',
    ruleId: 'ACTIVE_BEHAVIORAL_ANOMALY',
    severity,
    confidence,
    reviewStatus: 'open',
    title: 'Behavioral Anomaly During Safe Active Detection',
    description: `Endpoint ${diff.endpoint} responded differently for a benign edge-case input.`,
    recommendation:
      'Review server-side input validation, error handling, and query execution paths for this parameter.',
    location: {
      endpoint: diff.endpoint,
      url: diff.endpoint,
    },
    evidence: `Signals: ${diff.signals.join(', ')} (param=${diff.paramName}, mutation=${diff.mutationLabel})`,
    createdAt: new Date().toISOString(),
  };
}

function extractErrorMarkers(text: string): string[] {
  const markers: string[] = [];
  if (ERROR_MARKER_PATTERN.test(text)) {
    markers.push('backend_error_signature');
  }
  if (/\btraceback\b|\bstack\b|\bexception\b/i.test(text)) {
    markers.push('stack_or_exception');
  }
  return Array.from(new Set(markers));
}

function safeMutations(): Array<{ label: string; value: string }> {
  return [
    { label: 'empty_string', value: '' },
    { label: 'long_text', value: 'A'.repeat(256) },
    { label: 'numeric_negative', value: '-1' },
    { label: 'numeric_large', value: '999999999' },
    { label: 'symbol_text', value: 'hunter_test_!@#$%^&*()' },
  ];
}

function normalizeMethod(method: string): string {
  return method.toUpperCase() === 'POST' ? 'POST' : 'GET';
}

function safeEndpoint(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return url;
  }
}
