import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { Finding } from '../../types';

const PORT_SCAN_TIMEOUT_MS = Number(process.env.PORT_SCAN_TIMEOUT_MS || 1_200);
const PORT_SCAN_CONCURRENCY = Number(process.env.PORT_SCAN_CONCURRENCY || 24);
const PORT_SCAN_TOP_PORTS = Number(process.env.PORT_SCAN_TOP_PORTS || 200);
const PORT_SCAN_PORTS = parsePortList(process.env.PORT_SCAN_PORTS);

const PORT_VULN_SCAN_ENABLED = process.env.PORT_VULN_SCAN_ENABLED !== 'false';
const PORT_VULN_MAX_SERVICES = Number(process.env.PORT_VULN_MAX_SERVICES || 12);
const PORT_VULN_TIMEOUT_MS = Number(process.env.PORT_VULN_TIMEOUT_MS || 1_800);
const PORT_VULN_CONCURRENCY = Number(process.env.PORT_VULN_CONCURRENCY || 4);

const HTTP_BODY_LIMIT_BYTES = 64 * 1024;
const SCANNER_USER_AGENT =
  process.env.SCANNER_USER_AGENT ||
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36';

const HIGH_RISK_PORTS = new Set([
  21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 445, 1433, 1521, 3306, 3389, 5432, 6379, 9200, 27017,
]);
const MEDIUM_RISK_PORTS = new Set([80, 443, 5000, 5601, 8080, 8443, 9000]);
const HTTP_PORTS = new Set([80, 443, 5000, 5601, 8080, 8443, 9000, 9200, 2375]);
const TLS_PORTS = new Set([443, 8443]);
const PRIORITY_VULN_PORTS = [22, 80, 443, 2375, 6379, 11211, 9200, 5601, 8080, 8443, 27017, 3306];

const DEFAULT_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 11211, 1433, 1521, 2049, 2375,
  3306, 3389, 5000, 5432, 5601, 6379, 8080, 8443, 9000, 9200, 27017,
];

interface NmapResult {
  findings: Finding[];
  errors: string[];
}

interface HttpProbeResult {
  status?: number;
  headers: Record<string, string>;
  body: string;
}

export async function runNmapPortScan(targetUrl: string): Promise<NmapResult> {
  const target = new URL(targetUrl);
  const host = target.hostname;

  if (!host) {
    return {
      findings: [],
      errors: ['Port scan skipped: target host is empty.'],
    };
  }

  const configuredPorts = PORT_SCAN_PORTS || DEFAULT_PORTS;
  const topLimit = clamp(PORT_SCAN_TOP_PORTS, 1, configuredPorts.length);
  const portsToScan = configuredPorts.slice(0, topLimit);
  const concurrency = clamp(PORT_SCAN_CONCURRENCY, 1, Math.min(128, portsToScan.length || 1));

  const scan = await runTcpPortScan(host, portsToScan, PORT_SCAN_TIMEOUT_MS, concurrency);
  if (scan.error) {
    return {
      findings: [],
      errors: [`Built-in port scan failed for ${host}: ${scan.error}`],
    };
  }

  const openPortFindings = scan.openPorts.map((port) => buildOpenPortFinding(target, port));
  const vulnFindings = PORT_VULN_SCAN_ENABLED
    ? await runBuiltInVulnerabilityScan(target, scan.openPorts)
    : [];

  return {
    findings: [...openPortFindings, ...vulnFindings],
    errors: [],
  };
}

async function runTcpPortScan(
  host: string,
  ports: number[],
  timeoutMs: number,
  concurrency: number,
): Promise<{ openPorts: number[]; error: string | null }> {
  if (ports.length === 0) {
    return {
      openPorts: [],
      error: 'no ports configured',
    };
  }

  try {
    const openPorts: number[] = [];
    let cursor = 0;

    const workers = Array.from({ length: concurrency }, () =>
      (async () => {
        while (cursor < ports.length) {
          const index = cursor;
          cursor += 1;
          const port = ports[index];
          if (await probeTcpPort(host, port, timeoutMs)) {
            openPorts.push(port);
          }
        }
      })(),
    );

    await Promise.all(workers);
    openPorts.sort((a, b) => a - b);
    return {
      openPorts,
      error: null,
    };
  } catch (error) {
    return {
      openPorts: [],
      error: formatError(error),
    };
  }
}

async function runBuiltInVulnerabilityScan(target: URL, openPorts: number[]): Promise<Finding[]> {
  const candidatePorts = prioritizeVulnerabilityPorts(openPorts).slice(
    0,
    clamp(PORT_VULN_MAX_SERVICES, 1, Math.max(openPorts.length, 1)),
  );
  if (candidatePorts.length === 0) {
    return [];
  }

  const host = target.hostname;
  const timeoutMs = clamp(PORT_VULN_TIMEOUT_MS, 400, 10_000);
  const concurrency = clamp(PORT_VULN_CONCURRENCY, 1, Math.min(16, candidatePorts.length));
  const findings: Finding[] = [];
  let cursor = 0;

  const workers = Array.from({ length: concurrency }, () =>
    (async () => {
      while (cursor < candidatePorts.length) {
        const index = cursor;
        cursor += 1;
        const port = candidatePorts[index];
        const result = await probePortVulnerabilities(target, host, port, timeoutMs);
        if (result.length > 0) {
          findings.push(...result);
        }
      }
    })(),
  );

  await Promise.all(workers);
  return findings;
}

async function probePortVulnerabilities(
  target: URL,
  host: string,
  port: number,
  timeoutMs: number,
): Promise<Finding[]> {
  const findings: Finding[] = [];

  if (port === 22) {
    const sshFinding = await probeSshVersionFinding(target, host, port, timeoutMs);
    if (sshFinding) {
      findings.push(sshFinding);
    }
  }

  if (port === 6379) {
    const redisFinding = await probeRedisUnauthFinding(target, host, port, timeoutMs);
    if (redisFinding) {
      findings.push(redisFinding);
    }
  }

  if (port === 11211) {
    const memcachedFinding = await probeMemcachedUnauthFinding(target, host, port, timeoutMs);
    if (memcachedFinding) {
      findings.push(memcachedFinding);
    }
  }

  if (port === 2375) {
    const dockerFinding = await probeDockerApiFinding(target, host, port, timeoutMs);
    if (dockerFinding) {
      findings.push(dockerFinding);
    }
  }

  if (HTTP_PORTS.has(port)) {
    const httpFindings = await probeHttpVulnerabilities(target, host, port, timeoutMs);
    findings.push(...httpFindings);
  }

  return findings;
}

async function probeSshVersionFinding(
  target: URL,
  host: string,
  port: number,
  timeoutMs: number,
): Promise<Finding | null> {
  const banner = await probeTextProtocol(host, port, timeoutMs);
  if (!banner) {
    return null;
  }

  const versionMatch = banner.match(/OpenSSH[_-]([0-9]+(?:\.[0-9]+){1,2})/i);
  if (!versionMatch) {
    return null;
  }

  const version = versionMatch[1];
  if (!isVersionLessThan(version, '8.4.0')) {
    return null;
  }

  return buildVulnFinding(target, port, {
    ruleId: 'BUILTIN_PORT_VULN_OUTDATED_OPENSSH',
    title: 'Potentially Outdated OpenSSH Version',
    severity: 'medium',
    confidence: 'medium',
    description: `SSH banner reports OpenSSH ${version}, which may contain known vulnerabilities depending on patch level.`,
    recommendation:
      'Upgrade OpenSSH to a currently supported release and restrict SSH exposure to trusted management networks.',
    evidence: banner.trim().slice(0, 140),
  });
}

async function probeRedisUnauthFinding(
  target: URL,
  host: string,
  port: number,
  timeoutMs: number,
): Promise<Finding | null> {
  const response = await probeTextProtocol(host, port, timeoutMs, 'PING\r\n');
  if (!/^\+PONG\b/m.test(response)) {
    return null;
  }

  return buildVulnFinding(target, port, {
    ruleId: 'BUILTIN_PORT_VULN_REDIS_UNAUTH',
    title: 'Redis Responds Without Authentication',
    severity: 'critical',
    confidence: 'high',
    description: 'Redis answered PING without authentication, indicating unauthenticated remote access.',
    recommendation: 'Enable Redis authentication, disable public bind, and restrict network exposure immediately.',
    evidence: '+PONG',
  });
}

async function probeMemcachedUnauthFinding(
  target: URL,
  host: string,
  port: number,
  timeoutMs: number,
): Promise<Finding | null> {
  const response = await probeTextProtocol(host, port, timeoutMs, 'stats\r\nquit\r\n');
  if (!/\bSTAT\s+[A-Za-z0-9_.-]+\s+/i.test(response)) {
    return null;
  }

  return buildVulnFinding(target, port, {
    ruleId: 'BUILTIN_PORT_VULN_MEMCACHED_UNAUTH',
    title: 'Memcached Stats Exposed Without Authentication',
    severity: 'high',
    confidence: 'high',
    description: 'Memcached responded to `stats` over TCP without authentication.',
    recommendation: 'Bind memcached to localhost/private interfaces and block public access at the firewall.',
    evidence: extractOneLine(response, 140),
  });
}

async function probeDockerApiFinding(
  target: URL,
  host: string,
  port: number,
  timeoutMs: number,
): Promise<Finding | null> {
  const probe = await requestHttp(host, port, '/version', false, timeoutMs);
  if (probe.status !== 200 || !/"ApiVersion"\s*:/i.test(probe.body)) {
    return null;
  }

  return buildVulnFinding(target, port, {
    ruleId: 'BUILTIN_PORT_VULN_DOCKER_API_UNAUTH',
    title: 'Docker Remote API Exposed Without Auth',
    severity: 'critical',
    confidence: 'high',
    description: 'Docker API `/version` endpoint is reachable without authentication on TCP 2375.',
    recommendation:
      'Disable unauthenticated Docker TCP API or secure it with mutual TLS and strict network access controls.',
    evidence: extractOneLine(probe.body, 140) || 'ApiVersion field returned',
  });
}

async function probeHttpVulnerabilities(
  target: URL,
  host: string,
  port: number,
  timeoutMs: number,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const useTls = TLS_PORTS.has(port);
  const root = await requestHttp(host, port, '/', useTls, timeoutMs);
  const serverHeader = (root.headers.server || '').trim();
  const xPoweredBy = (root.headers['x-powered-by'] || '').trim();
  const body = root.body || '';

  const apacheMatch = serverHeader.match(/apache\/([0-9]+(?:\.[0-9]+){1,2})/i);
  if (apacheMatch && (apacheMatch[1] === '2.4.49' || apacheMatch[1] === '2.4.50')) {
    findings.push(
      buildVulnFinding(target, port, {
        ruleId: 'BUILTIN_PORT_VULN_APACHE_2_4_49_50',
        title: 'Apache Version with Known Critical CVEs',
        severity: 'critical',
        confidence: 'high',
        description:
          `Server header reports Apache/${apacheMatch[1]}, a version affected by high-impact CVEs (for example CVE-2021-41773/42013).`,
        recommendation:
          'Upgrade Apache HTTP Server to a patched version and verify path normalization protections are enabled.',
        evidence: `Server: ${serverHeader}`,
      }),
    );
  }

  const phpMatch = xPoweredBy.match(/php\/([0-9]+(?:\.[0-9]+){1,2})/i);
  if (phpMatch && isVersionLessThan(phpMatch[1], '8.0.0')) {
    findings.push(
      buildVulnFinding(target, port, {
        ruleId: 'BUILTIN_PORT_VULN_OLD_PHP_EXPOSED',
        title: 'Potentially Outdated PHP Runtime Exposed',
        severity: 'medium',
        confidence: 'medium',
        description:
          `Header reports PHP/${phpMatch[1]}. Older unsupported PHP branches have multiple known vulnerabilities.`,
        recommendation:
          'Upgrade PHP to a supported branch and hide version disclosure headers in production responses.',
        evidence: `X-Powered-By: ${xPoweredBy}`,
      }),
    );
  }

  if (port === 9200 && root.status === 200 && /"cluster_name"\s*:/i.test(body)) {
    findings.push(
      buildVulnFinding(target, port, {
        ruleId: 'BUILTIN_PORT_VULN_ELASTICSEARCH_UNAUTH',
        title: 'Elasticsearch API Appears Publicly Accessible',
        severity: 'high',
        confidence: 'high',
        description: 'Elasticsearch root endpoint returned cluster metadata without authentication.',
        recommendation: 'Enable Elasticsearch security features and restrict API access to trusted internal networks.',
        evidence: extractOneLine(body, 160) || 'cluster_name returned',
      }),
    );
  }

  if (port === 5601 && root.status === 200 && /kibana/i.test(body)) {
    findings.push(
      buildVulnFinding(target, port, {
        ruleId: 'BUILTIN_PORT_VULN_KIBANA_EXPOSED',
        title: 'Kibana Interface Appears Exposed',
        severity: 'medium',
        confidence: 'medium',
        description: 'Kibana web UI is reachable over the network and may expose sensitive operational data.',
        recommendation: 'Restrict Kibana access with SSO/authentication and network allowlists.',
        evidence: 'kibana marker found in HTTP response body',
      }),
    );
  }

  return findings;
}

async function probeTextProtocol(
  host: string,
  port: number,
  timeoutMs: number,
  payload?: string,
): Promise<string> {
  return await new Promise<string>((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    let buffer = '';
    let closeTimer: NodeJS.Timeout | null = null;

    const finish = () => {
      if (settled) {
        return;
      }
      settled = true;
      if (closeTimer) {
        clearTimeout(closeTimer);
      }
      socket.destroy();
      resolve(buffer);
    };

    const scheduleFinish = (delayMs: number) => {
      if (closeTimer) {
        clearTimeout(closeTimer);
      }
      closeTimer = setTimeout(finish, delayMs);
    };

    socket.setTimeout(timeoutMs);
    socket.once('timeout', finish);
    socket.once('error', finish);
    socket.once('close', finish);

    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      if (buffer.length > 12_000) {
        buffer = buffer.slice(0, 12_000);
        finish();
        return;
      }
      scheduleFinish(payload ? 180 : 80);
    });

    socket.once('connect', () => {
      if (payload) {
        socket.write(payload);
      }
      scheduleFinish(timeoutMs);
    });

    try {
      socket.connect(port, host);
    } catch {
      finish();
    }
  });
}

async function requestHttp(
  host: string,
  port: number,
  path: string,
  secure: boolean,
  timeoutMs: number,
): Promise<HttpProbeResult> {
  const requestModule = secure ? https : http;
  return await new Promise<HttpProbeResult>((resolve) => {
    const req = requestModule.request(
      {
        host,
        port,
        path,
        method: 'GET',
        rejectUnauthorized: false,
        headers: {
          'User-Agent': SCANNER_USER_AGENT,
          Accept: 'application/json,text/html;q=0.9,*/*;q=0.8',
          Connection: 'close',
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        let bytes = 0;

        res.on('data', (chunk: Buffer) => {
          bytes += chunk.length;
          if (bytes <= HTTP_BODY_LIMIT_BYTES) {
            chunks.push(chunk);
          }
        });
        res.on('end', () => {
          const headers = normalizeHeaders(res.headers);
          resolve({
            status: res.statusCode,
            headers,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`timeout ${timeoutMs}ms`));
    });
    req.on('error', () => {
      resolve({
        headers: {},
        body: '',
      });
    });
    req.end();
  });
}

async function probeTcpPort(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return await new Promise<boolean>((resolve) => {
    const socket = new net.Socket();
    let settled = false;

    const finish = (isOpen: boolean) => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      resolve(isOpen);
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));

    try {
      socket.connect(port, host);
    } catch {
      finish(false);
    }
  });
}

function buildOpenPortFinding(target: URL, port: number): Finding {
  const severity = classifySeverity(port);
  const service = serviceLabelFromPort(port);
  const recommendation =
    severity === 'high'
      ? 'Restrict this exposed service to trusted networks or disable it if not required.'
      : 'Confirm this port is expected and protected by network policy.';

  return {
    id: '',
    type: 'vuln',
    ruleId: 'BUILTIN_PORT_SCAN_OPEN_PORT',
    severity,
    confidence: 'medium',
    reviewStatus: 'open',
    title: 'Open Port Detected by Built-in Scanner',
    description: `Host ${target.hostname} has port ${port}/tcp open (${service}).`,
    recommendation,
    location: {
      url: target.origin,
      endpoint: `${target.hostname}:${port}`,
    },
    evidence: `${port}/tcp open ${service}`,
    createdAt: new Date().toISOString(),
  };
}

function buildVulnFinding(
  target: URL,
  port: number,
  data: {
    ruleId: string;
    title: string;
    severity: Finding['severity'];
    confidence: Finding['confidence'];
    description: string;
    recommendation: string;
    evidence: string;
  },
): Finding {
  return {
    id: '',
    type: 'vuln',
    ruleId: data.ruleId,
    severity: data.severity,
    confidence: data.confidence,
    reviewStatus: 'open',
    title: data.title,
    description: data.description,
    recommendation: data.recommendation,
    location: {
      url: target.origin,
      endpoint: `${target.hostname}:${port}`,
    },
    evidence: data.evidence,
    createdAt: new Date().toISOString(),
  };
}

function prioritizeVulnerabilityPorts(openPorts: number[]): number[] {
  const prioritized: number[] = [];
  for (const port of PRIORITY_VULN_PORTS) {
    if (openPorts.includes(port)) {
      prioritized.push(port);
    }
  }
  for (const port of openPorts) {
    if (!prioritized.includes(port) && HTTP_PORTS.has(port)) {
      prioritized.push(port);
    }
  }
  for (const port of openPorts) {
    if (!prioritized.includes(port)) {
      prioritized.push(port);
    }
  }
  return prioritized;
}

function normalizeHeaders(headers: http.IncomingHttpHeaders): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (Array.isArray(value)) {
      normalized[key.toLowerCase()] = value.join(', ');
    } else if (typeof value === 'string') {
      normalized[key.toLowerCase()] = value;
    }
  }
  return normalized;
}

function extractOneLine(value: string, maxLength: number): string {
  const line = value
    .split(/\r?\n/)
    .map((item) => item.trim())
    .find(Boolean);
  if (!line) {
    return '';
  }
  return line.length > maxLength ? `${line.slice(0, maxLength)}...` : line;
}

function classifySeverity(port: number): Finding['severity'] {
  if (HIGH_RISK_PORTS.has(port)) {
    return 'high';
  }
  if (MEDIUM_RISK_PORTS.has(port)) {
    return 'medium';
  }
  return 'low';
}

function serviceLabelFromPort(port: number): string {
  const map: Record<number, string> = {
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'dns',
    80: 'http',
    110: 'pop3',
    111: 'rpcbind',
    135: 'msrpc',
    139: 'netbios-ssn',
    143: 'imap',
    443: 'https',
    445: 'microsoft-ds',
    993: 'imaps',
    995: 'pop3s',
    11211: 'memcached',
    1433: 'mssql',
    1521: 'oracle',
    2049: 'nfs',
    2375: 'docker',
    3306: 'mysql',
    3389: 'rdp',
    5000: 'http-alt',
    5432: 'postgresql',
    5601: 'kibana',
    6379: 'redis',
    8080: 'http-proxy',
    8443: 'https-alt',
    9000: 'sonarqube',
    9200: 'elasticsearch',
    27017: 'mongodb',
  };
  return map[port] || 'unknown';
}

function parsePortList(raw: string | undefined): number[] | null {
  if (!raw?.trim()) {
    return null;
  }
  const ports = raw
    .split(',')
    .map((segment) => Number(segment.trim()))
    .filter((value) => Number.isInteger(value) && value > 0 && value <= 65_535);
  if (ports.length === 0) {
    return null;
  }
  return Array.from(new Set(ports));
}

function isVersionLessThan(left: string, right: string): boolean {
  const leftParts = left.split('.').map((item) => Number(item));
  const rightParts = right.split('.').map((item) => Number(item));
  const maxLength = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < maxLength; index += 1) {
    const a = leftParts[index] || 0;
    const b = rightParts[index] || 0;
    if (a < b) return true;
    if (a > b) return false;
  }
  return false;
}

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) {
    return min;
  }
  return Math.max(min, Math.min(max, value));
}

function formatError(error: unknown): string {
  if (!error) {
    return 'unknown error';
  }
  if (error instanceof Error) {
    return error.message || 'unknown error';
  }
  return String(error);
}
