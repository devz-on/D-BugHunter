import dotenv from 'dotenv';
import express from 'express';
import path from 'node:path';
import { JsonScanStore } from './store/jsonStore';
import { PreviewSessionManager } from './services/previewSessions';
import { ScanOrchestrator } from './services/scanOrchestrator';
import { ReviewStatus, ScanStartRequest } from './types';

dotenv.config();

const app = express();
app.use(express.json({ limit: '1mb' }));

const port = Number(process.env.PORT || 8787);
const dataDir = process.env.DATA_DIR || path.join(process.cwd(), 'data');

const store = new JsonScanStore(dataDir);
const orchestrator = new ScanOrchestrator(store);
const preview = new PreviewSessionManager();

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'hunter-server',
    timestamp: new Date().toISOString(),
  });
});

app.post('/api/scans', async (req, res) => {
  try {
    const body = req.body as ScanStartRequest;
    if (!body?.targetUrl) {
      res.status(400).json({ error: 'targetUrl is required' });
      return;
    }
    const scan = await orchestrator.startScan(body);
    res.status(202).json({
      scanId: scan.scanId,
      status: scan.status,
      targetUrl: scan.targetUrl,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Failed to start scan';
    res.status(400).json({ error: message });
  }
});

app.get('/api/scans', async (_req, res) => {
  const scans = await orchestrator.listSummaries();
  res.json(scans);
});

app.get('/api/scans/:scanId/events', async (req, res) => {
  const { scanId } = req.params;
  const scan = await orchestrator.getScan(scanId);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const unsubscribe = orchestrator.subscribe(scanId, res);
  const heartbeat = setInterval(() => {
    res.write(': heartbeat\n\n');
  }, 20_000);

  req.on('close', () => {
    clearInterval(heartbeat);
    unsubscribe();
    res.end();
  });
});

app.get('/api/scans/:scanId', async (req, res) => {
  const summary = await orchestrator.getSummary(req.params.scanId);
  if (!summary) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }
  res.json(summary);
});

app.get('/api/scans/:scanId/files', async (req, res) => {
  const scan = await orchestrator.getScan(req.params.scanId);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }
  res.json(
    scan.files.map((file) => ({
      fileId: file.fileId,
      url: file.url,
      kind: file.kind,
      size: file.size,
      discoveredFrom: file.discoveredFrom,
    })),
  );
});

app.get('/api/scans/:scanId/files/:fileId/content', async (req, res) => {
  const scan = await orchestrator.getScan(req.params.scanId);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }
  const file = scan.files.find((candidate) => candidate.fileId === req.params.fileId);
  if (!file) {
    res.status(404).json({ error: 'File not found' });
    return;
  }
  res.json({
    fileId: file.fileId,
    url: file.url,
    kind: file.kind,
    content: file.content,
  });
});

app.get('/api/scans/:scanId/findings', async (req, res) => {
  const scan = await orchestrator.getScan(req.params.scanId);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }
  const type = String(req.query.type || '').trim();
  const severity = String(req.query.severity || '').trim();
  const findings = scan.findings.filter((item) => {
    if (type && item.type !== type) {
      return false;
    }
    if (severity && item.severity !== severity) {
      return false;
    }
    return true;
  });
  res.json(findings);
});

app.patch('/api/scans/:scanId/findings/:findingId', async (req, res) => {
  const requestedStatus = req.body?.reviewStatus as ReviewStatus | undefined;
  const accepted: ReviewStatus[] = ['confirmed', 'false_positive', 'needs_review', 'open'];
  if (!requestedStatus || !accepted.includes(requestedStatus)) {
    res.status(400).json({ error: 'reviewStatus must be one of open/confirmed/false_positive/needs_review' });
    return;
  }
  const updated = await orchestrator.updateReviewStatus(
    req.params.scanId,
    req.params.findingId,
    requestedStatus,
  );
  if (!updated) {
    res.status(404).json({ error: 'Scan or finding not found' });
    return;
  }
  res.json(updated);
});

app.get('/api/scans/:scanId/network', async (req, res) => {
  const scan = await orchestrator.getScan(req.params.scanId);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }
  res.json(scan.requests);
});

app.get('/api/scans/:scanId/surface', async (req, res) => {
  const scan = await orchestrator.getScan(req.params.scanId);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }
  res.json(scan.surface);
});

app.get('/api/scans/:scanId/diffs', async (req, res) => {
  const scan = await orchestrator.getScan(req.params.scanId);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }
  res.json(scan.diffs);
});

app.post('/api/preview/sessions', (req, res) => {
  try {
    const targetUrl = String(req.body?.targetUrl || '');
    if (!targetUrl) {
      res.status(400).json({ error: 'targetUrl is required' });
      return;
    }
    const parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      res.status(400).json({ error: 'Only http/https URLs are supported' });
      return;
    }
    const session = preview.create(parsed.toString());
    res.status(201).json(session);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid URL';
    res.status(400).json({ error: message });
  }
});

app.delete('/api/preview/sessions/:sessionId', (req, res) => {
  const removed = preview.destroy(req.params.sessionId);
  if (!removed) {
    res.status(404).json({ error: 'Preview session not found' });
    return;
  }
  res.status(204).send();
});

app.listen(port, async () => {
  await store.init();
  console.log(`Hunter server listening on http://localhost:${port}`);
});
