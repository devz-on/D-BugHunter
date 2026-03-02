import { mkdir, readdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { ScanDocument } from '../types';

export class JsonScanStore {
  private readonly scansDir: string;

  constructor(dataDir: string) {
    this.scansDir = path.join(dataDir, 'scans');
  }

  async init(): Promise<void> {
    await mkdir(this.scansDir, { recursive: true });
  }

  async saveScan(scan: ScanDocument): Promise<void> {
    await this.init();
    const destination = this.filePath(scan.scanId);
    const tempPath = `${destination}.tmp`;
    const payload = JSON.stringify(scan, null, 2);
    await writeFile(tempPath, payload, 'utf8');
    await rename(tempPath, destination);
  }

  async loadScan(scanId: string): Promise<ScanDocument | null> {
    const destination = this.filePath(scanId);
    try {
      const raw = await readFile(destination, 'utf8');
      return JSON.parse(raw) as ScanDocument;
    } catch {
      return null;
    }
  }

  async listScans(): Promise<ScanDocument[]> {
    await this.init();
    const entries = await readdir(this.scansDir, { withFileTypes: true });
    const scans: ScanDocument[] = [];
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith('.json')) {
        continue;
      }
      try {
        const raw = await readFile(path.join(this.scansDir, entry.name), 'utf8');
        scans.push(JSON.parse(raw) as ScanDocument);
      } catch {
        // skip malformed files
      }
    }
    return scans.sort((a, b) => (a.startedAt < b.startedAt ? 1 : -1));
  }

  private filePath(scanId: string): string {
    return path.join(this.scansDir, `${scanId}.json`);
  }
}
