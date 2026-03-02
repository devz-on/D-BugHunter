import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  FileCode2,
  FileJson,
  FileType2,
  FolderOpen,
  Globe,
  KeyRound,
  Moon,
  Play,
  RefreshCw,
  Search,
  ShieldAlert,
  Sun,
  Terminal,
} from 'lucide-react';
import {
  createPreviewSession,
  getDiffs,
  getFileContent,
  getFiles,
  getFindings,
  getNetwork,
  getScanSummary,
  getSurface,
  startScan,
  updateFindingReviewStatus,
} from './api';
import {
  ActiveDiff,
  FileEntry,
  Finding,
  NetworkEntry,
  PreviewSession,
  ReviewStatus,
  ScanSummary,
  SurfaceItem,
} from './types';

type Tab = 'files' | 'findings' | 'secrets' | 'network' | 'surface' | 'diffs';

interface FolderNode {
  key: string;
  label: string;
  depth: number;
  parentKey: string | null;
  childKeys: string[];
  files: FileEntry[];
  findings: Finding[];
}

interface FolderModel {
  nodes: Record<string, FolderNode>;
  orderedKeys: string[];
  fileToFolder: Record<string, string>;
}

export default function App() {
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [url, setUrl] = useState('https://example.com/');
  const [previewUrl, setPreviewUrl] = useState('https://example.com/');
  const [previewCurrentUrl, setPreviewCurrentUrl] = useState<string | null>(null);
  const [previewSession, setPreviewSession] = useState<PreviewSession | null>(null);

  const [activeTab, setActiveTab] = useState<Tab>('files');
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanSummary, setScanSummary] = useState<ScanSummary | null>(null);

  const [files, setFiles] = useState<FileEntry[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [network, setNetwork] = useState<NetworkEntry[]>([]);
  const [surface, setSurface] = useState<SurfaceItem[]>([]);
  const [diffs, setDiffs] = useState<ActiveDiff[]>([]);

  const [selectedFolderKey, setSelectedFolderKey] = useState<string | null>(null);
  const [followPreviewFolder, setFollowPreviewFolder] = useState(true);
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);
  const [selectedFileName, setSelectedFileName] = useState('Select a file');
  const [selectedFileContent, setSelectedFileContent] = useState('');

  const [isScanning, setIsScanning] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const eventsRef = useRef<EventSource | null>(null);
  const pollingRef = useRef<number | null>(null);
  const refreshTimerRef = useRef<number | null>(null);
  const previewFrameRef = useRef<HTMLIFrameElement | null>(null);

  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [theme]);

  useEffect(() => {
    return () => {
      if (eventsRef.current) {
        eventsRef.current.close();
      }
      stopPolling();
      clearRefreshTimer();
    };
  }, []);

  const folderModel = useMemo(
    () => buildFolderModel(files, findings, scanSummary?.targetUrl || previewCurrentUrl || previewUrl),
    [files, findings, scanSummary?.targetUrl, previewCurrentUrl, previewUrl],
  );
  const folders = useMemo(() => folderModel.orderedKeys.map((key) => folderModel.nodes[key]), [folderModel]);

  const selectedFolderFiles = useMemo(() => {
    if (!selectedFolderKey) return files;
    return folderModel.nodes[selectedFolderKey]?.files || [];
  }, [files, folderModel, selectedFolderKey]);

  const selectedFolderFindings = useMemo(() => {
    if (!selectedFolderKey) return findings;
    return folderModel.nodes[selectedFolderKey]?.findings || [];
  }, [findings, folderModel, selectedFolderKey]);

  const vulnFindings = useMemo(
    () => selectedFolderFindings.filter((f) => f.type === 'vuln' || f.type === 'anomaly'),
    [selectedFolderFindings],
  );
  const secretFindings = useMemo(
    () => selectedFolderFindings.filter((f) => f.type === 'secret'),
    [selectedFolderFindings],
  );

  const selectedFolderLabel = useMemo(() => {
    if (!selectedFolderKey) return 'All Pages';
    return folderModel.nodes[selectedFolderKey]?.label || selectedFolderKey;
  }, [selectedFolderKey, folderModel]);

  const latestScanError = useMemo(() => {
    if (!scanSummary?.errors?.length) return null;
    return scanSummary.errors[scanSummary.errors.length - 1];
  }, [scanSummary]);

  const previewFrameSrc = useMemo(
    () => `/api/preview/proxy?target=${encodeURIComponent(previewUrl)}`,
    [previewUrl],
  );

  useEffect(() => {
    if (selectedFolderFiles.length === 0) {
      setSelectedFileId(null);
      setSelectedFileName('Select a file');
      setSelectedFileContent('');
      return;
    }
    if (!selectedFileId || !selectedFolderFiles.some((f) => f.fileId === selectedFileId)) {
      setSelectedFileId(selectedFolderFiles[0].fileId);
    }
  }, [selectedFileId, selectedFolderFiles]);

  useEffect(() => {
    if (!scanId || !selectedFileId) return;
    void loadFileContent(scanId, selectedFileId);
  }, [scanId, selectedFileId]);

  useEffect(() => {
    if (!followPreviewFolder || folders.length === 0) return;
    const preferred = resolveFolderForUrl(
      previewCurrentUrl || scanSummary?.targetUrl || previewUrl,
      folderModel.nodes,
    ) || folders[0].key;
    if (preferred !== selectedFolderKey) {
      setSelectedFolderKey(preferred);
    }
  }, [followPreviewFolder, folders, folderModel.nodes, previewCurrentUrl, scanSummary?.targetUrl, previewUrl, selectedFolderKey]);

  useEffect(() => {
    const onMessage = (event: MessageEvent) => {
      const previewWindow = previewFrameRef.current?.contentWindow;
      if (previewWindow && event.source !== previewWindow) return;

      const payload = event.data as { type?: string; url?: string } | null;
      if (!payload || payload.type !== 'hunter-preview-url' || !payload.url) return;

      const nextPreviewUrl = sanitizePreviewMessageUrl(payload.url, scanSummary?.targetUrl || previewUrl);
      if (!nextPreviewUrl) return;

      // Ignore loopback into the UI host unless the active scan target is also on this host.
      if (
        isSameOriginUrl(nextPreviewUrl, window.location.origin) &&
        !isSameOriginUrl(scanSummary?.targetUrl || previewUrl, window.location.origin)
      ) {
        return;
      }

      setPreviewCurrentUrl(nextPreviewUrl);
    };

    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [previewUrl, scanSummary?.targetUrl]);

  async function runScan(target: string) {
    setErrorMessage(null);
    setIsScanning(true);
    stopPolling();
    clearRefreshTimer();
    setFollowPreviewFolder(true);

    if (eventsRef.current) {
      eventsRef.current.close();
    }

    setScanSummary(null);
    setFiles([]);
    setFindings([]);
    setNetwork([]);
    setSurface([]);
    setDiffs([]);
    setSelectedFolderKey(null);
    setPreviewUrl(target);
    setPreviewCurrentUrl(target);

    try {
      const scan = await startScan(target);
      setScanId(scan.scanId);
      setPreviewUrl(scan.targetUrl);
      setPreviewCurrentUrl(scan.targetUrl);

      try {
        setPreviewSession(await createPreviewSession(scan.targetUrl));
      } catch {
        setPreviewSession(null);
      }

      connectScanEvents(scan.scanId);
      setScanSummary(await getScanSummary(scan.scanId));
      scheduleRefresh(scan.scanId);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Failed to start scan.');
      setIsScanning(false);
    }
  }

  async function handleScan(event: React.FormEvent) {
    event.preventDefault();
    void runScan(url);
  }

  function connectScanEvents(nextScanId: string) {
    if (eventsRef.current) eventsRef.current.close();
    startPolling(nextScanId);
    const source = new EventSource(`/api/scans/${nextScanId}/events`);
    eventsRef.current = source;

    const onEvent = (raw: MessageEvent<string>) => {
      try {
        const payload = JSON.parse(raw.data) as ScanSummary;
        setScanSummary(payload);
        scheduleRefresh(nextScanId);

        if (payload.status === 'completed' || payload.status === 'failed') {
          setIsScanning(false);
          stopPolling();
          void refreshScanDetails(nextScanId);
        }
      } catch {
        // ignore
      }
    };

    source.addEventListener('snapshot', onEvent);
    source.addEventListener('scan-updated', onEvent);
    source.addEventListener('scan-completed', onEvent);
    source.addEventListener('scan-failed', onEvent);
    source.onerror = () => source.close();
  }

  function clearRefreshTimer() {
    if (refreshTimerRef.current !== null) {
      window.clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = null;
    }
  }

  function scheduleRefresh(activeScanId: string) {
    if (refreshTimerRef.current !== null) return;
    refreshTimerRef.current = window.setTimeout(() => {
      refreshTimerRef.current = null;
      void refreshScanDetails(activeScanId);
    }, 600);
  }

  function stopPolling() {
    if (pollingRef.current !== null) {
      window.clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  }

  function startPolling(activeScanId: string) {
    stopPolling();
    pollingRef.current = window.setInterval(() => {
      void (async () => {
        try {
          const summary = await getScanSummary(activeScanId);
          setScanSummary(summary);
          scheduleRefresh(activeScanId);
          if (summary.status === 'completed' || summary.status === 'failed') {
            setIsScanning(false);
            stopPolling();
            if (eventsRef.current) eventsRef.current.close();
          }
        } catch {
          // keep polling
        }
      })();
    }, 4000);
  }

  async function refreshScanDetails(currentScanId?: string) {
    const activeScanId = currentScanId || scanId;
    if (!activeScanId) return;

    setIsRefreshing(true);
    try {
      const [summary, filesData, findingsData, networkData, surfaceData, diffData] = await Promise.all([
        getScanSummary(activeScanId),
        getFiles(activeScanId),
        getFindings(activeScanId),
        getNetwork(activeScanId),
        getSurface(activeScanId),
        getDiffs(activeScanId),
      ]);

      setScanSummary(summary);
      setFiles(filesData);
      setFindings(findingsData);
      setNetwork(networkData);
      setSurface(surfaceData);
      setDiffs(diffData);
      if (summary.status === 'completed' || summary.status === 'failed') {
        setIsScanning(false);
      }
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Failed to refresh scan details.');
    } finally {
      setIsRefreshing(false);
    }
  }

  async function loadFileContent(currentScanId: string, fileId: string) {
    try {
      const response = await getFileContent(currentScanId, fileId);
      setSelectedFileContent(response.content);
      setSelectedFileName(fileNameFromUrl(response.url));
    } catch {
      setSelectedFileContent('// File content unavailable');
      setSelectedFileName('Unavailable');
    }
  }

  async function changeReviewStatus(findingId: string, status: ReviewStatus) {
    if (!scanId) return;
    try {
      const updated = await updateFindingReviewStatus(scanId, findingId, status);
      setFindings((prev) => prev.map((f) => (f.id === findingId ? { ...f, reviewStatus: updated.reviewStatus } : f)));
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Failed to update review status.');
    }
  }

  return (
    <div className={`h-screen overflow-hidden flex flex-col ${theme === 'dark' ? 'bg-[#0a0a0a] text-gray-300' : 'bg-gray-50 text-gray-800'} font-sans transition-colors duration-200`}>
      <header className={`h-14 border-b flex items-center px-2 sm:px-4 justify-between shrink-0 ${theme === 'dark' ? 'bg-[#121212] border-[#222]' : 'bg-white border-gray-200'}`}>
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded bg-red-500/10 flex items-center justify-center text-red-500 shrink-0">
            <ShieldAlert size={20} />
          </div>
          <span className={`font-bold text-lg tracking-tight hidden md:block ${theme === 'dark' ? 'text-white' : 'text-gray-900'}`}>Hunter</span>
        </div>

        <form onSubmit={handleScan} className="flex-1 max-w-2xl mx-2 sm:mx-4 md:mx-8 flex items-center">
          <div className={`flex-1 flex items-center h-9 rounded-l-md px-2 sm:px-3 border-y border-l ${theme === 'dark' ? 'bg-[#1a1a1a] border-[#333]' : 'bg-gray-100 border-gray-300'}`}>
            <Globe size={16} className={`hidden sm:block shrink-0 ${theme === 'dark' ? 'text-gray-500' : 'text-gray-400'}`} />
            <input type="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com/" className="flex-1 bg-transparent border-none outline-none px-2 sm:px-3 text-sm min-w-0" required />
          </div>
          <button type="submit" disabled={isScanning} className={`h-9 px-3 sm:px-4 rounded-r-md flex items-center gap-1 sm:gap-2 text-sm font-medium transition-colors shrink-0 ${isScanning ? 'bg-red-500/50 cursor-not-allowed text-white' : 'bg-red-500 hover:bg-red-600 text-white'}`}>
            {isScanning ? <RefreshCw size={16} className="animate-spin" /> : <Play size={16} />}
            <span className="hidden sm:inline">{isScanning ? 'Scanning...' : 'Scan'}</span>
          </button>
        </form>

        <div className="flex items-center gap-2 shrink-0">
          <button onClick={() => void refreshScanDetails()} className="p-2 rounded-md hover:bg-black/5 dark:hover:bg-white/5 transition-colors disabled:opacity-60" disabled={!scanId || isRefreshing}>
            <RefreshCw size={18} className={isRefreshing ? 'animate-spin' : ''} />
          </button>
          <button onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} className="p-2 rounded-md hover:bg-black/5 dark:hover:bg-white/5 transition-colors">
            {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
          </button>
        </div>
      </header>

      <main className="flex-1 flex flex-col md:flex-row overflow-hidden min-h-0">
        <div className={`flex-1 border-b md:border-b-0 md:border-r flex flex-col min-h-0 min-w-0 overflow-hidden ${theme === 'dark' ? 'border-[#222] bg-[#0a0a0a]' : 'border-gray-200 bg-white'}`}>
          <div className={`h-10 border-b flex items-center justify-between px-3 shrink-0 ${theme === 'dark' ? 'border-[#222] bg-[#121212]' : 'border-gray-200 bg-gray-50'}`}>
            <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-gray-500 truncate">
              <Globe size={14} className="shrink-0" />
              <span className="truncate">Live Preview</span>
            </div>
            <div className="text-[10px] uppercase text-gray-500">{previewSession?.mode || 'proxy'}</div>
          </div>
          <div className="flex-1 flex flex-col bg-white min-h-0 overflow-hidden">
            <div className="h-8 bg-gray-100 border-b border-gray-200 flex items-center px-2 gap-2 shrink-0">
              <div className="flex gap-1.5 shrink-0">
                <div className="w-2.5 h-2.5 rounded-full bg-red-400"></div>
                <div className="w-2.5 h-2.5 rounded-full bg-amber-400"></div>
                <div className="w-2.5 h-2.5 rounded-full bg-green-400"></div>
              </div>
              <div className="flex-1 bg-white rounded text-xs px-2 py-1 text-gray-600 truncate border border-gray-200">{previewCurrentUrl || previewUrl}</div>
            </div>
            <div className="flex-1 min-h-0 overflow-hidden">
              <iframe ref={previewFrameRef} src={previewFrameSrc} className="w-full h-full border-none" title="Live Preview" sandbox="allow-same-origin allow-scripts allow-forms" />
            </div>
          </div>
        </div>

        <div className="flex-1 flex flex-col min-h-0 min-w-0">
          <div className={`h-10 border-b flex px-2 shrink-0 overflow-x-auto no-scrollbar ${theme === 'dark' ? 'border-[#222] bg-[#121212]' : 'border-gray-200 bg-gray-50'}`}>
            <TabButton active={activeTab === 'files'} onClick={() => setActiveTab('files')} icon={<FileCode2 size={14} />} label="Files" badge={String(selectedFolderFiles.length)} />
            <TabButton active={activeTab === 'findings'} onClick={() => setActiveTab('findings')} icon={<ShieldAlert size={14} />} label="Findings" badge={String(vulnFindings.length)} badgeColor="bg-red-500" />
            <TabButton active={activeTab === 'secrets'} onClick={() => setActiveTab('secrets')} icon={<KeyRound size={14} />} label="Secrets" badge={String(secretFindings.length)} badgeColor="bg-amber-500" />
            <TabButton active={activeTab === 'network'} onClick={() => setActiveTab('network')} icon={<Activity size={14} />} label="Network" badge={String(network.length)} />
            <TabButton active={activeTab === 'surface'} onClick={() => setActiveTab('surface')} icon={<Search size={14} />} label="Surface" badge={String(surface.length)} />
            <TabButton active={activeTab === 'diffs'} onClick={() => setActiveTab('diffs')} icon={<RefreshCw size={14} />} label="Diffs" badge={String(diffs.length)} />
          </div>

          <div className="flex-1 min-h-0 overflow-hidden">
            {activeTab === 'files' && (
              <FilesTab
                theme={theme}
                folders={folders}
                selectedFolderKey={selectedFolderKey}
                selectedFolderLabel={selectedFolderLabel}
                followPreviewFolder={followPreviewFolder}
                onFollowPreview={() => setFollowPreviewFolder(true)}
                onSelectFolder={(key) => {
                  setSelectedFolderKey(key);
                  setFollowPreviewFolder(false);
                }}
                files={selectedFolderFiles}
                selectedFileId={selectedFileId}
                selectedFileName={selectedFileName}
                selectedFileContent={selectedFileContent}
                onSelectFile={setSelectedFileId}
              />
            )}
            {activeTab === 'findings' && <FindingsTab theme={theme} findings={vulnFindings} onReviewChange={changeReviewStatus} />}
            {activeTab === 'secrets' && <FindingsTab theme={theme} findings={secretFindings} onReviewChange={changeReviewStatus} />}
            {activeTab === 'network' && <NetworkTab theme={theme} requests={network} />}
            {activeTab === 'surface' && <SurfaceTab theme={theme} items={surface} />}
            {activeTab === 'diffs' && <DiffsTab theme={theme} diffs={diffs} />}
          </div>
        </div>
      </main>

      <footer className={`h-7 border-t flex items-center px-3 text-xs shrink-0 ${theme === 'dark' ? 'bg-[#121212] border-[#222] text-gray-500' : 'bg-gray-100 border-gray-200 text-gray-500'}`}>
        <div className="flex items-center gap-2 sm:gap-4 truncate">
          <span className="flex items-center gap-1.5 shrink-0"><Terminal size={12} /> {scanSummary?.status || 'ready'}</span>
          <span className="truncate hidden sm:inline">Target: {scanSummary?.targetUrl || url}</span>
          {isScanning && <span className="text-red-500 animate-pulse shrink-0">Scanning...</span>}
          {errorMessage ? <span className="text-red-500 shrink-0 truncate">{errorMessage}</span> : null}
          {!errorMessage && latestScanError ? <span className="text-red-500 shrink-0 truncate">{latestScanError}</span> : null}
        </div>
        <div className="ml-auto flex items-center gap-2 sm:gap-4 shrink-0">
          <span className="hidden sm:inline">Pages: {scanSummary?.stats.pages ?? 0}</span>
          <span>Findings: {scanSummary?.stats.findings ?? 0}</span>
        </div>
      </footer>
    </div>
  );
}

function TabButton({
  active,
  onClick,
  icon,
  label,
  badge,
  badgeColor = 'bg-gray-500',
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
  badge?: string;
  badgeColor?: string;
}) {
  return (
    <button
      onClick={onClick}
      className={`h-full px-3 sm:px-4 flex items-center gap-1.5 sm:gap-2 text-xs sm:text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
        active
          ? 'border-red-500 text-red-500 dark:text-red-400'
          : 'border-transparent text-gray-500 hover:text-gray-800 dark:hover:text-gray-300'
      }`}
    >
      <span className="shrink-0">{icon}</span>
      {label}
      {badge ? <span className={`ml-1 px-1.5 py-0.5 rounded text-[10px] text-white ${badgeColor}`}>{badge}</span> : null}
    </button>
  );
}

function FilesTab({
  theme,
  folders,
  selectedFolderKey,
  selectedFolderLabel,
  followPreviewFolder,
  onFollowPreview,
  onSelectFolder,
  files,
  selectedFileId,
  selectedFileName,
  selectedFileContent,
  onSelectFile,
}: {
  theme: 'dark' | 'light';
  folders: FolderNode[];
  selectedFolderKey: string | null;
  selectedFolderLabel: string;
  followPreviewFolder: boolean;
  onFollowPreview: () => void;
  onSelectFolder: (key: string | null) => void;
  files: FileEntry[];
  selectedFileId: string | null;
  selectedFileName: string;
  selectedFileContent: string;
  onSelectFile: (fileId: string) => void;
}) {
  return (
    <div className="flex w-full h-full min-h-0">
      <div className={`w-1/3 sm:w-80 border-r flex flex-col shrink-0 min-h-0 ${theme === 'dark' ? 'border-[#222] bg-[#0a0a0a]' : 'border-gray-200 bg-gray-50/50'}`}>
        <div className={`px-2 py-2 border-b ${theme === 'dark' ? 'border-[#222]' : 'border-gray-200'}`}>
          <div className="text-[10px] sm:text-xs font-semibold text-gray-500 uppercase tracking-wider">Pages</div>
          <button
            onClick={onFollowPreview}
            className={`mt-2 w-full text-left px-2 py-1.5 rounded text-xs transition-colors ${
              followPreviewFolder
                ? 'bg-red-500/15 text-red-500 dark:text-red-400'
                : 'text-gray-600 dark:text-gray-400 hover:bg-black/5 dark:hover:bg-white/5'
            }`}
          >
            Follow preview
          </button>
        </div>

        <div className="flex-1 min-h-0 overflow-y-auto py-1">
          <button
            onClick={() => onSelectFolder(null)}
            className={`w-full text-left px-2 py-1.5 rounded flex items-center gap-2 text-xs sm:text-sm transition-colors ${
              selectedFolderKey === null
                ? theme === 'dark'
                  ? 'bg-[#222] text-white'
                  : 'bg-gray-200 text-gray-900'
                : 'text-gray-600 dark:text-gray-400 hover:bg-black/5 dark:hover:bg-white/5'
            }`}
          >
            <FolderOpen size={14} className="shrink-0" />
            <span className="truncate">All Pages</span>
          </button>
          {folders.map((folder) => (
            <button
              key={folder.key}
              onClick={() => onSelectFolder(folder.key)}
              className={`w-full text-left px-2 py-1.5 rounded flex items-center gap-2 text-xs sm:text-sm transition-colors ${
                selectedFolderKey === folder.key
                  ? theme === 'dark'
                    ? 'bg-[#222] text-white'
                    : 'bg-gray-200 text-gray-900'
                  : 'text-gray-600 dark:text-gray-400 hover:bg-black/5 dark:hover:bg-white/5'
              }`}
              style={{ paddingLeft: `${0.5 + folder.depth * 0.75}rem` }}
              title={folder.key}
            >
              <FolderOpen size={14} className="shrink-0" />
              <span className="truncate">{folder.label}</span>
              <span className="ml-auto text-[10px] opacity-70">{folder.files.length}</span>
            </button>
          ))}
        </div>

        <div className={`px-2 py-1.5 border-y text-[10px] sm:text-xs font-semibold text-gray-500 uppercase tracking-wider ${theme === 'dark' ? 'border-[#222]' : 'border-gray-200'}`}>
          Files ({files.length})
        </div>
        <div className="max-h-48 overflow-y-auto py-1">
          {files.length === 0 ? (
            <div className="text-xs text-gray-500 px-2 py-2">No files yet.</div>
          ) : (
            files.map((file) => (
              <button
                key={file.fileId}
                onClick={() => onSelectFile(file.fileId)}
                className={`w-full text-left px-2 py-1.5 rounded flex items-center gap-2 text-xs sm:text-sm transition-colors ${
                  selectedFileId === file.fileId
                    ? theme === 'dark'
                      ? 'bg-[#222] text-white'
                      : 'bg-gray-200 text-gray-900'
                    : 'text-gray-600 dark:text-gray-400 hover:bg-black/5 dark:hover:bg-white/5'
                }`}
                title={file.url}
              >
                <span className="shrink-0">{iconForFileKind(file.kind)}</span>
                <span className="truncate">{fileNameFromUrl(file.url)}</span>
              </button>
            ))
          )}
        </div>
      </div>
      <div className={`flex-1 flex flex-col min-w-0 min-h-0 ${theme === 'dark' ? 'bg-[#121212]' : 'bg-white'}`}>
        <div className={`h-8 border-b flex items-center px-2 sm:px-3 text-xs sm:text-sm truncate ${theme === 'dark' ? 'border-[#222] text-gray-400' : 'border-gray-200 text-gray-600'}`}>
          <span className="truncate">{selectedFileName}</span>
          <span className="ml-auto text-[10px] uppercase tracking-wider opacity-75">{selectedFolderLabel}</span>
        </div>
        <div className="flex-1 overflow-auto p-2 sm:p-4 min-h-0">
          {selectedFileContent ? (
            <pre className={`text-xs sm:text-sm font-mono leading-relaxed ${theme === 'dark' ? 'text-gray-300' : 'text-gray-800'}`}>
              <code>{selectedFileContent}</code>
            </pre>
          ) : (
            <div className="h-full flex items-center justify-center text-gray-500 text-xs sm:text-sm text-center p-4">Select a file to inspect its content.</div>
          )}
        </div>
      </div>
    </div>
  );
}

function FindingsTab({
  theme,
  findings,
  onReviewChange,
}: {
  theme: 'dark' | 'light';
  findings: Finding[];
  onReviewChange: (findingId: string, status: ReviewStatus) => void;
}) {
  return (
    <div className="h-full min-h-0 overflow-y-auto p-4 space-y-3">
      {findings.length === 0 ? (
        <div className="text-sm text-gray-500">No findings yet.</div>
      ) : (
        findings.map((finding) => (
          <div key={finding.id} className={`p-4 rounded-lg border ${theme === 'dark' ? 'bg-[#121212] border-[#333]' : 'bg-white border-gray-200 shadow-sm'}`}>
            <div className="flex items-start justify-between gap-2 mb-2">
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${severityClass(finding.severity)}`}>{finding.severity}</span>
                <h3 className={`font-semibold ${theme === 'dark' ? 'text-white' : 'text-gray-900'}`}>{finding.title}</h3>
              </div>
              <span className="text-xs text-gray-500 font-mono">{finding.ruleId}</span>
            </div>
            <div className="text-xs text-gray-500 mb-2">Confidence: {finding.confidence}</div>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">{finding.description}</p>
            <div className="text-xs text-gray-500 mb-2 font-mono bg-black/5 dark:bg-white/5 inline-block px-2 py-1 rounded">
              {finding.location.endpoint || finding.location.url || 'unknown location'}
              {finding.location.line ? `:${finding.location.line}` : ''}
            </div>
            <div className="text-xs text-gray-500 mb-3">Evidence: {finding.evidence}</div>
            <div className="text-xs text-gray-500 mb-3">Recommendation: {finding.recommendation}</div>
            <div className="flex items-center gap-2">
              <label className="text-xs text-gray-500">Review:</label>
              <select
                value={finding.reviewStatus}
                onChange={(event) => onReviewChange(finding.id, event.target.value as ReviewStatus)}
                className="bg-transparent border border-gray-400/40 rounded px-2 py-1 text-xs"
              >
                <option value="open">open</option>
                <option value="confirmed">confirmed</option>
                <option value="false_positive">false_positive</option>
                <option value="needs_review">needs_review</option>
              </select>
            </div>
          </div>
        ))
      )}
    </div>
  );
}

function NetworkTab({ theme, requests }: { theme: 'dark' | 'light'; requests: NetworkEntry[] }) {
  return (
    <div className="h-full min-h-0 overflow-auto">
      <table className="w-full text-sm text-left">
        <thead className={`text-xs uppercase border-b ${theme === 'dark' ? 'bg-[#1a1a1a] text-gray-400 border-[#222]' : 'bg-gray-50 text-gray-500 border-gray-200'}`}>
          <tr>
            <th className="px-4 py-2 font-medium">Method</th>
            <th className="px-4 py-2 font-medium">URL</th>
            <th className="px-4 py-2 font-medium">Status</th>
            <th className="px-4 py-2 font-medium">Type</th>
            <th className="px-4 py-2 font-medium">Size</th>
            <th className="px-4 py-2 font-medium">Time</th>
          </tr>
        </thead>
        <tbody>
          {requests.length === 0 ? (
            <tr>
              <td className="px-4 py-3 text-xs text-gray-500" colSpan={6}>
                No network records yet.
              </td>
            </tr>
          ) : (
            requests.map((request) => (
              <tr key={request.requestId} className={`border-b last:border-0 ${theme === 'dark' ? 'border-[#222] hover:bg-[#1a1a1a]' : 'border-gray-100 hover:bg-gray-50'}`}>
                <td className="px-4 py-2 font-mono text-xs">{request.method}</td>
                <td className="px-4 py-2 font-mono text-xs truncate max-w-[300px]" title={request.url}>
                  {request.url}
                </td>
                <td className="px-4 py-2 text-xs">{request.status ?? 'ERR'}</td>
                <td className="px-4 py-2 text-xs">{request.type || '-'}</td>
                <td className="px-4 py-2 text-xs">{formatBytes(request.size || 0)}</td>
                <td className="px-4 py-2 text-xs">{request.durationMs ? `${request.durationMs} ms` : '-'}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

function SurfaceTab({ theme, items }: { theme: 'dark' | 'light'; items: SurfaceItem[] }) {
  return (
    <div className="h-full min-h-0 overflow-y-auto p-4 space-y-3">
      {items.length === 0 ? (
        <div className="text-sm text-gray-500">No attack surface data yet.</div>
      ) : (
        items.map((item) => (
          <div key={item.id} className={`p-3 rounded-lg border ${theme === 'dark' ? 'bg-[#121212] border-[#333]' : 'bg-white border-gray-200'}`}>
            <div className="flex items-center justify-between gap-2 mb-2">
              <div className="font-mono text-xs sm:text-sm truncate">{item.method} {item.endpoint}</div>
              <div className="text-xs px-2 py-0.5 rounded bg-blue-500/15 text-blue-500">Risk {item.riskScore}</div>
            </div>
            <div className="text-xs text-gray-500 mb-1">Params: {item.params.map((param) => `${param.name}(${param.source})`).join(', ') || 'none'}</div>
            <div className="text-xs text-gray-500">Signals: {item.signals.join(', ') || 'none'}</div>
          </div>
        ))
      )}
    </div>
  );
}

function DiffsTab({ theme, diffs }: { theme: 'dark' | 'light'; diffs: ActiveDiff[] }) {
  return (
    <div className="h-full min-h-0 overflow-y-auto p-4 space-y-3">
      {diffs.length === 0 ? (
        <div className="text-sm text-gray-500">No active detection diffs yet.</div>
      ) : (
        diffs.map((diff) => (
          <div key={diff.id} className={`p-3 rounded-lg border ${theme === 'dark' ? 'bg-[#121212] border-[#333]' : 'bg-white border-gray-200'}`}>
            <div className="font-mono text-xs sm:text-sm mb-2">
              {diff.method} {diff.endpoint} [{diff.paramName}:{diff.mutationLabel}]
            </div>
            <div className="text-xs text-gray-500 mb-1">
              Baseline: status {diff.baseline.status ?? 'ERR'}, size {diff.baseline.bodyLength}, time {diff.baseline.durationMs} ms
            </div>
            <div className="text-xs text-gray-500 mb-1">
              Observed: status {diff.observed.status ?? 'ERR'}, size {diff.observed.bodyLength}, time {diff.observed.durationMs} ms
            </div>
            <div className="text-xs text-gray-500">
              Signals: {diff.signals.join(', ') || 'none'}
            </div>
          </div>
        ))
      )}
    </div>
  );
}

function iconForFileKind(kind: FileEntry['kind']) {
  switch (kind) {
    case 'html':
      return <FileType2 size={14} className="text-orange-500" />;
    case 'css':
      return <FileCode2 size={14} className="text-blue-500" />;
    case 'js':
      return <FileCode2 size={14} className="text-yellow-500" />;
    case 'json':
      return <FileJson size={14} className="text-green-500" />;
    default:
      return <FileCode2 size={14} />;
  }
}

function fileNameFromUrl(value: string): string {
  try {
    const parsed = new URL(value);
    const part = parsed.pathname.split('/').filter(Boolean).pop();
    if (part) {
      return safeDecodeSegment(part);
    }
    return `${parsed.hostname}/`;
  } catch {
    return value;
  }
}

function severityClass(severity: Finding['severity']): string {
  if (severity === 'critical' || severity === 'high') {
    return 'bg-red-500/10 text-red-500 border border-red-500/20';
  }
  if (severity === 'medium') {
    return 'bg-amber-500/10 text-amber-500 border border-amber-500/20';
  }
  return 'bg-blue-500/10 text-blue-500 border border-blue-500/20';
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function normalizeComparableUrl(value: string, baseUrl?: string): string | null {
  if (!value) return null;
  try {
    const parsed = baseUrl ? new URL(value, baseUrl) : new URL(value);
    const normalizedPath = parsed.pathname.replace(/\/+$/, '') || '/';
    return `${parsed.origin.toLowerCase()}${normalizedPath}${parsed.search}`;
  } catch {
    return null;
  }
}

function sanitizePreviewMessageUrl(value: string, baseUrl: string): string | null {
  try {
    const parsed = new URL(value, baseUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }
    parsed.hash = '';
    return parsed.toString();
  } catch {
    return null;
  }
}

function isSameOriginUrl(value: string, origin: string): boolean {
  try {
    return new URL(value).origin.toLowerCase() === origin.toLowerCase();
  } catch {
    return false;
  }
}

function resolveFolderForUrl(
  value: string,
  nodes: Record<string, FolderNode>,
  baseUrl?: string,
): string | null {
  const chain = folderChainForUrl(value, baseUrl);
  for (let i = chain.length - 1; i >= 0; i -= 1) {
    if (nodes[chain[i].key]) {
      return chain[i].key;
    }
  }

  const normalized = normalizeComparableUrl(value, baseUrl);
  if (!normalized) return null;

  let best: string | null = null;
  for (const key of Object.keys(nodes)) {
    const comparableKey = key.endsWith('/') ? key.slice(0, -1) : key;
    if (normalized.startsWith(comparableKey) && (!best || comparableKey.length > best.length)) {
      best = key;
    }
  }
  return best;
}

function buildFolderModel(
  files: FileEntry[],
  findings: Finding[],
  targetUrl: string,
): FolderModel {
  const nodes: Record<string, FolderNode> = {};
  const orderedKeys: string[] = [];
  const fileToFolder: Record<string, string> = {};

  const ensureNode = (entry: FolderDescriptor) => {
    if (!nodes[entry.key]) {
      nodes[entry.key] = {
        key: entry.key,
        label: entry.label,
        depth: entry.depth,
        parentKey: entry.parentKey,
        childKeys: [],
        files: [],
        findings: [],
      };
      orderedKeys.push(entry.key);
    }

    if (entry.parentKey && nodes[entry.parentKey] && !nodes[entry.parentKey].childKeys.includes(entry.key)) {
      nodes[entry.parentKey].childKeys.push(entry.key);
    }
  };

  const addFileToNodeChain = (leafKey: string, file: FileEntry) => {
    let cursor: string | null = leafKey;
    while (cursor) {
      const node = nodes[cursor];
      if (!node) break;
      node.files.push(file);
      cursor = node.parentKey;
    }
  };

  const addFindingToNodeChain = (leafKey: string, finding: Finding) => {
    let cursor: string | null = leafKey;
    while (cursor) {
      const node = nodes[cursor];
      if (!node) break;
      node.findings.push(finding);
      cursor = node.parentKey;
    }
  };

  for (const file of files) {
    const chain = folderChainForUrl(file.url, targetUrl);
    if (chain.length === 0) continue;
    chain.forEach(ensureNode);
    const leafKey = chain[chain.length - 1].key;
    fileToFolder[file.fileId] = leafKey;
    addFileToNodeChain(leafKey, file);
  }

  for (const finding of findings) {
    let folderKey: string | null = null;
    if (finding.location.fileId && fileToFolder[finding.location.fileId]) {
      folderKey = fileToFolder[finding.location.fileId];
    }
    if (!folderKey) {
      const locationValue = finding.location.url || finding.location.endpoint || targetUrl;
      folderKey = resolveFolderForUrl(locationValue, nodes, targetUrl);
    }
    if (folderKey && nodes[folderKey]) {
      addFindingToNodeChain(folderKey, finding);
    }
  }

  return { nodes, orderedKeys, fileToFolder };
}

interface FolderDescriptor {
  key: string;
  label: string;
  depth: number;
  parentKey: string | null;
}

function folderChainForUrl(value: string, baseUrl?: string): FolderDescriptor[] {
  if (!value) return [];

  let parsed: URL;
  try {
    parsed = baseUrl ? new URL(value, baseUrl) : new URL(value);
  } catch {
    return [];
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return [];
  }

  const rootKey = `${parsed.origin.toLowerCase()}/`;
  const chain: FolderDescriptor[] = [
    {
      key: rootKey,
      label: parsed.hostname,
      depth: 0,
      parentKey: null,
    },
  ];

  const segments = parsed.pathname.split('/').filter(Boolean);
  let parentKey = rootKey;
  let currentPath = '';

  segments.forEach((segment, index) => {
    currentPath += `/${segment}`;
    const key = `${parsed.origin.toLowerCase()}${currentPath}`;
    chain.push({
      key,
      label: safeDecodeSegment(segment),
      depth: index + 1,
      parentKey,
    });
    parentKey = key;
  });

  return chain;
}

function safeDecodeSegment(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
