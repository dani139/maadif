import axios from 'axios';
import type {
  TrackedVersion,
  TrackingStatus,
  ScrapeResult,
  AnalysisJob,
  ApkInfo,
  AnalysisResult,
  HealthStatus,
} from '../types';

const api = axios.create({
  baseURL: '/api',
  timeout: 120000, // 2 minutes for long operations
});

// ============================================================================
// Health & Status
// ============================================================================

export async function getHealth(): Promise<HealthStatus> {
  const { data } = await api.get('/health');
  return data;
}

// ============================================================================
// Version Tracking
// ============================================================================

export async function getTrackingStatus(): Promise<TrackingStatus> {
  const { data } = await api.get('/track/status');
  return data;
}

export async function getTrackedVersions(
  packageName: string,
  channel: 'stable' | 'beta' | 'all' = 'all',
  limit: number = 50
): Promise<{ package: string; versions: TrackedVersion[] }> {
  const { data } = await api.get('/track/versions', {
    params: { package: packageName, channel, limit },
  });
  return data;
}

export async function scrapeVersions(
  packageName: string,
  source: 'apkpure' | 'uptodown' | 'all' = 'all'
): Promise<ScrapeResult> {
  const { data } = await api.get('/track/scrape', {
    params: { package: packageName, source },
  });
  return data;
}

export async function addTrackedPackage(
  packageName: string,
  displayName?: string
): Promise<{ package: string; status: string }> {
  const { data } = await api.post('/track/add', {
    package: packageName,
    name: displayName,
  });
  return data;
}

// ============================================================================
// APK Management
// ============================================================================

export async function listApks(): Promise<{ apks: ApkInfo[] }> {
  const { data } = await api.get('/apks');
  return data;
}

export async function downloadApk(
  packageName: string,
  version: string = 'latest'
): Promise<AnalysisJob> {
  const { data } = await api.post('/download', {
    package: packageName,
    version,
  });
  return data;
}

export async function getDownloadVersions(
  packageName: string
): Promise<{ versions: string[] }> {
  const { data } = await api.get('/download/versions', {
    params: { package: packageName },
  });
  return data;
}

// ============================================================================
// Analysis
// ============================================================================

export async function startAnalysis(
  apkPath: string,
  options: { natives?: boolean; decompile?: boolean } = {}
): Promise<AnalysisJob> {
  const { data } = await api.post('/analyze', {
    apk: apkPath,
    natives: options.natives ?? true,
    decompile: options.decompile ?? true,
  });
  return data;
}

export async function getJobStatus(jobId: string): Promise<AnalysisJob> {
  const { data } = await api.get(`/status/${jobId}`);
  return data;
}

export async function getAnalysisResult(jobId: string): Promise<AnalysisResult> {
  const { data } = await api.get(`/analysis/${jobId}`);
  return data;
}

export async function analyzeNativeLib(
  apkPath: string,
  libraryPath: string
): Promise<AnalysisJob> {
  const { data } = await api.post('/native', {
    apk: apkPath,
    library: libraryPath,
  });
  return data;
}

// ============================================================================
// Utility Functions
// ============================================================================

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export function formatTimestamp(ts: number): string {
  if (!ts) return '-';
  return new Date(ts * 1000).toLocaleString();
}

export function formatRelativeTime(ts: number): string {
  if (!ts) return '-';
  const now = Date.now() / 1000;
  const diff = now - ts;

  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
  return formatTimestamp(ts);
}
