// Version Tracking Types
export interface TrackedVersion {
  id: number;
  package_name: string;
  version_name: string;
  version_code: number | null;
  channel: 'stable' | 'beta';
  arch: string;
  min_sdk: number | null;
  file_size: number | null;
  sha256: string | null;
  source: string;
  source_url: string;
  release_date: number | null;
  first_seen_at: number;
  downloaded_at: number | null;
  analyzed_at: number | null;
  analysis_db_path: string | null;
}

export interface TrackingStatus {
  database: string;
  exists: boolean;
  size_bytes?: number;
  size_kb?: number;
  packages?: number;
  total_versions?: number;
  stable_versions?: number;
  beta_versions?: number;
  tracked_packages?: { package: string; versions: number }[];
}

export interface ScrapeResult {
  package: string;
  versions: TrackedVersion[];
  new_count: number;
}

// Analysis Types
export interface AnalysisJob {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  message: string;
  started_at: number | null;
  completed_at: number | null;
}

export interface ApkInfo {
  path: string;
  name: string;
  size: number;
}

export interface AnalysisResult {
  id: string;
  database_path?: string;
  total_classes?: number;
  total_methods?: number;
  failed_classes?: number;
  failed_methods?: number;
  output_path?: string;
  permissions?: { permission: string; is_dangerous: number }[];
  components?: { type: string; name: string; exported: number }[];
  native_libs?: {
    path: string;
    name: string;
    arch: string;
    size: number;
    analyzed: number;
    function_count: number;
    string_count: number;
  }[];
  security_findings?: {
    type: string;
    severity: string;
    description: string;
    location: string | null;
  }[];
}

// Health Check
export interface HealthStatus {
  status: string;
  tools: {
    jadx: boolean;
    ghidra: boolean;
  };
  apks_dir: string;
  output_dir: string;
}
