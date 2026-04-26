import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  FileCode,
  Search,
  RefreshCw,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  ChevronRight,
  Shield,
  Link,
  Box,
  Code,
} from 'lucide-react';
import { getJobStatus, getAnalysisResult, formatTimestamp } from '../api/client';
import type { AnalysisResult } from '../types';

export function AnalysisJobs() {
  const [jobId, setJobId] = useState('');
  const [searchedJobId, setSearchedJobId] = useState('');

  const {
    data: job,
    isLoading: jobLoading,
    error: jobError,
  } = useQuery({
    queryKey: ['job', searchedJobId],
    queryFn: () => getJobStatus(searchedJobId),
    enabled: !!searchedJobId,
    refetchInterval: (query) =>
      query.state.data?.status === 'running' ? 2000 : false,
  });

  const { data: analysis, isLoading: analysisLoading } = useQuery({
    queryKey: ['analysis', searchedJobId],
    queryFn: () => getAnalysisResult(searchedJobId),
    enabled: job?.status === 'completed',
  });

  const handleSearch = () => {
    setSearchedJobId(jobId.trim());
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white">Analysis Jobs</h1>
        <p className="text-slate-400 mt-1">
          Track and view APK analysis results
        </p>
      </div>

      {/* Job Search */}
      <div className="card">
        <h2 className="text-lg font-semibold text-white mb-4">Find Job</h2>
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search
              className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
              size={20}
            />
            <input
              type="text"
              value={jobId}
              onChange={(e) => setJobId(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              placeholder="Enter job ID (e.g., a1b2c3d4)"
              className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-10 pr-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>
          <button onClick={handleSearch} className="btn-primary">
            <Search size={18} />
            Search
          </button>
        </div>
      </div>

      {/* Job Status */}
      {searchedJobId && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <FileCode size={20} className="text-indigo-500" />
              Job: {searchedJobId}
            </h2>
            {jobLoading && <RefreshCw className="animate-spin text-slate-400" size={18} />}
          </div>

          {jobError ? (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 flex items-center gap-3">
              <XCircle className="text-red-500" size={20} />
              <span className="text-red-400">Job not found</span>
            </div>
          ) : job ? (
            <div className="space-y-4">
              {/* Status Badge */}
              <div className="flex items-center gap-4">
                <StatusBadge status={job.status} />
                {job.status === 'running' && (
                  <div className="flex-1">
                    <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-indigo-500 transition-all duration-500"
                        style={{ width: `${job.progress}%` }}
                      />
                    </div>
                    <span className="text-xs text-slate-400 mt-1">
                      {job.progress}%
                    </span>
                  </div>
                )}
              </div>

              {/* Message */}
              {job.message && (
                <div className="bg-slate-800/50 rounded-lg p-3">
                  <p className="text-sm text-slate-300 font-mono">{job.message}</p>
                </div>
              )}

              {/* Timestamps */}
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-slate-500">Started:</span>{' '}
                  <span className="text-slate-300">
                    {job.started_at ? formatTimestamp(job.started_at) : '-'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500">Completed:</span>{' '}
                  <span className="text-slate-300">
                    {job.completed_at ? formatTimestamp(job.completed_at) : '-'}
                  </span>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      )}

      {/* Analysis Results */}
      {analysis && job?.status === 'completed' && (
        <AnalysisResults analysis={analysis} />
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  switch (status) {
    case 'completed':
      return (
        <span className="badge-success flex items-center gap-1">
          <CheckCircle size={14} /> Completed
        </span>
      );
    case 'running':
      return (
        <span className="badge-warning flex items-center gap-1">
          <RefreshCw size={14} className="animate-spin" /> Running
        </span>
      );
    case 'failed':
      return (
        <span className="badge-error flex items-center gap-1">
          <XCircle size={14} /> Failed
        </span>
      );
    case 'pending':
      return (
        <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-500/20 text-slate-400 border border-slate-500/30 flex items-center gap-1">
          <Clock size={14} /> Pending
        </span>
      );
    default:
      return <span className="text-slate-400">{status}</span>;
  }
}

function AnalysisResults({ analysis }: { analysis: AnalysisResult }) {
  const [activeTab, setActiveTab] = useState<
    'overview' | 'permissions' | 'components' | 'natives' | 'security'
  >('overview');

  return (
    <div className="card">
      <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
        <FileCode size={20} className="text-indigo-500" />
        Analysis Results
      </h2>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-slate-800 p-1 rounded-lg w-fit">
        {[
          { id: 'overview', label: 'Overview', icon: <Box size={16} /> },
          { id: 'permissions', label: 'Permissions', icon: <Shield size={16} /> },
          { id: 'components', label: 'Components', icon: <Code size={16} /> },
          { id: 'natives', label: 'Natives', icon: <FileCode size={16} /> },
          { id: 'security', label: 'Security', icon: <AlertTriangle size={16} /> },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as typeof activeTab)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-indigo-600 text-white'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatItem label="Total Classes" value={analysis.total_classes ?? 0} />
          <StatItem label="Total Methods" value={analysis.total_methods ?? 0} />
          <StatItem
            label="Failed Classes"
            value={analysis.failed_classes ?? 0}
            warning={analysis.failed_classes ? analysis.failed_classes > 0 : false}
          />
          <StatItem
            label="Failed Methods"
            value={analysis.failed_methods ?? 0}
            warning={analysis.failed_methods ? analysis.failed_methods > 0 : false}
          />
        </div>
      )}

      {activeTab === 'permissions' && (
        <div className="space-y-2">
          {analysis.permissions && analysis.permissions.length > 0 ? (
            analysis.permissions.map((p) => (
              <div
                key={p.permission}
                className="flex items-center justify-between py-2 px-3 bg-slate-800/50 rounded-lg"
              >
                <span className="text-slate-300 font-mono text-sm">
                  {p.permission.replace('android.permission.', '')}
                </span>
                {p.is_dangerous ? (
                  <span className="badge-error">Dangerous</span>
                ) : (
                  <span className="text-slate-500 text-xs">Normal</span>
                )}
              </div>
            ))
          ) : (
            <p className="text-slate-500">No permissions found</p>
          )}
        </div>
      )}

      {activeTab === 'components' && (
        <div className="space-y-2">
          {analysis.components && analysis.components.length > 0 ? (
            analysis.components.slice(0, 50).map((c, i) => (
              <div
                key={i}
                className="flex items-center justify-between py-2 px-3 bg-slate-800/50 rounded-lg"
              >
                <div className="flex items-center gap-2">
                  <span className="badge-stable">{c.type}</span>
                  <span className="text-slate-300 font-mono text-xs truncate max-w-md">
                    {c.name}
                  </span>
                </div>
                {c.exported ? (
                  <span className="badge-warning">Exported</span>
                ) : null}
              </div>
            ))
          ) : (
            <p className="text-slate-500">No components found</p>
          )}
        </div>
      )}

      {activeTab === 'natives' && (
        <div className="space-y-2">
          {analysis.native_libs && analysis.native_libs.length > 0 ? (
            analysis.native_libs.map((lib) => (
              <div
                key={lib.path}
                className="flex items-center justify-between py-3 px-4 bg-slate-800/50 rounded-lg"
              >
                <div>
                  <span className="text-white font-medium">{lib.name}</span>
                  <div className="flex items-center gap-3 mt-1 text-xs text-slate-400">
                    <span>{lib.arch}</span>
                    <span>{lib.function_count} functions</span>
                    <span>{lib.string_count} strings</span>
                  </div>
                </div>
                {lib.analyzed ? (
                  <span className="badge-success">Analyzed</span>
                ) : (
                  <span className="badge-warning">Pending</span>
                )}
              </div>
            ))
          ) : (
            <p className="text-slate-500">No native libraries found</p>
          )}
        </div>
      )}

      {activeTab === 'security' && (
        <div className="space-y-2">
          {analysis.security_findings && analysis.security_findings.length > 0 ? (
            analysis.security_findings.map((f, i) => (
              <div
                key={i}
                className="py-3 px-4 bg-slate-800/50 rounded-lg"
              >
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className={
                      f.severity === 'high'
                        ? 'badge-error'
                        : f.severity === 'medium'
                        ? 'badge-warning'
                        : 'badge-stable'
                    }
                  >
                    {f.severity}
                  </span>
                  <span className="text-white font-medium">{f.type}</span>
                </div>
                <p className="text-slate-400 text-sm">{f.description}</p>
                {f.location && (
                  <p className="text-slate-500 text-xs mt-1 font-mono">
                    {f.location}
                  </p>
                )}
              </div>
            ))
          ) : (
            <p className="text-slate-500">No security findings</p>
          )}
        </div>
      )}
    </div>
  );
}

function StatItem({
  label,
  value,
  warning,
}: {
  label: string;
  value: number;
  warning?: boolean;
}) {
  return (
    <div className="bg-slate-800/50 rounded-lg p-4 text-center">
      <div
        className={`text-2xl font-bold ${warning ? 'text-amber-400' : 'text-white'}`}
      >
        {value.toLocaleString()}
      </div>
      <div className="text-sm text-slate-400">{label}</div>
    </div>
  );
}
