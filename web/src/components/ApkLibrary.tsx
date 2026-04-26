import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Package,
  Play,
  RefreshCw,
  FileCode,
  HardDrive,
  FolderOpen,
  Search,
  Download,
  Cpu,
} from 'lucide-react';
import { listApks, startAnalysis, formatBytes } from '../api/client';
import type { ApkInfo } from '../types';

export function ApkLibrary() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedApk, setSelectedApk] = useState<ApkInfo | null>(null);
  const queryClient = useQueryClient();

  const { data: apks, isLoading, refetch } = useQuery({
    queryKey: ['apks'],
    queryFn: listApks,
  });

  const analyzeMutation = useMutation({
    mutationFn: (apk: ApkInfo) => startAnalysis(apk.path, { natives: true, decompile: true }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
    },
  });

  const filteredApks = apks?.apks?.filter(
    (apk) =>
      apk.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      apk.path.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const totalSize = apks?.apks?.reduce((acc, apk) => acc + apk.size, 0) ?? 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">APK Library</h1>
          <p className="text-slate-400 mt-1">
            Manage and analyze your APK collection
          </p>
        </div>
        <button onClick={() => refetch()} className="btn-secondary">
          <RefreshCw size={18} />
          Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card flex items-center gap-4">
          <div className="p-3 bg-indigo-500/20 rounded-lg">
            <Package className="text-indigo-400" size={24} />
          </div>
          <div>
            <div className="text-2xl font-bold text-white">
              {apks?.apks?.length ?? 0}
            </div>
            <div className="text-sm text-slate-400">Total APKs</div>
          </div>
        </div>

        <div className="card flex items-center gap-4">
          <div className="p-3 bg-emerald-500/20 rounded-lg">
            <HardDrive className="text-emerald-400" size={24} />
          </div>
          <div>
            <div className="text-2xl font-bold text-white">
              {formatBytes(totalSize)}
            </div>
            <div className="text-sm text-slate-400">Total Size</div>
          </div>
        </div>

        <div className="card flex items-center gap-4">
          <div className="p-3 bg-amber-500/20 rounded-lg">
            <Cpu className="text-amber-400" size={24} />
          </div>
          <div>
            <div className="text-2xl font-bold text-white">
              {analyzeMutation.isPending ? 'Running' : 'Ready'}
            </div>
            <div className="text-sm text-slate-400">Analysis Status</div>
          </div>
        </div>
      </div>

      {/* Search */}
      <div className="relative">
        <Search
          className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
          size={20}
        />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search APKs..."
          className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-10 pr-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
        />
      </div>

      {/* APK Grid */}
      {isLoading ? (
        <div className="card p-8 text-center">
          <RefreshCw className="animate-spin text-slate-400 mx-auto mb-2" size={24} />
          <p className="text-slate-500">Loading APKs...</p>
        </div>
      ) : filteredApks && filteredApks.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredApks.map((apk) => (
            <ApkCard
              key={apk.path}
              apk={apk}
              onAnalyze={() => {
                setSelectedApk(apk);
                analyzeMutation.mutate(apk);
              }}
              isAnalyzing={
                analyzeMutation.isPending &&
                analyzeMutation.variables?.path === apk.path
              }
            />
          ))}
        </div>
      ) : (
        <div className="card p-8 text-center">
          <FolderOpen className="text-slate-600 mx-auto mb-2" size={32} />
          <p className="text-slate-500">No APKs found</p>
          <p className="text-slate-600 text-sm mt-1">
            Download APKs using the Version Tracker
          </p>
        </div>
      )}

      {/* Analysis Started Toast */}
      {analyzeMutation.isSuccess && (
        <div className="fixed bottom-6 right-6 bg-emerald-500/20 border border-emerald-500/30 rounded-lg p-4 flex items-center gap-3 animate-in slide-in-from-bottom">
          <FileCode className="text-emerald-500" size={20} />
          <div>
            <span className="text-emerald-400 font-medium">Analysis started</span>
            <p className="text-emerald-500/70 text-sm">
              Job ID: {analyzeMutation.data.id}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

function ApkCard({
  apk,
  onAnalyze,
  isAnalyzing,
}: {
  apk: ApkInfo;
  onAnalyze: () => void;
  isAnalyzing: boolean;
}) {
  // Extract package name from path if possible
  const pathParts = apk.path.split('/');
  const packageName = pathParts.length > 1 ? pathParts[0] : null;

  return (
    <div className="card-hover group">
      <div className="flex items-start justify-between mb-3">
        <div className="p-2 bg-indigo-500/20 rounded-lg">
          <Package className="text-indigo-400" size={20} />
        </div>
        <span className="text-xs text-slate-500 font-mono">
          {formatBytes(apk.size)}
        </span>
      </div>

      <h3 className="font-medium text-white mb-1 truncate" title={apk.name}>
        {apk.name}
      </h3>

      {packageName && (
        <p className="text-xs text-slate-500 font-mono mb-3 truncate">
          {packageName}
        </p>
      )}

      <p className="text-xs text-slate-400 truncate mb-4" title={apk.path}>
        {apk.path}
      </p>

      <button
        onClick={onAnalyze}
        disabled={isAnalyzing}
        className="w-full btn-primary justify-center"
      >
        {isAnalyzing ? (
          <>
            <RefreshCw size={16} className="animate-spin" />
            Analyzing...
          </>
        ) : (
          <>
            <Play size={16} />
            Analyze
          </>
        )}
      </button>
    </div>
  );
}
