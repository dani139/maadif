import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Search,
  RefreshCw,
  Download,
  Plus,
  Filter,
  ExternalLink,
  CheckCircle,
  Clock,
  Package,
  Play,
  Loader2,
} from 'lucide-react';
import {
  getTrackedVersions,
  scrapeVersions,
  addTrackedPackage,
  getTrackingStatus,
  downloadApk,
  getJobStatus,
  startAnalysis,
  formatRelativeTime,
  formatTimestamp,
} from '../api/client';
import type { TrackedVersion } from '../types';

// Package groups - some apps have separate beta packages
const PACKAGE_GROUPS: Record<string, { name: string; packages: string[] }> = {
  'com.whatsapp': {
    name: 'WhatsApp',
    packages: ['com.whatsapp'],
  },
  'org.telegram.messenger': {
    name: 'Telegram',
    packages: ['org.telegram.messenger', 'org.telegram.messenger.beta'],
  },
  'com.instagram.android': {
    name: 'Instagram',
    packages: ['com.instagram.android'],
  },
  'com.facebook.katana': {
    name: 'Facebook',
    packages: ['com.facebook.katana'],
  },
};

const KNOWN_PACKAGES = Object.entries(PACKAGE_GROUPS).map(([id, { name }]) => ({
  id,
  name,
}));

export function VersionTracker() {
  const [selectedPackage, setSelectedPackage] = useState('com.whatsapp');
  const [channelFilter, setChannelFilter] = useState<'all' | 'stable' | 'beta'>('all');
  const [showAddModal, setShowAddModal] = useState(false);
  const queryClient = useQueryClient();

  const { data: tracking } = useQuery({
    queryKey: ['tracking-status'],
    queryFn: getTrackingStatus,
  });

  // Get all packages in the selected group
  const packageGroup = PACKAGE_GROUPS[selectedPackage];
  const packagesToFetch = packageGroup?.packages ?? [selectedPackage];

  const {
    data: versions,
    isLoading,
    refetch,
  } = useQuery({
    queryKey: ['versions', selectedPackage, channelFilter],
    queryFn: async () => {
      // Fetch versions from all packages in the group
      const results = await Promise.all(
        packagesToFetch.map((pkg) => getTrackedVersions(pkg, channelFilter, 100))
      );

      // Combine and sort by semantic version (newest first)
      const allVersions = results.flatMap((r) => r.versions || []);
      allVersions.sort((a, b) => {
        const aParts = (a.version_name || '').split('.').map(Number);
        const bParts = (b.version_name || '').split('.').map(Number);
        for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
          const aVal = aParts[i] || 0;
          const bVal = bParts[i] || 0;
          if (bVal !== aVal) return bVal - aVal;
        }
        return 0;
      });

      return {
        package: selectedPackage,
        versions: allVersions,
      };
    },
    enabled: !!selectedPackage,
  });

  const scrapeMutation = useMutation({
    mutationFn: async () => {
      // Scrape all packages in the group
      const results = await Promise.all(
        packagesToFetch.map((pkg) => scrapeVersions(pkg, 'all'))
      );
      // Return combined result
      return {
        package: selectedPackage,
        versions: results.flatMap((r) => r.versions || []),
        new_count: results.reduce((sum, r) => sum + (r.new_count || 0), 0),
      };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['versions'] });
      queryClient.invalidateQueries({ queryKey: ['tracking-status'] });
    },
  });

  const [downloadingVersions, setDownloadingVersions] = useState<Set<string>>(new Set());
  const [downloadMessages, setDownloadMessages] = useState<Map<string, string>>(new Map());

  const downloadMutation = useMutation({
    mutationFn: async ({ pkg, version }: { pkg: string; version: string }) => {
      const job = await downloadApk(pkg, version);
      // Poll for job completion
      let status = job;
      while (status.status === 'pending' || status.status === 'running') {
        await new Promise((r) => setTimeout(r, 2000));
        status = await getJobStatus(job.id);
      }
      return { version, status };
    },
    onMutate: ({ pkg, version }) => {
      setDownloadingVersions((prev) => new Set(prev).add(`${pkg}-${version}`));
      setDownloadMessages((prev) => new Map(prev).set(`${pkg}-${version}`, 'Starting download...'));
    },
    onSuccess: ({ version, status }, { pkg }) => {
      setDownloadingVersions((prev) => {
        const next = new Set(prev);
        next.delete(`${pkg}-${version}`);
        return next;
      });
      if (status.status === 'completed') {
        setDownloadMessages((prev) => new Map(prev).set(`${pkg}-${version}`, 'Downloaded!'));
        queryClient.invalidateQueries({ queryKey: ['versions'] });
      } else {
        setDownloadMessages((prev) => new Map(prev).set(`${pkg}-${version}`, `Failed: ${status.message}`));
      }
      // Clear message after 5 seconds
      setTimeout(() => {
        setDownloadMessages((prev) => {
          const next = new Map(prev);
          next.delete(`${pkg}-${version}`);
          return next;
        });
      }, 5000);
    },
    onError: (error, { pkg, version }) => {
      setDownloadingVersions((prev) => {
        const next = new Set(prev);
        next.delete(`${pkg}-${version}`);
        return next;
      });
      setDownloadMessages((prev) => new Map(prev).set(`${pkg}-${version}`, `Error: ${error}`));
    },
  });

  const [analyzingVersions, setAnalyzingVersions] = useState<Set<string>>(new Set());

  const analyzeMutation = useMutation({
    mutationFn: async ({ pkg, version }: { pkg: string; version: string }) => {
      // Construct APK path: {package}/{appname}-{version}.xapk or .apk
      const appName = pkg.split('.').pop() || pkg;
      // Try xapk first, then apk
      const apkPath = `${pkg}/${appName}-${version}.xapk`;
      const job = await startAnalysis(apkPath, { natives: true, decompile: true });
      // Poll for job completion
      let status = job;
      while (status.status === 'pending' || status.status === 'running') {
        await new Promise((r) => setTimeout(r, 3000));
        status = await getJobStatus(job.id);
      }
      return { version, status };
    },
    onMutate: ({ pkg, version }) => {
      setAnalyzingVersions((prev) => new Set(prev).add(`${pkg}-${version}`));
    },
    onSuccess: ({ version }, { pkg }) => {
      setAnalyzingVersions((prev) => {
        const next = new Set(prev);
        next.delete(`${pkg}-${version}`);
        return next;
      });
      queryClient.invalidateQueries({ queryKey: ['versions'] });
    },
    onError: (_, { pkg, version }) => {
      setAnalyzingVersions((prev) => {
        const next = new Set(prev);
        next.delete(`${pkg}-${version}`);
        return next;
      });
    },
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Version Tracker</h1>
          <p className="text-slate-400 mt-1">
            Track app versions from APKPure & Uptodown
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowAddModal(true)}
            className="btn-secondary"
          >
            <Plus size={18} />
            Add Package
          </button>
          <button
            onClick={() => scrapeMutation.mutate()}
            disabled={scrapeMutation.isPending}
            className="btn-primary"
          >
            <RefreshCw
              size={18}
              className={scrapeMutation.isPending ? 'animate-spin' : ''}
            />
            {scrapeMutation.isPending ? 'Scraping...' : 'Scrape Now'}
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4">
        {/* Package Selector */}
        <div className="flex items-center gap-2">
          <Package size={18} className="text-slate-400" />
          <select
            value={selectedPackage}
            onChange={(e) => setSelectedPackage(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            {KNOWN_PACKAGES.map((pkg) => (
              <option key={pkg.id} value={pkg.id}>
                {pkg.name} ({pkg.id})
              </option>
            ))}
            {tracking?.tracked_packages
              ?.filter((p) => !KNOWN_PACKAGES.find((k) => k.id === p.package))
              .map((pkg) => (
                <option key={pkg.package} value={pkg.package}>
                  {pkg.package}
                </option>
              ))}
          </select>
        </div>

        {/* Channel Filter */}
        <div className="flex items-center gap-2">
          <Filter size={18} className="text-slate-400" />
          <div className="flex bg-slate-800 rounded-lg p-1">
            {(['all', 'stable', 'beta'] as const).map((ch) => (
              <button
                key={ch}
                onClick={() => setChannelFilter(ch)}
                className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                  channelFilter === ch
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {ch.charAt(0).toUpperCase() + ch.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {/* Stats */}
        <div className="ml-auto flex items-center gap-4 text-sm text-slate-400">
          <span>
            {versions?.versions?.length ?? 0} versions
          </span>
        </div>
      </div>

      {/* Scrape Result */}
      {scrapeMutation.isSuccess && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-4 flex items-center gap-3">
          <CheckCircle className="text-emerald-500" size={20} />
          <span className="text-emerald-400">
            Found {scrapeMutation.data.versions?.length ?? 0} versions,{' '}
            {scrapeMutation.data.new_count ?? 0} new
          </span>
        </div>
      )}

      {/* Versions Table */}
      <div className="card p-0 overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center">
            <RefreshCw className="animate-spin text-slate-400 mx-auto mb-2\" size={24} />
            <p className="text-slate-500">Loading versions...</p>
          </div>
        ) : versions?.versions && versions.versions.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-800/50">
                <tr>
                  <th className="table-header">Version</th>
                  <th className="table-header">Channel</th>
                  <th className="table-header">Release Date</th>
                  <th className="table-header">Source</th>
                  <th className="table-header">Status</th>
                  <th className="table-header text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {versions.versions.map((v: TrackedVersion, idx: number) => (
                  <tr key={`${v.version_name}-${v.source}-${idx}`} className="table-row">
                    <td className="table-cell">
                      <span className="font-mono font-medium text-white">
                        {v.version_name}
                      </span>
                    </td>
                    <td className="table-cell">
                      <span
                        className={
                          v.channel === 'beta' ? 'badge-beta' : 'badge-stable'
                        }
                      >
                        {v.channel}
                      </span>
                    </td>
                    <td className="table-cell">
                      <span className="text-slate-300 text-sm">
                        {v.release_date
                          ? new Date(v.release_date * 1000).toLocaleDateString('en-US', {
                              year: 'numeric',
                              month: 'short',
                              day: 'numeric',
                            })
                          : '-'}
                      </span>
                    </td>
                    <td className="table-cell">
                      <span className="text-slate-400 capitalize">{v.source}</span>
                    </td>
                    <td className="table-cell">
                      {v.analyzed_at ? (
                        <span className="badge-success flex items-center gap-1 w-fit">
                          <CheckCircle size={12} /> Analyzed
                        </span>
                      ) : v.downloaded_at ? (
                        <span className="badge-warning flex items-center gap-1 w-fit">
                          <Download size={12} /> Downloaded
                        </span>
                      ) : (
                        <span className="text-slate-500 text-sm">Not downloaded</span>
                      )}
                    </td>
                    <td className="table-cell text-right">
                      <div className="flex items-center justify-end gap-2">
                        {v.source_url && (
                          <a
                            href={v.source_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="p-1.5 rounded hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
                            title="View on source"
                          >
                            <ExternalLink size={16} />
                          </a>
                        )}
                        {/* Download button */}
                        {v.downloaded_at ? (
                          <span className="p-1.5 text-emerald-500" title="Already downloaded">
                            <CheckCircle size={16} />
                          </span>
                        ) : downloadingVersions.has(`${v.package_name}-${v.version_name}`) ? (
                          <span className="p-1.5 text-indigo-400" title={downloadMessages.get(`${v.package_name}-${v.version_name}`) || 'Downloading...'}>
                            <RefreshCw size={16} className="animate-spin" />
                          </span>
                        ) : (
                          <button
                            onClick={() => downloadMutation.mutate({ pkg: v.package_name, version: v.version_name })}
                            className="p-1.5 rounded hover:bg-slate-700 text-slate-400 hover:text-indigo-400 transition-colors"
                            title="Download APK"
                          >
                            <Download size={16} />
                          </button>
                        )}
                        {/* Analyze button - show for downloaded but not analyzed */}
                        {v.downloaded_at && !v.analyzed_at && (
                          analyzingVersions.has(`${v.package_name}-${v.version_name}`) ? (
                            <span className="p-1.5 text-amber-400" title="Analyzing...">
                              <Loader2 size={16} className="animate-spin" />
                            </span>
                          ) : (
                            <button
                              onClick={() => analyzeMutation.mutate({ pkg: v.package_name, version: v.version_name })}
                              className="p-1.5 rounded hover:bg-slate-700 text-slate-400 hover:text-amber-400 transition-colors"
                              title="Analyze APK"
                            >
                              <Play size={16} />
                            </button>
                          )
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-8 text-center">
            <Search className="text-slate-600 mx-auto mb-2" size={32} />
            <p className="text-slate-500">No versions found</p>
            <p className="text-slate-600 text-sm mt-1">
              Click "Scrape Now" to fetch versions
            </p>
          </div>
        )}
      </div>

      {/* Add Package Modal */}
      {showAddModal && (
        <AddPackageModal onClose={() => setShowAddModal(false)} />
      )}
    </div>
  );
}

function AddPackageModal({ onClose }: { onClose: () => void }) {
  const [packageName, setPackageName] = useState('');
  const [displayName, setDisplayName] = useState('');
  const queryClient = useQueryClient();

  const addMutation = useMutation({
    mutationFn: () => addTrackedPackage(packageName, displayName),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tracking-status'] });
      queryClient.invalidateQueries({ queryKey: ['versions'] });
      onClose();
    },
  });

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-md">
        <h2 className="text-xl font-bold text-white mb-4">Add Package to Track</h2>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-1">
              Package Name
            </label>
            <input
              type="text"
              value={packageName}
              onChange={(e) => setPackageName(e.target.value)}
              placeholder="com.example.app"
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-400 mb-1">
              Display Name (optional)
            </label>
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="Example App"
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>
        </div>

        <div className="flex justify-end gap-3 mt-6">
          <button onClick={onClose} className="btn-secondary">
            Cancel
          </button>
          <button
            onClick={() => addMutation.mutate()}
            disabled={!packageName || addMutation.isPending}
            className="btn-primary"
          >
            {addMutation.isPending ? 'Adding...' : 'Add Package'}
          </button>
        </div>
      </div>
    </div>
  );
}
