import { useQuery } from '@tanstack/react-query';
import {
  Package,
  Layers,
  CheckCircle,
  AlertTriangle,
  Clock,
  Database,
  RefreshCw,
  TrendingUp,
} from 'lucide-react';
import { getTrackingStatus, getHealth, listApks, formatBytes } from '../api/client';

export function Dashboard() {
  const { data: tracking, isLoading: trackingLoading, refetch: refetchTracking } = useQuery({
    queryKey: ['tracking-status'],
    queryFn: getTrackingStatus,
    refetchInterval: 30000,
  });

  const { data: health, isLoading: healthLoading } = useQuery({
    queryKey: ['health'],
    queryFn: getHealth,
    retry: false,
  });

  const { data: apks, isLoading: apksLoading } = useQuery({
    queryKey: ['apks'],
    queryFn: listApks,
    retry: false,
  });

  const isLoading = trackingLoading || healthLoading || apksLoading;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Dashboard</h1>
          <p className="text-slate-400 mt-1">Mobile Application Analysis Overview</p>
        </div>
        <button
          onClick={() => refetchTracking()}
          className="btn-secondary"
          disabled={isLoading}
        >
          <RefreshCw size={18} className={isLoading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Tracked Packages"
          value={tracking?.packages ?? '-'}
          icon={<Package className="text-indigo-500" />}
          loading={trackingLoading}
        />
        <StatCard
          title="Total Versions"
          value={tracking?.total_versions ?? '-'}
          icon={<Layers className="text-emerald-500" />}
          loading={trackingLoading}
          subtitle={
            tracking
              ? `${tracking.stable_versions ?? 0} stable / ${tracking.beta_versions ?? 0} beta`
              : undefined
          }
        />
        <StatCard
          title="APKs Available"
          value={apks?.apks?.length ?? '-'}
          icon={<Database className="text-amber-500" />}
          loading={apksLoading}
        />
        <StatCard
          title="API Status"
          value={health?.status === 'ok' ? 'Online' : 'Offline'}
          icon={
            health?.status === 'ok' ? (
              <CheckCircle className="text-emerald-500" />
            ) : (
              <AlertTriangle className="text-red-500" />
            )
          }
          loading={healthLoading}
          valueColor={health?.status === 'ok' ? 'text-emerald-400' : 'text-red-400'}
        />
      </div>

      {/* Tools Status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <TrendingUp size={20} className="text-indigo-500" />
            Analysis Tools
          </h2>
          <div className="space-y-3">
            <ToolStatus name="JADX" available={health?.tools?.jadx} />
            <ToolStatus name="Ghidra" available={health?.tools?.ghidra} />
          </div>
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Package size={20} className="text-indigo-500" />
            Tracked Applications
          </h2>
          <div className="space-y-2">
            {tracking?.tracked_packages?.map((pkg) => (
              <div
                key={pkg.package}
                className="flex items-center justify-between py-2 px-3 bg-slate-800/50 rounded-lg"
              >
                <span className="text-slate-300 font-mono text-sm">{pkg.package}</span>
                <span className="badge-stable">{pkg.versions} versions</span>
              </div>
            )) ?? (
              <p className="text-slate-500 text-sm">No packages tracked yet</p>
            )}
          </div>
        </div>
      </div>

      {/* Recent APKs */}
      <div className="card">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Database size={20} className="text-indigo-500" />
          Recent APKs
        </h2>
        {apks?.apks && apks.apks.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="table-header">Name</th>
                  <th className="table-header">Path</th>
                  <th className="table-header text-right">Size</th>
                </tr>
              </thead>
              <tbody>
                {apks.apks.slice(0, 5).map((apk) => (
                  <tr key={apk.path} className="table-row">
                    <td className="table-cell font-medium text-white">{apk.name}</td>
                    <td className="table-cell font-mono text-xs text-slate-400">{apk.path}</td>
                    <td className="table-cell text-right text-slate-400">
                      {formatBytes(apk.size)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-slate-500 text-sm">No APKs found in library</p>
        )}
      </div>
    </div>
  );
}

function StatCard({
  title,
  value,
  icon,
  loading,
  subtitle,
  valueColor = 'text-white',
}: {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  loading?: boolean;
  subtitle?: string;
  valueColor?: string;
}) {
  return (
    <div className="stat-card">
      <div className="mb-3">{icon}</div>
      {loading ? (
        <div className="h-8 w-16 bg-slate-800 rounded animate-pulse" />
      ) : (
        <div className={`text-3xl font-bold ${valueColor}`}>{value}</div>
      )}
      <div className="text-sm text-slate-400 mt-1">{title}</div>
      {subtitle && <div className="text-xs text-slate-500 mt-1">{subtitle}</div>}
    </div>
  );
}

function ToolStatus({ name, available }: { name: string; available?: boolean }) {
  return (
    <div className="flex items-center justify-between py-2 px-3 bg-slate-800/50 rounded-lg">
      <span className="text-slate-300 font-medium">{name}</span>
      {available === undefined ? (
        <span className="badge-warning">Unknown</span>
      ) : available ? (
        <span className="badge-success flex items-center gap-1">
          <CheckCircle size={12} /> Available
        </span>
      ) : (
        <span className="badge-error flex items-center gap-1">
          <AlertTriangle size={12} /> Not Found
        </span>
      )}
    </div>
  );
}
