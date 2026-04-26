import { useQuery } from '@tanstack/react-query';
import {
  Settings as SettingsIcon,
  Server,
  HardDrive,
  CheckCircle,
  XCircle,
  ExternalLink,
} from 'lucide-react';
import { getHealth, getTrackingStatus } from '../api/client';

export function Settings() {
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: getHealth,
    retry: false,
  });

  const { data: tracking } = useQuery({
    queryKey: ['tracking-status'],
    queryFn: getTrackingStatus,
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white">Settings</h1>
        <p className="text-slate-400 mt-1">System configuration and status</p>
      </div>

      {/* API Server */}
      <div className="card">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Server size={20} className="text-indigo-500" />
          API Server
        </h2>

        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <InfoItem
              label="Status"
              value={
                health?.status === 'ok' ? (
                  <span className="flex items-center gap-1 text-emerald-400">
                    <CheckCircle size={16} /> Online
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-red-400">
                    <XCircle size={16} /> Offline
                  </span>
                )
              }
            />
            <InfoItem label="Endpoint" value="http://localhost:8080" />
            <InfoItem label="APKs Directory" value={health?.apks_dir ?? '-'} />
            <InfoItem label="Output Directory" value={health?.output_dir ?? '-'} />
          </div>
        </div>
      </div>

      {/* Analysis Tools */}
      <div className="card">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <SettingsIcon size={20} className="text-indigo-500" />
          Analysis Tools
        </h2>

        <div className="space-y-3">
          <ToolItem
            name="JADX"
            description="Java decompiler for APK analysis"
            available={health?.tools?.jadx}
            link="https://github.com/skylot/jadx"
          />
          <ToolItem
            name="Ghidra"
            description="Binary analysis for native libraries"
            available={health?.tools?.ghidra}
            link="https://ghidra-sre.org/"
          />
        </div>
      </div>

      {/* Database */}
      <div className="card">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <HardDrive size={20} className="text-indigo-500" />
          Tracking Database
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <InfoItem
            label="Location"
            value={tracking?.database ?? '-'}
            mono
          />
          <InfoItem
            label="Size"
            value={tracking?.size_kb ? `${tracking.size_kb} KB` : '-'}
          />
          <InfoItem
            label="Total Packages"
            value={tracking?.packages?.toString() ?? '-'}
          />
          <InfoItem
            label="Total Versions"
            value={tracking?.total_versions?.toString() ?? '-'}
          />
        </div>
      </div>

      {/* About */}
      <div className="card">
        <h2 className="text-lg font-semibold text-white mb-4">About MAADIF</h2>
        <p className="text-slate-400 mb-4">
          Mobile & Application Analysis Docker Image Framework - A comprehensive
          toolkit for Android APK analysis including decompilation, native library
          analysis, and version tracking.
        </p>
        <div className="flex items-center gap-4">
          <a
            href="https://github.com/maadif/maadif"
            target="_blank"
            rel="noopener noreferrer"
            className="btn-secondary"
          >
            <ExternalLink size={16} />
            GitHub
          </a>
        </div>
      </div>
    </div>
  );
}

function InfoItem({
  label,
  value,
  mono,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="bg-slate-800/50 rounded-lg p-3">
      <div className="text-xs text-slate-500 mb-1">{label}</div>
      <div className={`text-slate-200 ${mono ? 'font-mono text-sm' : ''}`}>
        {value}
      </div>
    </div>
  );
}

function ToolItem({
  name,
  description,
  available,
  link,
}: {
  name: string;
  description: string;
  available?: boolean;
  link: string;
}) {
  return (
    <div className="flex items-center justify-between py-3 px-4 bg-slate-800/50 rounded-lg">
      <div>
        <div className="flex items-center gap-2">
          <span className="text-white font-medium">{name}</span>
          <a
            href={link}
            target="_blank"
            rel="noopener noreferrer"
            className="text-slate-500 hover:text-indigo-400 transition-colors"
          >
            <ExternalLink size={14} />
          </a>
        </div>
        <p className="text-sm text-slate-500">{description}</p>
      </div>
      {available === undefined ? (
        <span className="badge-warning">Unknown</span>
      ) : available ? (
        <span className="badge-success flex items-center gap-1">
          <CheckCircle size={12} /> Installed
        </span>
      ) : (
        <span className="badge-error flex items-center gap-1">
          <XCircle size={12} /> Not Found
        </span>
      )}
    </div>
  );
}
