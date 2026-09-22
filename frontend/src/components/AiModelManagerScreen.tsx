import React, { useState, useEffect, useCallback } from 'react';
import {
  Cpu,
  HardDrive,
  Shield,
  Activity,
  Server,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Zap,
  Sliders,
  Sparkles,
  Info,
  Radio,
  Layers,
  ArrowRight
} from 'lucide-react';
import { getModelStatus, setModelMode } from '../api';
import { UserIdentity, ModelStatus, ModelMode } from '../types';

interface AiModelManagerScreenProps {
  currentUser?: UserIdentity | null;
  onNavigateToReview?: () => void;
}

export const AiModelManagerScreen: React.FC<AiModelManagerScreenProps> = ({
  currentUser,
  onNavigateToReview
}) => {
  const [status, setStatus] = useState<ModelStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Mode modification state
  const [selectedMode, setSelectedMode] = useState<ModelMode>('auto');
  const [selectedOverrideModel, setSelectedOverrideModel] = useState<string>('llama3.2:1b');
  const [isUpdating, setIsUpdating] = useState<boolean>(false);
  const [updateMessage, setUpdateMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const isReviewerApprover = currentUser?.role === 'reviewer' && currentUser?.is_authorized_approver === true;

  const fetchStatus = useCallback(async (isManualRefresh = false) => {
    if (isManualRefresh) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError(null);
    try {
      const data = await getModelStatus();
      setStatus(data);
      setSelectedMode(data.mode);
      if (data.override_model) {
        setSelectedOverrideModel(data.override_model);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to fetch AI Model Manager runtime status.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  const handleApplyMode = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!isReviewerApprover) {
      setUpdateMessage({
        type: 'error',
        text: 'Action Denied: You must possess the Security Reviewer role with Authorized Approver clearance to alter model operational modes.'
      });
      return;
    }

    setIsUpdating(true);
    setUpdateMessage(null);

    try {
      const payload = {
        mode: selectedMode,
        override_model: selectedMode === 'override' ? selectedOverrideModel : null
      };
      const res = await setModelMode(payload);
      setStatus(res);
      setUpdateMessage({
        type: 'success',
        text: res.message || `Operating mode successfully updated to '${res.mode}'.`
      });
    } catch (err: any) {
      setUpdateMessage({
        type: 'error',
        text: err.message || 'Failed to update model operational mode.'
      });
    } finally {
      setIsUpdating(false);
    }
  };

  const getModeBadgeColor = (mode: ModelMode) => {
    switch (mode) {
      case 'auto':
        return 'bg-sky-950/80 text-sky-300 border-sky-700/80';
      case 'fast':
        // indigo: performance choice — outside emerald (trust) and amber (warning) families
        return 'bg-indigo-950/80 text-indigo-300 border-indigo-700/80';
      case 'quality':
        // teal: depth/precision — informational, not alarming, not amber
        return 'bg-teal-950/80 text-teal-300 border-teal-700/80';
      case 'override':
        // amber: manual admin override is genuinely cautionary
        return 'bg-amber-950/80 text-amber-300 border-amber-700/80';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  // Compute RAM metrics safely
  const totalRam = status?.hardware_profile?.total_ram_gb ?? 16;
  const availRam = status?.hardware_profile?.available_ram_gb ?? 8;
  const usedRam = Math.max(0, totalRam - availRam);
  const ramPercent = Math.min(100, Math.round((usedRam / (totalRam || 1)) * 100));

  return (
    <div className="space-y-6 font-sans pb-12">
      {/* Top Breadcrumb & Screen Header */}
      <div className="border-b border-slate-800 pb-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs text-sky-400 mb-1">
            <Radio className="w-3.5 h-3.5 animate-pulse text-emerald-400" />
            <span>SOC SUBSYSTEM 06</span>
            <span className="text-slate-600">/</span>
            <span className="text-slate-400">Runtime Control</span>
            <span className="text-slate-600">/</span>
            <span>Air-gapped local inference</span>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <Sliders className="w-5 h-5 text-sky-400" />
              AI Model Manager &amp; Hardware Runtime
            </h1>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-sky-300 border border-slate-700 font-semibold">
              v4.2 LOCAL ENGINE
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Hardware-aware LLM routing, bounded latency enforcement, Ollama daemon loopback isolation,
            and automatic deterministic fallback management.
          </p>
        </div>

        {/* Global Action / Refresh Controls */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchStatus(true)}
            disabled={refreshing || loading}
            aria-label="Refresh telemetry and hardware status"
            className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white rounded border border-slate-700 text-xs font-mono flex items-center gap-2 transition-colors cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-sky-400 ${refreshing ? 'animate-spin' : ''}`} />
            <span>{refreshing ? 'Polling...' : 'Refresh Telemetry'}</span>
          </button>
        </div>
      </div>

      {/* Global Error Banner */}
      {error && (
        <div
          role="alert"
          className="bg-rose-950/50 border border-rose-800 rounded p-4 flex items-start gap-3 text-xs font-mono text-rose-200"
        >
          <AlertTriangle className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <div className="font-bold text-rose-300 mb-1">TELEMETRY PROBE FAULT</div>
            <p>{error}</p>
          </div>
          <button
            onClick={() => fetchStatus(false)}
            className="px-2.5 py-1 bg-rose-900/60 hover:bg-rose-900 text-rose-200 rounded border border-rose-700 text-[11px] cursor-pointer"
          >
            Retry Probe
          </button>
        </div>
      )}

      {/* Primary Connectivity & Fallback Banner */}
      {status && (
        <div
          className={`rounded-lg border p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-colors ${
            status.ollama_alive
              ? 'bg-slate-900/90 border-slate-800'
              : 'bg-amber-950/30 border-amber-800/80'
          }`}
        >
          <div className="flex items-start sm:items-center gap-3">
            <div
              className={`p-2 rounded-md ${
                status.ollama_alive
                  ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800'
                  : 'bg-amber-950 text-amber-400 border border-amber-800'
              }`}
            >
              {status.ollama_alive ? (
                <Server className="w-5 h-5" />
              ) : (
                <AlertTriangle className="w-5 h-5" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-bold text-sm text-white">
                  {status.ollama_alive
                    ? 'Local Ollama Daemon Online'
                    : 'Local Ollama Daemon Offline / Loopback Unreachable'}
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold tracking-wider ${
                    status.ollama_alive
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                      : 'bg-rose-950 text-rose-300 border border-rose-700 animate-pulse'
                  }`}
                >
                  {status.ollama_alive ? 'LOOPBACK VERIFIED' : 'FALLBACK ACTIVE'}
                </span>
              </div>
              <div className="text-xs text-slate-400 font-mono mt-0.5">
                Target Endpoint: <span className="text-slate-200">http://127.0.0.1:11434</span>
                <span className="mx-2 text-slate-600">•</span>
                SSRF Guard: <span className="text-emerald-400">Strict RFC-1918/Loopback Pinned</span>
                <span className="mx-2 text-slate-600">•</span>
                Cloud Egress: <span className="text-emerald-400">0 KB (Air-gapped)</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 self-start sm:self-center font-mono text-xs">
            {status.fallback_active ? (
              <div className="px-3 py-1.5 rounded bg-amber-950/80 border border-amber-700 text-amber-300 text-right">
                <div className="text-[10px] text-amber-400 uppercase font-semibold">Engine Operating State</div>
                <div className="font-bold">
                  {status.fallback_reason === 'ollama_offline'
                    ? 'Deterministic Engine Fallback'
                    : 'Deterministic Only Mode'}
                </div>
              </div>
            ) : (
              <div className="px-3 py-1.5 rounded bg-slate-800/80 border border-slate-700 text-emerald-400 text-right">
                <div className="text-[10px] text-slate-400 uppercase font-semibold">Inference Latency</div>
                <div className="font-bold">Sub-60s Bounded Profile</div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Operational Telemetry Strip — 2-column layout, no repeated icon-box pattern */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Left: Mode + Model (stacked, primary info) */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
          <div className="flex items-start justify-between">
            <div>
              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1">Operating mode</div>
              <div className="flex items-center gap-2">
                <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold uppercase border ${getModeBadgeColor(status?.mode || 'auto')}`}>
                  {status?.mode || 'AUTO'}
                </span>
                <span className="text-[11px] text-slate-400 font-mono">
                  configured: <span className="text-slate-300">{status?.configured_mode?.toUpperCase() || 'AUTO'}</span>
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-1.5 max-w-xs">
                {status?.mode === 'auto' && 'Adaptive routing based on workload complexity and host compute.'}
                {status?.mode === 'fast' && 'Pinned to ultra-low latency model (llama3.2:1b, 60s timeout).'}
                {status?.mode === 'quality' && 'Pinned to deep reasoning model (qwen2.5:7b, 180s timeout).'}
                {status?.mode === 'override' && `Manual administrator override: ${status.override_model || 'Custom'}.`}
                {!status && 'Loading operational mode...'}
              </p>
            </div>
            <Activity className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
          </div>

          <div className="border-t border-slate-800 pt-3">
            <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1">
              {status?.ollama_alive ? 'Active inference model' : 'Active execution path'}
            </div>
            <div className="text-sm font-bold font-mono text-white truncate" title={status?.effective_model}>
              {loading ? 'Probing...' : !status?.ollama_alive ? 'Deterministic Fallback Engine' : status?.effective_model || 'deterministic_only'}
            </div>
            <div className="flex items-center justify-between mt-1 text-[10px] font-mono">
              <span className="text-slate-500">{status?.effective_model || '—'}</span>
              <span className={status?.ollama_alive ? 'text-emerald-400' : 'text-amber-400 font-bold'}>
                {status?.ollama_alive ? 'ONLINE' : 'FALLBACK'}
              </span>
            </div>
          </div>
        </div>

        {/* Right: Hardware vitals (memory bar + acceleration inline) */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1">Host memory</div>
              <div className="flex items-baseline gap-1.5 text-sm font-bold font-mono text-white">
                <span>{availRam.toFixed(1)} GB</span>
                <span className="text-xs text-slate-400 font-normal">avail / {totalRam.toFixed(1)} GB total</span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all ${
                    ramPercent > 85 ? 'bg-rose-500' : ramPercent > 65 ? 'bg-amber-500' : 'bg-emerald-500'
                  }`}
                  style={{ width: `${ramPercent}%` }}
                />
              </div>
              <div className="flex justify-between text-[10px] font-mono text-slate-500 mt-1">
                <span>CPU cores: <span className="text-slate-300">{status?.hardware_profile?.cpu_cores ?? '—'}</span></span>
                <span>threads: <span className="text-slate-300">{status?.hardware_profile?.cpu_threads ?? '—'}</span></span>
              </div>
            </div>
            <HardDrive className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5 ml-3" />
          </div>

          <div className="border-t border-slate-800 pt-3">
            <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1">Acceleration</div>
            <div className="text-sm font-bold font-mono text-white flex items-center gap-2">
              {status?.hardware_profile?.has_gpu ? (
                <span className="text-emerald-400 flex items-center gap-1">
                  <Zap className="w-4 h-4" /> Dedicated GPU
                </span>
              ) : (
                <span className="text-sky-300 flex items-center gap-1">
                  <Cpu className="w-4 h-4 text-slate-400" /> CPU execution
                </span>
              )}
            </div>
            <div className="flex justify-between text-[10px] font-mono mt-1">
              <span className="text-slate-400 truncate">{status?.hardware_profile?.gpu_name || 'Host CPU AVX2 quantized'}</span>
              <span className="text-emerald-400 ml-2 shrink-0">AIR-GAPPED</span>
            </div>
          </div>
        </div>
      </div>

      {/* Interactive Control Panel & Mode Switcher */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-sky-400" />
            <h2 className="text-sm font-bold text-white">
              Runtime operational mode switcher
            </h2>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <span>GOVERNANCE GATE:</span>
            {isReviewerApprover ? (
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold uppercase text-[10px]">
                Authorized Approver Active
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded bg-slate-800 text-amber-400 border border-slate-700 uppercase text-[10px]">
                Read-Only Inspection
              </span>
            )}
          </div>
        </div>

        {/* Access Warning when non-approver */}
        {!isReviewerApprover && (
          <div className="mt-4 p-3 bg-amber-950/40 border border-amber-800/80 rounded flex items-start gap-2.5 text-xs text-amber-200 font-mono">
            <Lock className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
            <div>
              <span className="font-bold text-amber-300 uppercase">OPERATOR ACCESS POLICY: </span>
              Modifying inference modes or forcing manual overrides requires the{' '}
              <strong className="text-white">Reviewer</strong> role with{' '}
              <strong className="text-white">is_authorized_approver: true</strong> clearance.
              Viewers and standard Uploaders may inspect live telemetry but cannot alter runtime configuration.
            </div>
          </div>
        )}

        {/* Mode Form */}
        <form onSubmit={handleApplyMode} className="mt-5 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {/* Option: AUTO */}
            <button
              type="button"
              disabled={!isReviewerApprover || isUpdating}
              onClick={() => setSelectedMode('auto')}
              className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer disabled:cursor-not-allowed ${
                selectedMode === 'auto'
                  ? 'bg-sky-950/60 border-sky-500 ring-1 ring-sky-500'
                  : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 text-slate-300'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-mono text-xs font-bold text-sky-400 uppercase">AUTO (Adaptive)</span>
                {selectedMode === 'auto' && <CheckCircle2 className="w-4 h-4 text-sky-400" />}
              </div>
              <p className="text-[11px] text-slate-400">
                Workload-aware routing. Uses 1.3B for rapid line mapping, 7B for remediation reasoning.
              </p>
              <div className="mt-2 text-[10px] font-mono text-slate-500">
                Recommended for standard SOC operations.
              </div>
            </button>

            {/* Option: FAST */}
            <button
              type="button"
              disabled={!isReviewerApprover || isUpdating}
              onClick={() => setSelectedMode('fast')}
              className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer disabled:cursor-not-allowed ${
                selectedMode === 'fast'
                  ? 'bg-indigo-950/60 border-indigo-500 ring-1 ring-indigo-500'
                  : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 text-slate-300'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-mono text-xs font-bold text-indigo-400 uppercase">FAST (1.3B)</span>
                {selectedMode === 'fast' && <CheckCircle2 className="w-4 h-4 text-indigo-400" />}
              </div>
              <p className="text-[11px] text-slate-400">
                Pins all inference tasks to llama3.2:1b. Minimal RAM overhead (~1.5GB) and ~6s response.
              </p>
              <div className="mt-2 text-[10px] font-mono text-slate-500">
                Ideal for memory-constrained edge appliances.
              </div>
            </button>

            {/* Option: QUALITY */}
            <button
              type="button"
              disabled={!isReviewerApprover || isUpdating}
              onClick={() => setSelectedMode('quality')}
              className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer disabled:cursor-not-allowed ${
                selectedMode === 'quality'
                  ? 'bg-teal-950/60 border-teal-500 ring-1 ring-teal-500'
                  : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 text-slate-300'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-mono text-xs font-bold text-teal-400 uppercase">QUALITY (7.6B)</span>
                {selectedMode === 'quality' && <CheckCircle2 className="w-4 h-4 text-teal-400" />}
              </div>
              <p className="text-[11px] text-slate-400">
                Pins inference to qwen2.5:7b-instruct. High fidelity syntax reasoning and conflict analysis.
              </p>
              <div className="mt-2 text-[10px] font-mono text-slate-500">
                Requires &gt;8GB RAM (180s timeout window).
              </div>
            </button>

            {/* Option: OVERRIDE */}
            <button
              type="button"
              disabled={!isReviewerApprover || isUpdating}
              onClick={() => setSelectedMode('override')}
              className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer disabled:cursor-not-allowed ${
                selectedMode === 'override'
                  ? 'bg-amber-950/60 border-amber-500 ring-1 ring-amber-500'
                  : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 text-slate-300'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-mono text-xs font-bold text-amber-400 uppercase">MANUAL OVERRIDE</span>
                {selectedMode === 'override' && <CheckCircle2 className="w-4 h-4 text-amber-400" />}
              </div>
              <p className="text-[11px] text-slate-400">
                Explicit manual binding to a verified model from the air-gapped cryptographic allowlist.
              </p>
              <div className="mt-2 text-[10px] font-mono text-slate-500">
                Enables deterministic-only pinning.
              </div>
            </button>
          </div>

          {/* Conditional Override Selector */}
          {selectedMode === 'override' && (
            <div className="p-4 bg-slate-950 border border-amber-800/60 rounded-lg space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono text-amber-300 font-bold">
                <Shield className="w-4 h-4 text-amber-400" />
                <span>SELECT ALLOWLISTED TARGET MODEL:</span>
              </div>
              <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
                <select
                  aria-label="Allowlisted target model selection"
                  disabled={!isReviewerApprover || isUpdating}
                  value={selectedOverrideModel}
                  onChange={(e) => setSelectedOverrideModel(e.target.value)}
                  className="bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-amber-500 cursor-pointer w-full sm:w-80"
                >
                  {(status?.available_models || ['llama3.2:1b', 'qwen2.5:7b-instruct-q4_K_M', 'deterministic_only']).map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </select>
                <div className="text-[11px] text-slate-400 font-mono">
                  {selectedOverrideModel === 'deterministic_only' && (
                    <span className="text-emerald-400">
                      Zero-AI Mode: Completely bypasses Ollama. Deterministic rule evaluation only.
                    </span>
                  )}
                  {selectedOverrideModel === 'llama3.2:1b' && (
                    <span className="text-sky-400">
                      Lightweight 1.3B: Safe on low-RAM hosts. Bounded to 60s latency.
                    </span>
                  )}
                  {selectedOverrideModel.includes('qwen') && (
                    <span className="text-purple-400">
                      Instruction 7.6B: Deep multi-clause conflict justification.
                    </span>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Feedback Banner */}
          {updateMessage && (
            <div
              role="status"
              className={`p-3 rounded text-xs font-mono flex items-center gap-2 ${
                updateMessage.type === 'success'
                  ? 'bg-emerald-950/60 border border-emerald-800 text-emerald-200'
                  : 'bg-rose-950/60 border border-rose-800 text-rose-200'
              }`}
            >
              {updateMessage.type === 'success' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
              )}
              <span>{updateMessage.text}</span>
            </div>
          )}

          {/* Action Row */}
          {isReviewerApprover && (
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="submit"
                disabled={isUpdating}
                className="px-5 py-2.5 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-mono font-bold uppercase tracking-wider transition-colors shadow-sm flex items-center gap-2 border border-sky-400 cursor-pointer disabled:opacity-50"
              >
                {isUpdating ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                    <span>Applying Configuration...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-3.5 h-3.5" />
                    <span>Apply Runtime Configuration</span>
                  </>
                )}
              </button>
            </div>
          )}
        </form>
      </div>

      {/* Workload Intelligence & Routing Matrix */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-sky-400" />
            <h2 className="text-sm font-bold text-white">
              Workload routing &amp; latency guardrail matrix
            </h2>
          </div>
          <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
            ARCHITECTURE SPEC §4.2
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px] bg-slate-950/40">
                <th className="py-2.5 px-3">Workload Subsystem</th>
                <th className="py-2.5 px-3">Active Routing</th>
                <th className="py-2.5 px-3">Primary Model</th>
                <th className="py-2.5 px-3">Parameter Scale</th>
                <th className="py-2.5 px-3">Bounded Timeout</th>
                <th className="py-2.5 px-3">Benchmark Baseline Latency (Audit)</th>

                <th className="py-2.5 px-3">Authority Level</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {/* Row 1: Line Mapping */}
              <tr className="hover:bg-slate-800/30 transition-colors">
                <td className="py-3 px-3 font-semibold text-white">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                    <span>Unmapped Line Mapping</span>
                  </div>
                  <div className="text-[10px] text-slate-500 font-normal">CSM Step 2 Syntax Classification</div>
                </td>
                <td className="py-3 px-3">
                  <span className="px-2 py-0.5 rounded text-[10px] bg-sky-950 text-sky-300 border border-sky-800">
                    {status?.mode === 'quality' ? 'Quality Pinned' : 'Fast Path'}
                  </span>
                </td>
                <td className="py-3 px-3 text-emerald-400 font-bold">
                  {status?.mode === 'quality' ? 'qwen2.5:7b-instruct' : 'llama3.2:1b'}
                </td>
                <td className="py-3 px-3">{status?.mode === 'quality' ? '7.6 Billion' : '1.3 Billion'}</td>
                <td className="py-3 px-3 text-amber-400 font-semibold">{status?.mode === 'quality' ? '180s' : '60s'}</td>
                <td className="py-3 px-3 text-slate-300">~6.2 sec / 12.9 tok/s</td>
                <td className="py-3 px-3">
                  <span className="text-amber-400 text-[10px] uppercase font-bold">
                    Advisory Only (Human Gate)
                  </span>
                </td>
              </tr>

              {/* Row 2: Remediation Conflict Analysis */}
              <tr className="hover:bg-slate-800/30 transition-colors">
                <td className="py-3 px-3 font-semibold text-white">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-purple-400"></span>
                    <span>Remediation Conflict Reasoning</span>
                  </div>
                  <div className="text-[10px] text-slate-500 font-normal">CSM Step 4 CLI Side-Effect Proof</div>
                </td>
                <td className="py-3 px-3">
                  <span className="px-2 py-0.5 rounded text-[10px] bg-purple-950 text-purple-300 border border-purple-800">
                    {status?.mode === 'fast' ? 'Fast Forced' : 'Deep Reasoning'}
                  </span>
                </td>
                <td className="py-3 px-3 text-purple-400 font-bold">
                  {status?.mode === 'fast' ? 'llama3.2:1b' : 'qwen2.5:7b-instruct'}
                </td>
                <td className="py-3 px-3">{status?.mode === 'fast' ? '1.3 Billion' : '7.6 Billion'}</td>
                <td className="py-3 px-3 text-amber-400 font-semibold">{status?.mode === 'fast' ? '60s' : '180s'}</td>
                <td className="py-3 px-3 text-slate-300">~42.3 sec / 2.7 tok/s</td>
                <td className="py-3 px-3">
                  <span className="text-amber-400 text-[10px] uppercase font-bold">
                    Explanation Only (Display)
                  </span>
                </td>
              </tr>

              {/* Row 3: Deterministic Compliance Engine */}
              <tr className="hover:bg-slate-800/30 transition-colors bg-slate-950/20">
                <td className="py-3 px-3 font-semibold text-white">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-sky-400"></span>
                    <span>Deterministic Compliance Engine</span>
                  </div>
                  <div className="text-[10px] text-slate-500 font-normal">CSM Steps 1, 3, 5 + SHA-256 Ledger</div>
                </td>
                <td className="py-3 px-3">
                  <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-emerald-300 border border-slate-700 font-bold">
                    AUTHORITATIVE
                  </span>
                </td>
                <td className="py-3 px-3 text-sky-400 font-bold">Deterministic Rule AST</td>
                <td className="py-3 px-3">Zero-AI (Deterministic)</td>
                <td className="py-3 px-3 text-emerald-400 font-semibold">Immediate (&lt;10ms)</td>
                <td className="py-3 px-3 text-emerald-400">&lt; 0.01 sec</td>
                <td className="py-3 px-3">
                  <span className="text-emerald-400 text-[10px] uppercase font-bold">
                    Authoritative (100%)
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Hardware Probe Diagnostics Inspector */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-emerald-400" />
            <h2 className="text-sm font-bold text-white">
              Host hardware diagnostics &amp; environment
            </h2>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Probe:{' '}
            <span className={status?.hardware_profile?.probe_error ? 'text-rose-400' : 'text-emerald-400'}>
              {status?.hardware_profile?.probe_error ? 'Warning / fallback profile' : 'Nominal / accurate'}
            </span>
          </span>
        </div>

        {/* 2-column: RAM+CPU left, Acceleration right */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
          {/* Left: Memory + Processor combined */}
          <div className="bg-slate-950 border border-slate-800/80 rounded p-4 space-y-2">
            <div className="text-slate-400 font-bold text-[11px] flex items-center justify-between mb-2">
              <span>RAM &amp; PROCESSOR</span>
              <HardDrive className="w-3.5 h-3.5 text-slate-500" />
            </div>
            <div className="flex justify-between py-1 border-b border-slate-900">
              <span className="text-slate-500">Total RAM:</span>
              <span className="text-white font-semibold">{totalRam.toFixed(2)} GB</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-900">
              <span className="text-slate-500">Available headroom:</span>
              <span className="text-emerald-400 font-semibold">{availRam.toFixed(2)} GB</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-900">
              <span className="text-slate-500">Model memory ceiling:</span>
              <span className="text-sky-400 font-semibold">&lt; 8.0 GB configured</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-900">
              <span className="text-slate-500">Physical cores:</span>
              <span className="text-white font-semibold">{status?.hardware_profile?.cpu_cores ?? 'N/A'}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-900">
              <span className="text-slate-500">Logical threads:</span>
              <span className="text-sky-400 font-semibold">{status?.hardware_profile?.cpu_threads ?? 'N/A'}</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-500">Inference threads:</span>
              <span className="text-emerald-400 font-semibold">Max 4 parallel</span>
            </div>
          </div>

          {/* Right: Acceleration */}
          <div className="bg-slate-950 border border-slate-800/80 rounded p-4 space-y-2">
            <div className="text-slate-400 font-bold text-[11px] flex items-center justify-between mb-2">
              <span>ACCELERATION SUBSYSTEM</span>
              <Zap className="w-3.5 h-3.5 text-slate-500" />
            </div>
            <div className="flex justify-between py-1 border-b border-slate-900">
              <span className="text-slate-500">Acceleration mode:</span>
              <span className="text-white font-semibold">
                {status?.hardware_profile?.has_gpu ? 'Dedicated / CUDA' : 'CPU AVX2 quantized'}
              </span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-900">
              <span className="text-slate-500">Dedicated VRAM:</span>
              <span className="text-slate-300 font-semibold">
                {status?.hardware_profile?.vram_gb ? `${status.hardware_profile.vram_gb} GB` : 'Shared system RAM'}
              </span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-900">
              <span className="text-slate-500">Loopback IPC target:</span>
              <span className="text-emerald-400 font-semibold">&lt; 2 ms</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-900">
              <span className="text-slate-500">Egress:</span>
              <span className="text-emerald-400 font-semibold">AIR-GAPPED (0 KB)</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-500">Network restriction:</span>
              <span className="text-sky-400 font-semibold">Local only</span>
            </div>
          </div>
        </div>
      </div>

      {/* Security Principles & Air-Gap Compliance Assurance Card */}
      <div className="bg-slate-950 border border-slate-800 rounded-lg p-5 font-mono text-xs">
        <div className="flex items-center gap-2 text-slate-300 font-bold mb-3">
          <Shield className="w-4 h-4 text-sky-400" />
          <span>Air-gapped compliance assurances &amp; NTRO boundary rules</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-slate-400">
          <div className="border border-slate-800/80 rounded p-3 bg-slate-900/30">
            <div className="text-white font-semibold mb-1 flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              Zero External Ingestion
            </div>
            <p className="text-[11px] text-slate-400">
              Inference runs strictly via local loopback. No configuration snippets or IP addresses ever traverse external networks.
            </p>
          </div>
          <div className="border border-slate-800/80 rounded p-3 bg-slate-900/30">
            <div className="text-white font-semibold mb-1 flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-sky-400"></span>
              Deterministic Rule Authority
            </div>
            <p className="text-[11px] text-slate-400">
              AI suggestions require human reviewer approval before mapping. AI has 0% authority over Pass/Fail audit decisions.
            </p>
          </div>
          <div className="border border-slate-800/80 rounded p-3 bg-slate-900/30">
            <div className="text-white font-semibold mb-1 flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
              Zero Device Push Capability
            </div>
            <p className="text-[11px] text-slate-400">
              Remediation scripts are purely informational for operator review. The engine contains zero network execution primitives.
            </p>
          </div>
        </div>

        {onNavigateToReview && (
          <div className="mt-4 pt-3 border-t border-slate-900 flex justify-end">
            <button
              onClick={onNavigateToReview}
              className="text-sky-400 hover:text-sky-300 flex items-center gap-1 cursor-pointer transition-colors text-xs"
            >
              <span>View Unmapped AI Suggestions Queue</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default AiModelManagerScreen;
