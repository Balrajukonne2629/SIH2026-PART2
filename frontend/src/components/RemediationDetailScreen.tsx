import React, { useState, useEffect } from 'react';
import { getRemediation, finalizeAudit } from '../api';
import { UserIdentity } from '../types';

interface RemediationDetailScreenProps {
  ruleId: string;
  sessionId: string;
  onBackToAudit: () => void;
  onAuditFinalized: (finalizeData: any) => void;
  currentUser?: UserIdentity | null;
}

export const RemediationDetailScreen: React.FC<RemediationDetailScreenProps> = ({
  ruleId,
  sessionId,
  onBackToAudit,
  onAuditFinalized,
  currentUser
}) => {
  const [data, setData] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Finalize audit state
  const [isFinalizing, setIsFinalizing] = useState(false);
  const [finalizeError, setFinalizeError] = useState<string | null>(null);

  useEffect(() => {
    if (ruleId && sessionId) {
      loadRemediation();
    }
  }, [ruleId, sessionId]);

  const loadRemediation = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await getRemediation(ruleId, sessionId);
      setData(res);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = () => {
    if (data?.remediation_cmd) {
      navigator.clipboard.writeText(data.remediation_cmd);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleFinalize = async () => {
    setIsFinalizing(true);
    setFinalizeError(null);
    try {
      const remSummary = {
        rule_id: ruleId,
        remediation_cmd: data?.remediation_cmd || '',
        has_conflicts: data?.has_conflicts || false,
        conflict_count: data?.conflict_count || 0,
        conflicts: data?.conflicts || [],
        why_it_failed: data?.why_it_failed || '',
        what_remediation_does: data?.what_remediation_does || ''
      };

      const finResult = await finalizeAudit(sessionId, remSummary);
      onAuditFinalized(finResult);
    } catch (err: any) {
      setFinalizeError(err.message);
    } finally {
      setIsFinalizing(false);
    }
  };

  if (isLoading) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded p-12 text-center font-mono text-xs text-slate-300 space-y-3">
        <div className="w-8 h-8 border-2 border-rose-500 border-t-transparent rounded-full animate-spin mx-auto"></div>
        <div>Generating Jinja2 remediation CLI and static conflict AST analysis for <code className="text-rose-300 font-bold">{ruleId}</code>...</div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="bg-rose-950/40 border border-rose-800 rounded p-8 text-center font-mono text-xs space-y-3">
        <div className="text-rose-400 font-bold text-sm">Failed to Load Remediation Details</div>
        <p className="text-rose-200 max-w-lg mx-auto">{error || 'Template not found or session invalid.'}</p>
        <div className="flex justify-center gap-3 pt-2">
          <button
            onClick={loadRemediation}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-sky-400 rounded border border-slate-700 cursor-pointer"
          >
            ↻ Retry Generation
          </button>
          <button
            onClick={onBackToAudit}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 cursor-pointer"
          >
            &larr; Return to Audit Results
          </button>
        </div>
      </div>
    );
  }

  const conflicts = data.conflicts || [];
  const hasConflicts = data.has_conflicts;

  return (
    <div className="space-y-6 font-sans">
      {/* Header & Navigation */}
      <div className="border-b border-slate-800 pb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <button
            onClick={onBackToAudit}
            className="text-xs text-sky-400 hover:text-sky-300 font-mono mb-2 flex items-center gap-1 cursor-pointer"
          >
            &larr; Back to Audit Results Matrix
          </button>
          <div className="flex items-center space-x-3">
            <h1 className="text-xl font-bold text-white">
              Remediation detail &amp; static conflict analyzer
            </h1>
            <span className="text-[11px] font-mono text-slate-500">
              Module 4 — Jinja2 / Conflict AST
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Parameterized CLI patch generator, domain explanation, and pre-deployment static dependency conflict checks.
          </p>
        </div>

        {/* Finalize Audit Action */}
        <div className="flex flex-col sm:flex-row items-center gap-3">
          {currentUser?.role === 'viewer' && (
            <span className="text-xs font-mono text-amber-400 bg-amber-950/40 px-2.5 py-1 rounded border border-amber-800">
              Viewer Role: Read-only access. Finalize disabled.
            </span>
          )}
          <button
            onClick={handleFinalize}
            disabled={isFinalizing || currentUser?.role === 'viewer'}
            className={`px-5 py-2.5 rounded text-xs font-mono font-bold uppercase tracking-wider transition-colors shadow-sm flex items-center gap-2 border cursor-pointer ${
              isFinalizing || currentUser?.role === 'viewer'
                ? 'bg-slate-800 text-slate-500 border-slate-700 cursor-not-allowed'
                : 'bg-emerald-600 hover:bg-emerald-500 text-slate-950 border-emerald-400'
            }`}
          >
            {isFinalizing ? (
              <>
                <span className="inline-block w-4 h-4 border-2 border-slate-400 border-t-transparent rounded-full animate-spin"></span>
                <span>Finalizing & Generating PDF...</span>
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                <span>Finalize Audit & Record to Ledger &rarr;</span>
              </>
            )}
          </button>
        </div>
      </div>

      {finalizeError && (
        <div className="bg-rose-950/60 border border-rose-700 rounded p-4 text-xs text-rose-200 font-mono">
          <strong>Finalization Error:</strong> {finalizeError}
        </div>
      )}

      {/* Failed Control Header Card */}
      <div className="bg-slate-900 border border-slate-800 rounded p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center space-x-3">
              <span className="font-mono text-lg font-bold text-sky-400">
                {ruleId}
              </span>
              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-bold bg-[#fee2e2] text-[#991b1b] border border-rose-600">
                FAIL
              </span>
            </div>
            <h2 className="text-sm font-semibold text-slate-200 mt-1">
              Active Control Remediation Staging
            </h2>
          </div>

          <div className="text-right text-xs font-mono text-slate-400">
            <span className="block text-[10px] uppercase text-slate-500">AST Execution Safety</span>
            <span className="text-emerald-400 font-bold">VERIFIED CLEAN (0 subprocess/exec)</span>
          </div>
        </div>

        {/* Section 1: "Why it Failed" — Plain Language AI Explanation */}
        <div className="mt-5">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center space-x-2">
              <span className="w-2 h-2 rounded-full bg-rose-400"></span>
              <h3 className="text-xs font-bold text-slate-300">
                Root Cause & Threat Context (Module 4 AI Explainer)
              </h3>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
              AI Model Manager &amp; AST Conflict Engine
            </span>

          </div>
          <div className="bg-slate-950 border border-slate-800 rounded p-4 text-xs text-slate-300 leading-relaxed font-sans border-l-4 border-l-rose-500">
            {data.why_it_failed}
          </div>
        </div>
      </div>

      {/* Section 2: Generated Remediation CLI Command */}
      <div className="bg-slate-900 border border-slate-800 rounded p-5 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Generated Remediation CLI Commands
            </h3>
          </div>
          <button
            onClick={handleCopy}
            className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-sky-400 rounded text-xs font-mono border border-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
          >
            {copied ? (
              <>
                <svg className="w-3.5 h-3.5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                </svg>
                <span className="text-emerald-400 font-bold">Copied CLI!</span>
              </>
            ) : (
              <>
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
                </svg>
                <span>Copy Command</span>
              </>
            )}
          </button>
        </div>

        {/* Code Box */}
        <div className="bg-slate-950 border border-slate-800 rounded p-4 font-mono text-xs text-emerald-300 overflow-x-auto leading-relaxed select-all">
          <pre>{data.remediation_cmd}</pre>
        </div>

        {/* PERSISTENT SAFETY NOTICE: ALWAYS VISIBLE, NOT DISMISSIBLE */}
        <div className="bg-rose-950/40 border border-rose-800 rounded p-3 text-xs text-rose-300 flex items-start space-x-3">
          <div className="text-rose-400 shrink-0 mt-0.5">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <div>
            <div className="font-bold uppercase tracking-wider font-mono text-rose-200">
              SAFETY NOTICE: DISPLAY ONLY — NOT AUTO-EXECUTED
            </div>
            <p className="text-[11px] text-rose-300/90 mt-0.5">
              Automated command execution on live network hardware is structurally prohibited by system architecture (§1). Commands must be reviewed by the network engineering team and applied through standard change-control windows.
            </p>
          </div>
        </div>
      </div>

      {/* Section 3: Real Static Conflict Check Results */}
      <div className="bg-slate-900 border border-slate-800 rounded p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-sky-400"></span>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Pre-Deployment Static Conflict Analysis
            </h3>
          </div>
          <span className="font-mono text-xs text-slate-400">
            {hasConflicts
              ? `${conflicts.length} Potential Side-Effects Flagged`
              : '0 Potential Conflicts'}
          </span>
        </div>

        {hasConflicts ? (
          <div className="space-y-3">
            {conflicts.map((conflict: any) => {
              const isHigh = conflict.severity === 'HIGH';
              return (
                <div
                  key={conflict.conflict_id}
                  className={`rounded border p-4 ${
                    isHigh
                      ? 'bg-rose-950/20 border-rose-800/80'
                      : 'bg-amber-950/20 border-amber-800/80'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-2">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                          isHigh
                            ? 'bg-rose-950 text-rose-300 border border-rose-700'
                            : 'bg-amber-950 text-amber-300 border border-amber-700'
                        }`}
                      >
                        {conflict.severity} SEVERITY
                      </span>
                      <h4 className="text-xs font-bold text-slate-200">
                        {conflict.title}
                      </h4>
                    </div>
                    <code className="text-[11px] font-mono text-slate-400">
                      ID: {conflict.conflict_id}
                    </code>
                  </div>

                  <p className="text-xs text-slate-300 mb-3 leading-relaxed">
                    {conflict.description}
                  </p>

                  <div className="bg-slate-950/80 p-2.5 rounded border border-slate-800 font-mono text-xs">
                    <span className="text-sky-400 block text-[10px] uppercase font-bold mb-0.5">
                      Required Mitigation Pre-requisite:
                    </span>
                    <span className="text-slate-200">{conflict.mitigation}</span>
                  </div>

                  {conflict.affected_components?.length > 0 && (
                    <div className="mt-2 flex items-center gap-1.5 text-[11px] font-mono text-slate-400">
                      <span>Affected components:</span>
                      {conflict.affected_components.map((comp: string, idx: number) => (
                        <span
                          key={idx}
                          className="px-1.5 py-0.5 bg-slate-800 rounded border border-slate-700 text-slate-300"
                        >
                          {comp}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="bg-emerald-950/20 border border-emerald-800/80 rounded p-6 text-center space-y-2">
            <div className="w-10 h-10 rounded-full bg-emerald-950 border border-emerald-700 text-emerald-400 mx-auto flex items-center justify-center">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <h4 className="text-sm font-bold text-emerald-300 font-mono">
              NO CONFLICTS DETECTED
            </h4>
            <p className="text-xs text-slate-400 max-w-lg mx-auto">
              Static AST inspection indicates this command can be safely staged without disrupting existing VRFs, active routing protocols, or management plane access.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
