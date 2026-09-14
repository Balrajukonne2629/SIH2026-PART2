import React, { useState, useEffect } from 'react';
import { getAuditResults } from '../api';

interface AuditResultsScreenProps {
  sessionId: string;
  initialResults?: any;
  onReviewAiSuggestions: (unmappedLine: string) => void;
  onViewRemediation: (ruleId: string) => void;
  onNavigateToLedger: () => void;
}

export const AuditResultsScreen: React.FC<AuditResultsScreenProps> = ({
  sessionId,
  initialResults,
  onReviewAiSuggestions,
  onViewRemediation,
  onNavigateToLedger
}) => {
  const [data, setData] = useState<any>(initialResults || null);
  const [isLoading, setIsLoading] = useState(!initialResults);
  const [error, setError] = useState<string | null>(null);

  const [expandedEvidence, setExpandedEvidence] = useState<Record<string, boolean>>({});
  const [filter, setFilter] = useState<'ALL' | 'Pass' | 'Fail' | 'Unknown'>('ALL');

  useEffect(() => {
    if (sessionId) {
      loadResults();
    }
  }, [sessionId]);

  const loadResults = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await getAuditResults(sessionId);
      setData(res);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const toggleExpand = (ruleId: string) => {
    setExpandedEvidence((prev) => ({
      ...prev,
      [ruleId]: !prev[ruleId]
    }));
  };

  if (isLoading) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded p-12 text-center font-mono text-xs text-slate-300 space-y-3">
        <div className="w-8 h-8 border-2 border-sky-400 border-t-transparent rounded-full animate-spin mx-auto"></div>
        <div>Loading deterministic audit results from session <code className="text-sky-400 font-bold">{sessionId}</code>...</div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="bg-rose-950/40 border border-rose-800 rounded p-8 text-center font-mono text-xs space-y-3">
        <div className="text-rose-400 font-bold text-sm">Failed to Load Audit Results</div>
        <p className="text-rose-200 max-w-lg mx-auto">{error || 'Session expired or not found.'}</p>
        <button
          onClick={loadResults}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-sky-400 rounded border border-slate-700 cursor-pointer"
        >
          ↻ Retry Session Fetch
        </button>
      </div>
    );
  }

  const hostname = data.device_hostname || 'unknown';
  const platform = data.platform || 'Cisco IOS-XE';
  const timestamp = data.csm?.source?.parsed_at || new Date().toISOString();
  const configFileHash = data.config_file_hash || '';
  const ruleResults = data.rule_results || {};
  const unmappedLines: string[] = data.unmapped_lines || [];

  // Convert rule_results dict into array for table rendering
  const rulesList = Object.entries(ruleResults).map(([ruleId, details]: [string, any]) => ({
    ruleId,
    focus: details.focus || 'Security Control',
    status: details.status || 'Unknown',
    evidenceFound: details.evidence_found || [],
    description: details.description || ''
  }));

  const passCount = rulesList.filter((r) => r.status === 'Pass').length;
  const failCount = rulesList.filter((r) => r.status === 'Fail').length;
  const unknownCount = rulesList.filter((r) => r.status === 'Unknown').length;
  const totalCount = rulesList.length;

  const filteredRules = rulesList.filter((r) => {
    if (filter === 'ALL') return true;
    return r.status === filter;
  });

  return (
    <div className="space-y-6 font-sans">
      {/* Target Device Audit Header */}
      <div className="bg-slate-900 border border-slate-800 rounded p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center space-x-3">
              <span className="inline-block w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
              <h1 className="text-xl font-bold text-white tracking-wide uppercase font-mono">
                {hostname}
              </h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                {platform}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 font-mono">
              Session ID: <code className="text-sky-300 font-bold">{sessionId}</code>
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={loadResults}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-mono border border-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <span>↻ Refresh Session</span>
            </button>
            <button
              onClick={onNavigateToLedger}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-sky-400 rounded text-xs font-mono border border-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              View Full Ledger & Reports
            </button>
          </div>
        </div>

        {/* Header Metadata Ribbon */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4 text-xs font-mono">
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Audit Timestamp (UTC)</span>
            <span className="text-slate-300 font-semibold">{timestamp}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Config File Hash (SHA-256)</span>
            <span className="text-sky-400 select-all" title={configFileHash}>
              {configFileHash.length > 28
                ? `${configFileHash.substring(0, 20)}...${configFileHash.substring(configFileHash.length - 8)}`
                : configFileHash}
            </span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Evaluation Logic</span>
            <span className="text-emerald-400 font-semibold">Deterministic Modules 2 & 4</span>
          </div>
        </div>
      </div>

      {/* Summary Stat Bar */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Controls */}
        <div
          onClick={() => setFilter('ALL')}
          className={`p-4 rounded border cursor-pointer transition-all ${
            filter === 'ALL'
              ? 'bg-slate-800 border-sky-500 ring-1 ring-sky-500'
              : 'bg-slate-900 border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
            Total Controls
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-1">{totalCount}</div>
          <div className="text-[10px] text-slate-500 mt-1 font-mono">CIS / DISA-STIG / Trusted</div>
        </div>

        {/* Pass Count */}
        <div
          onClick={() => setFilter('Pass')}
          className={`p-4 rounded border cursor-pointer transition-all ${
            filter === 'Pass'
              ? 'bg-emerald-950/80 border-emerald-500 ring-1 ring-emerald-500'
              : 'bg-[#0c1f17] border-emerald-900/60 hover:border-emerald-700'
          }`}
        >
          <div className="text-[11px] font-mono text-emerald-400 uppercase tracking-wider flex items-center justify-between">
            <span>Pass Count</span>
            <span className="inline-block w-2 h-2 rounded-full bg-emerald-500"></span>
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-300 mt-1">{passCount}</div>
          <div className="text-[10px] text-emerald-400/80 mt-1 font-mono">
            {Math.round((passCount / (totalCount || 1)) * 100)}% Compliance
          </div>
        </div>

        {/* Fail Count */}
        <div
          onClick={() => setFilter('Fail')}
          className={`p-4 rounded border cursor-pointer transition-all ${
            filter === 'Fail'
              ? 'bg-rose-950/80 border-rose-500 ring-1 ring-rose-500'
              : 'bg-[#220d0f] border-rose-900/60 hover:border-rose-700'
          }`}
        >
          <div className="text-[11px] font-mono text-rose-400 uppercase tracking-wider flex items-center justify-between">
            <span>Fail Count</span>
            <span className="inline-block w-2 h-2 rounded-full bg-rose-500"></span>
          </div>
          <div className="text-2xl font-bold font-mono text-rose-300 mt-1">{failCount}</div>
          <div className="text-[10px] text-rose-400/80 mt-1 font-mono">
            Requires Remediation
          </div>
        </div>

        {/* Unknown Count */}
        <div
          onClick={() => setFilter('Unknown')}
          className={`p-4 rounded border cursor-pointer transition-all ${
            filter === 'Unknown'
              ? 'bg-amber-950/80 border-amber-500 ring-1 ring-amber-500'
              : 'bg-[#241a08] border-amber-900/60 hover:border-amber-700'
          }`}
        >
          <div className="text-[11px] font-mono text-amber-400 uppercase tracking-wider flex items-center justify-between">
            <span>Unknown Count</span>
            <span className="inline-block w-2 h-2 rounded-full bg-amber-500"></span>
          </div>
          <div className="text-2xl font-bold font-mono text-amber-300 mt-1">{unknownCount}</div>
          <div className="text-[10px] text-amber-400/80 mt-1 font-mono">
            Missing Direct Evidence
          </div>
        </div>
      </div>

      {/* Unmapped Lines Detected Callout Card */}
      {unmappedLines.length > 0 && (
        <div className="bg-amber-950/40 border-2 border-dashed border-amber-600/80 rounded p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-start space-x-3">
            <div className="p-2 rounded bg-amber-900/60 border border-amber-700 text-amber-300">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h4 className="text-sm font-bold text-amber-200">
                  {unmappedLines.length} Unmapped CLI Line{unmappedLines.length > 1 ? 's' : ''} Detected — AI Interpretation Available
                </h4>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-900 text-amber-200 border border-amber-700 font-semibold">
                  PENDING REVIEW
                </span>
              </div>
              <div className="mt-1.5 space-y-1">
                {unmappedLines.map((line, idx) => (
                  <div key={idx} className="text-xs text-amber-300/90 flex flex-wrap items-center gap-1.5">
                    {unmappedLines.length > 1 && (
                      <span className="text-[10px] font-mono text-amber-400/80 font-bold">#{idx + 1}</span>
                    )}
                    <code className="font-mono bg-amber-950 px-1.5 py-0.5 rounded border border-amber-800 text-amber-200 font-semibold">
                      {line}
                    </code>
                    <span className="text-[11px] text-amber-300/70">
                      not matched by deterministic rules. Candidate CSM mapping available.
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <button
            onClick={() => onReviewAiSuggestions(unmappedLines[0])}
            className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-slate-950 rounded text-xs font-bold uppercase tracking-wider transition-colors shrink-0 shadow-sm cursor-pointer"
          >
            Review AI Suggestions &rarr;
          </button>
        </div>
      )}

      {/* Rule Results Table */}
      <div className="bg-slate-900 border border-slate-800 rounded">
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-slate-400"></span>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Evaluated Rule Matrix ({filteredRules.length} of {rulesList.length})
            </h3>
          </div>
          <div className="flex items-center space-x-2 text-xs">
            <span className="text-slate-500 font-mono text-[11px]">FILTER:</span>
            {(['ALL', 'Pass', 'Fail', 'Unknown'] as const).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-2 py-0.5 text-[11px] font-mono rounded cursor-pointer ${
                  filter === f
                    ? 'bg-slate-800 text-sky-400 border border-slate-700'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-800 text-left">
            <thead className="bg-slate-950 font-mono text-[11px] text-slate-400 uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4 font-semibold">Rule ID</th>
                <th className="py-3 px-4 font-semibold">Control Focus</th>
                <th className="py-3 px-4 font-semibold">Verdict</th>
                <th className="py-3 px-4 font-semibold">Evidence Found (CSM Source)</th>
                <th className="py-3 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans text-xs">
              {filteredRules.map((rule) => {
                const isExpanded = expandedEvidence[rule.ruleId] || false;
                const hasEvidence = rule.evidenceFound && rule.evidenceFound.length > 0;

                let statusBadge = null;
                if (rule.status === 'Pass') {
                  statusBadge = (
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#dcfce7] text-[#166534] border border-emerald-600">
                      PASS
                    </span>
                  );
                } else if (rule.status === 'Fail') {
                  statusBadge = (
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#fee2e2] text-[#991b1b] border border-rose-600">
                      FAIL
                    </span>
                  );
                } else {
                  statusBadge = (
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#fef9c3] text-[#854d0e] border border-amber-600">
                      UNKNOWN
                    </span>
                  );
                }

                return (
                  <tr key={rule.ruleId} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-4 font-mono font-bold text-sky-400 whitespace-nowrap">
                      {rule.ruleId}
                    </td>
                    <td className="py-3 px-4 text-slate-200">
                      <div className="font-medium">{rule.focus}</div>
                      {rule.description && (
                        <div className="text-[11px] text-slate-400 mt-0.5">
                          {rule.description}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      {statusBadge}
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-300 max-w-md">
                      {hasEvidence ? (
                        <div>
                          <div className="bg-slate-950 p-1.5 rounded border border-slate-800 text-slate-300 break-all">
                            {isExpanded ? (
                              <ul className="space-y-1">
                                {rule.evidenceFound.map((ev: string, i: number) => (
                                  <li key={i} className="text-slate-300 font-mono">
                                    • {ev}
                                  </li>
                                ))}
                              </ul>
                            ) : (
                              <span>
                                {rule.evidenceFound[0].length > 45
                                  ? `${rule.evidenceFound[0].substring(0, 45)}...`
                                  : rule.evidenceFound[0]}
                                {rule.evidenceFound.length > 1 && (
                                  <span className="text-slate-500 ml-1">
                                    (+{rule.evidenceFound.length - 1} more)
                                  </span>
                                )}
                              </span>
                            )}
                          </div>
                          <button
                            onClick={() => toggleExpand(rule.ruleId)}
                            className="mt-1 text-[10px] text-sky-400 hover:text-sky-300 font-mono cursor-pointer"
                          >
                            {isExpanded ? '[-] Collapse evidence' : '[+] Expand full evidence'}
                          </button>
                        </div>
                      ) : (
                        <span className="text-slate-500 italic">No matching configuration directive detected</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      {rule.status === 'Fail' ? (
                        <button
                          onClick={() => onViewRemediation(rule.ruleId)}
                          className="px-2.5 py-1 rounded bg-rose-950/80 hover:bg-rose-900 text-rose-300 text-xs font-mono font-semibold transition-colors border border-rose-800 flex items-center gap-1 ml-auto cursor-pointer"
                        >
                          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
                          </svg>
                          Remediation &rarr;
                        </button>
                      ) : (
                        <span className="text-[11px] font-mono text-slate-500">
                          {rule.status === 'Pass' ? 'Compliant' : 'Inspect Manually'}
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
