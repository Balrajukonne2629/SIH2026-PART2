import React, { useState, useEffect } from 'react';
import { getLedger, verifyLedger, verifyReport, getReportDownloadUrl } from '../api';

export const AuditLogReportScreen: React.FC = () => {
  const [entries, setEntries] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [expandedEntries, setExpandedEntries] = useState<Record<string, boolean>>({});
  
  // Chain Verification State
  const [isVerifyingChain, setIsVerifyingChain] = useState(false);
  const [chainResult, setChainResult] = useState<{
    valid: boolean;
    message: string;
    broken_entry_index?: number;
  } | null>(null);

  // Per-entry PDF Verification State
  const [verifyingPdfMap, setVerifyingPdfMap] = useState<Record<string, boolean>>({});
  const [pdfVerifyResults, setPdfVerifyResults] = useState<Record<string, { valid: boolean; message: string }>>({});

  useEffect(() => {
    loadLedger();
  }, []);

  const loadLedger = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await getLedger();
      setEntries(data || []);
      // auto-expand latest entry if present
      if (data && data.length > 0) {
        setExpandedEntries({ [data[data.length - 1].entry_id]: true });
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const toggleExpand = (id: string) => {
    setExpandedEntries((prev) => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  // Real backend check: GET /api/ledger/verify
  const handleVerifyChain = async () => {
    setIsVerifyingChain(true);
    try {
      const res = await verifyLedger();
      setChainResult(res);
    } catch (err: any) {
      setChainResult({ valid: false, message: `Verification check error: ${err.message}` });
    } finally {
      setIsVerifyingChain(false);
    }
  };

  // Real backend check: GET /api/report/{entry_id}/verify
  const handleVerifyPdf = async (entryId: string) => {
    setVerifyingPdfMap((prev) => ({ ...prev, [entryId]: true }));
    try {
      const res = await verifyReport(entryId);
      setPdfVerifyResults((prev) => ({
        ...prev,
        [entryId]: { valid: res.valid, message: res.message }
      }));
    } catch (err: any) {
      setPdfVerifyResults((prev) => ({
        ...prev,
        [entryId]: { valid: false, message: err.message }
      }));
    } finally {
      setVerifyingPdfMap((prev) => ({ ...prev, [entryId]: false }));
    }
  };

  // Trigger browser download via GET /api/report/{entry_id}/download
  const handleDownloadPdf = (entryId: string) => {
    const downloadUrl = getReportDownloadUrl(entryId);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = `compliance_report_${entryId}.pdf`;
    link.target = '_blank';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Header & Verification Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center space-x-3">
              <span className="inline-block w-2.5 h-2.5 rounded-full bg-sky-500"></span>
              <h1 className="text-xl font-bold text-white uppercase tracking-wide">
                Cryptographic Audit Ledger & Compliance Reports
              </h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                MODULE 5 — NON-REPUDIATION
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Append-only SHA-256 hash-chained compliance registry (<code className="font-mono text-slate-300">audit_log.jsonl</code>) and generated PDF certificates.
            </p>
          </div>

          {/* Action & Verification Buttons */}
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={loadLedger}
              className="px-3 py-1.5 rounded text-xs font-mono bg-slate-800 text-slate-300 hover:text-white border border-slate-700 transition-colors cursor-pointer"
            >
              ↻ Reload Ledger
            </button>

            <button
              onClick={handleVerifyChain}
              disabled={isVerifyingChain || entries.length === 0}
              className={`px-4 py-2 rounded text-xs font-mono font-bold uppercase tracking-wider transition-colors shadow-sm flex items-center gap-2 border cursor-pointer ${
                isVerifyingChain
                  ? 'bg-slate-800 text-slate-400 border-slate-700 cursor-not-allowed'
                  : 'bg-sky-600 hover:bg-sky-500 text-white border-sky-400'
              }`}
            >
              {isVerifyingChain ? (
                <>
                  <span className="inline-block w-4 h-4 border-2 border-slate-400 border-t-transparent rounded-full animate-spin"></span>
                  <span>Verifying SHA-256 Hashes...</span>
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                  <span>Verify Chain Integrity</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Live Backend Verification Result Card */}
        {chainResult && (
          <div className="mt-4">
            {chainResult.valid ? (
              <div className="bg-emerald-950/40 border border-emerald-700 rounded p-4 flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-8 h-8 rounded bg-emerald-900 border border-emerald-600 text-emerald-300 flex items-center justify-center">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                  <div>
                    <h4 className="text-xs font-mono font-bold uppercase text-emerald-300">
                      CHAIN INTEGRITY VERIFIED (NON-REPUDIATION PASSED)
                    </h4>
                    <p className="text-xs text-emerald-400/90 mt-0.5 font-mono">
                      {chainResult.message}
                    </p>
                  </div>
                </div>
                <span className="px-2.5 py-1 rounded bg-emerald-900 text-emerald-200 border border-emerald-600 font-mono text-xs font-bold">
                  VALIDATED
                </span>
              </div>
            ) : (
              <div className="bg-rose-950/60 border-2 border-rose-600 rounded p-4 flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-8 h-8 rounded bg-rose-900 border border-rose-500 text-rose-300 flex items-center justify-center">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </div>
                  <div>
                    <h4 className="text-xs font-mono font-bold uppercase text-rose-300">
                      INTEGRITY DIVERGENCE DETECTED — TAMPER ALERT
                    </h4>
                    <p className="text-xs text-rose-300/90 mt-0.5 font-mono">
                      {chainResult.message}
                    </p>
                  </div>
                </div>
                <span className="px-2.5 py-1 rounded bg-rose-900 text-rose-200 border border-rose-500 font-mono text-xs font-bold">
                  TAMPERED
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Main Ledger Content */}
      {isLoading ? (
        <div className="bg-slate-900 border border-slate-800 rounded p-12 text-center font-mono text-xs text-slate-300 space-y-3">
          <div className="w-8 h-8 border-2 border-sky-400 border-t-transparent rounded-full animate-spin mx-auto"></div>
          <div>Reading cryptographic ledger from backend (<code className="text-sky-300">audit_log.jsonl</code>)...</div>
        </div>
      ) : error ? (
        <div className="bg-rose-950/40 border border-rose-800 rounded p-8 text-center font-mono text-xs space-y-3">
          <div className="text-rose-400 font-bold text-sm">Failed to Load Audit Ledger</div>
          <p className="text-rose-200 max-w-lg mx-auto">{error}</p>
          <button
            onClick={loadLedger}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-sky-400 rounded border border-slate-700 cursor-pointer"
          >
            ↻ Retry Ledger Fetch
          </button>
        </div>
      ) : entries.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded p-12 text-center space-y-3">
          <div className="w-12 h-12 rounded bg-slate-800 border border-slate-700 text-slate-400 mx-auto flex items-center justify-center">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <h4 className="text-base font-bold text-slate-200">Audit Ledger Is Currently Empty</h4>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            No compliance audits have been finalized yet. To create an entry in the cryptographic ledger, upload a config in Screen 1 and complete the review loop.
          </p>
        </div>
      ) : (
        /* Chronological Hash-Chained Timeline */
        <div className="space-y-4">
          {entries.map((entry, index) => {
            const isExpanded = expandedEntries[entry.entry_id] || false;
            const isGenesis = entry.prevEntryHash === '0000000000000000000000000000000000000000000000000000000000000000';
            const results = entry.audit_results || {};
            const passCount = Object.values(results).filter((v) => v === 'Pass').length;
            const failCount = Object.values(results).filter((v) => v === 'Fail').length;
            const unknownCount = Object.values(results).filter((v) => v === 'Unknown').length;

            const pdfVerification = pdfVerifyResults[entry.entry_id];
            const isVerifyingPdf = verifyingPdfMap[entry.entry_id];

            return (
              <div key={entry.entry_id} className="relative">
                {/* Vertical Chain Visual Link */}
                {index < entries.length - 1 && (
                  <div className="absolute left-8 top-full h-4 w-0.5 bg-slate-700 z-0 flex items-center justify-center">
                    <div className="w-2.5 h-2.5 rounded-full bg-sky-500/80 border border-slate-900"></div>
                  </div>
                )}

                <div className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded transition-all z-10 relative">
                  {/* Entry Summary Bar */}
                  <div className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="flex items-start md:items-center space-x-3">
                      <div
                        className={`w-9 h-9 rounded flex items-center justify-center font-mono text-xs font-bold shrink-0 ${
                          isGenesis
                            ? 'bg-slate-800 text-slate-300 border border-slate-700'
                            : 'bg-sky-950 text-sky-400 border border-sky-800'
                        }`}
                      >
                        #{(index + 1).toString().padStart(2, '0')}
                      </div>

                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-slate-100">
                            {entry.entry_id}
                          </span>
                          {isGenesis && (
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                              GENESIS BLOCK
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-3 text-xs text-slate-400 mt-1 font-mono">
                          <span>DEVICE: <strong className="text-slate-200">{entry.device_hostname}</strong></span>
                          <span className="text-slate-600">•</span>
                          <span>{entry.timestamp}</span>
                        </div>
                      </div>
                    </div>

                    {/* Badges & Actions */}
                    <div className="flex flex-wrap items-center gap-3">
                      <div className="flex items-center space-x-1.5 font-mono text-xs">
                        <span className="px-2 py-0.5 rounded bg-[#dcfce7] text-[#166534] font-bold border border-emerald-600">
                          {passCount} PASS
                        </span>
                        <span className="px-2 py-0.5 rounded bg-[#fee2e2] text-[#991b1b] font-bold border border-rose-600">
                          {failCount} FAIL
                        </span>
                        <span className="px-2 py-0.5 rounded bg-[#fef9c3] text-[#854d0e] font-bold border border-amber-600">
                          {unknownCount} UNKNOWN
                        </span>
                      </div>

                      <button
                        onClick={() => handleVerifyPdf(entry.entry_id)}
                        disabled={isVerifyingPdf}
                        className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono border border-slate-700 transition-colors cursor-pointer"
                      >
                        {isVerifyingPdf ? 'Verifying...' : 'Verify PDF'}
                      </button>

                      <button
                        onClick={() => handleDownloadPdf(entry.entry_id)}
                        className="px-3 py-1.5 bg-sky-950/80 hover:bg-sky-900 text-sky-300 rounded text-xs font-mono font-semibold transition-colors border border-sky-800 flex items-center gap-1.5 cursor-pointer"
                      >
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                        </svg>
                        Download PDF
                      </button>

                      <button
                        onClick={() => toggleExpand(entry.entry_id)}
                        className="p-1.5 text-slate-400 hover:text-white rounded bg-slate-800 border border-slate-700 cursor-pointer"
                      >
                        <svg
                          className={`w-4 h-4 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
                        </svg>
                      </button>
                    </div>
                  </div>

                  {/* Inline PDF Verification Banner */}
                  {pdfVerification && (
                    <div className="px-4 pb-3">
                      <div className={`p-2.5 rounded border text-xs font-mono flex items-center justify-between ${
                        pdfVerification.valid
                          ? 'bg-emerald-950/50 border-emerald-700 text-emerald-300'
                          : 'bg-rose-950/50 border-rose-700 text-rose-300'
                      }`}>
                        <span>{pdfVerification.message}</span>
                        <span className="font-bold uppercase ml-2">
                          {pdfVerification.valid ? 'AUTHENTIC' : 'INVALID'}
                        </span>
                      </div>
                    </div>
                  )}

                  {/* Expanded Cryptographic Detail Panel */}
                  {isExpanded && (
                    <div className="bg-slate-950 border-t border-slate-800 p-4 space-y-3 font-mono text-xs">
                      <div className="flex items-center space-x-2 text-slate-400 font-bold uppercase text-[11px]">
                        <svg className="w-4 h-4 text-sky-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                        </svg>
                        <span>SHA-256 Ledger Node Verification Linkage:</span>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div className="bg-slate-900/80 p-2.5 rounded border border-slate-800">
                          <span className="text-[10px] text-slate-500 uppercase block mb-1">
                            Previous Entry Hash (prevEntryHash):
                          </span>
                          <div className="text-slate-300 break-all select-all text-[11px]">
                            {entry.prevEntryHash}
                          </div>
                        </div>

                        <div className="bg-slate-900/80 p-2.5 rounded border border-slate-800">
                          <span className="text-[10px] text-slate-500 uppercase block mb-1">
                            Current Entry Hash (entryHash):
                          </span>
                          <div className="break-all select-all text-[11px] font-bold text-emerald-400">
                            {entry.entryHash}
                          </div>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800/80">
                        <div>
                          <span>CONFIG SHA-256: </span>
                          <code className="text-sky-300">{(entry.config_file_hash || '').substring(0, 24)}...</code>
                        </div>
                        <div>
                          <span>REMEDIATED RULE: </span>
                          <code className="text-slate-200">{entry.remediation_summary?.rule_id || 'None'}</code>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
