import React, { useState, useEffect } from 'react';
import {
  suggestMapping,
  approveSuggestion,
  getTrustedMappings,
  deleteTrustedMapping,
  getPendingSuggestions,
} from '../api';
import { UserIdentity, TrustedMappingItem, SuggestionQueueItem } from '../types';

interface AiSuggestionReviewScreenProps {
  unmappedLine: string;
  sessionId?: string;
  currentUser?: UserIdentity | null;
  onApprovalCompleted: () => void;
  onBackToAudit: () => void;
}

type TabType = 'active_review' | 'trusted_library' | 'queue';
type VendorFilter = 'all' | 'cisco' | 'juniper';

export const AiSuggestionReviewScreen: React.FC<AiSuggestionReviewScreenProps> = ({
  unmappedLine,
  sessionId,
  currentUser,
  onApprovalCompleted,
  onBackToAudit
}) => {
  // Navigation & Tab state
  const [activeTab, setActiveTab] = useState<TabType>('active_review');
  const [vendorFilter, setVendorFilter] = useState<VendorFilter>('all');

  // Active Review State
  const [currentLine, setCurrentLine] = useState<string>(unmappedLine);
  const [currentVendor, setCurrentVendor] = useState<string>('cisco');
  const [suggestionData, setSuggestionData] = useState<any>(null);
  const [suggestionId, setSuggestionId] = useState<string>('');
  const [isLoadingSuggestion, setIsLoadingSuggestion] = useState(true);
  const [suggestionError, setSuggestionError] = useState<string | null>(null);

  // Reviewer form state
  const [isEditing, setIsEditing] = useState(false);
  const [editTitle, setEditTitle] = useState('');
  const [editField, setEditField] = useState('');
  const [editCondition, setEditCondition] = useState('');

  // Action state
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitSuccess, setSubmitSuccess] = useState<any>(null);

  // Trusted Rule Library state
  const [trustedRules, setTrustedRules] = useState<TrustedMappingItem[]>([]);
  const [isLoadingLibrary, setIsLoadingLibrary] = useState(false);
  const [libraryError, setLibraryError] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // Suggestions Queue state
  const [queueItems, setQueueItems] = useState<SuggestionQueueItem[]>([]);
  const [isLoadingQueue, setIsLoadingQueue] = useState(false);

  // Initial load
  useEffect(() => {
    if (currentLine) {
      loadAiSuggestion(currentLine, currentVendor);
    }
  }, [currentLine, currentVendor]);

  useEffect(() => {
    if (activeTab === 'trusted_library') {
      loadTrustedLibrary();
    } else if (activeTab === 'queue') {
      loadQueue();
    }
  }, [activeTab, vendorFilter]);

  const loadAiSuggestion = async (line: string, vendor: string) => {
    setIsLoadingSuggestion(true);
    setSuggestionError(null);
    setSubmitSuccess(null);
    setIsEditing(false);
    try {
      const res = await suggestMapping(line, vendor);
      setSuggestionId(res.suggestion_id);
      setSuggestionData(res.suggestion);

      const newRule = res.suggestion?.suggested_new_rule;
      if (newRule) {
        setEditTitle(newRule.internalTitle || '');
        setEditField(newRule.csmFieldChecked || '');
        setEditCondition(newRule.condition || '');
      }
    } catch (err: any) {
      setSuggestionError(err.message);
    } finally {
      setIsLoadingSuggestion(false);
    }
  };

  const loadTrustedLibrary = async () => {
    setIsLoadingLibrary(true);
    setLibraryError(null);
    try {
      const rules = await getTrustedMappings(vendorFilter === 'all' ? undefined : vendorFilter);
      setTrustedRules(rules);
    } catch (err: any) {
      setLibraryError(err.message);
    } finally {
      setIsLoadingLibrary(false);
    }
  };

  const loadQueue = async () => {
    setIsLoadingQueue(true);
    try {
      const items = await getPendingSuggestions(vendorFilter === 'all' ? undefined : vendorFilter);
      setQueueItems(items);
    } catch (err: any) {
      console.error('Failed to load queue:', err);
    } finally {
      setIsLoadingQueue(false);
    }
  };

  const handleDecision = async (decision: 'approve' | 'reject' | 'approve_with_correction') => {
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      let correctedMapping = undefined;
      if (decision === 'approve_with_correction') {
        correctedMapping = {
          common_rule_id: currentVendor === 'juniper' ? 'COMMON-DIAG-001' : 'COMMON-DIAG-001',
          vendor_rule_id: currentVendor === 'juniper' ? 'JUNOS-DIAG-001' : 'CISCO-DIAG-001',
          internalTitle: editTitle,
          csmFieldChecked: editField,
          condition: editCondition,
          vendor: currentVendor
        };
      }

      const res = await approveSuggestion({
        suggestion_id: suggestionId,
        decision,
        corrected_mapping: correctedMapping,
        session_id: sessionId
      });

      setSubmitSuccess(res);
      // Also refresh library if loaded
      loadTrustedLibrary();
    } catch (err: any) {
      setSubmitError(err.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRetireRule = async (ruleId: string) => {
    if (!window.confirm(`Are you sure you want to retire trusted rule mapping '${ruleId}'?`)) {
      return;
    }
    try {
      await deleteTrustedMapping(ruleId);
      setActionNotice(`Trusted mapping '${ruleId}' was successfully retired.`);
      loadTrustedLibrary();
      setTimeout(() => setActionNotice(null), 5000);
    } catch (err: any) {
      setLibraryError(`Failed to retire rule: ${err.message}`);
    }
  };

  const selectQueueItem = (item: SuggestionQueueItem) => {
    setCurrentLine(item.suggestion.raw_line);
    setCurrentVendor(item.vendor || 'cisco');
    setActiveTab('active_review');
  };

  const confidence = suggestionData?.confidence ?? 0.5;
  const confidencePercent = Math.round(confidence * 100);
  const frameworkHints: Array<{ framework: string; possible_control_id: string }> =
    suggestionData?.framework_hints || [];

  return (
    <div className="space-y-6 font-sans">
      {/* Top Header & Breadcrumbs */}
      <div className="border-b border-slate-800 pb-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <button
            onClick={onBackToAudit}
            className="text-xs text-sky-400 hover:text-sky-300 font-mono mb-2 flex items-center gap-1 cursor-pointer"
          >
            &larr; Back to Audit Results Matrix
          </button>
          <div className="flex items-center space-x-3">
            <h1 className="text-xl font-bold text-white">
              Trusted rule library &amp; human review
            </h1>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-800 font-semibold">
              TRUSTED REPOSITORY (§3B)
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic compliance authority governed strictly by authorized human reviewers. AI suggestions remain quarantined until approved.
          </p>
        </div>

        {/* Tab Selector */}
        <div className="flex items-center bg-slate-900 border border-slate-800 p-1 rounded font-mono text-xs">
          <button
            onClick={() => setActiveTab('active_review')}
            className={`px-3 py-1.5 rounded cursor-pointer transition-colors ${
              activeTab === 'active_review'
                ? 'bg-[#00FF41] text-black font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Active Review
          </button>
          <button
            onClick={() => setActiveTab('trusted_library')}
            className={`px-3 py-1.5 rounded cursor-pointer transition-colors ${
              activeTab === 'trusted_library'
                ? 'bg-[#00FF41] text-black font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Trusted Rules Library
          </button>
          <button
            onClick={() => setActiveTab('queue')}
            className={`px-3 py-1.5 rounded cursor-pointer transition-colors ${
              activeTab === 'queue'
                ? 'bg-[#00FF41] text-black font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Suggestions Queue
          </button>
        </div>
      </div>

      {/* Mandatory Invariant Notice */}
      <div className="bg-amber-950/30 border border-amber-800/80 rounded p-4 flex items-start space-x-3 text-xs">
        <div className="text-amber-400 shrink-0 mt-0.5">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        </div>
        <div>
          <span className="font-bold uppercase tracking-wider text-amber-300 font-mono">
            Mandatory Security Boundary (§3B Invariant):
          </span>
          <p className="text-amber-200/80 mt-0.5 leading-relaxed">
            AI suggestions NEVER directly decide compliance or write to the Trusted Rule Library. Only an authorized reviewer (<code className="font-mono text-amber-200 bg-amber-950 px-1 py-0.2 rounded border border-amber-800">is_authorized_approver: true</code>) can promote or correct an interpretation into a trusted deterministic rule.
          </p>
        </div>
      </div>

      {/* Vendor Filter Bar (for Library & Queue views) */}
      {(activeTab === 'trusted_library' || activeTab === 'queue') && (
        <div className="flex items-center justify-between bg-slate-900 border border-slate-800 rounded px-4 py-2.5 font-mono text-xs">
          <div className="flex items-center space-x-2">
            <span className="text-slate-400 uppercase">Vendor Filter:</span>
            {(['all', 'cisco', 'juniper'] as VendorFilter[]).map((vf) => (
              <button
                key={vf}
                onClick={() => setVendorFilter(vf)}
                className={`px-2.5 py-1 rounded border uppercase text-[11px] cursor-pointer transition-colors ${
                  vendorFilter === vf
                    ? 'bg-[#00FF41] text-black border-[#00FF41]/60 font-bold'
                    : 'bg-slate-800 text-slate-400 border-slate-700 hover:text-white'
                }`}
              >
                {vf === 'all' ? 'All Vendors' : vf}
              </button>
            ))}
          </div>
          <div className="text-slate-500 text-[11px]">
            Strict vendor isolation enforced on backend
          </div>
        </div>
      )}

      {/* TAB 1: ACTIVE SUGGESTION REVIEW */}
      {activeTab === 'active_review' && (
        <div className="space-y-6">
          {isLoadingSuggestion ? (
            <div className="bg-slate-900 border border-slate-800 rounded p-12 text-center font-mono text-xs text-slate-300 space-y-3">
              <div className="w-8 h-8 border-2 border-amber-400 border-t-transparent rounded-full animate-spin mx-auto"></div>
              <div>Running semantic similarity & AI rationale generation for: <code className="text-amber-300 font-bold">{currentLine}</code> ({currentVendor})...</div>
            </div>
          ) : suggestionError || !suggestionData ? (
            <div className="bg-rose-950/40 border border-rose-800 rounded p-8 text-center font-mono text-xs space-y-3">
              <div className="text-rose-400 font-bold text-sm">AI Suggestion Error</div>
              <p className="text-rose-200 max-w-lg mx-auto">{suggestionError || 'Unable to generate suggestion.'}</p>
              <button
                onClick={() => loadAiSuggestion(currentLine, currentVendor)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-sky-400 rounded border border-slate-700 cursor-pointer font-bold"
              >
                ↻ Retry Inference
              </button>
            </div>
          ) : (
            <div
              className={`bg-slate-900 rounded p-6 border-2 ${
                submitSuccess
                  ? 'border-slate-700'
                  : 'border-dashed border-amber-600/90 shadow-lg shadow-amber-950/20'
              }`}
            >
              {/* Status Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 mb-5 border-b border-slate-800 gap-2">
                <div className="flex items-center space-x-3">
                  <span className="font-mono text-xs text-slate-500 uppercase">Suggestion ID:</span>
                  <span className="font-mono text-xs text-sky-400 font-semibold">{suggestionId}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700 uppercase">
                    VENDOR: {suggestionData.vendor || currentVendor}
                  </span>
                </div>

                <div>
                  {!submitSuccess ? (
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-amber-950 text-amber-300 border border-amber-700">
                      <span className="w-1.5 h-1.5 rounded-full bg-amber-400 mr-1.5 animate-pulse"></span>
                      STATUS: PENDING HUMAN REVIEW
                    </span>
                  ) : submitSuccess.status === 'rejected' ? (
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-rose-950 text-rose-300 border border-rose-700">
                      STATUS: REJECTED (REMAINS UNTRUSTED)
                    </span>
                  ) : submitSuccess.status === 'approve_with_correction' || submitSuccess.status === 'corrected' ? (
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-sky-950 text-sky-300 border border-sky-700">
                      STATUS: PROMOTED (HUMAN CORRECTED)
                    </span>
                  ) : (
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-700">
                      STATUS: PROMOTED TO TRUSTED RULE LIBRARY
                    </span>
                  )}
                </div>
              </div>

              {/* Error notice if submission failed */}
              {submitError && (
                <div className="mb-5 bg-rose-950/60 border border-rose-700 rounded p-4 text-xs text-rose-200 flex items-start space-x-2 font-mono">
                  <span className="font-bold text-rose-300">Approval Conflict / Error:</span>
                  <span>{submitError}</span>
                </div>
              )}

              {/* Raw CLI line */}
              <div className="space-y-2 mb-6">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">
                    Raw Configuration Line
                  </label>
                  <span className="text-[11px] font-mono text-slate-500">Unmapped Input Evidence</span>
                </div>
                <div className="bg-slate-950 border border-slate-800 rounded p-3 font-mono text-sm text-amber-300 flex items-center justify-between select-all">
                  <code>{currentLine}</code>
                  <span className="text-[10px] text-slate-500 font-mono px-2 py-0.5 bg-slate-900 rounded border border-slate-800 uppercase">
                    {currentVendor}
                  </span>
                </div>
              </div>

              {/* AI suggestion body */}
              <div className="bg-slate-950/70 border border-slate-800 rounded p-5 space-y-5 mb-6">
                <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                  <div className="flex items-center space-x-2">
                    <span className="w-2 h-2 rounded-full bg-amber-400"></span>
                    <span className="text-xs font-mono font-bold uppercase text-slate-200">
                      Offline AI Interpretation & Rationale
                    </span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
                    ADVISORY ONLY — NOT DETERMINISTIC
                  </span>
                </div>

                {/* Confidence Bar */}
                <div>
                  <div className="flex items-center justify-between text-xs font-mono mb-1.5">
                    <span className="text-slate-400 uppercase">Interpretation Confidence</span>
                    <span className="font-bold text-emerald-400">
                      {confidencePercent}% ({confidence.toFixed(2)} / 1.00)
                    </span>
                  </div>
                  <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden border border-slate-700">
                    <div
                      className="bg-emerald-500 h-full rounded-full transition-all duration-500"
                      style={{ width: `${confidencePercent}%` }}
                    ></div>
                  </div>
                </div>

                {/* Suggested Rule Details */}
                {!isEditing ? (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono pt-2">
                    <div className="md:col-span-3">
                      <span className="text-slate-500 block text-[10px] uppercase">Rule Title</span>
                      <span className="text-slate-100 font-semibold text-sm">{editTitle}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">CSM Field Checked</span>
                      <code className="text-sky-400 font-bold bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                        {editField}
                      </code>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Condition</span>
                      <code className="text-amber-300 font-bold bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                        {editCondition}
                      </code>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Target Vendor</span>
                      <span className="text-slate-300 uppercase font-semibold">{currentVendor}</span>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4 pt-2 border-t border-slate-800">
                    <div className="text-xs font-mono text-sky-400 font-bold">
                      CORRECT RULE DEFINITION (HUMAN AUDIT OVERRIDE):
                    </div>
                    <div>
                      <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                        Rule Title
                      </label>
                      <input
                        type="text"
                        value={editTitle}
                        onChange={(e) => setEditTitle(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200 font-mono focus:border-sky-500 focus:outline-none"
                      />
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                          CSM Field Checked
                        </label>
                        <input
                          type="text"
                          value={editField}
                          onChange={(e) => setEditField(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200 font-mono focus:border-sky-500 focus:outline-none"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                          Condition (e.g. "equals False", "not_null")
                        </label>
                        <input
                          type="text"
                          value={editCondition}
                          onChange={(e) => setEditCondition(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200 font-mono focus:border-sky-500 focus:outline-none"
                        />
                      </div>
                    </div>
                  </div>
                )}

                {/* Explanation */}
                <div className="pt-2 border-t border-slate-800/80">
                  <span className="text-slate-400 block text-xs font-mono uppercase mb-1">
                    AI Inference Explanation:
                  </span>
                  <p className="text-xs text-slate-300 leading-relaxed font-sans bg-slate-900/60 p-3 rounded border border-slate-800">
                    {suggestionData.rationale}
                  </p>
                </div>

                {/* Framework Hints */}
                {frameworkHints.length > 0 && (
                  <div className="pt-2 border-t border-slate-800/80">
                    <span className="text-slate-400 block text-xs font-mono uppercase mb-2">
                      Inferred Framework References:
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {frameworkHints.map((hint, idx) => (
                        <div
                          key={idx}
                          className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-xs font-mono"
                        >
                          <span className="text-sky-400 font-bold">{hint.framework}:</span>
                          <span className="text-slate-200">{hint.possible_control_id}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Reviewer Accountability Card */}
              <div className="space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 bg-slate-950 rounded border border-slate-800">
                  <div className="flex items-center space-x-3 text-xs font-mono">
                    <span className="text-slate-400 uppercase font-semibold">Authoritative Approver:</span>
                    <span className="text-sky-400 font-bold bg-slate-900 px-2.5 py-1 rounded border border-slate-800">
                      {currentUser?.username || 'SecOps Reviewer'}
                    </span>
                    <span className="text-[10px] text-emerald-400 bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-800">
                      Bound to JWT sub: {currentUser?.user_id || 'usr-reviewer'}
                    </span>
                  </div>
                  <div className="text-xs font-mono">
                    <span className="text-slate-500 uppercase">Approver Clearance: </span>
                    {currentUser?.is_authorized_approver ? (
                      <span className="text-emerald-400 font-bold">AUTHORIZED</span>
                    ) : (
                      <span className="text-rose-400 font-bold">UNAUTHORIZED (Read-Only)</span>
                    )}
                  </div>
                </div>

                {!currentUser?.is_authorized_approver && (
                  <div className="bg-amber-950/40 border border-amber-800 text-amber-300 text-xs rounded p-3 font-mono">
                    <strong>Notice:</strong> Rule mutation requires SecOps Reviewer authorization (<code className="text-amber-200">is_authorized_approver: true</code>). Approval actions are disabled for role <code className="text-sky-300">{currentUser?.role || 'operator'}</code>.
                  </div>
                )}

                {/* Actions */}
                {!submitSuccess ? (
                  <div className="flex flex-wrap items-center justify-end gap-3 pt-2">
                    <button
                      type="button"
                      disabled={isSubmitting || !currentUser?.is_authorized_approver}
                      onClick={() => handleDecision('reject')}
                      className="px-4 py-2 bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 rounded text-xs font-mono font-bold uppercase transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      {isSubmitting ? 'Submitting...' : 'Reject (Do Not Trust)'}
                    </button>

                    {!isEditing ? (
                      <button
                        type="button"
                        disabled={isSubmitting || !currentUser?.is_authorized_approver}
                        onClick={() => setIsEditing(true)}
                        className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded text-xs font-mono font-bold uppercase transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                      >
                        Correct Details...
                      </button>
                    ) : (
                      <button
                        type="button"
                        disabled={isSubmitting || !currentUser?.is_authorized_approver}
                        onClick={() => handleDecision('approve_with_correction')}
                        className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white border border-sky-400 rounded text-xs font-mono font-bold uppercase transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                      >
                        {isSubmitting ? 'Submitting...' : 'Approve with Correction'}
                      </button>
                    )}

                    {!isEditing && (
                      <button
                        type="button"
                        disabled={isSubmitting || !currentUser?.is_authorized_approver}
                        onClick={() => handleDecision('approve')}
                        className="px-5 py-2 bg-emerald-600 hover:bg-emerald-500 text-slate-950 border border-emerald-400 rounded text-xs font-mono font-bold uppercase transition-colors cursor-pointer shadow-sm disabled:opacity-40 disabled:cursor-not-allowed"
                      >
                        {isSubmitting ? 'Submitting...' : 'Approve as Trusted Rule'}
                      </button>
                    )}
                  </div>
                ) : (
                  <div className="flex flex-col sm:flex-row justify-between items-center gap-3 pt-2">
                    <div className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
                      <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                      </svg>
                      <span>
                        Decision recorded ({submitSuccess.status}). Trusted mapping library updated.
                      </span>
                    </div>
                    <div className="flex items-center space-x-3">
                      <button
                        onClick={() => setActiveTab('trusted_library')}
                        className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-sky-400 border border-slate-700 rounded text-xs font-mono font-bold uppercase cursor-pointer"
                      >
                        View in Trusted Library &rarr;
                      </button>
                      <button
                        onClick={onApprovalCompleted}
                        className="px-5 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-mono font-bold uppercase cursor-pointer"
                      >
                        Return to Audit &rarr;
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: TRUSTED RULE LIBRARY */}
      {activeTab === 'trusted_library' && (
        <div className="space-y-4">
          {actionNotice && (
            <div className="bg-emerald-950/60 border border-emerald-700 rounded p-3 text-xs text-emerald-200 font-mono">
              {actionNotice}
            </div>
          )}
          {libraryError && (
            <div className="bg-rose-950/60 border border-rose-700 rounded p-3 text-xs text-rose-200 font-mono">
              {libraryError}
            </div>
          )}

          <div className="bg-slate-900 border border-slate-800 rounded p-5">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-4 mb-4 border-b border-slate-800 gap-3">
              <div>
                <h2 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                  <span>Deterministic Trusted Rules</span>
                  <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px]">
                    {trustedRules.length} Approved Mappings
                  </span>
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Only mappings in this library are evaluated during deterministic compliance audits.
                </p>
              </div>
              <button
                onClick={loadTrustedLibrary}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 text-xs font-mono cursor-pointer"
              >
                ↻ Refresh Library
              </button>
            </div>

            {isLoadingLibrary ? (
              <div className="text-center py-10 font-mono text-xs text-slate-400">
                Loading trusted mappings...
              </div>
            ) : trustedRules.length === 0 ? (
              <div className="text-center py-10 font-mono text-xs text-slate-400 space-y-2">
                <div>No trusted rule mappings found for vendor: <strong className="text-white uppercase">{vendorFilter}</strong></div>
                <p className="text-slate-500">Approve AI suggestions to add deterministic rules to this library.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Vendor</th>
                      <th className="py-2.5 px-3">Rule ID</th>
                      <th className="py-2.5 px-3">Title & Field Checked</th>
                      <th className="py-2.5 px-3">Condition</th>
                      <th className="py-2.5 px-3">Provenance / Source</th>
                      <th className="py-2.5 px-3">Reviewer & Date</th>
                      <th className="py-2.5 px-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {trustedRules.map((rule) => {
                      const isHuman = rule.version_info?.source === 'human_corrected';
                      const approvedBy = rule.version_info?.approved_by || 'Unknown';
                      const approvedAt = rule.version_info?.approved_at || rule.created_at || '—';

                      return (
                        <tr key={rule.vendor_rule_id} className="hover:bg-slate-800/40 transition-colors">
                          <td className="py-3 px-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                              (rule.vendor || '').toLowerCase() === 'juniper'
                                ? 'bg-amber-950 text-amber-300 border-amber-800'
                                : 'bg-sky-950 text-sky-300 border-sky-800'
                            }`}>
                              {rule.vendor || 'cisco'}
                            </span>
                          </td>
                          <td className="py-3 px-3 font-semibold text-white">
                            <div>{rule.vendor_rule_id}</div>
                            {rule.common_rule_id && (
                              <div className="text-[10px] text-slate-500">{rule.common_rule_id}</div>
                            )}
                          </td>
                          <td className="py-3 px-3">
                            <div className="text-slate-200">{rule.internalTitle}</div>
                            <code className="text-[11px] text-sky-400">{rule.csmFieldChecked}</code>
                          </td>
                          <td className="py-3 px-3">
                            <code className="text-amber-300 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
                              {rule.condition}
                            </code>
                          </td>
                          <td className="py-3 px-3">
                            {isHuman ? (
                              <span className="px-1.5 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-800 text-[10px] font-semibold">
                                Human Corrected
                              </span>
                            ) : (
                              <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px] font-semibold">
                                AI Suggested
                              </span>
                            )}
                          </td>
                          <td className="py-3 px-3 text-[11px]">
                            <div className="text-slate-300 font-semibold">{approvedBy}</div>
                            <div className="text-slate-500">{approvedAt.slice(0, 19).replace('T', ' ')}</div>
                          </td>
                          <td className="py-3 px-3 text-right">
                            {currentUser?.is_authorized_approver ? (
                              <button
                                onClick={() => handleRetireRule(rule.vendor_rule_id)}
                                className="px-2 py-1 bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 rounded text-[10px] font-bold uppercase cursor-pointer"
                                title="Retire trusted mapping from deterministic library"
                              >
                                Retire
                              </button>
                            ) : (
                              <span className="text-slate-600 text-[10px]">Read-Only</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: SUGGESTIONS QUEUE */}
      {activeTab === 'queue' && (
        <div className="bg-slate-900 border border-slate-800 rounded p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div>
              <h2 className="text-sm font-bold font-mono text-white">
                AI interpretation queue &amp; historical decisions
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Audit trail of all interpretations generated by local AI models.
              </p>
            </div>
            <button
              onClick={loadQueue}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 text-xs font-mono cursor-pointer"
            >
              ↻ Refresh Queue
            </button>
          </div>

          {isLoadingQueue ? (
            <div className="text-center py-10 font-mono text-xs text-slate-400">Loading queue...</div>
          ) : queueItems.length === 0 ? (
            <div className="text-center py-10 font-mono text-xs text-slate-400">No suggestions recorded in queue.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3">Vendor</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3">Configuration Line</th>
                    <th className="py-2.5 px-3">Confidence</th>
                    <th className="py-2.5 px-3">Reviewer</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {queueItems.map((item) => {
                    const status = item.status || 'pending';
                    const isPending = status === 'pending';
                    const isRejected = status === 'rejected';

                    return (
                      <tr key={item.suggestion_id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-3 px-3">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase border bg-slate-800 text-slate-300 border-slate-700">
                            {item.vendor || 'cisco'}
                          </span>
                        </td>
                        <td className="py-3 px-3">
                          {isPending ? (
                            <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px] font-bold uppercase">
                              Pending Review
                            </span>
                          ) : isRejected ? (
                            <span className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-bold uppercase">
                              Rejected
                            </span>
                          ) : (
                            <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-bold uppercase">
                              Approved
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-3 text-slate-200">
                          <code>{item.suggestion?.raw_line}</code>
                        </td>
                        <td className="py-3 px-3 font-semibold text-emerald-400">
                          {item.suggestion?.confidence ? `${Math.round(item.suggestion.confidence * 100)}%` : '—'}
                        </td>
                        <td className="py-3 px-3 text-[11px] text-slate-400">
                          {item.reviewed_by ? `${item.reviewed_by}` : 'Awaiting Reviewer'}
                        </td>
                        <td className="py-3 px-3 text-right">
                          <button
                            onClick={() => selectQueueItem(item)}
                            className="px-2.5 py-1 bg-sky-600 hover:bg-sky-500 text-white rounded text-[10px] font-bold uppercase cursor-pointer"
                          >
                            Inspect &rarr;
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
