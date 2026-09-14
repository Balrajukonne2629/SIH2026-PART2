import React, { useState, useEffect } from 'react';
import { suggestMapping, approveSuggestion } from '../api';

interface AiSuggestionReviewScreenProps {
  unmappedLine: string;
  sessionId?: string;
  onApprovalCompleted: () => void;
  onBackToAudit: () => void;
}

export const AiSuggestionReviewScreen: React.FC<AiSuggestionReviewScreenProps> = ({
  unmappedLine,
  sessionId,
  onApprovalCompleted,
  onBackToAudit
}) => {
  const [suggestionData, setSuggestionData] = useState<any>(null);
  const [suggestionId, setSuggestionId] = useState<string>('');
  const [isLoadingSuggestion, setIsLoadingSuggestion] = useState(true);
  const [suggestionError, setSuggestionError] = useState<string | null>(null);

  // Reviewer form state
  const [reviewerName, setReviewerName] = useState('SecOps_Lead_Reviewer');
  const [isEditing, setIsEditing] = useState(false);
  const [editTitle, setEditTitle] = useState('');
  const [editField, setEditField] = useState('');
  const [editCondition, setEditCondition] = useState('');

  // Action state
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitSuccess, setSubmitSuccess] = useState<any>(null);

  // Fetch real AI suggestion on mount
  useEffect(() => {
    if (unmappedLine) {
      loadAiSuggestion();
    }
  }, [unmappedLine]);

  const loadAiSuggestion = async () => {
    setIsLoadingSuggestion(true);
    setSuggestionError(null);
    try {
      const res = await suggestMapping(unmappedLine);
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

  const handleDecision = async (decision: 'approve' | 'reject' | 'approve_with_correction') => {
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      let correctedMapping = undefined;
      if (decision === 'approve_with_correction') {
        correctedMapping = {
          common_rule_id: 'COMMON-DIAG-001',
          vendor_rule_id: 'CISCO-DIAG-001',
          internalTitle: editTitle,
          csmFieldChecked: editField,
          condition: editCondition
        };
      }

      const res = await approveSuggestion({
        suggestion_id: suggestionId,
        reviewer_name: reviewerName,
        decision,
        corrected_mapping: correctedMapping,
        session_id: sessionId
      });

      setSubmitSuccess(res);
    } catch (err: any) {
      setSubmitError(err.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoadingSuggestion) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded p-12 text-center font-mono text-xs text-slate-300 space-y-3">
        <div className="w-8 h-8 border-2 border-amber-400 border-t-transparent rounded-full animate-spin mx-auto"></div>
        <div>Running local DistilBERT (66M) semantic inference on CLI line: <code className="text-amber-300 font-bold">{unmappedLine}</code>...</div>
      </div>
    );
  }

  if (suggestionError || !suggestionData) {
    return (
      <div className="bg-rose-950/40 border border-rose-800 rounded p-8 text-center font-mono text-xs space-y-3">
        <div className="text-rose-400 font-bold text-sm">AI Suggestion Generation Error</div>
        <p className="text-rose-200 max-w-lg mx-auto">{suggestionError || 'Unable to generate suggestion from backend.'}</p>
        <div className="flex justify-center gap-3 pt-2">
          <button
            onClick={loadAiSuggestion}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-sky-400 rounded border border-slate-700 cursor-pointer"
          >
            ↻ Retry Inference
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

  const confidence = suggestionData.confidence ?? 0.5;
  const confidencePercent = Math.round(confidence * 100);
  const frameworkHints: Array<{ framework: string; possible_control_id: string }> =
    suggestionData.framework_hints || [];

  return (
    <div className="space-y-6 font-sans">
      {/* Top Header & Breadcrumb */}
      <div className="border-b border-slate-800 pb-4 flex items-center justify-between">
        <div>
          <button
            onClick={onBackToAudit}
            className="text-xs text-sky-400 hover:text-sky-300 font-mono mb-2 flex items-center gap-1 cursor-pointer"
          >
            &larr; Back to Audit Results Matrix
          </button>
          <div className="flex items-center space-x-3">
            <h1 className="text-xl font-bold text-white uppercase tracking-wide">
              AI Suggestion Queue & Operator Review
            </h1>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-amber-950 text-amber-300 border border-amber-800 font-semibold">
              HUMAN-IN-THE-LOOP GATEWAY
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Unmapped CLI lines are parsed by offline NLP. Suggestions remain quarantined until validated by an authorized reviewer.
          </p>
        </div>
      </div>

      {/* Mandatory Safety Notice Banner (Non-dismissible) */}
      <div className="bg-amber-950/30 border border-amber-800/80 rounded p-4 flex items-start space-x-3 text-xs">
        <div className="text-amber-400 shrink-0 mt-0.5">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        </div>
        <div>
          <span className="font-bold uppercase tracking-wider text-amber-300 font-mono">
            Safety Boundary Notice (§1 & §3 Architecture Rule):
          </span>
          <p className="text-amber-200/80 mt-0.5 leading-relaxed">
            AI suggestions do NOT directly decide compliance or alter device rule logic. Once approved, this suggestion becomes a deterministic rule entry in <code className="font-mono text-amber-200 bg-amber-950 px-1 py-0.2 rounded border border-amber-800">trusted_mappings.json</code> signed with your reviewer ID and audit timestamp.
          </p>
        </div>
      </div>

      {/* Submission Error Banner */}
      {submitError && (
        <div className="bg-rose-950/60 border border-rose-700 rounded p-4 text-xs text-rose-200 flex items-start space-x-2 font-mono">
          <span className="font-bold text-rose-300">Approval Error:</span>
          <span>{submitError}</span>
        </div>
      )}

      {/* Primary Review Card with distinct Pending/Amber Dashed Border */}
      <div
        className={`bg-slate-900 rounded p-6 border-2 ${
          submitSuccess
            ? 'border-slate-700'
            : 'border-dashed border-amber-600/90 shadow-lg shadow-amber-950/20'
        }`}
      >
        {/* Status Indicator Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 mb-5 border-b border-slate-800 gap-2">
          <div className="flex items-center space-x-2">
            <span className="font-mono text-xs text-slate-500 uppercase">Queue Item ID:</span>
            <span className="font-mono text-xs text-sky-400 font-semibold">{suggestionId}</span>
          </div>

          <div className="flex items-center space-x-2">
            {!submitSuccess ? (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-amber-950 text-amber-300 border border-amber-700">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 mr-1.5 animate-pulse"></span>
                STATUS: PENDING HUMAN REVIEW
              </span>
            ) : (submitSuccess.status === 'approved' || submitSuccess.status === 'approve') ? (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-700">
                STATUS: APPROVED & COMMITTED TO TRUSTED RULES
              </span>
            ) : (submitSuccess.status === 'approved_with_correction' || submitSuccess.status === 'approve_with_correction') ? (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-sky-950 text-sky-300 border border-sky-700">
                STATUS: APPROVED WITH CORRECTIONS
              </span>
            ) : (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-rose-950 text-rose-300 border border-rose-700">
                STATUS: REJECTED / DISMISSED
              </span>
            )}
          </div>
        </div>

        {/* Section 1: Raw Unmapped CLI Line */}
        <div className="space-y-2 mb-6">
          <div className="flex items-center justify-between">
            <label className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">
              Raw Configuration Line (Unmatched in Deterministic Parser)
            </label>
            <span className="text-[11px] font-mono text-slate-500">Live Input</span>
          </div>
          <div className="bg-slate-950 border border-slate-800 rounded p-3 font-mono text-sm text-amber-300 flex items-center justify-between select-all">
            <code>{unmappedLine}</code>
            <span className="text-[10px] text-slate-500 font-mono px-2 py-0.5 bg-slate-900 rounded border border-slate-800">
              IOS-XE GLOBAL
            </span>
          </div>
        </div>

        {/* Section 2: AI Suggestion Card with Unverified Banner */}
        <div className="bg-slate-950/70 border border-slate-800 rounded p-5 space-y-5 mb-6">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div className="flex items-center space-x-2">
              <span className="w-2 h-2 rounded-full bg-amber-400"></span>
              <span className="text-xs font-mono font-bold uppercase text-slate-200">
                Local AI Model Inference (DistilBERT-66M)
              </span>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
              AI BEST GUESS — UNVERIFIED
            </span>
          </div>

          {/* Confidence Score Visual Meter */}
          <div>
            <div className="flex items-center justify-between text-xs font-mono mb-1.5">
              <span className="text-slate-400 uppercase">Semantic Match Confidence</span>
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

          {/* Suggested Rule Details (View or Edit mode) */}
          {!isEditing ? (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono pt-2">
              <div className="md:col-span-3">
                <span className="text-slate-500 block text-[10px] uppercase">Suggested Rule Title</span>
                <span className="text-slate-100 font-semibold text-sm">{editTitle}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">CSM Field Checked</span>
                <code className="text-sky-400 font-bold bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                  {editField}
                </code>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Evaluation Condition</span>
                <code className="text-amber-300 font-bold bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                  {editCondition}
                </code>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Target Scope</span>
                <span className="text-slate-300">Custom / Dynamic Rule Mapping</span>
              </div>
            </div>
          ) : (
            /* Inline Edit Fields for "Approve with Correction" */
            <div className="space-y-4 pt-2 border-t border-slate-800">
              <div className="text-xs font-mono text-sky-400 font-bold">
                EDIT MAPPING DEFINITION BEFORE COMMITTING:
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

          {/* Plain Language Rationale */}
          <div className="pt-2 border-t border-slate-800/80">
            <span className="text-slate-400 block text-xs font-mono uppercase mb-1">
              AI Inference Rationale:
            </span>
            <p className="text-xs text-slate-300 leading-relaxed font-sans bg-slate-900/60 p-3 rounded border border-slate-800">
              {suggestionData.rationale}
            </p>
          </div>

          {/* Framework Hints Chips: ONLY REAL DATA FROM API */}
          {frameworkHints.length > 0 && (
            <div className="pt-2 border-t border-slate-800/80">
              <span className="text-slate-400 block text-xs font-mono uppercase mb-2">
                Inferred Framework Control References (API Response Only):
              </span>
              <div className="flex flex-wrap gap-2">
                {frameworkHints.map((hint, idx) => (
                  <div
                    key={idx}
                    className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-xs font-mono"
                  >
                    <span className="text-sky-400 font-bold">{hint.framework}:</span>
                    <span className="text-slate-200">{hint.possible_control_id}</span>
                    <span className="text-[9px] text-amber-400 bg-amber-950 px-1 rounded border border-amber-900 ml-1">
                      AI best guess — unverified
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Section 3: Reviewer Sign-Off Stamp & Action Buttons */}
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 bg-slate-950 rounded border border-slate-800">
            <div className="flex items-center space-x-3">
              <label className="text-xs font-mono text-slate-400 uppercase font-semibold">
                Authorized Reviewer ID:
              </label>
              <input
                type="text"
                disabled={!!submitSuccess}
                value={reviewerName}
                onChange={(e) => setReviewerName(e.target.value)}
                className="bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-xs font-mono text-sky-300 focus:border-sky-500 focus:outline-none"
              />
            </div>
          </div>

          {/* Action Buttons */}
          {!submitSuccess ? (
            <div className="flex flex-wrap items-center justify-end gap-3 pt-2">
              <button
                type="button"
                disabled={isSubmitting}
                onClick={() => handleDecision('reject')}
                className="px-4 py-2 bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 rounded text-xs font-mono font-bold uppercase transition-colors cursor-pointer disabled:opacity-50"
              >
                {isSubmitting ? 'Submitting...' : 'Reject Suggestion'}
              </button>

              {!isEditing ? (
                <button
                  type="button"
                  disabled={isSubmitting}
                  onClick={() => setIsEditing(true)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded text-xs font-mono font-bold uppercase transition-colors cursor-pointer"
                >
                  Edit / Correct Details...
                </button>
              ) : (
                <button
                  type="button"
                  disabled={isSubmitting}
                  onClick={() => handleDecision('approve_with_correction')}
                  className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white border border-sky-400 rounded text-xs font-mono font-bold uppercase transition-colors cursor-pointer disabled:opacity-50"
                >
                  {isSubmitting ? 'Submitting...' : 'Approve with Correction'}
                </button>
              )}

              {!isEditing && (
                <button
                  type="button"
                  disabled={isSubmitting}
                  onClick={() => handleDecision('approve')}
                  className="px-5 py-2 bg-emerald-600 hover:bg-emerald-500 text-slate-950 border border-emerald-400 rounded text-xs font-mono font-bold uppercase transition-colors cursor-pointer shadow-sm disabled:opacity-50"
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
                  Action recorded ({submitSuccess.status}). Re-audited with updated trusted mappings.
                </span>
              </div>
              <button
                onClick={onApprovalCompleted}
                className="px-5 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-mono font-bold uppercase transition-colors cursor-pointer"
              >
                Return to Audit Results &rarr;
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
