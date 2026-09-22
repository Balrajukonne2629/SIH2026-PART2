/**
 * NTRO PS26155 — Report Workflow Panel (Phase 3D Repair)
 *
 * Attaches to a canonical AuditReport (identified by report_id from the finalize response).
 * Provides:
 *  - Edit Report: inline form for allowlisted editable fields, shows [Edited manually] badge.
 *  - Export Report: PDF or DOCX download using authenticated fetch (Bearer token forwarded).
 *
 * Authorization is enforced by the backend; the UI simply reflects what the backend allows.
 * Viewer can export but not edit. Uploader/reviewer can also edit.
 * The panel is shown only when a report_id is available (post-finalize).
 */

import React, { useState } from 'react';
import { patchCanonicalReport, exportCanonicalReportBlob, getCanonicalReport, ApiError } from '../api';
import type { UserIdentity } from '../types';

// The editable fields the backend allows — kept in sync with audit_report.ALLOWED_TOP_LEVEL_EDITABLE_FIELDS
const EDITABLE_FIELDS = [
  { key: 'executive_summary', label: 'Executive Summary' },
  { key: 'auditor_observations', label: 'Auditor Observations' },
  { key: 'recommendations', label: 'Recommendations' },
  { key: 'additional_findings', label: 'Additional Findings' },
  { key: 'final_reviewer_notes', label: 'Final Reviewer Notes' },
] as const;

type EditableFieldKey = typeof EDITABLE_FIELDS[number]['key'];

interface Props {
  reportId: string;
  currentUser: UserIdentity;
  initialEditMode?: boolean;
}

export const ReportWorkflowPanel: React.FC<Props> = ({ reportId, currentUser, initialEditMode = false }) => {
  const canEdit = currentUser.role === 'reviewer' || currentUser.role === 'uploader';

  // --- Edit state ---
  const [editMode, setEditMode] = useState(initialEditMode);
  const [report, setReport] = useState<any>(null);
  const [loadingReport, setLoadingReport] = useState(false);
  const [selectedField, setSelectedField] = useState<EditableFieldKey>('executive_summary');
  const [editValue, setEditValue] = useState('');
  const [saving, setSaving] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);
  const [editSuccess, setEditSuccess] = useState<string | null>(null);

  // Auto-open and load when initialEditMode is set
  React.useEffect(() => {
    if (initialEditMode) {
      setEditMode(true);
      loadReport();
    }
  }, [initialEditMode, reportId]);

  // --- Export state ---
  const [exporting, setExporting] = useState(false);
  const [exportFormat, setExportFormat] = useState<'pdf' | 'docx'>('pdf');
  const [exportError, setExportError] = useState<string | null>(null);

  const loadReport = async () => {
    setLoadingReport(true);
    setEditError(null);
    try {
      const data = await getCanonicalReport(reportId);
      setReport(data);
      // Pre-populate the selected field's current value
      setEditValue(data?.editable_content?.[selectedField] ?? '');
    } catch (err: any) {
      setEditError(err.message);
    } finally {
      setLoadingReport(false);
    }
  };

  const handleOpenEdit = async () => {
    setEditMode(true);
    setEditSuccess(null);
    await loadReport();
  };

  const handleFieldChange = (field: EditableFieldKey) => {
    setSelectedField(field);
    setEditValue(report?.editable_content?.[field] ?? '');
    setEditError(null);
    setEditSuccess(null);
  };

  const handleSave = async () => {
    if (!report) return;
    setSaving(true);
    setEditError(null);
    setEditSuccess(null);
    try {
      const updated = await patchCanonicalReport(
        reportId,
        selectedField,
        editValue,
        report.version
      );
      setReport(updated);
      setEditValue(updated?.editable_content?.[selectedField] ?? '');
      setEditSuccess(`Saved. Report version is now v${updated.version}.`);
    } catch (err: any) {
      if (err instanceof ApiError && err.status === 409) {
        // Stale version: reload and inform user
        setEditError('Another edit was made concurrently. Reloaded latest version — please review and retry.');
        await loadReport();
      } else {
        setEditError(err.message);
      }
    } finally {
      setSaving(false);
    }
  };

  const handleExport = async () => {
    setExporting(true);
    setExportError(null);
    try {
      const blob = await exportCanonicalReportBlob(reportId, exportFormat);
      const ext = exportFormat;
      const filename = `audit_report_${reportId}.${ext}`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setExportError(err.message);
    } finally {
      setExporting(false);
    }
  };

  // Determine which fields have been manually edited
  const editedFields = new Set<string>(
    (report?.edit_metadata ?? []).map((e: any) => e.field_path)
  );

  return (
    <div className="mt-3 border border-slate-700 rounded bg-slate-950">
      {/* Panel header */}
      <div className="flex flex-wrap items-center gap-2 px-4 py-3 border-b border-slate-800">
        <span className="text-[11px] font-mono font-bold uppercase text-slate-400 mr-2">
          Canonical Report
        </span>
        <code className="text-[10px] font-mono text-sky-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-700">
          {reportId}
        </code>

        {/* Edit Report button — only for reviewer/uploader */}
        {canEdit && (
          <button
            onClick={editMode ? () => { setEditMode(false); setEditError(null); setEditSuccess(null); } : handleOpenEdit}
            className={`ml-auto px-3 py-1.5 rounded text-xs font-mono font-semibold border transition-colors cursor-pointer ${
              editMode
                ? 'bg-slate-800 text-slate-300 border-slate-600 hover:text-white'
                : 'bg-amber-900/60 hover:bg-amber-800/80 text-amber-300 border-amber-700'
            }`}
          >
            {editMode ? '✕ Close Editor' : '✎ Edit Report'}
          </button>
        )}

        {/* Export controls */}
        <div className="flex items-center gap-1.5">
          <select
            value={exportFormat}
            onChange={(e) => setExportFormat(e.target.value as 'pdf' | 'docx')}
            className="text-xs font-mono bg-slate-800 border border-slate-700 text-slate-200 rounded px-2 py-1.5 cursor-pointer"
          >
            <option value="pdf">PDF</option>
            <option value="docx">DOCX</option>
          </select>
          <button
            onClick={handleExport}
            disabled={exporting}
            className={`px-3 py-1.5 rounded text-xs font-mono font-semibold border transition-colors flex items-center gap-1.5 ${
              exporting
                ? 'bg-slate-800 text-slate-500 border-slate-700 cursor-not-allowed'
                : 'bg-sky-900/60 hover:bg-sky-800 text-sky-300 border-sky-700 cursor-pointer'
            }`}
          >
            {exporting ? (
              <><span className="inline-block w-3 h-3 border border-slate-400 border-t-transparent rounded-full animate-spin" /> Exporting…</>
            ) : (
              <><svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg> Export {exportFormat.toUpperCase()}</>
            )}
          </button>
        </div>
      </div>

      {/* Export error */}
      {exportError && (
        <div className="px-4 py-2 bg-rose-950/50 border-b border-rose-800 text-rose-300 text-xs font-mono">
          Export failed: {exportError}
        </div>
      )}

      {/* Edit panel */}
      {editMode && (
        <div className="p-4 space-y-4">
          {loadingReport ? (
            <div className="text-xs font-mono text-slate-400 flex items-center gap-2">
              <span className="inline-block w-4 h-4 border-2 border-sky-400 border-t-transparent rounded-full animate-spin" />
              Loading report…
            </div>
          ) : report ? (
            <>
              {/* Field selector */}
              <div className="flex flex-wrap gap-2">
                {EDITABLE_FIELDS.map(({ key, label }) => (
                  <button
                    key={key}
                    onClick={() => handleFieldChange(key)}
                    className={`px-2.5 py-1 rounded text-[11px] font-mono border transition-colors cursor-pointer ${
                      selectedField === key
                        ? 'bg-amber-900/60 border-amber-700 text-amber-200'
                        : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {label}
                    {editedFields.has(key) && (
                      <span className="ml-1 text-amber-400 text-[10px]">[Edited manually]</span>
                    )}
                  </button>
                ))}
              </div>

              {/* System-generated fields notice */}
              <p className="text-[11px] font-mono text-slate-500">
                System-generated fields (PASS/FAIL verdicts, evidence, frameworks, AI provenance) are read-only and cannot be modified.
              </p>

              {/* Editable textarea */}
              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">
                  {EDITABLE_FIELDS.find(f => f.key === selectedField)?.label}
                  {editedFields.has(selectedField) && (
                    <span className="ml-2 px-1.5 py-0.5 rounded bg-amber-900/50 text-amber-400 border border-amber-700 text-[10px]">
                      [Edited manually]
                    </span>
                  )}
                </label>
                <textarea
                  value={editValue}
                  onChange={(e) => setEditValue(e.target.value)}
                  rows={5}
                  className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-amber-600 resize-y"
                  placeholder={`Enter ${EDITABLE_FIELDS.find(f => f.key === selectedField)?.label}…`}
                />
              </div>

              {/* Version indicator */}
              <div className="text-[11px] font-mono text-slate-500">
                Current report version: <span className="text-slate-300 font-bold">v{report.version}</span>
              </div>

              {/* Success / error feedback */}
              {editSuccess && (
                <div className="px-3 py-2 bg-emerald-950/50 border border-emerald-700 rounded text-emerald-300 text-xs font-mono">
                  ✓ {editSuccess}
                </div>
              )}
              {editError && (
                <div className="px-3 py-2 bg-rose-950/50 border border-rose-700 rounded text-rose-300 text-xs font-mono">
                  ✗ {editError}
                </div>
              )}

              {/* Save button */}
              <div className="flex items-center gap-3">
                <button
                  onClick={handleSave}
                  disabled={saving}
                  className={`px-4 py-2 rounded text-xs font-mono font-bold border transition-colors ${
                    saving
                      ? 'bg-slate-800 text-slate-500 border-slate-700 cursor-not-allowed'
                      : 'bg-emerald-800/70 hover:bg-emerald-700/80 text-emerald-200 border-emerald-700 cursor-pointer'
                  }`}
                >
                  {saving ? 'Saving…' : '↳ Save Edit'}
                </button>
                <span className="text-[11px] font-mono text-slate-500">
                  Identity recorded from authenticated JWT (cannot be spoofed).
                </span>
              </div>
            </>
          ) : (
            editError && (
              <div className="text-xs font-mono text-rose-300">Failed to load report: {editError}</div>
            )
          )}
        </div>
      )}
    </div>
  );
};
