/**
 * Real API client for Network Security Compliance Auditor FastAPI backend.
 * Endpoints at http://127.0.0.1:8000
 */

// Use relative path '' so Vite dev proxy forwards /api -> http://127.0.0.1:8000
export const API_BASE = '';

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = 'ApiError';
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${path}`;
  try {
    const res = await fetch(url, options);
    if (!res.ok) {
      let errorMsg = `HTTP ${res.status} ${res.statusText}`;
      try {
        const body = await res.json();
        if (body.detail) {
          errorMsg = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
        }
      } catch {
        // use default errorMsg
      }
      throw new ApiError(res.status, errorMsg);
    }
    return (await res.json()) as T;
  } catch (err: any) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(0, `Cannot connect to compliance backend at ${API_BASE}. Ensure server is running (python -m uvicorn main:app --host 127.0.0.1 --port 8000). Error: ${err.message}`);
  }
}

// 1. POST /api/audit/upload
export async function uploadAuditConfig(file?: File, rawConfig?: string, filename?: string) {
  if (file) {
    const formData = new FormData();
    formData.append('file', file);
    return request<any>('/api/audit/upload', {
      method: 'POST',
      body: formData,
    });
  } else {
    return request<any>('/api/audit/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw_config: rawConfig, filename: filename || 'labeled_test_config.txt' }),
    });
  }
}

// 2. GET /api/audit/{session_id}/results
export async function getAuditResults(sessionId: string) {
  return request<any>(`/api/audit/${sessionId}/results`);
}

// 3. POST /api/ai/suggest
export async function suggestMapping(unmappedLine: string) {
  return request<{
    suggestion_id: string;
    suggestion: {
      raw_line: string;
      suggested_rule_id: string | null;
      suggested_new_rule: {
        internalTitle: string;
        csmFieldChecked: string;
        condition: string;
      };
      confidence: number;
      rationale: string;
      framework_hints: Array<{ framework: string; possible_control_id: string }>;
    };
  }>('/api/ai/suggest', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ unmapped_line: unmappedLine }),
  });
}

// 4. POST /api/ai/approve
export async function approveSuggestion(payload: {
  suggestion_id: string;
  reviewer_name: string;
  decision: 'approve' | 'reject' | 'approve_with_correction';
  corrected_mapping?: any;
  session_id?: string;
}) {
  return request<any>('/api/ai/approve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

// 5. POST /api/remediation/{rule_id}
export async function getRemediation(ruleId: string, sessionId?: string, csm?: any) {
  return request<{
    rule_id: string;
    remediation_cmd: string;
    conflicts: Array<{
      conflict_id: string;
      title: string;
      severity: 'HIGH' | 'MEDIUM' | 'LOW';
      description: string;
      mitigation: string;
      affected_components: string[];
    }>;
    has_conflicts: boolean;
    conflict_count: number;
    why_it_failed: string;
    what_remediation_does: string;
    safety_notice: string;
    execution_safety_verified: boolean;
  }>(`/api/remediation/${ruleId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, csm }),
  });
}

// 6. POST /api/audit/finalize
export async function finalizeAudit(sessionId: string, remediationSummary?: any) {
  return request<{
    entry_id: string;
    entryHash: string;
    prevEntryHash: string;
    timestamp: string;
    pdf_download_url: string;
    pdf_filename: string;
    pdf_size_bytes: number;
  }>('/api/audit/finalize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, remediation_summary: remediationSummary }),
  });
}

// 7. GET /api/ledger
export async function getLedger() {
  return request<any[]>('/api/ledger');
}

// 8. GET /api/ledger/verify
export async function verifyLedger() {
  return request<{
    valid: boolean;
    message: string;
    broken_entry_index: number;
  }>('/api/ledger/verify');
}

// 9. GET /api/report/{entry_id}/download (URL builder)
export function getReportDownloadUrl(entryId: string) {
  return `${API_BASE}/api/report/${entryId}/download`;
}

// 10. GET /api/report/{entry_id}/verify
export async function verifyReport(entryId: string) {
  return request<{
    valid: boolean;
    message: string;
    entry_id: string;
  }>(`/api/report/${entryId}/verify`);
}
