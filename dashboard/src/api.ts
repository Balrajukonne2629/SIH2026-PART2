/**
 * Real API client for Network Security Compliance Auditor FastAPI backend.
 * Endpoints at http://127.0.0.1:8000
 */

import type { LoginResponse, UserIdentity, ModelStatus, ModelModeUpdateRequest, ModelModeUpdateResponse, TrustedMappingItem, SuggestionQueueItem } from './types';

// Use relative path '' so Vite dev proxy forwards /api -> http://127.0.0.1:8000
export const API_BASE = '';

let inMemoryToken: string | null = null;
const unauthorizedListeners: Set<() => void> = new Set();

export function getAccessToken(): string | null {
  if (inMemoryToken) return inMemoryToken;
  if (typeof window !== 'undefined' && window.sessionStorage) {
    inMemoryToken = window.sessionStorage.getItem('ntro_auth_token');
  }
  return inMemoryToken;
}

export function setAccessToken(token: string | null): void {
  inMemoryToken = token;
  if (typeof window !== 'undefined' && window.sessionStorage) {
    if (token) {
      window.sessionStorage.setItem('ntro_auth_token', token);
    } else {
      window.sessionStorage.removeItem('ntro_auth_token');
    }
  }
}

export function clearAccessToken(): void {
  setAccessToken(null);
}

export function onUnauthorized(callback: () => void): () => void {
  unauthorizedListeners.add(callback);
  return () => {
    unauthorizedListeners.delete(callback);
  };
}

function notifyUnauthorized(): void {
  unauthorizedListeners.forEach((cb) => {
    try {
      cb();
    } catch {
      // ignore callback error
    }
  });
}

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
  const token = getAccessToken();
  const headers: Record<string, string> = {
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...((options?.headers as Record<string, string>) || {})
  };

  const reqOptions: RequestInit = {
    ...options,
    headers
  };

  try {
    const res = await fetch(url, reqOptions);
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
      if (res.status === 401) {
        clearAccessToken();
        notifyUnauthorized();
      }
      throw new ApiError(res.status, errorMsg);
    }
    return (await res.json()) as T;
  } catch (err: any) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(0, `Cannot connect to compliance backend at ${API_BASE}. Ensure server is running (python -m uvicorn main:app --host 127.0.0.1 --port 8000). Error: ${err.message}`);
  }
}

// Auth API helpers
export async function login(username: string, password: string): Promise<LoginResponse> {
  const data = await request<LoginResponse>('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  if (data?.access_token) {
    setAccessToken(data.access_token);
  }
  return data;
}

export async function getCurrentUser(): Promise<UserIdentity> {
  return request<UserIdentity>('/api/auth/me');
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
export async function suggestMapping(unmappedLine: string, vendor: string = 'cisco') {
  return request<{
    suggestion_id: string;
    suggestion: {
      raw_line: string;
      suggested_rule_id: string | null;
      suggested_new_rule: {
        internalTitle: string;
        csmFieldChecked: string;
        condition: string;
        vendor?: string;
      };
      confidence: number;
      rationale: string;
      framework_hints: Array<{ framework: string; possible_control_id: string }>;
      vendor?: string;
    };
  }>('/api/ai/suggest', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ unmapped_line: unmappedLine, vendor }),
  });
}

// 4. POST /api/ai/approve
export async function approveSuggestion(payload: {
  suggestion_id: string;
  decision: 'approve' | 'reject' | 'approve_with_correction';
  corrected_mapping?: any;
  session_id?: string;
  reviewer_name?: string;
}) {
  const { reviewer_name: _ignored, ...wirePayload } = payload;
  return request<any>('/api/ai/approve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(wirePayload),
  });
}

// 4a. Trusted Rule Library Endpoints
export async function getTrustedMappings(vendor?: string, status?: string): Promise<TrustedMappingItem[]> {
  const params = new URLSearchParams();
  if (vendor && vendor !== 'all') params.append('vendor', vendor);
  if (status && status !== 'all') params.append('status', status);
  const qs = params.toString() ? `?${params.toString()}` : '';
  return request<TrustedMappingItem[]>(`/api/trusted-mappings${qs}`);
}

export async function getTrustedMapping(vendorRuleId: string): Promise<TrustedMappingItem> {
  return request<TrustedMappingItem>(`/api/trusted-mappings/${encodeURIComponent(vendorRuleId)}`);
}

export async function deleteTrustedMapping(vendorRuleId: string): Promise<{ success: boolean; message: string; vendor_rule_id: string; retired_by: string }> {
  return request<{ success: boolean; message: string; vendor_rule_id: string; retired_by: string }>(`/api/trusted-mappings/${encodeURIComponent(vendorRuleId)}`, {
    method: 'DELETE',
  });
}

export async function getPendingSuggestions(vendor?: string, status?: string): Promise<SuggestionQueueItem[]> {
  const params = new URLSearchParams();
  if (vendor && vendor !== 'all') params.append('vendor', vendor);
  if (status && status !== 'all') params.append('status', status);
  const qs = params.toString() ? `?${params.toString()}` : '';
  return request<SuggestionQueueItem[]>(`/api/ai/suggestions${qs}`);
}

export async function getPendingSuggestion(suggestionId: string): Promise<SuggestionQueueItem> {
  return request<SuggestionQueueItem>(`/api/ai/suggestions/${encodeURIComponent(suggestionId)}`);
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

// 11. GET /api/model/status
export async function getModelStatus(): Promise<ModelStatus> {
  return request<ModelStatus>('/api/model/status');
}

// 12. POST /api/model/mode
export async function setModelMode(payload: ModelModeUpdateRequest): Promise<ModelModeUpdateResponse> {
  return request<ModelModeUpdateResponse>('/api/model/mode', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

// 13. GET /api/compliance/frameworks
export async function getComplianceFrameworks() {
  return request<{
    frameworks: Array<{
      framework_id: string;
      display_name: string;
      version: string;
      authority: string;
      control_count: number;
      platform: string;
      enabled: boolean;
    }>;
    total_count: number;
  }>('/api/compliance/frameworks');
}

// 14. POST /api/compliance/evaluate
export async function evaluateCompliance(payload: {
  session_id?: string;
  csm?: any;
  raw_config?: string;
  framework_ids?: string[];
}) {
  return request<{
    audit_id: string | null;
    device_hostname: string;
    evaluation_timestamp: string;
    overall_metrics: {
      total_frameworks: number;
      total_controls: number;
      total_pass: number;
      total_fail: number;
      total_unknown: number;
      compliance_percentage: number;
      by_severity: {
        CRITICAL: { total: number; pass: number; fail: number; unknown: number };
        HIGH: { total: number; pass: number; fail: number; unknown: number };
        MEDIUM: { total: number; pass: number; fail: number; unknown: number };
        LOW: { total: number; pass: number; fail: number; unknown: number };
      };
    };
    framework_summaries: Record<string, any>;
    consolidated_evidence: any[];
  }>('/api/compliance/evaluate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

