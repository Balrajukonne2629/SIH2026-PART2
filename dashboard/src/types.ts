export type AuditStatus = 'Pass' | 'Fail' | 'Unknown';

export interface FrameworkMapping {
  framework: 'CIS' | 'DISA-STIG' | 'NIST-800-53';
  controlId: string;
  sourceRef?: string;
}

export interface RuleResult {
  ruleId: string;
  focus: string;
  status: AuditStatus;
  evidenceFound: string[];
  description?: string;
  category?: string;
  frameworkMappings?: FrameworkMapping[];
}

export interface UnmappedLineItem {
  id: string;
  rawLine: string;
  suggestedRuleTitle: string;
  suggestedField: string;
  suggestedCondition: string;
  confidence: number; // 0.0 to 1.0
  rationale: string;
  frameworkHints: {
    framework: string;
    possibleControlId: string;
  }[];
  status: 'pending' | 'approved' | 'approved_with_correction' | 'rejected';
  reviewedBy?: string;
  reviewedAt?: string;
}

export interface ConflictItem {
  conflictId: string;
  title: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  mitigation: string;
  affectedComponents: string[];
}

export interface RemediationDetail {
  ruleId: string;
  focus: string;
  status: 'Fail';
  whyItFailed: string;
  remediationCommand: string;
  conflicts: ConflictItem[];
  hasConflicts: boolean;
  affectedInterfaces?: string[];
  referenceDocument?: string;
}

export interface AuditLogEntry {
  entryId: string;
  sequence: number;
  timestamp: string;
  deviceHostname: string;
  platform: string;
  configFileHash: string;
  entryHash: string;
  prevEntryHash: string;
  summary: {
    total: number;
    pass: number;
    fail: number;
    unknown: number;
  };
  remediationRule?: string;
  conflictCount?: number;
  pdfReportFileName: string;
  pdfSizeBytes: number;
}

export interface RecentAudit {
  id: string;
  deviceHostname: string;
  platform: string;
  date: string;
  configFile: string;
  configFileHash: string;
  counts: {
    pass: number;
    fail: number;
    unknown: number;
  };
  overallStatus: 'COMPLIANT' | 'NON-COMPLIANT' | 'NEEDS-REVIEW';
}

export interface UserIdentity {
  user_id: string;
  username: string;
  role: 'uploader' | 'reviewer' | 'viewer';
  is_authorized_approver: boolean;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  user: UserIdentity;
}

export type ScreenId = 'upload' | 'results' | 'ai_review' | 'remediation' | 'audit_log' | 'model_ops';

export type ModelMode = 'auto' | 'fast' | 'quality' | 'override' | 'deterministic_only';

export interface HardwareProfile {
  total_ram_gb: number;
  available_ram_gb: number;
  cpu_cores: number;
  cpu_threads: number;
  has_gpu: boolean;
  gpu_type: string;
  vram_gb: number;
  gpu_name: string | null;
  probe_error: string | null;
}

export interface ModelStatus {
  mode: ModelMode;
  configured_mode: ModelMode;
  effective_model: string;
  override_model: string | null;
  available_models: string[];
  hardware_profile: HardwareProfile;
  ollama_alive: boolean;
  fallback_active: boolean;
  fallback_reason: string | null;
}

export interface ModelModeUpdateRequest {
  mode: ModelMode;
  override_model?: string | null;
}

export interface ModelModeUpdateResponse extends ModelStatus {
  success: boolean;
  message: string;
}

