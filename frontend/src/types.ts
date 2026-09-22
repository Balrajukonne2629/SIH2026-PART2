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

export interface AuditLedgerItem {
  entry_id: string;
  timestamp: string;
  device_hostname: string;
  config_file_hash: string;
  audit_results: Record<string, any>;
  remediation_summary?: any;
  prevEntryHash: string;
  entryHash: string;
  has_canonical_report: boolean;
  report_id: string | null;
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

export interface TrustedMappingItem {
  vendor_rule_id: string;
  common_rule_id?: string;
  internalTitle: string;
  csmFieldChecked: string;
  condition: string;
  configuration_evidence?: string[];
  check_focus?: string[];
  frameworkMappings?: Array<{ framework: string; possible_control_id?: string; controlId?: string }>;
  version_info?: {
    version?: string;
    approved_by?: string;
    approved_at?: string;
    source?: 'ai_suggested' | 'human_corrected' | string;
  };
  vendor?: string;
  status?: 'approved' | 'corrected' | 'rejected' | 'retired' | string;
  created_at?: string;
  updated_at?: string;
}

export interface SuggestionQueueItem {
  suggestion_id: string;
  timestamp: string;
  status: 'pending' | 'approve' | 'approved' | 'approve_with_correction' | 'corrected' | 'rejected' | string;
  suggestion: {
    raw_line: string;
    suggested_rule_id: string | null;
    suggested_new_rule?: {
      internalTitle: string;
      csmFieldChecked: string;
      condition: string;
      vendor?: string;
    };
    confidence: number;
    rationale: string;
    framework_hints?: Array<{ framework: string; possible_control_id: string }>;
    vendor?: string;
  };
  reviewed_by?: string | null;
  reviewed_at?: string | null;
  vendor?: string;
}

export interface FrameworkMetadataItem {
  framework_id: string;
  name: string;
  version: string;
  description: string;
  vendor_scope: string;
  control_namespace: string;
  control_count: number;
  severity_distribution: Record<string, number>;
  enabled: boolean;
}

export interface FrameworksListResponse {
  frameworks: FrameworkMetadataItem[];
  total_count: number;
}

export interface FrameworkSummaryItem {
  framework_id: string;
  framework_name: string | null;
  framework_version: string | null;
  total_controls: number;
  pass_count: number;
  fail_count: number;
  unknown_count: number;
  pass_rate: number | null;
  unknown_rate: number | null;
  results: Array<{
    control_id: string;
    status: string;
    observed_value: any;
    expected_value: any;
    location: string;
    rationale: string;
    framework_id: string;
    confidence: number;
    source_lines: string[];
  }>;
}

export interface OverallMetricsItem {
  total_frameworks: number;
  total_controls: number;
  total_pass: number;
  total_fail: number;
  total_unknown: number;
  overall_pass_rate: number | null;
  overall_unknown_rate: number | null;
}

export interface ConsolidatedEvidenceItem {
  framework_id: string;
  control_id: string;
  status: string;
  observed_value: any;
  location: string;
  expected_value: any;
  rationale: string;
  confidence: number;
  source_lines: string[];
}

export interface MultiFrameworkAuditResult {
  audit_id: string | null;
  device_hostname: string | null;
  framework_summaries: Record<string, FrameworkSummaryItem>;
  overall_metrics: OverallMetricsItem;
  consolidated_evidence: ConsolidatedEvidenceItem[];
  timestamp: string | null;
}

