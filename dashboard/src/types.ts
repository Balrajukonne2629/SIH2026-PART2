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
