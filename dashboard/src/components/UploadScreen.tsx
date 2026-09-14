import React, { useState, useEffect, useRef } from 'react';
import { uploadAuditConfig, getLedger } from '../api';

interface UploadScreenProps {
  onAuditStarted: (sessionId: string, initialResults: any) => void;
  onNavigateToLedger: () => void;
}

const SAMPLE_CONFIG = `! Labeled Reference Configuration - Cisco IOS-XE
! System and Platform Identification
hostname EDGE-RTR-01
!
! Management Plane Isolation (CISCO-MGMT-001 -> Pass)
vrf definition Mgmt-intf
 description Dedicated Management Network
 address-family ipv4
 exit-address-family
!
! Administrative Authentication & AAA Security (CISCO-AAA-001 -> Pass)
aaa new-model
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
aaa accounting exec default start-stop group tacacs+
!
! Secure Remote Administration (CISCO-SSH-001 -> Pass)
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
!
! Security Event Logging (CISCO-LOG-001 -> Pass)
service timestamps log datetime msec
logging buffered 64000
logging trap informational
logging host 10.10.10.50
!
! Approved Time Source (CISCO-NTP-001 -> Fail: server configured without authentication)
ntp server 192.168.100.1
no ntp authenticate
!
! Network Monitoring Access (CISCO-SNMP-001 -> Fail: insecure SNMPv1/v2c plaintext community string)
snmp-server community public RO
!
! Access Control Lists (CISCO-ACL-001 -> Pass)
ip access-list standard MGMT-ACCESS
 permit 10.10.0.0 0.0.255.255
 deny any
!
! Interface Hardening (CISCO-INT-001 -> Pass: unused port administratively shut down)
interface GigabitEthernet0/0/0
 description WAN-Uplink
 ip address 192.0.2.1 255.255.255.252
 no shutdown
!
interface GigabitEthernet0/0/1
 description Unused-Interface-1
 shutdown
!
interface GigabitEthernet0
 description Out-of-Band Management
 vrf forwarding Mgmt-intf
 ip address 10.255.255.1 255.255.255.0
 no shutdown
!
! Routing Protocol Security (CISCO-ROUTING-001 -> Pass: BGP peer with authentication)
router bgp 65000
 neighbor 192.0.2.2 remote-as 65000
 neighbor 192.0.2.2 password 7 BGPSecretAuthKey123!
!
! Management Service Restrictions (CISCO-MGMT-001 & CISCO-ACL-001)
ip http access-class MGMT-ACCESS
!
! VTY Lines Configuration (CISCO-SSH-001 & CISCO-ACL-001)
line vty 0 4
 access-class MGMT-ACCESS in
 transport input ssh
 login authentication default
!
! Deliberately unmapped CLI line not covered by any of the 10 rules (for AI-flow testing)
service call-home
!
end`;

export const UploadScreen: React.FC<UploadScreenProps> = ({
  onAuditStarted,
  onNavigateToLedger
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFileName, setSelectedFileName] = useState<string>('labeled_test_config.txt');
  const [fileContent, setFileContent] = useState<string>(SAMPLE_CONFIG);
  const [fileObject, setFileObject] = useState<File | undefined>(undefined);
  const [fileSize, setFileSize] = useState<number>(SAMPLE_CONFIG.length);

  // Async States
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  // Recent Audits from Real Ledger (GET /api/ledger)
  const [ledgerEntries, setLedgerEntries] = useState<any[]>([]);
  const [isLoadingLedger, setIsLoadingLedger] = useState(true);
  const [ledgerError, setLedgerError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Fetch real recent audits on mount
  useEffect(() => {
    fetchRecentAudits();
  }, []);

  const fetchRecentAudits = async () => {
    setIsLoadingLedger(true);
    setLedgerError(null);
    try {
      const entries = await getLedger();
      setLedgerEntries(entries || []);
    } catch (err: any) {
      setLedgerError(err.message);
    } finally {
      setIsLoadingLedger(false);
    }
  };

  const processSelectedFile = (file: File) => {
    setSelectedFileName(file.name);
    setFileSize(file.size);
    setFileObject(file);
    setUploadError(null);

    const reader = new FileReader();
    reader.onload = (e) => {
      const text = (e.target?.result as string) || '';
      setFileContent(text);
    };
    reader.readAsText(file);
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleBrowseChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      processSelectedFile(e.target.files[0]);
    }
  };

  const handleLoadSample = () => {
    setSelectedFileName('labeled_test_config.txt');
    setFileContent(SAMPLE_CONFIG);
    setFileSize(SAMPLE_CONFIG.length);
    setFileObject(undefined);
    setUploadError(null);
  };

  // Real Upload Execution: POST /api/audit/upload
  const handleExecuteAudit = async () => {
    setIsUploading(true);
    setUploadError(null);
    try {
      const result = await uploadAuditConfig(fileObject, fileContent, selectedFileName);
      onAuditStarted(result.session_id, result);
    } catch (err: any) {
      setUploadError(err.message);
    } finally {
      setIsUploading(false);
    }
  };

  const lineCount = fileContent.split('\n').length;

  return (
    <div className="space-y-8 font-sans">
      {/* Screen Title Bar */}
      <div className="border-b border-slate-800 pb-4 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white uppercase tracking-wide">
            Configuration Ingestion & Intake
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Upload raw Cisco IOS-XE configuration (.cfg, .txt) to execute deterministic CSM parsing and baseline compliance verification.
          </p>
        </div>
        <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
          API: http://127.0.0.1:8000
        </span>
      </div>

      {/* Upload Error Banner */}
      {uploadError && (
        <div className="bg-rose-950/60 border border-rose-700 rounded p-4 flex items-start space-x-3 text-xs text-rose-200">
          <svg className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div className="flex-1">
            <strong className="block font-mono uppercase font-bold text-rose-300">Upload & Parsing Error:</strong>
            <p className="mt-0.5">{uploadError}</p>
          </div>
          <button
            onClick={() => setUploadError(null)}
            className="text-rose-400 hover:text-white font-mono text-xs cursor-pointer"
          >
            ✕ Dismiss
          </button>
        </div>
      )}

      {/* Main Ingestion Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Drag & Drop Zone */}
        <div className="lg:col-span-8 space-y-4">
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            className={`border-2 border-dashed rounded p-8 text-center transition-all ${
              dragActive
                ? 'border-sky-500 bg-sky-950/20'
                : 'border-slate-700 bg-slate-900/60 hover:border-slate-600'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".cfg,.txt,.conf,.log"
              onChange={handleBrowseChange}
              className="hidden"
            />

            <div className="mx-auto w-12 h-12 rounded bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 mb-3">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
              </svg>
            </div>

            <h3 className="text-sm font-semibold text-slate-200">
              Select or Drag & Drop Cisco IOS-XE Configuration File
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Supports standard Cisco CLI output (<code className="font-mono text-slate-300">show running-config</code>), .txt or .cfg
            </p>

            <div className="mt-5 flex items-center justify-center gap-3">
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-medium transition-colors cursor-pointer border border-sky-400"
              >
                Browse Local File
              </button>
              <button
                type="button"
                onClick={handleLoadSample}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono transition-colors border border-slate-700 cursor-pointer"
              >
                Load Canonical Test Config (EDGE-RTR-01)
              </button>
            </div>

            <div className="mt-4 text-[11px] text-slate-500 font-mono">
              Processed offline in backend memory sandbox • No device connection made
            </div>
          </div>

          {/* Active File Stage Inspection Card */}
          {selectedFileName && (
            <div className="bg-slate-900 border border-slate-800 rounded p-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
                <div className="flex items-center space-x-2">
                  <span className="w-2 h-2 rounded-full bg-sky-400"></span>
                  <span className="text-xs font-semibold uppercase text-slate-300">
                    Staged Configuration Payload
                  </span>
                </div>
                <span className="font-mono text-[11px] text-emerald-400 bg-emerald-950/60 border border-emerald-800 px-2 py-0.5 rounded">
                  READY FOR AUDIT
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono mb-4">
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">File Name</span>
                  <span className="text-slate-200 font-bold">{selectedFileName}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Size</span>
                  <span className="text-slate-200">{fileSize} bytes</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Line Count</span>
                  <span className="text-slate-200">{lineCount} lines</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Target Vendor</span>
                  <span className="text-slate-200">Cisco IOS-XE</span>
                </div>
              </div>

              {/* Action Button */}
              <div className="flex justify-end items-center gap-3">
                <button
                  type="button"
                  disabled={isUploading}
                  onClick={handleExecuteAudit}
                  className={`px-6 py-2.5 rounded text-xs font-bold uppercase tracking-wider transition-colors shadow-sm flex items-center gap-2 border cursor-pointer ${
                    isUploading
                      ? 'bg-slate-800 text-slate-400 border-slate-700 cursor-not-allowed'
                      : 'bg-sky-600 hover:bg-sky-500 text-white border-sky-400'
                  }`}
                >
                  {isUploading ? (
                    <>
                      <span className="inline-block w-4 h-4 border-2 border-slate-400 border-t-transparent rounded-full animate-spin"></span>
                      <span>Executing Deterministic Audit...</span>
                    </>
                  ) : (
                    <>
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <span>Execute Deterministic Audit</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Ingestion Protocol & Validation Policy */}
        <div className="lg:col-span-4 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded p-4">
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider mb-3 flex items-center gap-2">
              <span className="w-1.5 h-1.5 bg-sky-400 rounded-sm"></span>
              CSM Audit Protocol Verification
            </h4>
            <div className="space-y-3 text-xs text-slate-400">
              <div className="border-l-2 border-emerald-500 pl-2.5 py-0.5">
                <div className="text-slate-200 font-medium">100% Deterministic Rule Engine</div>
                <div className="text-[11px] text-slate-400 mt-0.5">
                  CIS, DISA-STIG, and NIST 800-53 controls evaluate through fixed CSM conditions. Zero stochastic drift.
                </div>
              </div>

              <div className="border-l-2 border-amber-500 pl-2.5 py-0.5">
                <div className="text-slate-200 font-medium">Isolated AI Suggestion Sandbox</div>
                <div className="text-[11px] text-slate-400 mt-0.5">
                  Unrecognized CLI lines route to the local AI suggester. Suggestions require explicit human approval before mapping into trusted rules.
                </div>
              </div>

              <div className="border-l-2 border-sky-500 pl-2.5 py-0.5">
                <div className="text-slate-200 font-medium">Cryptographic Hash Chaining</div>
                <div className="text-[11px] text-slate-400 mt-0.5">
                  Every audit produces a linked hash entry in <code className="font-mono text-slate-300">audit_log.jsonl</code>, providing tamper-evident non-repudiation.
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800">
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>PARSER RUNTIME</span>
                <span className="text-emerald-400">OFFLINE / LOCAL</span>
              </div>
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mt-1">
                <span>ESTIMATED DURATION</span>
                <span className="text-slate-300">&lt; 150 ms (Deterministic)</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Audits Table Section (Fetched live from GET /api/ledger) */}
      <div className="bg-slate-900 border border-slate-800 rounded">
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-slate-400"></span>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Recent Audits Log (Ledger Source of Truth)
            </h3>
          </div>
          <button
            onClick={fetchRecentAudits}
            className="text-[11px] font-mono text-sky-400 hover:text-sky-300 flex items-center gap-1 cursor-pointer"
          >
            <span>↻ Refresh Ledger</span>
          </button>
        </div>

        {isLoadingLedger ? (
          <div className="p-8 text-center text-xs text-slate-400 font-mono">
            <span className="inline-block w-4 h-4 border-2 border-sky-400 border-t-transparent rounded-full animate-spin mr-2"></span>
            Loading recorded audits from backend ledger...
          </div>
        ) : ledgerError ? (
          <div className="p-6 text-center text-xs text-rose-300 font-mono">
            Failed to load ledger records: {ledgerError}
          </div>
        ) : ledgerEntries.length === 0 ? (
          /* UX Copy Empty State Pattern */
          <div className="p-10 text-center space-y-2">
            <div className="w-10 h-10 rounded bg-slate-800 border border-slate-700 text-slate-400 mx-auto flex items-center justify-center">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
            <h4 className="text-sm font-bold text-slate-300">No Prior Audits in Ledger</h4>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              The cryptographic ledger (<code className="font-mono text-slate-300">audit_log.jsonl</code>) has no entries yet because no compliance scans have been finalized.
            </p>
            <p className="text-xs text-sky-400 font-mono pt-1">
              Upload a Cisco IOS-XE configuration file above or click "Load Canonical Test Config" to execute your first audit.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-800 text-left">
              <thead className="bg-slate-950 font-mono text-[11px] text-slate-400 uppercase tracking-wider">
                <tr>
                  <th className="py-2.5 px-4 font-semibold">Entry ID / Sequence</th>
                  <th className="py-2.5 px-4 font-semibold">Device Hostname</th>
                  <th className="py-2.5 px-4 font-semibold">Timestamp (UTC)</th>
                  <th className="py-2.5 px-4 font-semibold">Config SHA-256</th>
                  <th className="py-2.5 px-4 font-semibold">Audit Breakdown</th>
                  <th className="py-2.5 px-4 font-semibold">Status</th>
                  <th className="py-2.5 px-4 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans text-xs">
                {ledgerEntries.map((entry, idx) => {
                  const results = entry.audit_results || {};
                  const passCount = Object.values(results).filter((v) => v === 'Pass').length;
                  const failCount = Object.values(results).filter((v) => v === 'Fail').length;
                  const unknownCount = Object.values(results).filter((v) => v === 'Unknown').length;

                  const overallStatus =
                    failCount > 0
                      ? 'NON-COMPLIANT'
                      : unknownCount > 0
                      ? 'NEEDS-REVIEW'
                      : 'COMPLIANT';

                  const statusColor =
                    overallStatus === 'COMPLIANT'
                      ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                      : overallStatus === 'NON-COMPLIANT'
                      ? 'bg-rose-950 text-rose-300 border-rose-800'
                      : 'bg-amber-950 text-amber-300 border-amber-800';

                  return (
                    <tr key={entry.entry_id || idx} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-mono font-bold text-sky-400">
                        #{idx + 1} <span className="text-slate-300 text-[11px] font-normal">{entry.entry_id}</span>
                      </td>
                      <td className="py-3 px-4 font-mono font-semibold text-slate-200">
                        {entry.device_hostname || 'unknown'}
                      </td>
                      <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                        {entry.timestamp}
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                        <span title={entry.config_file_hash}>
                          {(entry.config_file_hash || '').substring(0, 16)}...
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono">
                        <div className="flex items-center space-x-2 text-[11px]">
                          <span className="text-emerald-400 font-semibold" title="Pass">
                            {passCount}P
                          </span>
                          <span className="text-slate-600">/</span>
                          <span className="text-rose-400 font-semibold" title="Fail">
                            {failCount}F
                          </span>
                          <span className="text-slate-600">/</span>
                          <span className="text-amber-400 font-semibold" title="Unknown">
                            {unknownCount}U
                          </span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${statusColor}`}>
                          {overallStatus}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={onNavigateToLedger}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 text-xs font-mono transition-colors border border-slate-700 cursor-pointer"
                        >
                          View in Ledger &rarr;
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
    </div>
  );
};
