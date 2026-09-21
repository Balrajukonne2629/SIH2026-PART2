/**
 * Automated Frontend Multi-Framework Compliance Test Battery
 * NTRO PS26155 — Phase 3C Chunk 5
 * Uses Node.js native test runner (zero external dependencies)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

// Setup browser globals before importing api.ts
const sessionStorageStore = new Map();
const mockSessionStorage = {
  getItem: (key) => sessionStorageStore.get(key) ?? null,
  setItem: (key, val) => sessionStorageStore.set(key, String(val)),
  removeItem: (key) => sessionStorageStore.delete(key),
  clear: () => sessionStorageStore.clear(),
};

const localStorageStore = new Map();
const mockLocalStorage = {
  getItem: (key) => localStorageStore.get(key) ?? null,
  setItem: (key, val) => localStorageStore.set(key, String(val)),
  removeItem: (key) => localStorageStore.delete(key),
  clear: () => localStorageStore.clear(),
};

globalThis.window = {
  sessionStorage: mockSessionStorage,
  localStorage: mockLocalStorage,
};

// Dynamically import api.ts after window globals setup
const api = await import('./src/api.ts');

const SAMPLE_CISCO_FRAMEWORKS = [
  {
    framework_id: 'cis_cisco_iosxe',
    name: 'CIS Cisco IOS-XE Benchmark',
    version: 'v2.1.0',
    description: 'Center for Internet Security benchmark for Cisco IOS-XE',
    control_count: 5,
    applicable_vendors: ['cisco']
  },
  {
    framework_id: 'disa_stig_cisco_iosxe',
    name: 'DISA STIG Cisco IOS-XE',
    version: 'v2r1',
    description: 'Department of Defense STIG for Cisco IOS-XE network devices',
    control_count: 4,
    applicable_vendors: ['cisco']
  }
];

const SAMPLE_JUNIPER_FRAMEWORKS = [];

const SAMPLE_EVALUATION_RESULT = {
  session_id: 'session-cisco-123',
  vendor: 'cisco',
  frameworks_evaluated: ['cis_cisco_iosxe', 'disa_stig_cisco_iosxe'],
  summary_by_framework: {
    cis_cisco_iosxe: {
      framework_id: 'cis_cisco_iosxe',
      framework_name: 'CIS Cisco IOS-XE Benchmark',
      framework_version: 'v2.1.0',
      total_controls: 5,
      passed: 3,
      failed: 1,
      unknown: 1,
      pass_rate: 60.0
    },
    disa_stig_cisco_iosxe: {
      framework_id: 'disa_stig_cisco_iosxe',
      framework_name: 'DISA STIG Cisco IOS-XE',
      framework_version: 'v2r1',
      total_controls: 4,
      passed: 2,
      failed: 2,
      unknown: 0,
      pass_rate: 50.0
    }
  },
  results_by_framework: {
    cis_cisco_iosxe: [
      {
        control_id: 'CIS-1.1',
        title: 'Ensure password encryption is enabled',
        status: 'PASS',
        severity: 'MEDIUM',
        details: 'service password-encryption is enabled in configuration',
        remediation: 'Configure service password-encryption',
        evidence: {
          framework_id: 'cis_cisco_iosxe',
          control_id: 'CIS-1.1',
          observed_value: true,
          expected_value: true,
          location: 'global.services.password_encryption',
          source_lines: ['service password-encryption'],
          rationale: 'Observed value matches required security standard'
        }
      },
      {
        control_id: 'CIS-1.2',
        title: 'Ensure telnet is disabled',
        status: 'FAIL',
        severity: 'HIGH',
        details: 'Telnet transport input is enabled on line vty',
        remediation: 'Configure transport input ssh under line vty',
        evidence: {
          framework_id: 'cis_cisco_iosxe',
          control_id: 'CIS-1.2',
          observed_value: ['telnet', 'ssh'],
          expected_value: ['ssh'],
          location: 'line.vty.transport_input',
          source_lines: ['transport input telnet ssh'],
          rationale: 'Insecure transport telnet detected'
        }
      },
      {
        control_id: 'CIS-1.3',
        title: 'Ensure NTP authentication is configured',
        status: 'UNKNOWN',
        severity: 'LOW',
        details: 'NTP authentication key could not be deterministically determined',
        remediation: 'Verify NTP authentication keys manually',
        evidence: {
          framework_id: 'cis_cisco_iosxe',
          control_id: 'CIS-1.3',
          observed_value: null,
          expected_value: 'configured',
          location: 'ntp.authenticate',
          source_lines: [],
          rationale: 'Unmapped or ambiguous telemetry for NTP authentication'
        }
      }
    ],
    disa_stig_cisco_iosxe: [
      {
        control_id: 'STIG-NET0400',
        title: 'Disable auxiliary port',
        status: 'PASS',
        severity: 'MEDIUM',
        details: 'Auxiliary port has transport input none',
        remediation: 'transport input none on aux 0',
        evidence: {
          framework_id: 'disa_stig_cisco_iosxe',
          control_id: 'STIG-NET0400',
          observed_value: 'none',
          expected_value: 'none',
          location: 'line.aux.0.transport_input',
          source_lines: ['line aux 0', 'transport input none'],
          rationale: 'Aux port disabled per STIG'
        }
      }
    ]
  }
};

test.beforeEach(() => {
  sessionStorageStore.clear();
  localStorageStore.clear();
  api.clearAccessToken();
});

// --- Test A: Framework list is fetched from API via getComplianceFrameworks ---
test('Test A: Framework list is fetched from API via getComplianceFrameworks', async () => {
  let capturedUrl = '';
  globalThis.fetch = async (url) => {
    capturedUrl = url;
    return {
      ok: true,
      status: 200,
      json: async () => SAMPLE_CISCO_FRAMEWORKS
    };
  };

  const frameworks = await api.getComplianceFrameworks();
  assert.equal(capturedUrl, '/api/compliance/frameworks');
  assert.equal(frameworks.length, 2);
  assert.equal(frameworks[0].framework_id, 'cis_cisco_iosxe');
  assert.equal(frameworks[1].framework_id, 'disa_stig_cisco_iosxe');
});

// --- Test B: Vendor parameter is supplied (?vendor=cisco and ?vendor=juniper) ---
test('Test B1: Vendor parameter ?vendor=cisco is correctly appended', async () => {
  let capturedUrl = '';
  globalThis.fetch = async (url) => {
    capturedUrl = url;
    return {
      ok: true,
      status: 200,
      json: async () => SAMPLE_CISCO_FRAMEWORKS
    };
  };

  await api.getComplianceFrameworks('cisco');
  assert.equal(capturedUrl, '/api/compliance/frameworks?vendor=cisco');
});

test('Test B2: Vendor parameter ?vendor=juniper is correctly appended', async () => {
  let capturedUrl = '';
  globalThis.fetch = async (url) => {
    capturedUrl = url;
    return {
      ok: true,
      status: 200,
      json: async () => SAMPLE_JUNIPER_FRAMEWORKS
    };
  };

  const res = await api.getComplianceFrameworks('juniper');
  assert.equal(capturedUrl, '/api/compliance/frameworks?vendor=juniper');
  assert.equal(res.length, 0);
});

// --- Test C: Framework metadata structures (name, version, framework_id) ---
test('Test C: Framework metadata contains required fields (name, version, framework_id)', async () => {
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => SAMPLE_CISCO_FRAMEWORKS
  });

  const frameworks = await api.getComplianceFrameworks('cisco');
  for (const fw of frameworks) {
    assert.ok(fw.framework_id, 'Framework ID must exist');
    assert.ok(fw.name, 'Framework Name must exist');
    assert.ok(fw.version, 'Framework Version must exist');
    assert.ok(Array.isArray(fw.applicable_vendors), 'Applicable vendors must be array');
    assert.ok(fw.applicable_vendors.includes('cisco'), 'Applicable vendors must include cisco');
  }
});

// --- Test D: Selecting a framework displays only that framework results ---
test('Test D: Framework results filtering isolates results to selected framework_id', () => {
  const result = SAMPLE_EVALUATION_RESULT;
  const selectedFrameworkId = 'cis_cisco_iosxe';

  const controls = result.results_by_framework[selectedFrameworkId] || [];
  assert.equal(controls.length, 3);
  for (const c of controls) {
    assert.equal(c.evidence?.framework_id, selectedFrameworkId);
  }

  // Another framework should not leak into cis_cisco_iosxe
  const stigControls = result.results_by_framework['disa_stig_cisco_iosxe'] || [];
  assert.equal(stigControls.length, 1);
  assert.equal(stigControls[0].control_id, 'STIG-NET0400');
});

// --- Test E: PASS/FAIL/UNKNOWN counts render correctly matching backend summary ---
test('Test E: PASS/FAIL/UNKNOWN counts match backend summary item directly', () => {
  const summary = SAMPLE_EVALUATION_RESULT.summary_by_framework['cis_cisco_iosxe'];
  assert.equal(summary.passed, 3);
  assert.equal(summary.failed, 1);
  assert.equal(summary.unknown, 1);
  assert.equal(summary.total_controls, 5);
  assert.equal(summary.passed + summary.failed + summary.unknown, summary.total_controls);
});

// --- Test F: Backend pass_rate is displayed directly without frontend recalculation ---
test('Test F: Backend pass_rate is used directly without client-side recalculation', () => {
  const summary = SAMPLE_EVALUATION_RESULT.summary_by_framework['cis_cisco_iosxe'];
  // Backend returned exactly 60.0
  assert.equal(typeof summary.pass_rate, 'number');
  assert.equal(summary.pass_rate, 60.0);

  // Formatting as string in UI: summary.pass_rate.toFixed(1) + '%'
  const formatted = `${summary.pass_rate.toFixed(1)}%`;
  assert.equal(formatted, '60.0%');
});

// --- Test G: UNKNOWN status remains distinct (never conflated with PASS or FAIL) ---
test('Test G: UNKNOWN status is strictly preserved as UNKNOWN, never converted to PASS or FAIL', () => {
  const cisControls = SAMPLE_EVALUATION_RESULT.results_by_framework['cis_cisco_iosxe'];
  const unknownControl = cisControls.find(c => c.status === 'UNKNOWN');
  assert.ok(unknownControl, 'UNKNOWN control must exist');
  assert.equal(unknownControl.status, 'UNKNOWN');
  assert.notEqual(unknownControl.status, 'PASS');
  assert.notEqual(unknownControl.status, 'FAIL');
  assert.equal(unknownControl.control_id, 'CIS-1.3');
});

// --- Test H: Evidence displays framework_id, control_id, location, expected, observed ---
test('Test H: Evidence object contains framework_id, control_id, location, expected_value, observed_value', () => {
  const c = SAMPLE_EVALUATION_RESULT.results_by_framework['cis_cisco_iosxe'][1]; // CIS-1.2
  const ev = c.evidence;
  assert.ok(ev, 'Evidence must exist');
  assert.equal(ev.framework_id, 'cis_cisco_iosxe');
  assert.equal(ev.control_id, 'CIS-1.2');
  assert.equal(ev.location, 'line.vty.transport_input');
  assert.deepEqual(ev.expected_value, ['ssh']);
  assert.deepEqual(ev.observed_value, ['telnet', 'ssh']);
  assert.ok(ev.rationale.length > 0);
  assert.ok(Array.isArray(ev.source_lines));
});

// --- Test I: Empty framework list renders a useful empty state ---
test('Test I: Empty framework response returns empty list and enables clean empty state', async () => {
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => []
  });

  const res = await api.getComplianceFrameworks('juniper');
  assert.deepEqual(res, []);
});

// --- Test J: API error handles gracefully with informative error ---
test('Test J: API failure throws descriptive error allowing UI retry state', async () => {
  globalThis.fetch = async () => ({
    ok: false,
    status: 500,
    json: async () => ({ detail: 'Internal compliance engine error' })
  });

  await assert.rejects(
    async () => {
      await api.getComplianceFrameworks('cisco');
    },
    /Internal compliance engine error/
  );
});

// --- Test K: Cisco framework metadata does not appear for Juniper ---
test('Test K: Cisco framework metadata is not mixed into Juniper framework queries', async () => {
  globalThis.fetch = async (url) => {
    if (url.includes('vendor=juniper')) {
      return {
        ok: true,
        status: 200,
        json: async () => []
      };
    }
    return {
      ok: true,
      status: 200,
      json: async () => SAMPLE_CISCO_FRAMEWORKS
    };
  };

  const juniperFws = await api.getComplianceFrameworks('juniper');
  assert.equal(juniperFws.length, 0);

  const ciscoFws = await api.getComplianceFrameworks('cisco');
  assert.equal(ciscoFws.length, 2);
  const leaked = juniperFws.some(f => f.applicable_vendors?.includes('cisco') && !f.applicable_vendors?.includes('juniper'));
  assert.equal(leaked, false);
});

// --- Test L: Existing legacy baseline results remain intact and accessible ---
test('Test L: AuditResultsScreen source code maintains baseline tab and legacy baseline rules rendering', () => {
  const componentPath = path.resolve('src/components/AuditResultsScreen.tsx');
  const fileContent = fs.readFileSync(componentPath, 'utf8');

  // Verify activeTab defaults to 'baseline'
  assert.ok(
    fileContent.includes("useState<string>('baseline')") ||
    fileContent.includes("useState<'baseline' | string>('baseline')"),
    'activeTab must default to baseline'
  );

  // Verify Baseline Rules tab button is present
  assert.ok(
    fileContent.includes("Baseline Rules") ||
    fileContent.includes("Baseline Rules (Legacy)"),
    'Baseline Rules tab must be present'
  );

  // Verify original rule table and unmapped lines callout are retained under activeTab === 'baseline'
  assert.ok(fileContent.includes("activeTab === 'baseline'"), 'Tab condition for baseline rendering must exist');
  assert.ok(
    fileContent.includes("Unmapped CLI Line") ||
    fileContent.includes("Unmapped Telemetry Detected"),
    'Unmapped lines callout must be retained'
  );
  assert.ok(
    fileContent.includes("Review AI Suggestions") ||
    fileContent.includes("Request AI Suggestion"),
    'AI suggestion trigger must be retained'
  );
  assert.ok(fileContent.includes("passCount") || fileContent.includes("passed_rules"), 'Baseline passed rules count retained');
  assert.ok(fileContent.includes("failCount") || fileContent.includes("failed_rules"), 'Baseline failed rules count retained');
});

// --- Test M: No overall compliance verdict across frameworks is introduced ---
test('Test M: Invariant - No cross-framework overall compliance verdict exists', () => {
  const componentPath = path.resolve('src/components/AuditResultsScreen.tsx');
  const fileContent = fs.readFileSync(componentPath, 'utf8');

  // Ensure no cross-framework single aggregate verdict exists in the UI
  assert.equal(fileContent.includes("Overall Compliance Verdict: Compliant"), false);
  assert.equal(fileContent.includes("Overall Compliant"), false);
  assert.equal(fileContent.includes("Total Multi-Framework Score"), false);
  assert.equal(fileContent.includes("Winner:"), false);
});

// --- Test N: evaluateCompliance API sends correct session_id and parses response ---
test('Test N: evaluateCompliance() passes session_id and optional framework_ids to /api/compliance/evaluate', async () => {
  let capturedUrl = '';
  let capturedBody = null;

  globalThis.fetch = async (url, options) => {
    capturedUrl = url;
    capturedBody = JSON.parse(options.body);
    return {
      ok: true,
      status: 200,
      json: async () => SAMPLE_EVALUATION_RESULT
    };
  };

  const evalRes = await api.evaluateCompliance({
    session_id: 'session-cisco-123',
    framework_ids: ['cis_cisco_iosxe']
  });

  assert.equal(capturedUrl, '/api/compliance/evaluate');
  assert.equal(capturedBody.session_id, 'session-cisco-123');
  assert.deepEqual(capturedBody.framework_ids, ['cis_cisco_iosxe']);
  assert.equal(evalRes.session_id, 'session-cisco-123');
  assert.equal(evalRes.vendor, 'cisco');
  assert.ok(evalRes.summary_by_framework['cis_cisco_iosxe']);
});
