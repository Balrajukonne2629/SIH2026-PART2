/**
 * Automated Frontend Report Workflow & Export Verification Test Battery
 * NTRO PS26155 — Phase 3D Report Workflow Repair
 * Uses Node.js native test runner
 */

import test from 'node:test';
import assert from 'node:assert/strict';

// Setup browser globals before importing api.ts
const sessionStorageStore = new Map();
const mockSessionStorage = {
  getItem: (key) => sessionStorageStore.get(key) ?? null,
  setItem: (key, val) => sessionStorageStore.set(key, String(val)),
  removeItem: (key) => sessionStorageStore.delete(key),
  clear: () => sessionStorageStore.clear(),
};

globalThis.window = {
  sessionStorage: mockSessionStorage,
};

// Import api functions
const api = await import('./src/api.ts');

test.beforeEach(() => {
  sessionStorageStore.clear();
  api.clearAccessToken();
});

test('1. Reviewer login stores bearer token for subsequent calls', async () => {
  globalThis.fetch = async (url, options) => {
    if (url === '/api/auth/login') {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'valid.reviewer.jwt.token',
          token_type: 'bearer',
          user: {
            user_id: 'usr-reviewer-1',
            username: 'reviewer_lead',
            role: 'reviewer',
            is_authorized_approver: true,
          },
        }),
      };
    }
    throw new Error(`Unexpected url: ${url}`);
  };

  const loginRes = await api.login('reviewer_lead', 'ValidPass123!');
  assert.equal(loginRes.access_token, 'valid.reviewer.jwt.token');
  assert.equal(api.getAccessToken(), 'valid.reviewer.jwt.token');
});

test('2. getReportByEntryId resolves canonical report_id using Bearer token', async () => {
  api.setAccessToken('valid.reviewer.jwt.token');
  let capturedUrl = '';
  let capturedHeaders = null;

  globalThis.fetch = async (url, options) => {
    capturedUrl = url;
    capturedHeaders = options.headers;
    return {
      ok: true,
      status: 200,
      json: async () => ({
        report_id: 'RPT-abc12345-AUDIT-001',
        audit_entry_id: 'AUDIT-001',
        version: 1,
      }),
    };
  };

  const rep = await api.getReportByEntryId('AUDIT-001');
  assert.equal(capturedUrl, '/api/reports/by-entry/AUDIT-001');
  assert.equal(capturedHeaders.Authorization, 'Bearer valid.reviewer.jwt.token');
  assert.equal(rep.report_id, 'RPT-abc12345-AUDIT-001');
});

test('3. patchCanonicalReport sends PATCH with Bearer token, field_path, and expected_version', async () => {
  api.setAccessToken('valid.reviewer.jwt.token');
  let capturedUrl = '';
  let capturedMethod = '';
  let capturedBody = null;
  let capturedHeaders = null;

  globalThis.fetch = async (url, options) => {
    capturedUrl = url;
    capturedMethod = options.method;
    capturedBody = JSON.parse(options.body);
    capturedHeaders = options.headers;
    return {
      ok: true,
      status: 200,
      json: async () => ({
        report_id: 'RPT-abc12345-AUDIT-001',
        version: 2,
        editable_content: {
          executive_summary: 'Updated by reviewer lead.',
        },
      }),
    };
  };

  const updated = await api.patchCanonicalReport(
    'RPT-abc12345-AUDIT-001',
    'executive_summary',
    'Updated by reviewer lead.',
    1
  );

  assert.equal(capturedUrl, '/api/reports/RPT-abc12345-AUDIT-001');
  assert.equal(capturedMethod, 'PATCH');
  assert.equal(capturedHeaders.Authorization, 'Bearer valid.reviewer.jwt.token');
  assert.equal(capturedBody.field_path, 'executive_summary');
  assert.equal(capturedBody.new_value, 'Updated by reviewer lead.');
  assert.equal(capturedBody.expected_version, 1);
  assert.equal(updated.version, 2);
});

test('4. exportCanonicalReportBlob sends POST to /api/reports/{id}/export/pdf with Bearer token', async () => {
  api.setAccessToken('valid.reviewer.jwt.token');
  let capturedUrl = '';
  let capturedMethod = '';
  let capturedHeaders = null;

  globalThis.fetch = async (url, options) => {
    capturedUrl = url;
    capturedMethod = options.method;
    capturedHeaders = options.headers;
    return {
      ok: true,
      status: 200,
      blob: async () => new Blob(['%PDF-1.4 simulated pdf'], { type: 'application/pdf' }),
    };
  };

  const blob = await api.exportCanonicalReportBlob('RPT-abc12345-AUDIT-001', 'pdf');
  assert.equal(capturedUrl, '/api/reports/RPT-abc12345-AUDIT-001/export/pdf');
  assert.equal(capturedMethod, 'POST');
  assert.equal(capturedHeaders.Authorization, 'Bearer valid.reviewer.jwt.token');
  assert.ok(blob);
});

test('5. exportCanonicalReportBlob sends POST to /api/reports/{id}/export/docx with Bearer token', async () => {
  api.setAccessToken('valid.reviewer.jwt.token');
  let capturedUrl = '';
  let capturedMethod = '';
  let capturedHeaders = null;

  globalThis.fetch = async (url, options) => {
    capturedUrl = url;
    capturedMethod = options.method;
    capturedHeaders = options.headers;
    return {
      ok: true,
      status: 200,
      blob: async () => new Blob(['PK simulated docx'], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' }),
    };
  };

  const blob = await api.exportCanonicalReportBlob('RPT-abc12345-AUDIT-001', 'docx');
  assert.equal(capturedUrl, '/api/reports/RPT-abc12345-AUDIT-001/export/docx');
  assert.equal(capturedMethod, 'POST');
  assert.equal(capturedHeaders.Authorization, 'Bearer valid.reviewer.jwt.token');
  assert.ok(blob);
});

test('6. Invariant: Active workflow NEVER invokes legacy GET /api/report/{entry_id}/download', async () => {
  api.setAccessToken('valid.reviewer.jwt.token');
  const calledUrls = [];

  globalThis.fetch = async (url, options) => {
    calledUrls.push(url);
    if (url.includes('/download')) {
      throw new Error(`VIOLATION: Legacy download endpoint was invoked: ${url}`);
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({}),
      blob: async () => new Blob(['data']),
    };
  };

  // Simulate complete workflow
  await api.getReportByEntryId('AUDIT-SEQ-001');
  await api.patchCanonicalReport('RPT-123', 'executive_summary', 'Test edit', 1);
  await api.exportCanonicalReportBlob('RPT-123', 'pdf');
  await api.exportCanonicalReportBlob('RPT-123', 'docx');

  // Verify none of the called URLs were the legacy endpoint
  for (const u of calledUrls) {
    assert.ok(!u.includes('/download'), `Found legacy download in called URLs: ${u}`);
  }
});

test('7. getLedger returns has_canonical_report and report_id without client-side N+1 requests', async () => {
  api.setAccessToken('valid.reviewer.jwt.token');
  const calledUrls = [];

  globalThis.fetch = async (url, options) => {
    calledUrls.push(url);
    if (url === '/api/ledger') {
      return {
        ok: true,
        status: 200,
        json: async () => [
          {
            entry_id: 'AUDIT-LEGACY-001',
            device_hostname: 'rtr-old',
            timestamp: '2026-01-01T00:00:00Z',
            has_canonical_report: false,
            report_id: null,
          },
          {
            entry_id: 'AUDIT-CANONICAL-002',
            device_hostname: 'rtr-new',
            timestamp: '2026-09-22T00:00:00Z',
            has_canonical_report: true,
            report_id: 'RPT-CANONICAL-002',
          },
        ],
      };
    }
    throw new Error(`Unexpected N+1 call: ${url}`);
  };

  const ledger = await api.getLedger();
  assert.equal(ledger.length, 2);
  assert.equal(ledger[0].has_canonical_report, false);
  assert.equal(ledger[0].report_id, null);
  assert.equal(ledger[1].has_canonical_report, true);
  assert.equal(ledger[1].report_id, 'RPT-CANONICAL-002');

  // Verify only 1 network request was made (no N+1 loop)
  assert.deepEqual(calledUrls, ['/api/ledger']);
});

