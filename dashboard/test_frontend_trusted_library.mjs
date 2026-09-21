/**
 * Automated Frontend Trusted Rule Library & Integration Test Battery
 * NTRO PS26155 — Phase 3B
 * Uses Node.js native test runner (zero external dependencies)
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

// Import api functions using dynamic import to ensure globals are in place
const api = await import('./src/api.ts');

test.beforeEach(() => {
  sessionStorageStore.clear();
  api.clearAccessToken();
});

test('1. getTrustedMappings() sends GET request to /api/trusted-mappings and includes Bearer token', async () => {
  let capturedUrl = '';
  let capturedHeaders = {};

  api.setAccessToken('valid.test.jwt.token');

  globalThis.fetch = async (url, options) => {
    capturedUrl = url;
    capturedHeaders = options?.headers || {};
    return {
      ok: true,
      status: 200,
      json: async () => ([
        {
          vendor_rule_id: 'CISCO-DIAG-001',
          common_rule_id: 'COMMON-DIAG-001',
          internalTitle: 'Disable unneeded telemetry',
          csmFieldChecked: 'csm.services.call_home',
          condition: 'equals False',
          vendor: 'cisco',
          status: 'approved',
          version_info: { approved_by: 'usr-reviewer', approved_at: '2026-09-21T00:00:00Z', source: 'ai_suggested' }
        }
      ]),
    };
  };

  const results = await api.getTrustedMappings();
  assert.equal(capturedUrl, '/api/trusted-mappings');
  assert.equal(capturedHeaders['Authorization'], 'Bearer valid.test.jwt.token');
  assert.equal(results.length, 1);
  assert.equal(results[0].vendor_rule_id, 'CISCO-DIAG-001');
  assert.equal(results[0].vendor, 'cisco');
});

test('2. getTrustedMappings(vendor="juniper") appends vendor query parameter', async () => {
  let capturedUrl = '';

  api.setAccessToken('valid.test.jwt.token');

  globalThis.fetch = async (url) => {
    capturedUrl = url;
    return {
      ok: true,
      status: 200,
      json: async () => ([]),
    };
  };

  await api.getTrustedMappings('juniper');
  assert.equal(capturedUrl, '/api/trusted-mappings?vendor=juniper');
});

test('3. getTrustedMapping(vendorRuleId) fetches specific rule by encoded ID', async () => {
  let capturedUrl = '';

  api.setAccessToken('valid.test.jwt.token');

  globalThis.fetch = async (url) => {
    capturedUrl = url;
    return {
      ok: true,
      status: 200,
      json: async () => ({
        vendor_rule_id: 'JUNOS-DIAG-001',
        internalTitle: 'Junos Call Home',
        csmFieldChecked: 'csm.services.call_home',
        condition: 'equals False',
        vendor: 'juniper',
        status: 'approved',
      }),
    };
  };

  const rule = await api.getTrustedMapping('JUNOS-DIAG-001');
  assert.equal(capturedUrl, '/api/trusted-mappings/JUNOS-DIAG-001');
  assert.equal(rule.vendor_rule_id, 'JUNOS-DIAG-001');
  assert.equal(rule.vendor, 'juniper');
});

test('4. deleteTrustedMapping(vendorRuleId) sends DELETE request to /api/trusted-mappings/{id}', async () => {
  let capturedUrl = '';
  let capturedMethod = '';

  api.setAccessToken('valid.test.jwt.token');

  globalThis.fetch = async (url, options) => {
    capturedUrl = url;
    capturedMethod = options?.method;
    return {
      ok: true,
      status: 200,
      json: async () => ({
        success: true,
        message: "Trusted mapping 'CISCO-TEST-001' successfully retired.",
        vendor_rule_id: 'CISCO-TEST-001',
        retired_by: 'usr-reviewer-1'
      }),
    };
  };

  const res = await api.deleteTrustedMapping('CISCO-TEST-001');
  assert.equal(capturedUrl, '/api/trusted-mappings/CISCO-TEST-001');
  assert.equal(capturedMethod, 'DELETE');
  assert.equal(res.success, true);
  assert.equal(res.retired_by, 'usr-reviewer-1');
});

test('5. getPendingSuggestions() fetches suggestions queue with optional vendor filter', async () => {
  let capturedUrl = '';

  api.setAccessToken('valid.test.jwt.token');

  globalThis.fetch = async (url) => {
    capturedUrl = url;
    return {
      ok: true,
      status: 200,
      json: async () => ([
        {
          suggestion_id: 'sug-123',
          timestamp: '2026-09-21T00:00:00Z',
          status: 'pending',
          vendor: 'cisco',
          suggestion: { raw_line: 'service call-home', confidence: 0.88, rationale: 'Test' }
        }
      ]),
    };
  };

  const queue = await api.getPendingSuggestions('cisco', 'pending');
  assert.equal(capturedUrl, '/api/ai/suggestions?vendor=cisco&status=pending');
  assert.equal(queue.length, 1);
  assert.equal(queue[0].suggestion_id, 'sug-123');
  assert.equal(queue[0].status, 'pending');
});

test('6. suggestMapping(unmappedLine, vendor="juniper") sends vendor in JSON body', async () => {
  let capturedUrl = '';
  let capturedBody = null;

  api.setAccessToken('valid.test.jwt.token');

  globalThis.fetch = async (url, options) => {
    capturedUrl = url;
    capturedBody = JSON.parse(options?.body);
    return {
      ok: true,
      status: 200,
      json: async () => ({
        suggestion_id: 'sug-juniper-456',
        suggestion: {
          raw_line: 'set system services call-home',
          suggested_new_rule: { internalTitle: 'Disable Junos Call Home', csmFieldChecked: 'csm.services.call_home', condition: 'equals False' },
          confidence: 0.88,
          rationale: 'Junos rationale',
          vendor: 'juniper'
        }
      }),
    };
  };

  const res = await api.suggestMapping('set system services call-home', 'juniper');
  assert.equal(capturedUrl, '/api/ai/suggest');
  assert.equal(capturedBody.unmapped_line, 'set system services call-home');
  assert.equal(capturedBody.vendor, 'juniper');
  assert.equal(res.suggestion_id, 'sug-juniper-456');
});
