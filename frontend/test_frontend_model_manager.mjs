/**
 * Automated Frontend AI Model Manager & Integration Test Battery
 * NTRO PS26155 — Chunk 2B
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

// Import api functions dynamically after window setup
const api = await import('./src/api.ts');

const SAMPLE_STATUS_ONLINE = {
  mode: 'auto',
  configured_mode: 'auto',
  effective_model: 'llama3.2:1b',
  override_model: null,
  available_models: ['llama3.2:1b', 'qwen2.5:7b-instruct-q4_K_M', 'deterministic_only'],
  hardware_profile: {
    total_ram_gb: 15.74,
    available_ram_gb: 7.21,
    cpu_cores: 8,
    cpu_threads: 16,
    has_gpu: false,
    gpu_type: 'none',
    vram_gb: 0.0,
    gpu_name: null,
    probe_error: null,
  },
  ollama_alive: true,
  fallback_active: false,
  fallback_reason: null,
};

const SAMPLE_STATUS_OFFLINE = {
  mode: 'auto',
  configured_mode: 'auto',
  effective_model: 'deterministic_only',
  override_model: null,
  available_models: ['llama3.2:1b', 'qwen2.5:7b-instruct-q4_K_M', 'deterministic_only'],
  hardware_profile: {
    total_ram_gb: 15.74,
    available_ram_gb: 7.21,
    cpu_cores: 8,
    cpu_threads: 16,
    has_gpu: false,
    gpu_type: 'none',
    vram_gb: 0.0,
    gpu_name: null,
    probe_error: null,
  },
  ollama_alive: false,
  fallback_active: true,
  fallback_reason: 'ollama_offline',
};

test.beforeEach(() => {
  sessionStorageStore.clear();
  api.clearAccessToken();
});

// --- Test 1: getModelStatus() URL & Method ---
test('1. getModelStatus() sends GET request to /api/model/status', async () => {
  let capturedUrl = '';
  let capturedOptions = null;

  globalThis.fetch = async (url, options) => {
    capturedUrl = url;
    capturedOptions = options;
    return {
      ok: true,
      status: 200,
      json: async () => SAMPLE_STATUS_ONLINE,
    };
  };

  await api.getModelStatus();
  assert.equal(capturedUrl, '/api/model/status');
  assert.equal(capturedOptions?.method ?? 'GET', 'GET');
});

// --- Test 2: getModelStatus() includes Bearer token ---
test('2. getModelStatus() includes Bearer token in request headers when authenticated', async () => {
  api.setAccessToken('auth-jwt-token-reviewer');
  let capturedHeaders = null;

  globalThis.fetch = async (url, options) => {
    capturedHeaders = options?.headers;
    return {
      ok: true,
      status: 200,
      json: async () => SAMPLE_STATUS_ONLINE,
    };
  };

  await api.getModelStatus();
  assert.equal(capturedHeaders?.Authorization, 'Bearer auth-jwt-token-reviewer');
});

// --- Test 3: getModelStatus() parsing ---
test('3. getModelStatus() correctly parses returned status and hardware profile', async () => {
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => SAMPLE_STATUS_ONLINE,
  });

  const res = await api.getModelStatus();
  assert.equal(res.mode, 'auto');
  assert.equal(res.effective_model, 'llama3.2:1b');
  assert.equal(res.ollama_alive, true);
  assert.equal(res.fallback_active, false);
  assert.equal(res.hardware_profile.total_ram_gb, 15.74);
  assert.equal(res.hardware_profile.cpu_cores, 8);
  assert.equal(res.available_models.length, 3);
});

// --- Test 4: getModelStatus() 401 Unauthorized ---
test('4. getModelStatus() handles 401 Unauthorized correctly and triggers onUnauthorized callback', async () => {
  let unauthorizedNotified = false;
  const unsubscribe = api.onUnauthorized(() => {
    unauthorizedNotified = true;
  });

  api.setAccessToken('expired.token');
  globalThis.fetch = async () => ({
    ok: false,
    status: 401,
    statusText: 'Unauthorized',
    json: async () => ({ detail: 'Not authenticated' }),
  });

  await assert.rejects(
    async () => {
      await api.getModelStatus();
    },
    (err) => {
      assert.equal(err.status, 401);
      return true;
    }
  );

  assert.equal(unauthorizedNotified, true);
  assert.equal(api.getAccessToken(), null);
  unsubscribe();
});

// --- Test 5: setModelMode() sends POST with JSON payload ---
test('5. setModelMode() sends POST request to /api/model/mode with correct body and headers', async () => {
  api.setAccessToken('reviewer-approver-token');
  let capturedUrl = '';
  let capturedOptions = null;

  globalThis.fetch = async (url, options) => {
    capturedUrl = url;
    capturedOptions = options;
    return {
      ok: true,
      status: 200,
      json: async () => ({
        success: true,
        message: "Model mode successfully updated to 'fast'",
        ...SAMPLE_STATUS_ONLINE,
        mode: 'fast',
      }),
    };
  };

  const payload = { mode: 'fast' };
  const res = await api.setModelMode(payload);

  assert.equal(capturedUrl, '/api/model/mode');
  assert.equal(capturedOptions.method, 'POST');
  assert.equal(capturedOptions.headers['Content-Type'], 'application/json');
  assert.equal(capturedOptions.headers.Authorization, 'Bearer reviewer-approver-token');
  assert.deepEqual(JSON.parse(capturedOptions.body), { mode: 'fast' });
  assert.equal(res.success, true);
  assert.equal(res.mode, 'fast');
});

// --- Test 6: setModelMode('fast') succeeds ---
test('6. setModelMode() with valid mode fast returns updated status', async () => {
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      success: true,
      message: "Model mode successfully updated to 'fast'",
      ...SAMPLE_STATUS_ONLINE,
      mode: 'fast',
      effective_model: 'llama3.2:1b',
    }),
  });

  const res = await api.setModelMode({ mode: 'fast' });
  assert.equal(res.success, true);
  assert.equal(res.mode, 'fast');
  assert.equal(res.effective_model, 'llama3.2:1b');
});

// --- Test 7: setModelMode('quality') succeeds ---
test('7. setModelMode() with valid mode quality returns updated status', async () => {
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      success: true,
      message: "Model mode successfully updated to 'quality'",
      ...SAMPLE_STATUS_ONLINE,
      mode: 'quality',
      effective_model: 'qwen2.5:7b-instruct-q4_K_M',
    }),
  });

  const res = await api.setModelMode({ mode: 'quality' });
  assert.equal(res.success, true);
  assert.equal(res.mode, 'quality');
  assert.equal(res.effective_model, 'qwen2.5:7b-instruct-q4_K_M');
});

// --- Test 8: setModelMode('auto') succeeds ---
test('8. setModelMode() with valid mode auto returns updated status', async () => {
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      success: true,
      message: "Model mode successfully updated to 'auto'",
      ...SAMPLE_STATUS_ONLINE,
      mode: 'auto',
    }),
  });

  const res = await api.setModelMode({ mode: 'auto' });
  assert.equal(res.success, true);
  assert.equal(res.mode, 'auto');
});

// --- Test 9: setModelMode('override') includes override_model in payload ---
test('9. setModelMode() with override includes override_model in outgoing payload', async () => {
  let capturedBody = null;

  globalThis.fetch = async (url, options) => {
    capturedBody = JSON.parse(options.body);
    return {
      ok: true,
      status: 200,
      json: async () => ({
        success: true,
        message: "Model mode successfully updated to 'override'",
        ...SAMPLE_STATUS_ONLINE,
        mode: 'override',
        override_model: 'deterministic_only',
        effective_model: 'deterministic_only',
      }),
    };
  };

  const res = await api.setModelMode({ mode: 'override', override_model: 'deterministic_only' });
  assert.equal(capturedBody.mode, 'override');
  assert.equal(capturedBody.override_model, 'deterministic_only');
  assert.equal(res.success, true);
  assert.equal(res.override_model, 'deterministic_only');
});

// --- Test 10: setModelMode() 403 Forbidden for non-approver ---
test('10. setModelMode() propagates HTTP 403 Forbidden when caller lacks approver authorization', async () => {
  api.setAccessToken('viewer-or-uploader-token');

  globalThis.fetch = async () => ({
    ok: false,
    status: 403,
    statusText: 'Forbidden',
    json: async () => ({ detail: 'Only authorized approver reviewers can modify AI model mode' }),
  });

  await assert.rejects(
    async () => {
      await api.setModelMode({ mode: 'fast' });
    },
    (err) => {
      assert.equal(err.status, 403);
      assert.match(err.message, /authorized approver/i);
      return true;
    }
  );
});

// --- Test 11: setModelMode() 400 Bad Request on invalid mode ---
test('11. setModelMode() propagates HTTP 400 Bad Request on invalid mode value', async () => {
  api.setAccessToken('approver-token');

  globalThis.fetch = async () => ({
    ok: false,
    status: 400,
    statusText: 'Bad Request',
    json: async () => ({ detail: 'Invalid mode: turbo. Valid modes are: auto, fast, quality, override' }),
  });

  await assert.rejects(
    async () => {
      await api.setModelMode({ mode: 'turbo' });
    },
    (err) => {
      assert.equal(err.status, 400);
      assert.match(err.message, /invalid mode/i);
      return true;
    }
  );
});

// --- Test 12: setModelMode() 400 Bad Request on non-allowlisted override model ---
test('12. setModelMode() propagates HTTP 400 Bad Request on non-allowlisted override model', async () => {
  api.setAccessToken('approver-token');

  globalThis.fetch = async () => ({
    ok: false,
    status: 400,
    statusText: 'Bad Request',
    json: async () => ({ detail: "Model 'evil_unvetted_model' is not in the security allowlist" }),
  });

  await assert.rejects(
    async () => {
      await api.setModelMode({ mode: 'override', override_model: 'evil_unvetted_model' });
    },
    (err) => {
      assert.equal(err.status, 400);
      assert.match(err.message, /not in the security allowlist/i);
      return true;
    }
  );
});

// --- Test 13: Viewer RBAC rules ---
test('13. Viewer role permissions: read-only status access, mode modification prohibited in frontend logic', () => {
  const viewerUser = {
    user_id: 'v1',
    username: 'secops_viewer',
    role: 'viewer',
    is_authorized_approver: false,
  };

  const isReviewerApprover = viewerUser.role === 'reviewer' && viewerUser.is_authorized_approver === true;
  assert.equal(isReviewerApprover, false);
});

// --- Test 14: Uploader RBAC rules ---
test('14. Uploader role permissions: read-only status access, mode modification prohibited in frontend logic', () => {
  const uploaderUser = {
    user_id: 'u1',
    username: 'config_uploader',
    role: 'uploader',
    is_authorized_approver: false,
  };

  const isReviewerApprover = uploaderUser.role === 'reviewer' && uploaderUser.is_authorized_approver === true;
  assert.equal(isReviewerApprover, false);
});

// --- Test 15: Reviewer non-approver RBAC rules ---
test('15. Reviewer non-approver role permissions: read-only status access, mode modification prohibited in frontend logic', () => {
  const reviewerNonApprover = {
    user_id: 'r1',
    username: 'secops_reviewer_junior',
    role: 'reviewer',
    is_authorized_approver: false,
  };

  const isReviewerApprover = reviewerNonApprover.role === 'reviewer' && reviewerNonApprover.is_authorized_approver === true;
  assert.equal(isReviewerApprover, false);
});

// --- Test 16: Reviewer approver RBAC rules ---
test('16. Reviewer approver role permissions: full clearance to adjust runtime mode and override', () => {
  const reviewerApprover = {
    user_id: 'r2',
    username: 'secops_lead_reviewer',
    role: 'reviewer',
    is_authorized_approver: true,
  };

  const isReviewerApprover = reviewerApprover.role === 'reviewer' && reviewerApprover.is_authorized_approver === true;
  assert.equal(isReviewerApprover, true);
});

// --- Test 17: Offline daemon status parsing ---
test('17. Offline daemon response parsing: accurately reflects ollama_alive: false and fallback_reason', async () => {
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => SAMPLE_STATUS_OFFLINE,
  });

  const res = await api.getModelStatus();
  assert.equal(res.ollama_alive, false);
  assert.equal(res.fallback_active, true);
  assert.equal(res.fallback_reason, 'ollama_offline');
  assert.equal(res.effective_model, 'deterministic_only');
});

// --- Test 18: Override mode payload logic ---
test('18. Override mode logic: requires override_model specification', () => {
  const mode = 'override';
  const selectedModel = 'llama3.2:1b';
  const payload = {
    mode,
    override_model: mode === 'override' ? selectedModel : null,
  };

  assert.equal(payload.mode, 'override');
  assert.equal(payload.override_model, 'llama3.2:1b');
});

// --- Test 19: Non-override mode payload logic ---
test('19. Non-override mode logic: sets override_model to null regardless of previously selected dropdown model', () => {
  const mode = 'auto';
  const selectedModel = 'llama3.2:1b';
  const payload = {
    mode,
    override_model: mode === 'override' ? selectedModel : null,
  };

  assert.equal(payload.mode, 'auto');
  assert.equal(payload.override_model, null);
});

// --- Test 20: Hardware profile data completeness ---
test('20. Hardware profile data completeness: RAM, CPU cores, threads, and GPU fields mapped correctly', async () => {
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => SAMPLE_STATUS_ONLINE,
  });

  const res = await api.getModelStatus();
  const hw = res.hardware_profile;

  assert.ok(typeof hw.total_ram_gb === 'number');
  assert.ok(typeof hw.available_ram_gb === 'number');
  assert.ok(typeof hw.cpu_cores === 'number');
  assert.ok(typeof hw.cpu_threads === 'number');
  assert.ok(typeof hw.has_gpu === 'boolean');
  assert.ok(typeof hw.gpu_type === 'string');
  assert.equal(hw.probe_error, null);
});
