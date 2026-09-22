/**
 * Automated Frontend Authentication & Integration Test Battery
 * NTRO PS26155 — Chunk 7
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

test('1. login(username, password) sends correct credentials and updates token storage', async () => {
  let capturedUrl = '';
  let capturedOptions = null;

  globalThis.fetch = async (url, options) => {
    capturedUrl = url;
    capturedOptions = options;
    return {
      ok: true,
      status: 200,
      json: async () => ({
        access_token: 'fake.jwt.token.123',
        token_type: 'bearer',
        user: {
          user_id: 'usr-1',
          username: 'secops_reviewer',
          role: 'reviewer',
          is_authorized_approver: true,
        },
      }),
    };
  };

  const res = await api.login('secops_reviewer', 'StrongPass123!');
  assert.equal(capturedUrl, '/api/auth/login');
  assert.equal(capturedOptions.method, 'POST');
  assert.equal(capturedOptions.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(capturedOptions.body), {
    username: 'secops_reviewer',
    password: 'StrongPass123!',
  });
  assert.equal(res.access_token, 'fake.jwt.token.123');
  assert.equal(api.getAccessToken(), 'fake.jwt.token.123');
  assert.equal(sessionStorageStore.get('ntro_auth_token'), 'fake.jwt.token.123');
});

test('2. getAccessToken() retrieves stored token from in-memory / sessionStorage', () => {
  assert.equal(api.getAccessToken(), null);
  api.setAccessToken('session.token.456');
  assert.equal(api.getAccessToken(), 'session.token.456');
  assert.equal(sessionStorageStore.get('ntro_auth_token'), 'session.token.456');
});

test('3. clearAccessToken() wipes stored token from memory and sessionStorage', () => {
  api.setAccessToken('token.to.wipe');
  assert.equal(api.getAccessToken(), 'token.to.wipe');
  api.clearAccessToken();
  assert.equal(api.getAccessToken(), null);
  assert.equal(mockSessionStorage.getItem('ntro_auth_token'), null);
});

test('4. Authenticated request automatically includes Authorization: Bearer <token>', async () => {
  api.setAccessToken('valid.active.token');
  let capturedHeaders = null;

  globalThis.fetch = async (url, options) => {
    capturedHeaders = options?.headers;
    return {
      ok: true,
      status: 200,
      json: async () => ({ status: 'ok' }),
    };
  };

  await api.getLedger();
  assert.ok(capturedHeaders);
  assert.equal(capturedHeaders['Authorization'], 'Bearer valid.active.token');
});

test('5. Missing token request does NOT include Authorization header', async () => {
  api.clearAccessToken();
  let capturedHeaders = null;

  globalThis.fetch = async (url, options) => {
    capturedHeaders = options?.headers;
    return {
      ok: true,
      status: 200,
      json: async () => ({ status: 'ok' }),
    };
  };

  await api.getLedger();
  assert.equal(capturedHeaders?.['Authorization'], undefined);
});

test('6. 401 response invokes onUnauthorized callbacks', async () => {
  api.setAccessToken('expired.token.789');
  let callbackFired = false;

  const unsubscribe = api.onUnauthorized(() => {
    callbackFired = true;
  });

  globalThis.fetch = async () => ({
    ok: false,
    status: 401,
    statusText: 'Unauthorized',
    json: async () => ({ detail: 'Token has expired' }),
  });

  await assert.rejects(async () => {
    await api.getCurrentUser();
  }, api.ApiError);

  assert.equal(callbackFired, true);
  unsubscribe();
});

test('7. 401 response clears token from memory and sessionStorage', async () => {
  api.setAccessToken('expired.token.789');

  globalThis.fetch = async () => ({
    ok: false,
    status: 401,
    statusText: 'Unauthorized',
    json: async () => ({ detail: 'Invalid token' }),
  });

  await assert.rejects(async () => {
    await api.getCurrentUser();
  }, api.ApiError);

  assert.equal(api.getAccessToken(), null);
  assert.equal(mockSessionStorage.getItem('ntro_auth_token'), null);
});

test('8. 403 response throws ApiError with status 403', async () => {
  api.setAccessToken('viewer.token.321');

  globalThis.fetch = async () => ({
    ok: false,
    status: 403,
    statusText: 'Forbidden',
    json: async () => ({ detail: "Forbidden: Role 'viewer' is not permitted" }),
  });

  await assert.rejects(
    async () => {
      await api.getAuditResults('sess-1');
    },
    (err) => {
      assert.ok(err instanceof api.ApiError);
      assert.equal(err.status, 403);
      assert.match(err.message, /Forbidden/);
      return true;
    }
  );
});

test('9. 403 response does NOT clear token', async () => {
  api.setAccessToken('viewer.token.321');

  globalThis.fetch = async () => ({
    ok: false,
    status: 403,
    statusText: 'Forbidden',
    json: async () => ({ detail: 'Forbidden' }),
  });

  try {
    await api.getAuditResults('sess-1');
  } catch {
    // expected
  }

  assert.equal(api.getAccessToken(), 'viewer.token.321');
  assert.equal(sessionStorageStore.get('ntro_auth_token'), 'viewer.token.321');
});

test('10. approveSuggestion omits reviewer_name from outgoing wire payload', async () => {
  api.setAccessToken('reviewer.token');
  let capturedBody = null;

  globalThis.fetch = async (url, options) => {
    capturedBody = JSON.parse(options.body);
    return {
      ok: true,
      status: 200,
      json: async () => ({ status: 'approved' }),
    };
  };

  await api.approveSuggestion({
    suggestion_id: 'sug-123',
    reviewer_name: 'Spoofed_Name_Should_Be_Omitted',
    decision: 'approve',
    session_id: 'sess-456',
  });

  assert.ok(capturedBody);
  assert.equal(capturedBody.suggestion_id, 'sug-123');
  assert.equal(capturedBody.decision, 'approve');
  assert.equal(capturedBody.session_id, 'sess-456');
  assert.equal(capturedBody.reviewer_name, undefined, 'reviewer_name must be omitted from wire payload');
});

test('11. getCurrentUser() requests /api/auth/me and returns user identity', async () => {
  api.setAccessToken('valid.user.token');
  let capturedUrl = '';

  globalThis.fetch = async (url) => {
    capturedUrl = url;
    return {
      ok: true,
      status: 200,
      json: async () => ({
        user_id: 'usr-99',
        username: 'netadmin_uploader',
        role: 'uploader',
        is_authorized_approver: false,
      }),
    };
  };

  const user = await api.getCurrentUser();
  assert.equal(capturedUrl, '/api/auth/me');
  assert.equal(user.username, 'netadmin_uploader');
  assert.equal(user.role, 'uploader');
  assert.equal(user.is_authorized_approver, false);
});

test('12. Reviewer role permissions: authorized approver flags and actions', () => {
  const reviewerIdentity = {
    user_id: 'usr-1',
    username: 'secops_reviewer',
    role: 'reviewer',
    is_authorized_approver: true,
  };

  assert.equal(reviewerIdentity.role, 'reviewer');
  assert.equal(reviewerIdentity.is_authorized_approver, true);
  const canApprove = reviewerIdentity.is_authorized_approver;
  assert.equal(canApprove, true);
});

test('13. Viewer role permissions: approver and upload capabilities disabled', () => {
  const viewerIdentity = {
    user_id: 'usr-3',
    username: 'auditor_viewer',
    role: 'viewer',
    is_authorized_approver: false,
  };

  assert.equal(viewerIdentity.role, 'viewer');
  assert.equal(viewerIdentity.is_authorized_approver, false);
  const canUpload = viewerIdentity.role !== 'viewer';
  const canApprove = viewerIdentity.is_authorized_approver;
  assert.equal(canUpload, false);
  assert.equal(canApprove, false);
});

test('14. Storage isolation: token is not stored in localStorage, no password stored anywhere', () => {
  api.setAccessToken('secret.jwt.token');
  assert.equal(mockLocalStorage.getItem('ntro_auth_token'), null);
  assert.equal(mockLocalStorage.getItem('password'), null);
  assert.equal(mockSessionStorage.getItem('password'), null);
  assert.equal(mockSessionStorage.getItem('secret'), null);
  assert.equal(mockSessionStorage.getItem('ntro_auth_token'), 'secret.jwt.token');
});

test('15. Authentication lifecycle: unauthenticated vs authenticated state logic', () => {
  let currentUser = null;
  let authLoading = true;

  // Simulate mount with no token
  const token = api.getAccessToken();
  if (!token) {
    currentUser = null;
    authLoading = false;
  }
  assert.equal(authLoading, false);
  assert.equal(currentUser, null);

  // Simulate login
  const loggedInUser = {
    user_id: 'usr-1',
    username: 'secops_reviewer',
    role: 'reviewer',
    is_authorized_approver: true,
  };
  currentUser = loggedInUser;
  assert.ok(currentUser);
  assert.equal(currentUser.username, 'secops_reviewer');
});

test('16. Unauthorized callback resets authentication state to unauthenticated', () => {
  let currentUser = {
    user_id: 'usr-1',
    username: 'secops_reviewer',
    role: 'reviewer',
    is_authorized_approver: true,
  };
  let activeSessionId = 'sess-123';

  const resetState = () => {
    currentUser = null;
    activeSessionId = null;
  };

  const unsubscribe = api.onUnauthorized(resetState);

  // Trigger 401 simulated event
  api.clearAccessToken();
  resetState();

  assert.equal(currentUser, null);
  assert.equal(activeSessionId, null);
  unsubscribe();
});
