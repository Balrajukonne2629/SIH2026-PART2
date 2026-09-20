import React, { useState } from 'react';
import { login } from '../api';
import { UserIdentity } from '../types';

interface LoginScreenProps {
  onLoginSuccess: (user: UserIdentity) => void;
}

export const LoginScreen: React.FC<LoginScreenProps> = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setErrorMessage('Please enter both operator ID / username and password.');
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);

    try {
      const response = await login(username.trim(), password);
      onLoginSuccess(response.user);
    } catch (err: any) {
      setErrorMessage(err.message || 'Authentication failed. Please check credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  const setDemoRole = (user: string) => {
    setUsername(user);
    setPassword('StrongPassword123!');
    setErrorMessage(null);
  };


  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-center items-center px-4 font-sans selection:bg-sky-500 selection:text-white">
      {/* Classification banner */}
      <div className="fixed top-0 left-0 right-0 bg-slate-950 border-b border-slate-800 px-4 py-1.5 flex items-center justify-between text-xs tracking-wider text-slate-400 font-mono">
        <div className="flex items-center space-x-2">
          <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
          <span className="text-slate-300 font-semibold">SECURITY CLEARANCE: LEVEL-3 RESTRICTED ACCESS</span>
        </div>
        <div>
          <span>SYSTEM: NTRO-CSM-COMPLIANCE-ENGINE v4.2</span>
        </div>
      </div>

      <div className="w-full max-w-md space-y-6">
        {/* Header Branding */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-slate-900 border border-slate-700 font-mono text-sky-400 font-bold text-lg shadow-lg">
            NT
          </div>
          <h1 className="text-xl font-bold tracking-tight text-white uppercase">
            Network Security Compliance Auditor
          </h1>
          <p className="text-xs text-slate-400 font-mono">
            Deterministic Compliance Subsystem • Operator Authentication
          </p>
        </div>

        {/* Login Box */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 sm:p-8 shadow-xl shadow-slate-950/50">
          <form onSubmit={handleSubmit} className="space-y-4">
            {errorMessage && (
              <div
                role="alert"
                className="bg-rose-950/60 border border-rose-800 text-rose-200 text-xs rounded p-3 font-mono flex items-start space-x-2"
              >
                <span className="text-rose-400 font-bold shrink-0">FAIL:</span>
                <span className="flex-1">{errorMessage}</span>
              </div>
            )}

            <div>
              <label htmlFor="username" className="block text-xs font-mono text-slate-300 uppercase tracking-wider mb-1.5 font-semibold">
                Operator Username
              </label>
              <input
                id="username"
                name="username"
                type="text"
                autoComplete="username"
                required
                disabled={isLoading}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. secops_reviewer"
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 font-mono focus:border-sky-500 focus:ring-1 focus:ring-sky-500 focus:outline-none transition-colors disabled:opacity-50"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-xs font-mono text-slate-300 uppercase tracking-wider mb-1.5 font-semibold">
                Authorization Credential / Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                disabled={isLoading}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 font-mono focus:border-sky-500 focus:ring-1 focus:ring-sky-500 focus:outline-none transition-colors disabled:opacity-50"
              />
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full mt-2 py-2.5 px-4 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-mono font-bold uppercase tracking-wider transition-colors border border-sky-400 flex items-center justify-center space-x-2 disabled:opacity-50 cursor-pointer shadow-sm"
            >
              {isLoading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  <span>Verifying Credentials...</span>
                </>
              ) : (
                <span>Authenticate & Access Console &rarr;</span>
              )}
            </button>
          </form>

          {/* Quick Select Operator Roles for Evaluation */}
          <div className="mt-6 pt-5 border-t border-slate-800 space-y-2.5">
            <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider font-semibold text-center">
              Operator Role Presets (Click to autofill):
            </div>
            <div className="text-[10px] font-mono text-slate-500 text-center">
              Credential: <code className="text-sky-400 font-bold">StrongPassword123!</code>
            </div>

            <div className="grid grid-cols-1 gap-2 text-xs font-mono">
              <button
                type="button"
                onClick={() => setDemoRole('secops_reviewer')}
                className="w-full py-1.5 px-3 bg-slate-950 hover:bg-slate-800 text-slate-300 rounded border border-slate-800 hover:border-slate-700 text-left flex items-center justify-between cursor-pointer transition-colors"
              >
                <span className="font-semibold text-sky-400">secops_reviewer</span>
                <span className="text-[10px] text-emerald-400 font-sans px-1.5 py-0.5 rounded bg-emerald-950/60 border border-emerald-800">
                  Reviewer + Approver
                </span>
              </button>

              <button
                type="button"
                onClick={() => setDemoRole('netadmin_uploader')}
                className="w-full py-1.5 px-3 bg-slate-950 hover:bg-slate-800 text-slate-300 rounded border border-slate-800 hover:border-slate-700 text-left flex items-center justify-between cursor-pointer transition-colors"
              >
                <span className="font-semibold text-sky-400">netadmin_uploader</span>
                <span className="text-[10px] text-sky-300 font-sans px-1.5 py-0.5 rounded bg-sky-950/60 border border-sky-800">
                  Uploader
                </span>
              </button>

              <button
                type="button"
                onClick={() => setDemoRole('auditor_viewer')}
                className="w-full py-1.5 px-3 bg-slate-950 hover:bg-slate-800 text-slate-300 rounded border border-slate-800 hover:border-slate-700 text-left flex items-center justify-between cursor-pointer transition-colors"
              >
                <span className="font-semibold text-sky-400">auditor_viewer</span>
                <span className="text-[10px] text-slate-400 font-sans px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700">
                  Viewer (Read-Only)
                </span>
              </button>
            </div>
          </div>
        </div>

        {/* Security watermark footer */}
        <div className="text-center font-mono text-[11px] text-slate-600">
          AIR-GAPPED COMPLIANT • DETERMINISTIC ZERO SUBPROCESS ENGINE
        </div>
      </div>
    </div>
  );
};
