import React from 'react';

interface NavbarProps {
  currentScreen: 'upload' | 'results' | 'ai_review' | 'remediation' | 'audit_log';
  onNavigate: (screen: 'upload' | 'results' | 'ai_review' | 'remediation' | 'audit_log') => void;
  unmappedCount?: number;
  activeOperator?: string;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentScreen,
  onNavigate,
  unmappedCount = 0,
  activeOperator = 'SecOps_Lead_Reviewer'
}) => {
  return (
    <header className="bg-slate-900 border-b border-slate-800 text-slate-100 font-sans sticky top-0 z-50">
      {/* Top Classification Banner */}
      <div className="bg-slate-950 px-4 py-1 border-b border-slate-800/80 flex items-center justify-between text-xs tracking-wider text-slate-400">
        <div className="flex items-center space-x-3">
          <span className="inline-block w-2 h-2 rounded-full bg-emerald-500"></span>
          <span className="font-mono text-slate-300 font-semibold">SECURITY CLEARANCE: LEVEL-3 RESTRICTED</span>
          <span className="text-slate-600">|</span>
          <span>SYSTEM: NTRO-CSM-COMPLIANCE-ENGINE v4.2</span>
        </div>
        <div className="flex items-center space-x-4 font-mono text-[11px]">
          <span>ENGINE: <span className="text-emerald-400">DETERMINISTIC (OFFLINE)</span></span>
          <span className="text-slate-600">|</span>
          <span>OPERATOR: <span className="text-sky-400">{activeOperator}</span></span>
        </div>
      </div>

      {/* Main Header Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14">
          <div className="flex items-center space-x-3">
            <div className="flex items-center justify-center w-8 h-8 rounded bg-slate-800 border border-slate-700 font-mono text-sky-400 font-bold text-sm">
              NT
            </div>
            <div>
              <div className="text-sm font-bold tracking-tight text-white uppercase flex items-center gap-2">
                Network Security Compliance Auditor
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  Cisco IOS-XE
                </span>
              </div>
              <div className="text-[11px] text-slate-400 font-mono">
                CSM Specification §4 Steps 1–5 • SHA-256 Ledger
              </div>
            </div>
          </div>

          {/* Navigation Items */}
          <nav className="flex space-x-1 font-sans text-xs font-medium">
            <button
              onClick={() => onNavigate('upload')}
              className={`px-3 py-2 rounded-sm transition-colors flex items-center gap-1.5 ${
                currentScreen === 'upload'
                  ? 'bg-slate-800 text-white border border-slate-700 shadow-sm'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/50'
              }`}
            >
              <span className="font-mono text-[10px] text-slate-400">01</span>
              <span>Upload Config</span>
            </button>

            <button
              onClick={() => onNavigate('results')}
              className={`px-3 py-2 rounded-sm transition-colors flex items-center gap-1.5 ${
                currentScreen === 'results'
                  ? 'bg-slate-800 text-white border border-slate-700 shadow-sm'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/50'
              }`}
            >
              <span className="font-mono text-[10px] text-slate-400">02</span>
              <span>Audit Results</span>
            </button>

            <button
              onClick={() => onNavigate('ai_review')}
              className={`px-3 py-2 rounded-sm transition-colors flex items-center gap-1.5 ${
                currentScreen === 'ai_review'
                  ? 'bg-slate-800 text-white border border-slate-700 shadow-sm'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/50'
              }`}
            >
              <span className="font-mono text-[10px] text-slate-400">03</span>
              <span>AI Review</span>
              {unmappedCount > 0 && (
                <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-800 font-semibold">
                  {unmappedCount}
                </span>
              )}
            </button>

            <button
              onClick={() => onNavigate('remediation')}
              className={`px-3 py-2 rounded-sm transition-colors flex items-center gap-1.5 ${
                currentScreen === 'remediation'
                  ? 'bg-slate-800 text-white border border-slate-700 shadow-sm'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/50'
              }`}
            >
              <span className="font-mono text-[10px] text-slate-400">04</span>
              <span>Remediation Engine</span>
            </button>

            <button
              onClick={() => onNavigate('audit_log')}
              className={`px-3 py-2 rounded-sm transition-colors flex items-center gap-1.5 ${
                currentScreen === 'audit_log'
                  ? 'bg-slate-800 text-white border border-slate-700 shadow-sm'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/50'
              }`}
            >
              <span className="font-mono text-[10px] text-slate-400">05</span>
              <span>Audit Log & Reports</span>
            </button>
          </nav>
        </div>
      </div>
    </header>
  );
};
