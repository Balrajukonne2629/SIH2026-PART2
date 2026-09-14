import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { UploadScreen } from './components/UploadScreen';
import { AuditResultsScreen } from './components/AuditResultsScreen';
import { AiSuggestionReviewScreen } from './components/AiSuggestionReviewScreen';
import { RemediationDetailScreen } from './components/RemediationDetailScreen';
import { AuditLogReportScreen } from './components/AuditLogReportScreen';

export const App: React.FC = () => {
  const [currentScreen, setCurrentScreen] = useState<
    'upload' | 'results' | 'ai_review' | 'remediation' | 'audit_log'
  >('upload');

  // Real active session state (Prop-drilled across screens)
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [cachedResults, setCachedResults] = useState<any>(null);
  const [activeUnmappedLine, setActiveUnmappedLine] = useState<string>('service call-home');
  const [activeRemediationRuleId, setActiveRemediationRuleId] = useState<string>('CISCO-NTP-001');

  // Screen transition handlers
  const handleAuditStarted = (sessionId: string, initialResults: any) => {
    setActiveSessionId(sessionId);
    setCachedResults(initialResults);
    setCurrentScreen('results');
  };

  const handleReviewAi = (unmappedLine: string) => {
    setActiveUnmappedLine(unmappedLine || 'service call-home');
    setCurrentScreen('ai_review');
  };

  const handleViewRemediation = (ruleId: string) => {
    setActiveRemediationRuleId(ruleId);
    setCurrentScreen('remediation');
  };

  const handleApprovalCompleted = () => {
    // Return to results, trigger re-fetch
    setCachedResults(null);
    setCurrentScreen('results');
  };

  const handleAuditFinalized = (_finalizeData: any) => {
    setCurrentScreen('audit_log');
  };

  const unmappedCount = cachedResults?.unmapped_lines?.length ?? 0;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-sky-500 selection:text-white">
      {/* Top SOC Navigation Bar */}
      <Navbar
        currentScreen={currentScreen}
        onNavigate={(screen) => setCurrentScreen(screen)}
        unmappedCount={unmappedCount}
      />

      {/* Main Screen Content Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {currentScreen === 'upload' && (
          <UploadScreen
            onAuditStarted={handleAuditStarted}
            onNavigateToLedger={() => setCurrentScreen('audit_log')}
          />
        )}

        {currentScreen === 'results' && (
          activeSessionId ? (
            <AuditResultsScreen
              sessionId={activeSessionId}
              initialResults={cachedResults}
              onReviewAiSuggestions={handleReviewAi}
              onViewRemediation={handleViewRemediation}
              onNavigateToLedger={() => setCurrentScreen('audit_log')}
            />
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded p-10 text-center space-y-3 font-mono text-xs">
              <div className="text-amber-400 font-bold text-sm">No Active Audit Session</div>
              <p className="text-slate-400 max-w-md mx-auto">
                No configuration has been ingested yet in this session.
              </p>
              <button
                onClick={() => setCurrentScreen('upload')}
                className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded border border-sky-400 font-bold uppercase tracking-wider cursor-pointer"
              >
                Go to Ingestion Screen &rarr;
              </button>
            </div>
          )
        )}

        {currentScreen === 'ai_review' && (
          <AiSuggestionReviewScreen
            unmappedLine={activeUnmappedLine}
            sessionId={activeSessionId || undefined}
            onApprovalCompleted={handleApprovalCompleted}
            onBackToAudit={() => setCurrentScreen('results')}
          />
        )}

        {currentScreen === 'remediation' && (
          activeSessionId ? (
            <RemediationDetailScreen
              ruleId={activeRemediationRuleId}
              sessionId={activeSessionId}
              onBackToAudit={() => setCurrentScreen('results')}
              onAuditFinalized={handleAuditFinalized}
            />
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded p-10 text-center space-y-3 font-mono text-xs">
              <div className="text-rose-400 font-bold text-sm">Session Required for Remediation</div>
              <p className="text-slate-400 max-w-md mx-auto">
                Cannot run static conflict checks without an active parsed configuration session.
              </p>
              <button
                onClick={() => setCurrentScreen('upload')}
                className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded border border-sky-400 font-bold uppercase tracking-wider cursor-pointer"
              >
                Upload Config First &rarr;
              </button>
            </div>
          )
        )}

        {currentScreen === 'audit_log' && (
          <AuditLogReportScreen />
        )}
      </main>

      {/* Footer Classification & Compliance Watermark */}
      <footer className="bg-slate-950 border-t border-slate-900 py-3 px-4 text-center font-mono text-[11px] text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            <span>RESTRICTED // NTRO CYBER COMPLIANCE AUDITOR (SIH 2026)</span>
            <span className="mx-2 text-slate-700">•</span>
            <span>BACKEND: http://127.0.0.1:8000</span>
          </div>
          <div>
            <span>AIR-GAPPED COMPLIANT • ZERO DEVICE EXECUTION</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
