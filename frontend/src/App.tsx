import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { UploadScreen } from './components/UploadScreen';
import { AuditResultsScreen } from './components/AuditResultsScreen';
import { AiSuggestionReviewScreen } from './components/AiSuggestionReviewScreen';
import { RemediationDetailScreen } from './components/RemediationDetailScreen';
import { AuditLogReportScreen } from './components/AuditLogReportScreen';
import { AiModelManagerScreen } from './components/AiModelManagerScreen';
import { LoginScreen } from './components/LoginScreen';
import { UserIdentity, ScreenId } from './types';
import { getAccessToken, getCurrentUser, clearAccessToken, onUnauthorized, getModelStatus } from './api';

export const App: React.FC = () => {
  const [currentUser, setCurrentUser] = useState<UserIdentity | null>(null);
  const [authLoading, setAuthLoading] = useState<boolean>(true);

  const [currentScreen, setCurrentScreen] = useState<ScreenId>('upload');

  // Live model runtime status for top classification bar
  const [liveModelMode, setLiveModelMode] = useState<string>('auto');
  const [liveOllamaAlive, setLiveOllamaAlive] = useState<boolean>(true);

  // Real active session state (Prop-drilled across screens)
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);

  const [cachedResults, setCachedResults] = useState<any>(null);
  const [activeUnmappedLine, setActiveUnmappedLine] = useState<string>('service call-home');
  const [activeRemediationRuleId, setActiveRemediationRuleId] = useState<string>('CISCO-NTP-001');

  // Check existing session on mount & register 401 callback
  useEffect(() => {
    let isMounted = true;

    const initAuth = async () => {
      const token = getAccessToken();
      if (!token) {
        if (isMounted) setAuthLoading(false);
        return;
      }
      try {
        const user = await getCurrentUser();
        if (isMounted) setCurrentUser(user);
        try {
          const modelStat = await getModelStatus();
          if (isMounted) {
            setLiveModelMode(modelStat.mode);
            setLiveOllamaAlive(modelStat.ollama_alive);
          }
        } catch {
          // Model status fetch failure is non-fatal for auth
        }
      } catch {
        clearAccessToken();
        if (isMounted) setCurrentUser(null);
      } finally {
        if (isMounted) setAuthLoading(false);
      }
    };

    initAuth();


    // Centralized 401 handler: immediately resets auth state without page reload
    const unsubscribe = onUnauthorized(() => {
      if (isMounted) {
        setCurrentUser(null);
        setActiveSessionId(null);
        setCachedResults(null);
      }
    });

    return () => {
      isMounted = false;
      unsubscribe();
    };
  }, []);

  // Screen transition handlers
  const handleLoginSuccess = (user: UserIdentity) => {
    setCurrentUser(user);
    getModelStatus()
      .then((stat) => {
        setLiveModelMode(stat.mode);
        setLiveOllamaAlive(stat.ollama_alive);
      })
      .catch(() => {});
  };


  const handleLogout = () => {
    clearAccessToken();
    setCurrentUser(null);
    setActiveSessionId(null);
    setCachedResults(null);
    setCurrentScreen('upload');
  };

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

  // Gate privileged interface while initializing
  if (authLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center font-mono text-xs text-slate-400 space-y-3">
        <div className="w-8 h-8 border-2 border-sky-400 border-t-transparent rounded-full animate-spin"></div>
        <div>INITIALIZING OPERATOR SECURITY CONTEXT...</div>
      </div>
    );
  }

  // If unauthenticated, display the login screen
  if (!currentUser) {
    return <LoginScreen onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-sky-500 selection:text-white">
      {/* Top SOC Navigation Bar */}
      <Navbar
        currentScreen={currentScreen}
        onNavigate={(screen) => setCurrentScreen(screen)}
        unmappedCount={unmappedCount}
        currentUser={currentUser}
        onLogout={handleLogout}
        modelMode={liveModelMode}
        ollamaAlive={liveOllamaAlive}
      />

      {/* Main Screen Content Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {currentScreen === 'upload' && (
          <UploadScreen
            onAuditStarted={handleAuditStarted}
            onNavigateToLedger={() => setCurrentScreen('audit_log')}
            currentUser={currentUser}
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
            currentUser={currentUser}
            onApprovalCompleted={handleApprovalCompleted}
            onBackToAudit={() => setCurrentScreen('results')}
          />
        )}

        {currentScreen === 'remediation' && (
          activeSessionId ? (
            <RemediationDetailScreen
              ruleId={activeRemediationRuleId}
              sessionId={activeSessionId}
              currentUser={currentUser}
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

        {currentScreen === 'model_ops' && (
          <AiModelManagerScreen
            currentUser={currentUser}
            onNavigateToReview={() => setCurrentScreen('ai_review')}
          />
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
