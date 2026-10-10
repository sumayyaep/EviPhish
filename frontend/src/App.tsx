import React, { useState, useEffect, Suspense } from 'react';
import { Navbar } from './components/Navbar';
import { Loader2 } from 'lucide-react';

const Dashboard = React.lazy(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })));
const Investigations = React.lazy(() => import('./pages/Investigations').then(m => ({ default: m.Investigations })));
const NewInvestigation = React.lazy(() => import('./pages/NewInvestigation').then(m => ({ default: m.NewInvestigation })));
const EmailAnalysis = React.lazy(() => import('./pages/EmailAnalysis').then(m => ({ default: m.EmailAnalysis })));
const SettingsAbout = React.lazy(() => import('./pages/SettingsAbout').then(m => ({ default: m.SettingsAbout })));
const AddressChecker = React.lazy(() => import('./pages/AddressChecker').then(m => ({ default: m.AddressChecker })));

export function App() {
  const [activeView, setActiveView] = useState<string>('dashboard');
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);

  // Sync with browser URL hash for direct links and browser back/forward buttons
  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace(/^#\/?/, '');
      if (hash.startsWith('analysis:')) {
        const id = hash.replace('analysis:', '');
        setSelectedCaseId(id);
        setActiveView('analysis');
      } else if (['dashboard', 'investigations', 'new', 'about', 'address-checker'].includes(hash)) {
        setActiveView(hash);
        setSelectedCaseId(null);
      } else {
        setActiveView('dashboard');
        setSelectedCaseId(null);
      }
    };

    handleHashChange();
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  const handleNavigate = (view: string, investigationId?: string) => {
    if (view === 'analysis' && investigationId) {
      setSelectedCaseId(investigationId);
      setActiveView('analysis');
      window.location.hash = `analysis:${investigationId}`;
    } else {
      setSelectedCaseId(null);
      setActiveView(view);
      window.location.hash = view;
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-100 flex flex-col font-sans">
      <Navbar activeView={activeView} setActiveView={(view) => handleNavigate(view)} />

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
        <Suspense fallback={
          <div className="flex flex-col items-center justify-center min-h-[50vh] text-slate-400 space-y-4">
            <Loader2 className="w-8 h-8 animate-spin text-sky-500" />
            <span className="text-sm tracking-widest uppercase font-semibold">Loading Module...</span>
          </div>
        }>
          {activeView === 'dashboard' && <Dashboard onNavigate={handleNavigate} />}

          {activeView === 'investigations' && <Investigations onNavigate={handleNavigate} />}

          {activeView === 'new' && <NewInvestigation onNavigate={handleNavigate} />}

          {activeView === 'analysis' && selectedCaseId && (
            <EmailAnalysis investigationId={selectedCaseId} onNavigate={handleNavigate} />
          )}

          {activeView === 'about' && <SettingsAbout />}

          {activeView === 'address-checker' && <AddressChecker />}
        </Suspense>
      </main>

      <footer className="border-t border-slate-800/80 bg-[#070b12] py-4 px-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>EviPhish • Evidence-First Phishing Email Forensics Platform</span>
          <span className="font-mono text-[11px] text-slate-400">
            Rule: Evidence First, Conclusion Second
          </span>
        </div>
      </footer>
    </div>
  );
}

export default App;
