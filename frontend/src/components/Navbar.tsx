import React, { useEffect, useState } from 'react';
import { Shield, Activity, Database, PlusCircle, Info, CheckCircle2, AlertCircle, Search } from 'lucide-react';
import { api } from '../services/api';

interface NavbarProps {
  activeView: string;
  setActiveView: (view: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ activeView, setActiveView }) => {
  const [backendStatus, setBackendStatus] = useState<'checking' | 'online' | 'offline'>('checking');

  useEffect(() => {
    let isMounted = true;
    const checkApi = async () => {
      try {
        const res = await api.getHealth();
        if (isMounted) {
          setBackendStatus(res.status === 'healthy' ? 'online' : 'offline');
        }
      } catch {
        if (isMounted) setBackendStatus('offline');
      }
    };

    checkApi();
    const interval = setInterval(checkApi, 30000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'address-checker', label: 'Email Address Checker', icon: Search },
    { id: 'new', label: 'New Email Investigation', icon: PlusCircle },
    { id: 'investigations', label: 'Investigations', icon: Database },
    { id: 'about', label: 'Methodology & About', icon: Info },
  ];

  return (
    <header className="border-b border-slate-800 bg-[#0b111e]/95 backdrop-blur sticky top-0 z-50 px-6 py-3.5">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        {/* Brand */}
        <button
          onClick={() => setActiveView('dashboard')}
          className="flex items-center space-x-3 text-left group transition-opacity hover:opacity-90 cursor-pointer"
        >
          <div className="p-2 rounded-lg bg-sky-500/10 border border-sky-500/30 text-sky-400 group-hover:border-sky-500/60 transition-colors">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-base font-bold tracking-tight text-white">EviPhish</span>
              <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800/60 font-mono">
                v0.1.0 Forensics
              </span>
            </div>
            <p className="text-[11px] text-slate-400">Evidence-First Phishing Investigation</p>
          </div>
        </button>

        {/* Navigation Tabs */}
        <div className="flex items-center space-x-2">
          <nav className="flex items-center space-x-1 bg-slate-900/80 p-1 rounded-lg border border-slate-800">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeView === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveView(item.id)}
                  className={`flex items-center space-x-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all cursor-pointer ${
                    isActive
                      ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Health Status Indicator */}
          <div className="hidden sm:flex items-center pl-3 pr-2 py-1 rounded-md text-xs bg-slate-900/60 border border-slate-800">
            {backendStatus === 'online' ? (
              <span className="flex items-center gap-1.5 text-emerald-400 text-[11px]">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>API Connected</span>
              </span>
            ) : backendStatus === 'offline' ? (
              <span className="flex items-center gap-1.5 text-rose-400 text-[11px]" title="Backend unavailable. Ensure Uvicorn is running.">
                <AlertCircle className="w-3.5 h-3.5" />
                <span>API Offline</span>
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-slate-400 text-[11px]">
                <span className="w-2 h-2 rounded-full bg-slate-500 animate-pulse" />
                <span>Connecting...</span>
              </span>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
