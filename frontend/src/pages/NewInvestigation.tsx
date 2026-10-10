import React, { useState, useRef } from 'react';
import {
  UploadCloud,
  FileText,
  AlertTriangle,
  CheckCircle2,
  HardDrive,
  ShieldAlert,
  Loader2,
  X,
  FileCode,
} from 'lucide-react';
import { api } from '../services/api';

interface NewInvestigationProps {
  onNavigate: (view: string, investigationId?: string) => void;
}

export const NewInvestigation: React.FC<NewInvestigationProps> = ({ onNavigate }) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [caseTitle, setCaseTitle] = useState<string>('');
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const MAX_FILE_SIZE = 15 * 1024 * 1024; // 15 MB limit

  const validateAndSelectFile = (file: File) => {
    setValidationError(null);
    setApiError(null);

    if (!file.name.toLowerCase().endsWith('.eml')) {
      setValidationError('Invalid file format. Only RFC 5322 .eml files are accepted.');
      return;
    }

    if (file.size > MAX_FILE_SIZE) {
      setValidationError('File exceeds the 15 MB maximum size constraint.');
      return;
    }

    if (file.size === 0) {
      setValidationError('Selected file is empty (0 bytes).');
      return;
    }

    setSelectedFile(file);
    if (!caseTitle) {
      const suggested = file.name.replace(/\.eml$/i, '').replace(/[_\-+.]/g, ' ');
      setCaseTitle(`Investigation: ${suggested}`);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSelectFile(e.target.files[0]);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSelectFile(e.dataTransfer.files[0]);
    }
  };

  const handleClearSelection = () => {
    setSelectedFile(null);
    setValidationError(null);
    setApiError(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile || isUploading) return;

    setIsUploading(true);
    setApiError(null);
    setValidationError(null);

    try {
      const createdCase = await api.uploadInvestigation(selectedFile, caseTitle);
      // Navigate using the real returned ID from the backend
      onNavigate('analysis', createdCase.id);
    } catch (err: any) {
      setApiError(err?.message || 'Upload and forensics analysis failed. Please verify the file.');
      setIsUploading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Title */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight">New Email Investigation</h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Submit an untrusted RFC 5322 (<code className="font-mono text-sky-400">.eml</code>) sample for safe forensic parsing
        </p>
      </div>

      {/* Security constraints reminder */}
      <div className="p-4 rounded-xl bg-[#0e1626] border border-slate-800 text-xs text-slate-300 space-y-2 shadow-sm">
        <div className="flex items-center gap-2 text-sky-400 font-semibold">
          <ShieldAlert className="w-4 h-4" />
          <span>Defensive Forensics Safety Sandbox</span>
        </div>
        <ul className="text-slate-400 text-[11px] space-y-1 list-disc list-inside">
          <li>Untrusted email inputs are parsed strictly without executing scripts, macros, or HTML.</li>
          <li>Extracted hyperlinks and domains are analyzed statically with zero live DNS/HTTP queries.</li>
          <li>Enforces a maximum file size limit of 15 MB per upload.</li>
        </ul>
      </div>

      {/* Upload Form */}
      <form onSubmit={handleSubmit} className="space-y-5">
        {/* Drag and Drop Zone */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => !selectedFile && fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-xl p-8 text-center transition-all ${
            selectedFile
              ? 'border-sky-500/50 bg-sky-950/10 cursor-default'
              : isDragging
              ? 'border-sky-400 bg-sky-950/20 cursor-pointer'
              : 'border-slate-800 hover:border-slate-700 bg-[#0e1626]/80 cursor-pointer'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".eml"
            onChange={handleFileChange}
            className="hidden"
          />

          {selectedFile ? (
            <div className="space-y-3">
              <div className="w-12 h-12 rounded-xl bg-sky-500/10 border border-sky-500/30 text-sky-400 flex items-center justify-center mx-auto">
                <FileCode className="w-6 h-6" />
              </div>
              <div>
                <h4 className="text-sm font-semibold text-white font-mono break-all">
                  {selectedFile.name}
                </h4>
                <div className="flex items-center justify-center gap-2 mt-1 text-xs text-slate-400">
                  <span className="flex items-center gap-1 font-mono">
                    <HardDrive className="w-3 h-3 text-slate-500" />
                    {(selectedFile.size / 1024).toFixed(1)} KB
                  </span>
                  <span>•</span>
                  <span className="text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" />
                    Valid .eml Format
                  </span>
                </div>
              </div>
              <div>
                <button
                  type="button"
                  onClick={handleClearSelection}
                  disabled={isUploading}
                  className="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer disabled:opacity-50"
                >
                  <X className="w-3 h-3" />
                  <span>Choose Different File</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="w-12 h-12 rounded-xl bg-slate-900 border border-slate-800 text-sky-400 flex items-center justify-center mx-auto">
                <UploadCloud className="w-6 h-6" />
              </div>
              <div>
                <p className="text-sm font-medium text-slate-200">
                  Drag and drop an <span className="text-sky-400 font-mono">.eml</span> email here, or browse
                </p>
                <p className="text-xs text-slate-400 mt-1">
                  Standard RFC 5322 raw email files supported (maximum 15 MB)
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Validation or API Errors */}
        {validationError && (
          <div className="p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 text-amber-400" />
            <span>{validationError}</span>
          </div>
        )}

        {apiError && (
          <div className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 text-rose-400" />
            <span>{apiError}</span>
          </div>
        )}

        {/* Title Input */}
        <div className="space-y-1.5">
          <label htmlFor="case-title" className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
            Investigation Case Title (Optional)
          </label>
          <input
            id="case-title"
            type="text"
            value={caseTitle}
            onChange={(e) => setCaseTitle(e.target.value)}
            disabled={isUploading}
            placeholder="e.g., Investigation: Suspicious Banking Notification"
            className="w-full px-3.5 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 transition-colors disabled:opacity-50"
          />
        </div>

        {/* Submit Button */}
        <div className="pt-2">
          <button
            type="submit"
            disabled={!selectedFile || isUploading}
            className={`w-full py-2.5 px-4 rounded-xl text-xs font-bold transition-all flex items-center justify-center gap-2 shadow-lg ${
              !selectedFile || isUploading
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700/40'
                : 'bg-sky-500 hover:bg-sky-400 text-slate-950 cursor-pointer'
            }`}
          >
            {isUploading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-slate-950" />
                <span>Forensic Engine Parsing Headers & Evidence...</span>
              </>
            ) : (
              <>
                <FileText className="w-4 h-4" />
                <span>Initiate Forensic Analysis</span>
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
