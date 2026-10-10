import type {
  Investigation,
  InvestigationDetail,
  EvidenceGraphData,
  ReconstructionEvent,
  EvidenceGap,
  ForensicReport,
} from '../types/investigation';
import type { ReputationResult } from '../types/reputation';

const API_BASE = '/api';

class ApiError extends Error {
  statusCode?: number;
  constructor(message: string, statusCode?: number) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
  }
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorMessage = `Request failed with status ${res.status}`;
    try {
      const errJson = await res.json();
      if (errJson && errJson.detail) {
        if (typeof errJson.detail === 'string') {
          errorMessage = errJson.detail;
        } else if (Array.isArray(errJson.detail)) {
          errorMessage = errJson.detail.map((d: any) => d.msg || JSON.stringify(d)).join('; ');
        }
      }
    } catch {
      // Non-JSON error body
      const text = await res.text().catch(() => '');
      if (text) errorMessage = text;
    }
    throw new ApiError(errorMessage, res.status);
  }
  return res.json();
}

export const api = {
  async getHealth(): Promise<{ status: string; service: string; version: string }> {
    const res = await fetch(`${API_BASE}/health`);
    return handleResponse(res);
  },

  async getInvestigations(params?: { query?: string; verdict?: string }): Promise<Investigation[]> {
    const searchParams = new URLSearchParams();
    if (params?.query && params.query.trim()) {
      searchParams.set('query', params.query.trim());
    }
    if (params?.verdict && params.verdict.trim()) {
      searchParams.set('verdict', params.verdict.trim());
    }
    const queryString = searchParams.toString();
    const url = queryString ? `${API_BASE}/investigations?${queryString}` : `${API_BASE}/investigations`;
    const res = await fetch(url);
    return handleResponse<Investigation[]>(res);
  },

  async getInvestigation(id: string): Promise<InvestigationDetail> {
    const res = await fetch(`${API_BASE}/investigations/${encodeURIComponent(id)}`);
    return handleResponse<InvestigationDetail>(res);
  },

  async uploadInvestigation(file: File, title?: string): Promise<InvestigationDetail> {
    const formData = new FormData();
    formData.append('file', file);
    if (title && title.trim()) {
      formData.append('title', title.trim());
    }

    const res = await fetch(`${API_BASE}/investigations/upload`, {
      method: 'POST',
      body: formData,
    });
    return handleResponse<InvestigationDetail>(res);
  },

  async getInvestigationGraph(id: string): Promise<EvidenceGraphData> {
    const res = await fetch(`${API_BASE}/investigations/${encodeURIComponent(id)}/graph`);
    return handleResponse<EvidenceGraphData>(res);
  },

  async getInvestigationReconstruction(id: string): Promise<ReconstructionEvent[]> {
    const res = await fetch(`${API_BASE}/investigations/${encodeURIComponent(id)}/reconstruction`);
    return handleResponse<ReconstructionEvent[]>(res);
  },

  async getInvestigationGaps(id: string): Promise<EvidenceGap[]> {
    const res = await fetch(`${API_BASE}/investigations/${encodeURIComponent(id)}/gaps`);
    return handleResponse<EvidenceGap[]>(res);
  },

  async deleteInvestigation(id: string): Promise<{ deleted: boolean; id: string }> {
    const res = await fetch(`${API_BASE}/investigations/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
    return handleResponse<{ deleted: boolean; id: string }>(res);
  },

  async exportReport(id: string): Promise<ForensicReport> {
    const res = await fetch(`${API_BASE}/reports/${encodeURIComponent(id)}/export`);
    return handleResponse<ForensicReport>(res);
  },

  async checkReputation(email: string, consent_given: boolean): Promise<ReputationResult> {
    const res = await fetch(`${API_BASE}/reputation/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, consent_given }),
    });
    return handleResponse<ReputationResult>(res);
  },
};
