# EviPhish

EviPhish is an Evidence-First Phishing Email Forensics Platform. It analyzes raw RFC 5322 (`.eml`) emails, extracts artifacts without making external network calls, runs static heuristics, and builds an interactive evidence graph.

## Getting Started (Windows)

### Prerequisites
- Python 3.10+
- Node.js 18+

### 1. Start the Backend API
The backend is built with FastAPI and runs on Python.

Open a PowerShell terminal and run:

```powershell
cd backend
# Create a virtual environment (if not already created)
python -m venv .venv
# Activate the virtual environment
.venv\Scripts\Activate.ps1
# Install dependencies
pip install -r requirements.txt
# Start the FastAPI server
uvicorn app.main:app --reload --port 8000
```
The API will be available at `http://localhost:8000`.

### 2. Configure Environment Variables
Copy `.env.example` to `.env` in the root directory (or in `backend/`) and add your EmailRep API key (optional, for reputation checking).
```
EMAILREP_API_KEY=your_key_here
```

### 3. Start the Frontend
The frontend is built with React, Vite, and Tailwind CSS.

Open a separate PowerShell terminal and run:

```powershell
cd frontend
# Install dependencies
npm install
# Start the development server
npm run dev
```
The frontend will be available at `http://localhost:5173`.
