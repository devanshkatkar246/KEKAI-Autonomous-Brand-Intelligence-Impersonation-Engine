# KEKAI

Autonomous Brand Intelligence & Impersonation Engine

## Overview

KEKAI is an enterprise-grade brand protection and website impersonation investigation platform combining multi-source threat intelligence, domain permutation analysis, visual brand recognition, logo similarity, infrastructure intelligence, evidence correlation, human-controlled takedown workflows, and workflow automation.

## Project Status

The project is actively being developed and functionality is being integrated incrementally.

## Architecture

```
Discovery
    ↓
Threat Intelligence
    ↓
Visual Brand Intelligence
    ↓
Infrastructure Correlation
    ↓
Evidence
    ↓
Human Approval
    ↓
Controlled Response
    ↓
Automation
```

## Repository Structure

- `frontend/`: React + Tailwind CSS dashboard user interface.
- `services/`: Backend threat intelligence, visual recognition, and takedown control services.
- `Phishpedia/`: Local deep-learning visual brand detection model and fallbacks.
- `dnstwist/`: Local domain permutation generator CLI.
- `database.py`: SQLite evidence persistence and control plane claims.
- `main.py`: FastAPI server endpoints and routing.
- `test_*.py`: Automated test suites for safety, intelligence, and integration.

## Quick Start

1. **Clone repository**:
   ```bash
   git clone https://github.com/devanshkatkar246/KEKAI-Autonomous-Brand-Intelligence-Impersonation-Engine.git
   cd KEKAI-Autonomous-Brand-Intelligence-Impersonation-Engine
   ```
2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Install Frontend dependencies**:
   ```bash
   cd frontend
   npm install
   cd ..
   ```
4. **Copy Environment Template**:
   ```bash
   cp .env.example .env
   ```
5. **Leave optional credentials empty for local/demo mode**.
6. **Start Application**:
   ```bash
   python steps.py
   ```

## Security

- Secrets belong in `.env` and are never committed to version control.
- `.env` is ignored in `.gitignore`; `.env.example` contains safe placeholders.
- Takedown submission defaults strictly to `ABUSE_SUBMISSION_MODE=DRY_RUN`.
- External actions require explicit human approval and server-side configuration.

## License

License: To be determined.
