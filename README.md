# AI-SOC — AI-Powered Security Operations Centre

A final-year project implementing an automated, ML-driven SOC with live threat detection, alert triage, and a React dashboard.

## Repository Layout

```
ai-soc/
├── backend/          ← ALL ML & API code lives here
│   ├── src/          ← Python source packages
│   ├── data/         ← Raw input files & processed outputs
│   ├── models/       ← Trained model artefacts
│   ├── notebooks/    ← EDA & experimentation
│   ├── configs/      ← config.yaml, env var names
│   ├── tests/        ← Pytest suite
│   └── requirements.txt
│
├── frontend/         ← React / Next.js dashboard (separate)
├── Markdown/         ← Module specification docs
└── venv/             ← Root venv (optional; backend has its own)
```

## Quick Navigation

| Area | Path |
|------|------|
| Ingestion pipeline | [backend/src/ingestion/](backend/src/ingestion/) |
| Live feed connectors | [backend/src/live_feeds/](backend/src/live_feeds/) *(planned)* |
| Raw data | [backend/data/raw/](backend/data/raw/) |
| Module specs | [Markdown/](Markdown/) |
| Frontend | [frontend/](frontend/) |

## Getting Started

```bash
# Backend
cd backend
pip install -r requirements.txt
python -m src.ingestion.pipeline

# Frontend
cd frontend
npm install && npm run dev
```

## Dashboard data sources

With the API running on port 8000, the **Data Sources & URL Scanner** dashboard tab supports:

* local log/data upload (`.csv`, `.json`, `.log`, `.syslog`, `.txt`, `.md`, `.xlsx`);
* one-time import from a public JSON, NDJSON, or CSV URL; and
* a runtime URL polling feed, configurable from 2 seconds to 1 hour.

URL feeds are deliberately restricted to public HTTP(S) endpoints, do not follow redirects, and are capped at 5 MB per poll. Configured URL feeds exist for the lifetime of the API process; add them again after a server restart.
