# AI-SOC — Backend

This folder contains **all ML pipeline, data, and API source code** for the AI Security Operations Centre project.

```
backend/
├── src/                   # Python source packages
│   └── ingestion/         # Module 1 — static file ingestion pipeline
│       ├── format_detector.py
│       ├── schema_mapper.py
│       ├── pipeline.py            (to be completed)
│       └── parsers/
│           ├── csv_xlsx_parser.py
│           ├── log_parser.py
│           └── text_parser.py
│   └── live_feeds/        # Module 2 — live data feed connectors (to be completed)
├── data/
│   ├── raw/               # Drop input files here for ingestion
│   └── processed/         # Parquet, JSONL outputs written here
├── models/                # Trained model artefacts (pkl, joblib)
├── notebooks/             # Exploratory data analysis notebooks
├── configs/               # config.yaml, env var references
├── tests/                 # Pytest test suite
│   └── fixtures/
│       └── ingestion/     # Sample files for pipeline smoke tests
└── requirements.txt       # Python dependencies
```

## Quickstart

```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt

# Run ingestion on the test fixtures
python -m src.ingestion.pipeline
```

## Module Status

| Module | Status |
|--------|--------|
| `src/ingestion` | 🔄 In progress |
| `src/live_feeds` | ⏳ Planned |
| `src/api` (FastAPI) | ⏳ Planned |
