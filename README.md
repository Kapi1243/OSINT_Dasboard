# OSINT Threat Intelligence Dashboard

A 5-stage automated threat-intel pipeline that ingests public security news, performs NLP and risk scoring, stores outputs in SQLite, and serves a live Streamlit dashboard with responsible AI controls.

## Architecture (5 stages)

1. **Ingest**
- Pulls RSS/ATOM from: CISA Alerts, NCSC UK, Krebs on Security, The Hacker News, and BleepingComputer.
- Captures title, description, publish date, source URL.

2. **Parse & Deduplicate**
- Cleans HTML from descriptions with BeautifulSoup.
- Creates SHA-256 hash of title + URL and stores only unseen articles.

3. **NLP**
- spaCy NER (`en_core_web_sm`) for actors/orgs/products.
- CVE extraction via regex: `CVE-\d{4}-\d+`.
- TF-IDF + Logistic Regression classifier over labels:
  - `malware`, `phishing`, `vulnerability`, `ransomware`, `data_breach`
- Urgency signal from severity keywords + TextBlob sentiment polarity.

4. **Risk Scoring**
- Formula:
  - `risk = 0.4 * severity_keywords + 0.3 * classifier_confidence + 0.2 * source_credibility + 0.1 * recency`
- Outputs:
  - `risk_score` (0-100)
  - `confidence_percent`
  - `needs_human_review` (true if confidence < 60%)

5. **Dashboard (Streamlit)**
- Risk leaderboard.
- Entity frequency charts (top threat actors, top CVEs).
- Source reliability/bias table (false positive rate by feed source).
- Article detail view with reasoning + top TF-IDF drivers.
- Human override form for low-confidence articles.

## Responsible AI layer

- **Bias detection**: false positive rates by source are tracked and shown in the dashboard.
- **Audit log**: every classification stores input text, predicted label, confidence, timestamp, and driving features.
- **Human-in-the-loop**: low-confidence results are flagged and can be overridden in the UI.
- **Explainability**: top TF-IDF feature drivers are shown per article.
- **Privacy**: this system processes only public OSINT news feeds. No PII collection is intended.

## Project structure

- `src/osint_dashboard/ingest.py`: feed ingestion and cleanup
- `src/osint_dashboard/database.py`: SQLite schema and data access
- `src/osint_dashboard/nlp.py`: model training, NER, classification, explainability
- `src/osint_dashboard/risk.py`: risk formula
- `src/osint_dashboard/pipeline.py`: stage orchestration
- `src/osint_dashboard/scheduler.py`: APScheduler loop
- `app/streamlit_app.py`: live dashboard UI
- `scripts/run_pipeline.py`: manual pipeline execution
- `scripts/run_scheduler.py`: scheduled execution
- `scripts/train_model.py`: classifier retraining

## Quickstart

### 1) Create and activate environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2) Install dependencies

```powershell
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 3) Run one-shot pipeline

```powershell
$env:PYTHONPATH = "src"
python scripts/run_pipeline.py
```

### 4) Start dashboard

```powershell
$env:PYTHONPATH = "src"
streamlit run app/streamlit_app.py
```

### 5) Optional scheduler

```powershell
$env:PYTHONPATH = "src"
python scripts/run_scheduler.py
```

## Notes for interviews

- This implementation demonstrates production traits: deduplication, scheduled jobs, structured storage, explainability, auditability, and human review workflows.
- Source credibility is weighted explicitly in scoring to avoid over-amplifying lower-trust feeds.
- Bias monitoring is measurable through false positive rate trend per feed.
