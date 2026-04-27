from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"
DB_PATH = DATA_DIR / "threat_intel.db"
LABELS_PATH = DATA_DIR / "labels.csv"
MODEL_PATH = MODELS_DIR / "classifier.joblib"
VECTORIZER_PATH = MODELS_DIR / "vectorizer.joblib"

FEEDS = [
    {"name": "CISA Alerts", "url": "https://www.cisa.gov/uscert/ncas/alerts.xml", "credibility": 1.0},
    {"name": "NCSC UK", "url": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", "credibility": 0.95},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "credibility": 0.9},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "credibility": 0.8},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "credibility": 0.85},
]

THREAT_LABELS = ["malware", "phishing", "vulnerability", "ransomware", "data_breach"]

SEVERITY_KEYWORDS = [
    "critical",
    "zero-day",
    "zero day",
    "actively exploited",
    "ransom",
    "wiper",
    "urgent",
    "exploited in the wild",
    "remote code execution",
    "credential theft",
]

RISK_HIGH_THRESHOLD = 70
HUMAN_REVIEW_CONFIDENCE_THRESHOLD = 0.60
MAX_INGEST_PER_FEED = 50
