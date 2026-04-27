import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .config import DB_PATH


SCHEMA = """
CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_hash TEXT UNIQUE NOT NULL,
    source_name TEXT NOT NULL,
    source_url TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    published_at TEXT,
    ingested_at TEXT NOT NULL,
    processed INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS nlp_results (
    article_id INTEGER PRIMARY KEY,
    predicted_label TEXT NOT NULL,
    classifier_confidence REAL NOT NULL,
    severity_keyword_score REAL NOT NULL,
    sentiment_polarity REAL NOT NULL,
    urgency_signal REAL NOT NULL,
    entities_json TEXT NOT NULL,
    top_features_json TEXT NOT NULL,
    reasoning TEXT NOT NULL,
    FOREIGN KEY(article_id) REFERENCES articles(id)
);

CREATE TABLE IF NOT EXISTS risk_scores (
    article_id INTEGER PRIMARY KEY,
    risk_score REAL NOT NULL,
    confidence_percent REAL NOT NULL,
    needs_human_review INTEGER NOT NULL,
    source_credibility REAL NOT NULL,
    recency_score REAL NOT NULL,
    scored_at TEXT NOT NULL,
    FOREIGN KEY(article_id) REFERENCES articles(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL,
    input_text TEXT NOT NULL,
    predicted_label TEXT NOT NULL,
    confidence_score REAL NOT NULL,
    feature_drivers TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(article_id) REFERENCES articles(id)
);

CREATE TABLE IF NOT EXISTS review_feedback (
    article_id INTEGER PRIMARY KEY,
    original_label TEXT NOT NULL,
    override_label TEXT NOT NULL,
    notes TEXT,
    marked_false_positive INTEGER NOT NULL,
    reviewed_at TEXT NOT NULL,
    FOREIGN KEY(article_id) REFERENCES articles(id)
);
"""


@contextmanager
def get_connection(db_path: Path = DB_PATH):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def initialize_database() -> None:
    with get_connection() as conn:
        conn.executescript(SCHEMA)


def insert_article(article: Dict) -> Optional[int]:
    query = """
    INSERT INTO articles (
        article_hash, source_name, source_url, title, description, published_at, ingested_at, processed
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    ON CONFLICT(article_hash) DO NOTHING;
    """
    with get_connection() as conn:
        cur = conn.execute(
            query,
            (
                article["article_hash"],
                article["source_name"],
                article["source_url"],
                article["title"],
                article["description"],
                article["published_at"],
                article["ingested_at"],
            ),
        )
        return cur.lastrowid if cur.rowcount > 0 else None


def fetch_unprocessed_articles(limit: int = 100) -> List[sqlite3.Row]:
    query = """
    SELECT id, source_name, source_url, title, description, published_at, ingested_at
    FROM articles
    WHERE processed = 0
    ORDER BY id ASC
    LIMIT ?;
    """
    with get_connection() as conn:
        rows = conn.execute(query, (limit,)).fetchall()
    return rows


def mark_articles_processed(article_ids: Iterable[int]) -> None:
    ids = list(article_ids)
    if not ids:
        return
    placeholders = ",".join("?" for _ in ids)
    query = f"UPDATE articles SET processed = 1 WHERE id IN ({placeholders})"
    with get_connection() as conn:
        conn.execute(query, ids)


def upsert_nlp_result(result: Dict) -> None:
    query = """
    INSERT INTO nlp_results (
        article_id, predicted_label, classifier_confidence, severity_keyword_score,
        sentiment_polarity, urgency_signal, entities_json, top_features_json, reasoning
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(article_id) DO UPDATE SET
        predicted_label = excluded.predicted_label,
        classifier_confidence = excluded.classifier_confidence,
        severity_keyword_score = excluded.severity_keyword_score,
        sentiment_polarity = excluded.sentiment_polarity,
        urgency_signal = excluded.urgency_signal,
        entities_json = excluded.entities_json,
        top_features_json = excluded.top_features_json,
        reasoning = excluded.reasoning;
    """
    with get_connection() as conn:
        conn.execute(
            query,
            (
                result["article_id"],
                result["predicted_label"],
                result["classifier_confidence"],
                result["severity_keyword_score"],
                result["sentiment_polarity"],
                result["urgency_signal"],
                result["entities_json"],
                result["top_features_json"],
                result["reasoning"],
            ),
        )


def upsert_risk_score(result: Dict) -> None:
    query = """
    INSERT INTO risk_scores (
        article_id, risk_score, confidence_percent, needs_human_review,
        source_credibility, recency_score, scored_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(article_id) DO UPDATE SET
        risk_score = excluded.risk_score,
        confidence_percent = excluded.confidence_percent,
        needs_human_review = excluded.needs_human_review,
        source_credibility = excluded.source_credibility,
        recency_score = excluded.recency_score,
        scored_at = excluded.scored_at;
    """
    with get_connection() as conn:
        conn.execute(
            query,
            (
                result["article_id"],
                result["risk_score"],
                result["confidence_percent"],
                result["needs_human_review"],
                result["source_credibility"],
                result["recency_score"],
                result["scored_at"],
            ),
        )


def insert_audit_log(entry: Dict) -> None:
    query = """
    INSERT INTO audit_log (
        article_id, input_text, predicted_label, confidence_score, feature_drivers, created_at
    ) VALUES (?, ?, ?, ?, ?, ?)
    """
    with get_connection() as conn:
        conn.execute(
            query,
            (
                entry["article_id"],
                entry["input_text"],
                entry["predicted_label"],
                entry["confidence_score"],
                entry["feature_drivers"],
                entry["created_at"],
            ),
        )


def upsert_feedback(feedback: Dict) -> None:
    query = """
    INSERT INTO review_feedback (
        article_id, original_label, override_label, notes, marked_false_positive, reviewed_at
    ) VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(article_id) DO UPDATE SET
        original_label = excluded.original_label,
        override_label = excluded.override_label,
        notes = excluded.notes,
        marked_false_positive = excluded.marked_false_positive,
        reviewed_at = excluded.reviewed_at;
    """
    with get_connection() as conn:
        conn.execute(
            query,
            (
                feedback["article_id"],
                feedback["original_label"],
                feedback["override_label"],
                feedback.get("notes", ""),
                feedback["marked_false_positive"],
                feedback["reviewed_at"],
            ),
        )


def fetch_dashboard_rows(limit: int = 500) -> List[sqlite3.Row]:
    query = """
    SELECT
        a.id,
        a.source_name,
        a.source_url,
        a.title,
        a.description,
        a.published_at,
        n.predicted_label,
        n.classifier_confidence,
        n.entities_json,
        n.top_features_json,
        n.reasoning,
        r.risk_score,
        r.confidence_percent,
        r.needs_human_review,
        r.scored_at,
        f.override_label,
        f.marked_false_positive,
        f.reviewed_at
    FROM articles a
    LEFT JOIN nlp_results n ON a.id = n.article_id
    LEFT JOIN risk_scores r ON a.id = r.article_id
    LEFT JOIN review_feedback f ON a.id = f.article_id
    ORDER BY r.risk_score DESC, a.id DESC
    LIMIT ?;
    """
    with get_connection() as conn:
        rows = conn.execute(query, (limit,)).fetchall()
    return rows
