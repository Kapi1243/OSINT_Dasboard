from datetime import datetime, timezone
from typing import Dict, List

from .config import FEEDS
from .database import (
    fetch_unprocessed_articles,
    initialize_database,
    insert_article,
    insert_audit_log,
    mark_articles_processed,
    upsert_nlp_result,
    upsert_risk_score,
)
from .ingest import ingest_all_feeds
from .nlp import ThreatNLP, serialize_json
from .risk import compute_recency_score, compute_risk_score


def _source_credibility_lookup() -> Dict[str, float]:
    return {item["name"]: item["credibility"] for item in FEEDS}


def run_ingestion_stage() -> Dict[str, int]:
    initialize_database()
    articles = ingest_all_feeds()
    inserted = 0
    for article in articles:
        if insert_article(article):
            inserted += 1
    return {"fetched": len(articles), "inserted_new": inserted}


def run_nlp_and_risk_stage(limit: int = 200) -> Dict[str, int]:
    initialize_database()
    model = ThreatNLP()
    lookup = _source_credibility_lookup()

    rows = fetch_unprocessed_articles(limit=limit)
    processed_ids: List[int] = []

    for row in rows:
        article_id = int(row["id"])
        title = row["title"] or ""
        description = row["description"] or ""
        text = f"{title}. {description}".strip()

        nlp_output = model.analyze_text(text)

        upsert_nlp_result(
            {
                "article_id": article_id,
                "predicted_label": nlp_output["predicted_label"],
                "classifier_confidence": nlp_output["classifier_confidence"],
                "severity_keyword_score": nlp_output["severity_keyword_score"],
                "sentiment_polarity": nlp_output["sentiment_polarity"],
                "urgency_signal": nlp_output["urgency_signal"],
                "entities_json": serialize_json(nlp_output["entities"]),
                "top_features_json": serialize_json(nlp_output["top_features"]),
                "reasoning": nlp_output["reasoning"],
            }
        )

        recency_score = compute_recency_score(row["published_at"])
        source_credibility = lookup.get(row["source_name"], 0.7)

        risk = compute_risk_score(
            severity_keywords=nlp_output["severity_keyword_score"],
            classifier_confidence=nlp_output["classifier_confidence"],
            source_credibility=source_credibility,
            recency=recency_score,
        )

        upsert_risk_score(
            {
                "article_id": article_id,
                **risk,
                "scored_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        insert_audit_log(
            {
                "article_id": article_id,
                "input_text": text,
                "predicted_label": nlp_output["predicted_label"],
                "confidence_score": nlp_output["classifier_confidence"],
                "feature_drivers": serialize_json(nlp_output["top_features"]),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        processed_ids.append(article_id)

    mark_articles_processed(processed_ids)
    return {"processed": len(processed_ids)}


def run_full_pipeline() -> Dict[str, Dict[str, int]]:
    ingestion = run_ingestion_stage()
    nlp_and_risk = run_nlp_and_risk_stage()
    return {
        "ingestion": ingestion,
        "nlp_and_risk": nlp_and_risk,
    }
