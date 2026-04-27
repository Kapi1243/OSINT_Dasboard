from datetime import datetime, timezone

from dateutil import parser as date_parser

from .config import HUMAN_REVIEW_CONFIDENCE_THRESHOLD


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def compute_recency_score(published_at: str) -> float:
    try:
        published = date_parser.parse(published_at)
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return 50.0

    age_hours = max(0.0, (datetime.now(timezone.utc) - published).total_seconds() / 3600)
    if age_hours <= 24:
        return 100.0
    if age_hours <= 72:
        return 80.0
    if age_hours <= 168:
        return 60.0
    return 35.0


def compute_risk_score(
    severity_keywords: float,
    classifier_confidence: float,
    source_credibility: float,
    recency: float,
) -> dict:
    classifier_percent = classifier_confidence * 100.0
    credibility_percent = source_credibility * 100.0

    risk = (
        0.4 * severity_keywords
        + 0.3 * classifier_percent
        + 0.2 * credibility_percent
        + 0.1 * recency
    )

    confidence_percent = _clamp(
        0.5 * classifier_percent + 0.3 * severity_keywords + 0.2 * credibility_percent
    )

    return {
        "risk_score": round(_clamp(risk), 2),
        "confidence_percent": round(confidence_percent, 2),
        "needs_human_review": int(confidence_percent < HUMAN_REVIEW_CONFIDENCE_THRESHOLD * 100),
        "source_credibility": round(credibility_percent, 2),
        "recency_score": round(recency, 2),
    }
