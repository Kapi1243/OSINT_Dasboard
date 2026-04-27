import hashlib
from datetime import datetime, timezone
from html import unescape
from typing import Dict, List

import feedparser
from bs4 import BeautifulSoup
from dateutil import parser as date_parser

from .config import FEEDS, MAX_INGEST_PER_FEED


def clean_html(raw_html: str) -> str:
    if not raw_html:
        return ""
    soup = BeautifulSoup(raw_html, "html.parser")
    text = soup.get_text(separator=" ", strip=True)
    return unescape(text)


def compute_article_hash(title: str, url: str) -> str:
    blob = f"{title.strip().lower()}::{url.strip().lower()}".encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def parse_published(entry: Dict) -> str:
    candidates = [
        entry.get("published"),
        entry.get("updated"),
        entry.get("created"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            dt = date_parser.parse(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except (ValueError, TypeError):
            continue
    return datetime.now(timezone.utc).isoformat()


def parse_feed(source: Dict, max_items: int = MAX_INGEST_PER_FEED) -> List[Dict]:
    feed = feedparser.parse(source["url"])
    articles: List[Dict] = []

    for entry in feed.entries[:max_items]:
        title = (entry.get("title") or "").strip()
        source_url = (entry.get("link") or "").strip()
        if not title or not source_url:
            continue

        description = clean_html(entry.get("summary") or entry.get("description") or "")
        published_at = parse_published(entry)
        ingested_at = datetime.now(timezone.utc).isoformat()
        article_hash = compute_article_hash(title, source_url)

        articles.append(
            {
                "article_hash": article_hash,
                "source_name": source["name"],
                "source_url": source_url,
                "title": title,
                "description": description,
                "published_at": published_at,
                "ingested_at": ingested_at,
                "source_credibility": source["credibility"],
            }
        )

    return articles


def ingest_all_feeds() -> List[Dict]:
    records: List[Dict] = []
    for source in FEEDS:
        records.extend(parse_feed(source))
    return records
