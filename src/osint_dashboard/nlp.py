import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import spacy
from joblib import dump, load
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from textblob import TextBlob

from .config import (
    HUMAN_REVIEW_CONFIDENCE_THRESHOLD,
    LABELS_PATH,
    MODEL_PATH,
    SEVERITY_KEYWORDS,
    THREAT_LABELS,
    VECTORIZER_PATH,
)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


@dataclass
class NLPArtifacts:
    vectorizer: TfidfVectorizer
    classifier: LogisticRegression


class ThreatNLP:
    def __init__(self, labels_path: Path = LABELS_PATH):
        self.labels_path = labels_path
        self.nlp = self._load_spacy_model()
        self.artifacts = self._load_or_train_model()

    @staticmethod
    def _load_spacy_model():
        try:
            return spacy.load("en_core_web_sm")
        except OSError:
            return spacy.blank("en")

    def _load_or_train_model(self) -> NLPArtifacts:
        if MODEL_PATH.exists() and VECTORIZER_PATH.exists():
            return NLPArtifacts(load(VECTORIZER_PATH), load(MODEL_PATH))
        return self.train_and_save_model()

    def train_and_save_model(self) -> NLPArtifacts:
        df = pd.read_csv(self.labels_path)
        df = df.dropna(subset=["text", "label"])
        df = df[df["label"].isin(THREAT_LABELS)]

        vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            min_df=1,
            max_df=0.95,
            stop_words="english",
        )
        X = vectorizer.fit_transform(df["text"].astype(str))
        y = df["label"].astype(str)

        classifier = LogisticRegression(
            max_iter=1500,
            class_weight="balanced",
            random_state=42,
            multi_class="multinomial",
        )
        classifier.fit(X, y)

        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        dump(vectorizer, VECTORIZER_PATH)
        dump(classifier, MODEL_PATH)

        return NLPArtifacts(vectorizer, classifier)

    def extract_entities(self, text: str) -> Dict[str, List[str]]:
        doc = self.nlp(text)

        entities = {
            "threat_actors": sorted({ent.text for ent in doc.ents if ent.label_ in {"ORG", "PERSON"}}),
            "organizations": sorted({ent.text for ent in doc.ents if ent.label_ == "ORG"}),
            "cves": sorted({match.upper() for match in CVE_PATTERN.findall(text)}),
            "products": sorted({ent.text for ent in doc.ents if ent.label_ in {"PRODUCT", "ORG"}}),
        }
        return entities

    def keyword_severity_score(self, text: str) -> Tuple[float, List[str]]:
        lowered = text.lower()
        matched = [kw for kw in SEVERITY_KEYWORDS if kw in lowered]
        if not matched:
            return 10.0, []
        score = min(100.0, 25.0 + len(matched) * 15.0)
        return score, matched

    @staticmethod
    def compute_urgency_signal(severity_score: float, sentiment_polarity: float) -> float:
        negative_sentiment = max(0.0, -sentiment_polarity)
        urgency = min(100.0, 0.85 * severity_score + 15.0 * negative_sentiment)
        return round(urgency, 2)

    def classify(self, text: str) -> Tuple[str, float, np.ndarray]:
        vec = self.artifacts.vectorizer.transform([text])
        probabilities = self.artifacts.classifier.predict_proba(vec)[0]
        idx = int(np.argmax(probabilities))
        label = self.artifacts.classifier.classes_[idx]
        confidence = float(probabilities[idx])
        return label, confidence, vec.toarray()[0]

    def explain_top_features(self, label: str, feature_values: np.ndarray, top_k: int = 5) -> List[Dict]:
        class_index = int(np.where(self.artifacts.classifier.classes_ == label)[0][0])
        weights = self.artifacts.classifier.coef_[class_index]
        vocab = np.array(self.artifacts.vectorizer.get_feature_names_out())

        contributions = feature_values * weights
        active_indices = np.where(feature_values > 0)[0]
        if len(active_indices) == 0:
            return []

        top_indices = active_indices[np.argsort(contributions[active_indices])[::-1][:top_k]]
        return [
            {
                "feature": str(vocab[i]),
                "contribution": round(float(contributions[i]), 4),
                "value": round(float(feature_values[i]), 4),
            }
            for i in top_indices
            if contributions[i] > 0
        ]

    def analyze_text(self, text: str) -> Dict:
        entities = self.extract_entities(text)
        label, confidence, feature_values = self.classify(text)
        top_features = self.explain_top_features(label, feature_values)

        severity_score, matched_keywords = self.keyword_severity_score(text)
        sentiment_polarity = TextBlob(text).sentiment.polarity
        urgency_signal = self.compute_urgency_signal(severity_score, sentiment_polarity)

        reasoning_parts = [
            f"label={label}",
            f"confidence={confidence:.2f}",
            f"severity_keywords={','.join(matched_keywords) if matched_keywords else 'none'}",
            f"top_features={','.join(f['feature'] for f in top_features) if top_features else 'n/a'}",
        ]

        return {
            "predicted_label": label,
            "classifier_confidence": confidence,
            "severity_keyword_score": severity_score,
            "sentiment_polarity": sentiment_polarity,
            "urgency_signal": urgency_signal,
            "entities": entities,
            "top_features": top_features,
            "reasoning": " | ".join(reasoning_parts),
            "needs_human_review": confidence < HUMAN_REVIEW_CONFIDENCE_THRESHOLD,
        }


def serialize_json(data: Dict | List[Dict]) -> str:
    return json.dumps(data, ensure_ascii=True)
