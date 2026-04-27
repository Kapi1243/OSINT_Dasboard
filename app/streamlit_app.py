import json
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from osint_dashboard.config import THREAT_LABELS
from osint_dashboard.database import fetch_dashboard_rows, initialize_database, upsert_feedback
from osint_dashboard.pipeline import run_full_pipeline

st.set_page_config(page_title="OSINT Threat Intelligence Dashboard", layout="wide")


@st.cache_data(ttl=60)
def load_data(limit: int = 500) -> pd.DataFrame:
    rows = fetch_dashboard_rows(limit=limit)
    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame([dict(row) for row in rows])
    for col in ["entities_json", "top_features_json"]:
        df[col] = df[col].fillna("{}" if col == "entities_json" else "[]")
        df[col] = df[col].apply(lambda x: json.loads(x) if isinstance(x, str) else x)

    df["needs_human_review"] = df["needs_human_review"].fillna(1).astype(int)
    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce").fillna(0)
    df["confidence_percent"] = pd.to_numeric(df["confidence_percent"], errors="coerce").fillna(0)
    return df


def entity_frequency(df: pd.DataFrame, key: str) -> pd.DataFrame:
    counts = {}
    for entities in df["entities_json"]:
        values = entities.get(key, []) if isinstance(entities, dict) else []
        for value in values:
            counts[value] = counts.get(value, 0) + 1
    freq = pd.DataFrame(counts.items(), columns=["entity", "count"]).sort_values("count", ascending=False)
    return freq.head(10)


def source_reliability(df: pd.DataFrame) -> pd.DataFrame:
    frame = df.copy()
    frame["marked_false_positive"] = frame["marked_false_positive"].fillna(0).astype(int)
    grouped = frame.groupby("source_name", dropna=False).agg(
        total_articles=("id", "count"),
        reviewed_items=("override_label", lambda x: x.notna().sum()),
        false_positives=("marked_false_positive", "sum"),
    )
    grouped["false_positive_rate_pct"] = (
        (grouped["false_positives"] / grouped["reviewed_items"].replace({0: pd.NA})) * 100
    ).fillna(0).round(2)
    return grouped.reset_index().sort_values("false_positive_rate_pct", ascending=False)


def render_override_panel(selected_row: pd.Series):
    st.subheader("Human Review Override")
    st.write("Use this when model confidence is low or classification is incorrect.")

    with st.form("override_form"):
        override_label = st.selectbox("Override label", THREAT_LABELS)
        notes = st.text_area("Review notes", placeholder="Why was this overridden?")
        marked_false_positive = st.checkbox("Mark as false positive")
        submitted = st.form_submit_button("Save review")

        if submitted:
            upsert_feedback(
                {
                    "article_id": int(selected_row["id"]),
                    "original_label": str(selected_row.get("predicted_label") or "unknown"),
                    "override_label": override_label,
                    "notes": notes,
                    "marked_false_positive": int(marked_false_positive),
                    "reviewed_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            st.success("Review saved. Refresh the page to update charts.")


def render_reasoning(top_features):
    if not top_features:
        st.write("No top feature explanation available.")
        return
    for item in top_features:
        feature = item.get("feature", "")
        contribution = item.get("contribution", 0)
        st.write(f"- {feature} (contribution: {contribution})")


initialize_database()
st.title("OSINT Threat Intelligence Dashboard")

with st.sidebar:
    st.header("Controls")
    if st.button("Run Full Pipeline Now"):
        result = run_full_pipeline()
        st.success(f"Pipeline completed: {result}")
        st.cache_data.clear()
    refresh = st.button("Refresh Data")
    if refresh:
        st.cache_data.clear()


df = load_data()
if df.empty:
    st.info("No data found. Click 'Run Full Pipeline Now' to ingest and score articles.")
    st.stop()

col1, col2, col3 = st.columns(3)
col1.metric("Total Articles", int(df["id"].count()))
col2.metric("Needs Human Review", int((df["needs_human_review"] == 1).sum()))
col3.metric("Average Risk", round(df["risk_score"].mean(), 2))

st.subheader("Risk Score Leaderboard")
leaderboard_cols = [
    "id",
    "source_name",
    "title",
    "predicted_label",
    "risk_score",
    "confidence_percent",
    "needs_human_review",
]
st.dataframe(df[leaderboard_cols].head(50), use_container_width=True)

left, right = st.columns(2)
with left:
    st.subheader("Top Threat Actors")
    actors = entity_frequency(df, "threat_actors")
    if actors.empty:
        st.write("No actors extracted yet.")
    else:
        st.bar_chart(actors.set_index("entity"))

with right:
    st.subheader("Top CVEs")
    cves = entity_frequency(df, "cves")
    if cves.empty:
        st.write("No CVEs extracted yet.")
    else:
        st.bar_chart(cves.set_index("entity"))

st.subheader("Feed Source Reliability (Bias / False Positives)")
st.dataframe(source_reliability(df), use_container_width=True)

st.subheader("Article Detail View")
options = df.apply(lambda r: f"{int(r['id'])} | {r['title'][:120]}", axis=1).tolist()
selected_option = st.selectbox("Select article", options=options)
selected_id = int(selected_option.split("|")[0].strip())
selected_row = df[df["id"] == selected_id].iloc[0]

st.markdown(f"**Title:** {selected_row['title']}")
st.markdown(f"**Source:** {selected_row['source_name']}")
st.markdown(f"**Predicted label:** {selected_row.get('predicted_label', 'n/a')}")
st.markdown(f"**Risk score:** {selected_row.get('risk_score', 0)}")
st.markdown(f"**Confidence %:** {selected_row.get('confidence_percent', 0)}")
st.markdown(f"**Needs review:** {bool(selected_row.get('needs_human_review', 1))}")
st.markdown(f"**Reasoning:** {selected_row.get('reasoning', '')}")

st.markdown("**Top TF-IDF Drivers:**")
render_reasoning(selected_row.get("top_features_json", []))

entities = selected_row.get("entities_json", {})
st.markdown("**Extracted Entities:**")
st.json(entities)

if int(selected_row.get("needs_human_review", 1)) == 1:
    render_override_panel(selected_row)
