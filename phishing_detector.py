import streamlit as st
import re
import pandas as pd
import numpy as np
from urllib.parse import urlparse

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB

# ---------------- PAGE CONFIG ----------------
st.set_page_config(page_title="SOC Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ SOC Email Threat Detection Dashboard")

# ---------------- SAMPLE TRAINING DATA ----------------
emails = [
    "Your account is suspended click here to verify password",
    "Urgent invoice payment required wire transfer now",
    "Dear friend let's meet for lunch tomorrow",
    "Your Amazon order has been shipped",
    "Confirm your account login immediately",
    "Hey are we still meeting today?"
]

labels = [1, 1, 0, 0, 1, 0]

vectorizer = CountVectorizer()
X = vectorizer.fit_transform(emails)

model = MultinomialNB()
model.fit(X, labels)

# ---------------- URL ANALYSIS ----------------

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "tk", "ml", "cf"}

URL_RE = re.compile(r"https?://[^\s<>\")]+", re.I)


def url_risk(text):
    score = 0
    urls = URL_RE.findall(text)

    for url in urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        if host in SHORTENERS:
            score += 20
        if any(host.endswith(tld) for tld in RISKY_TLDS):
            score += 10
        if "@" in parsed.netloc:
            score += 15

    return min(score, 100), urls


# ---------------- PREDICTION ----------------

def analyze(text):
    X_input = vectorizer.transform([text])
    prob = model.predict_proba(X_input)[0]

    confidence = float(np.max(prob)) * 100
    ml_score = confidence if np.argmax(prob) == 1 else (100 - confidence)

    url_score, urls = url_risk(text)

    final_score = (ml_score * 0.6) + (url_score * 0.4)

    if final_score >= 70:
        risk = "🔴 HIGH"
    elif final_score >= 40:
        risk = "🟠 MEDIUM"
    else:
        risk = "🟢 LOW"

    return risk, final_score, ml_score, url_score, urls


# ---------------- SESSION STATE (SOC LOGS) ----------------

if "logs" not in st.session_state:
    st.session_state.logs = pd.DataFrame(columns=[
        "Email", "Risk", "Score", "ML Score", "URL Score"
    ])

# ---------------- DASHBOARD LAYOUT ----------------

tab1, tab2 = st.tabs(["📧 Email Analyzer", "📊 SOC Logs"])

# ================= TAB 1 =================
with tab1:

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Email Input")
        email = st.text_area("Paste Email Here", height=250)

        if st.button("Analyze Email"):

            if email.strip():

                risk, score, ml_score, url_score, urls = analyze(email)

                st.subheader("Results")

                st.metric("Risk Level", risk)
                st.metric("Final Score", f"{score:.2f}/100")

                st.write(f"**ML Score:** {ml_score:.2f}")
                st.write(f"**URL Risk Score:** {url_score}")

                if urls:
                    st.write("**Detected URLs:**")
                    for u in urls:
                        st.code(u)

                # add to logs
                new_row = {
                    "Email": email[:50] + "...",
                    "Risk": risk,
                    "Score": round(score, 2),
                    "ML Score": round(ml_score, 2),
                    "URL Score": url_score
                }

                st.session_state.logs = pd.concat(
                    [st.session_state.logs, pd.DataFrame([new_row])],
                    ignore_index=True
                )

            else:
                st.warning("Please enter an email")

    with col2:
        st.subheader("SOC Summary")

        logs = st.session_state.logs

        if len(logs) > 0:
            st.metric("Total Emails Analyzed", len(logs))
            st.metric("High Risk Alerts",
                      len(logs[logs["Risk"] == "🔴 HIGH"]))

            st.write("Recent Activity:")
            st.dataframe(logs.tail(10))
        else:
            st.info("No logs yet")

# ================= TAB 2 =================
with tab2:
    st.subheader("SOC Incident Logs")

    if len(st.session_state.logs) > 0:
        st.dataframe(st.session_state.logs, use_container_width=True)

        st.download_button(
            "Download Logs",
            st.session_state.logs.to_csv(index=False),
            "soc_logs.csv",
            "text/csv"
        )
    else:
        st.info("No incidents recorded yet")re analyzing.")
