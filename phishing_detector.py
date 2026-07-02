import streamlit as st
import pandas as pd
import numpy as np
import re
import time
from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# ---------------- PAGE SETUP ----------------
st.set_page_config(page_title="Enterprise SOC Simulator", layout="wide")

st.title("🛡️ Enterprise SOC Simulation Dashboard")

# ---------------- SOC LOGIN ----------------
st.sidebar.title("SOC Analyst Login")

role = st.sidebar.selectbox(
    "Select Role",
    ["Tier 1 Analyst", "Tier 2 Analyst", "SOC Manager"]
)

st.sidebar.write(f"Logged in as: **{role}**")

# ---------------- DATASET ----------------
data = [
    ("Urgent verify your password immediately", 1),
    ("Click here to confirm account login", 1),
    ("Wire transfer invoice overdue urgent", 1),
    ("Your Amazon package has shipped", 0),
    ("Team meeting scheduled for tomorrow", 0),
    ("Please review the attached report", 0),
    ("Account suspended login required", 1),
    ("Happy birthday hope you are well", 0),
]

df = pd.DataFrame(data, columns=["text", "label"])

X_train, X_test, y_train, y_test = train_test_split(
    df["text"], df["label"], test_size=0.25, random_state=42
)

vectorizer = TfidfVectorizer(stop_words="english")
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

model = MultinomialNB()
model.fit(X_train_vec, y_train)

# ---------------- URL THREAT INTEL ----------------
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co"}
RISKY_TLDS = {"zip", "xyz", "click", "tk", "ml"}
URL_RE = re.compile(r"https?://[^\s<>\")]+", re.I)


# ---------------- EXPLAINABILITY ----------------
def explain_email(text):
    keywords = [
        "urgent", "verify", "password", "click",
        "login", "account", "suspended",
        "wire", "transfer"
    ]

    found = []
    lower = text.lower()

    for k in keywords:
        if k in lower:
            found.append(k)

    return found


# ---------------- URL SCORING ----------------
def url_score(text):
    score = 0
    urls = URL_RE.findall(text)

    for url in urls:
        host = urlparse(url).hostname or ""

        if host in SHORTENERS:
            score += 25
        if any(host.endswith(t) for t in RISKY_TLDS):
            score += 15
        if "@" in url:
            score += 20

    return min(score, 100), urls


# ---------------- INCIDENT LOG SYSTEM ----------------
if "logs" not in st.session_state:
    st.session_state.logs = pd.DataFrame(columns=[
        "Email", "Risk", "Score", "ML Score", "URL Score"
    ])


# ---------------- MAIN ANALYSIS ----------------
def analyze(text):
    vec = vectorizer.transform([text])
    ml_prob = model.predict_proba(vec)[0][1] * 100

    url_s, urls = url_score(text)
    keywords = explain_email(text)

    final = (ml_prob * 0.7) + (url_s * 0.3)

    if final >= 70:
        risk = "🔴 HIGH"
    elif final >= 40:
        risk = "🟠 MEDIUM"
    else:
        risk = "🟢 LOW"

    return risk, final, ml_prob, url_s, urls, keywords


# ---------------- TABS ----------------
tab1, tab2, tab3 = st.tabs([
    "📧 Live SOC Feed",
    "📊 Threat Analytics",
    "📁 Incident Reports"
])

# ================= TAB 1 =================
with tab1:

    st.subheader("Live Email Threat Detection")

    email = st.text_area("Paste Email", height=200)

    col1, col2 = st.columns(2)

    if st.button("Analyze Email"):

        if email.strip():

            risk, score, ml, url_s, urls, keywords = analyze(email)

            col1.metric("Risk Level", risk)
            col2.metric("Threat Score", f"{score:.2f}")

            st.progress(min(int(score), 100))

            st.subheader("🧠 Explanation Engine")
            if keywords:
                st.write("Suspicious keywords detected:")
                st.write(keywords)
            else:
                st.write("No major phishing keywords found")

            if urls:
                st.subheader("🔗 Detected URLs")
                for u in urls:
                    st.code(u)

            # LOG INCIDENT (UPGRADED)
            st.session_state.logs = pd.concat([
                st.session_state.logs,
                pd.DataFrame([{
                    "Email": email[:60],
                    "Risk": risk,
                    "Score": round(score, 2),
                    "ML Score": round(ml, 2),
                    "URL Score": url_s
                }])
            ], ignore_index=True)

        else:
            st.warning("Enter email first")

    # LIVE SIMULATION MODE
    if st.button("Run Live SOC Simulation"):

        samples = [
            "Urgent verify your account now",
            "Team meeting tomorrow",
            "Click here to reset password",
            "Project update attached"
        ]

        for s in samples:
            st.write("Analyzing:", s)
            time.sleep(1)

# ================= TAB 2 =================
with tab2:

    st.subheader("Threat Analytics Dashboard")

    logs = st.session_state.logs

    if len(logs) > 0:

        st.metric("Total Alerts", len(logs))
        st.metric("High Risk Alerts", len(logs[logs["Risk"] == "🔴 HIGH"]))

        st.bar_chart(logs["Risk"].value_counts())

        st.dataframe(logs)

    else:
        st.info("No incidents yet")

# ================= TAB 3 =================
with tab3:

    st.subheader("Incident Export System")

    logs = st.session_state.logs

    if len(logs) > 0:

        st.download_button(
            "Download SOC Report",
            logs.to_csv(index=False),
            "soc_report.csv"
        )

        st.dataframe(logs)

    else:
        st.info("No reports available")
