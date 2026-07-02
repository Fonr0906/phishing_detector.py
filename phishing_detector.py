import streamlit as st
import pandas as pd
import numpy as np
import re
import time
import random
import threading
from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# ---------------- PAGE SETUP ----------------
st.set_page_config(page_title="SOC Threat Intelligence Platform", layout="wide")

st.title("🛡️ SOC Threat Intelligence & Live Attack Simulation Platform")

# ---------------- SOC ROLE LOGIN ----------------
st.sidebar.title("SOC Analyst Panel")

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

# ---------------- THREAT INTEL ----------------
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

    return [k for k in keywords if k in text.lower()]

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

# ---------------- INCIDENT LOG ----------------
if "logs" not in st.session_state:
    st.session_state.logs = pd.DataFrame(columns=[
        "Email", "Risk", "Score", "ML Score", "URL Score"
    ])

# ---------------- ANALYSIS ENGINE ----------------
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

# ---------------- ATTACK STREAM ----------------
attack_pool = [
    "URGENT: Your account has been suspended verify immediately",
    "Click here to reset your password before access is lost",
    "Security alert: unusual login detected from unknown device",
    "Your bank account is locked confirm identity now",
    "Invoice overdue wire transfer required ASAP",
    "Hey just checking in about the meeting tomorrow",
    "Project update attached please review",
    "You have won a gift card claim it now"
]

if "streaming" not in st.session_state:
    st.session_state.streaming = False

def stream_attacks():
    while st.session_state.streaming:
        email = random.choice(attack_pool)

        risk, score, ml, url_s, urls, keywords = analyze(email)

        new_log = pd.DataFrame([{
            "Email": email[:60],
            "Risk": risk,
            "Score": round(score, 2),
            "ML Score": round(ml, 2),
            "URL Score": url_s
        }])

        st.session_state.logs = pd.concat(
            [st.session_state.logs, new_log],
            ignore_index=True
        )

        time.sleep(2)

# ---------------- TABS ----------------
tab1, tab2, tab3 = st.tabs([
    "📧 Live SOC Feed",
    "🔥 Real-Time Stream",
    "📁 Incident Reports"
])

# ================= TAB 1 =================
with tab1:

    st.subheader("Manual Email Analysis")

    email = st.text_area("Paste Email", height=200)

    if st.button("Analyze Email"):

        if email.strip():

            risk, score, ml, url_s, urls, keywords = analyze(email)

            col1, col2 = st.columns(2)
            col1.metric("Risk Level", risk)
            col2.metric("Threat Score", f"{score:.2f}")

            st.progress(min(int(score), 100))

            st.subheader("🧠 Explanation Engine")
            st.write(keywords if keywords else "No suspicious keywords detected")

            if urls:
                st.subheader("🔗 URLs Found")
                for u in urls:
                    st.code(u)

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

# ================= TAB 2 =================
with tab2:

    st.subheader("🔥 Live SOC Stream Control")

    col1, col2 = st.columns(2)

    if col1.button("▶ Start Stream"):
        st.session_state.streaming = True
        threading.Thread(target=stream_attacks, daemon=True).start()
        st.success("SOC stream started")

    if col2.button("⛔ Stop Stream"):
        st.session_state.streaming = False
        st.warning("SOC stream stopped")

    st.subheader("🚨 Live Threat Feed")

    latest = st.session_state.logs.tail(10)

    for _, row in latest.iterrows():
        if row["Risk"] == "🔴 HIGH":
            st.error(f"{row['Email']} | Score: {row['Score']}")
        elif row["Risk"] == "🟠 MEDIUM":
            st.warning(f"{row['Email']} | Score: {row['Score']}")
        else:
            st.info(f"{row['Email']} | Score: {row['Score']}")

# ================= TAB 3 =================
with tab3:

    st.subheader("SOC Incident Reports")

    if len(st.session_state.logs) > 0:

        st.dataframe(st.session_state.logs)

        st.download_button(
            "Download SOC Report",
            st.session_state.logs.to_csv(index=False),
            "soc_report.csv"
        )

    else:
        st.info("No incidents recorded yet")
