import streamlit as st
import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = {
    "urgent": 10,
    "verify": 12,
    "password": 18,
    "account suspended": 18,
    "login": 14,
    "payment": 10,
    "invoice": 8,
    "gift card": 16,
    "wire transfer": 18,
    "limited time": 10,
    "click here": 10,
    "confirm your account": 18,
}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "tk", "ml", "cf"}

URL_RE = re.compile(r"https?://[^\s<>\")]+", re.I)


def analyze_email(email_text):
    findings = []
    score = 0
    text = email_text.lower()

    # Check suspicious phrases
    for phrase, points in SUSPICIOUS_WORDS.items():
        if phrase in text:
            score += points
            findings.append(f"+{points}: suspicious phrase found: '{phrase}'")

    # Extract URLs
    urls = URL_RE.findall(email_text)

    for url in urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        # IP address check
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            score += 18
            findings.append(f"+18: link uses raw IP address: {host}")

        # URL shorteners
        if host in SHORTENERS:
            score += 14
            findings.append(f"+14: shortened URL detected: {host}")

        # @ symbol hiding real domain
        if "@" in parsed.netloc:
            score += 16
            findings.append(f"+16: suspicious '@' usage in URL: {url}")

        # risky TLD
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in RISKY_TLDS:
            score += 8
            findings.append(f"+8: risky domain ending '.{tld}' in {host}")

    # generic greetings
    if "dear customer" in text or "dear user" in text:
        score += 5
        findings.append("+5: generic greeting detected")

    score = min(score, 100)

    if score >= 70:
        verdict = "🔴 High Risk - Likely Phishing"
    elif score >= 40:
        verdict = "🟠 Medium Risk - Suspicious"
    elif score >= 20:
        verdict = "🟡 Low Risk - Review Carefully"
    else:
        verdict = "🟢 Minimal Risk"

    return score, verdict, findings


# ---------------- STREAMLIT UI ----------------

st.set_page_config(page_title="Phishing Detector", page_icon="🛡️")

st.title("🛡️ AI Phishing Email Detector")
st.write("Paste an email below to analyze it for phishing risks.")

email = st.text_area("Email Content", height=250)

if st.button("Analyze Email"):
    if email.strip():
        score, verdict, findings = analyze_email(email)

        st.subheader("Result")
        st.metric("Risk Score", f"{score}/100")
        st.write(f"**Verdict:** {verdict}")

        st.subheader("Findings")

        if findings:
            for f in findings:
                st.write("• " + f)
        else:
            st.success("No major phishing indicators found.")
    else:
        st.warning("Please paste an email before analyzing.")
