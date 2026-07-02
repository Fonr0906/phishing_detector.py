# AI-Powered Phishing Email Detector

## Overview
The AI-Powered Phishing Email Detector is a Python application that analyzes email content to identify potential phishing attempts. It checks for common phishing indicators such as suspicious language, risky links, and spoofing techniques, then generates a risk score and explains why the email may be malicious.

## Features
- Analyze email text for phishing indicators
- Detect suspicious links and phishing language
- Generate a Low, Medium, or High risk score
- Explain why an email was flagged
- Simple web interface built with Streamlit

## Technologies Used
- Python
- Streamlit
- Regular Expressions (Regex)
- urllib

## How to Run
1. Install the required package:
   ```
   pip install -r requirements.txt
   ```
2. Start the application:
   ```
   streamlit run phishing_detector.py
   ```

## Goal
This project demonstrates how Python can be used to improve cybersecurity awareness by helping users identify phishing emails quickly and accurately.
