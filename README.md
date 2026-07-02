# SOC Threat Intelligence & Live Attack Simulation Platform

## Overview
This project is a Security Operations Center (SOC) simulation platform that combines machine learning, rule-based threat intelligence, and real-time attack stream simulation to mimic enterprise cybersecurity monitoring environments.

It analyzes emails for phishing attempts, assigns risk scores, and generates live security alerts similar to what SOC analysts use in real-world operations.

---

## Features

### AI Threat Detection
- Machine learning model (Naive Bayes)
- TF-IDF text classification
- Phishing probability scoring

### Threat Intelligence Engine
- Suspicious URL detection
- Risky domain analysis
- Obfuscated link detection

### Live SOC Simulation
- Real-time attack stream generator
- Continuous email threat ingestion
- Automatic risk classification

### SOC Dashboard
- Live threat feed (HIGH / MEDIUM / LOW alerts)
- Incident logging system
- Historical security event tracking

### Incident Reporting
- Exportable SOC logs (CSV format)
- Analyst-ready structured reports

---

##  How It Works
1. Email is input or generated in live stream
2. ML model predicts phishing probability
3. URL intelligence engine evaluates links
4. Combined scoring system calculates risk level
5. Result is displayed in SOC dashboard
6. Event is logged for auditing and analysis

---

## Technologies Used
- Python
- Streamlit
- Scikit-learn
- Pandas
- NumPy

---

## SOC Simulation Capabilities
This system simulates:
- Security Operations Center alert pipelines
- Real-time threat monitoring
- Incident triage workflows
- Analyst decision-making environments

---

## Future Enhancements
- Integration with VirusTotal API
- MITRE ATT&CK classification mapping
- Role-based authentication system
- Database persistence (PostgreSQL)
- Docker deployment for enterprise simulation
- FastAPI backend microservice architecture

---

## Career Relevance
This project demonstrates practical skills in:
- Cybersecurity threat detection
- Machine learning applications in security
- SOC workflow simulation
- Data analysis and incident response

---

## Author
Built as a cybersecurity portfolio project demonstrating SOC-level threat intelligence simulation and machine learning integration.
