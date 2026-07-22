# 🛡️ SentinelAI

> **Detect. Explain. Protect.**

SentinelAI is an AI-powered fraud detection platform developed for the **ET AI Hackathon 2026** under the problem statement:

> **AI for Digital Public Safety: Defeating Counterfeiting, Fraud & Digital Arrest Scams**

The platform analyzes suspicious messages and scam content using a hybrid AI pipeline that combines rule-based detection, semantic similarity search, and Large Language Models (LLMs) to generate explainable fraud assessments and risk scores.

---

# 🚀 Features

- 🔍 Digital Arrest Scam Detection
- 📱 SMS & WhatsApp Scam Detection
- 📧 Email Phishing Detection
- 🏦 Banking Fraud Detection
- 🤖 AI-Powered Threat Explanation
- 📊 Risk Score & Confidence Score
- 💬 AI Chat Assistant
- 📄 PDF Report Generation
- 🧠 Conversation Memory
- 📈 Analytics APIs
- 🔐 JWT Authentication
- 🗄 MongoDB Integration

---

# 🏗️ Architecture

```
                User Input
                     │
                     ▼
              FastAPI Backend
                     │
     ┌───────────────┼───────────────┐
     │               │               │
     ▼               ▼               ▼
 Rule Engine   Similarity Engine   Gemini LLM
     │               │               │
     └───────────────┼───────────────┘
                     ▼
            Risk Score Generator
                     ▼
          Explainable Fraud Verdict
                     ▼
          MongoDB + Analytics APIs
```

---

# 🧠 AI Detection Pipeline

1. User submits suspicious content.
2. Rule engine detects known scam patterns.
3. Semantic similarity compares against known fraud campaigns.
4. AI model analyzes context and intent.
5. Risk score is calculated.
6. Fraud explanation is generated.
7. Final verdict is returned through the API.

---

# 📂 Project Structure

```
backend/
├── main.py
├── config.py
├── database.py
├── security.py
├── schemas.py
├── auth.py
├── analyze.py
├── analytics.py
├── chat.py
├── detector.py
├── llm.py
├── similarity.py
├── rules.py
├── red_flags.py
├── report.py
├── memory.py
├── campaigns.py
├── common.py
├── deps.py
├── evaluate.py
├── seed.py
└── generate_dataset.py
```

---

# 🛠 Tech Stack

### Backend

- Python
- FastAPI
- MongoDB
- Pydantic
- JWT Authentication
- bcrypt

### AI & Machine Learning

- Google Gemini
- LangChain
- Rule-Based NLP
- Semantic Similarity Matching

---

# 📊 Backend Capabilities

- Authentication APIs
- Scam Detection APIs
- AI Chat APIs
- Analytics APIs
- Report Generation
- Campaign Detection
- Risk Assessment
- Synthetic Dataset Generation

---

# ⚙️ Getting Started

### Clone the repository

```bash
git clone <repository-url>
cd SentinelAI
```

### Create a virtual environment

```bash
python -m venv venv
```

### Activate the environment

**Windows**

```bash
venv\Scripts\activate
```

**Linux / macOS**

```bash
source venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Configure Environment

Create a `.env` file and add the required configuration values for MongoDB, JWT authentication, and your Google Gemini API key.

### Run the server

```bash
uvicorn main:app --reload
```

The API will be available at:

```
http://127.0.0.1:8000
```

Interactive API documentation:

```
http://127.0.0.1:8000/docs
```

---

# 📈 Future Enhancements

- React Dashboard
- Interactive Analytics
- India Fraud Heatmap
- Real-time Scam Monitoring
- Multi-language Support
- Voice Scam Detection
- Mobile Application

---

# 🏆 Hackathon

Developed for the **ET AI Hackathon 2026**.

Problem Statement:

**AI for Digital Public Safety: Defeating Counterfeiting, Fraud & Digital Arrest Scams**

---

# 📄 License

This project was developed as a hackathon prototype for educational and demonstration purposes.
