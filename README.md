# 🛡️ SentinelAI

> **Detect. Explain. Protect.**

SentinelAI is an AI-powered fraud detection platform developed for the **ET AI Hackathon 2026** under the problem statement:

**"AI for Digital Public Safety: Defeating Counterfeiting, Fraud & Digital Arrest Scams."**

The platform analyzes suspicious messages and scam content using a hybrid AI pipeline that combines deterministic rule-based detection, semantic similarity search, and Large Language Models (LLMs) to provide explainable threat assessments.

---

## 🚀 Features

- 🔍 Digital Arrest Scam Detection
- 📱 SMS & WhatsApp Scam Detection
- 📧 Email Phishing Detection
- 🏦 Fake Banking Message Detection
- 🤖 AI-powered Threat Explanation
- 📊 Risk Score & Confidence Score
- 💬 AI Chat Assistance
- 📄 PDF Evidence Report Generation
- 🧠 Conversation Memory
- 📈 Analytics APIs
- 🔐 JWT Authentication
- 🗄 MongoDB Integration

---

## 🏗️ Backend Architecture

```
FastAPI
   │
   ├── Authentication
   ├── Fraud Detection Engine
   ├── Rule Engine
   ├── Similarity Matching
   ├── Gemini (LangChain)
   ├── Analytics
   ├── Chat Service
   ├── Report Generator
   └── MongoDB
```

---

## 🧠 AI Detection Pipeline

1. Input Message
2. Rule-based Red Flag Detection
3. Campaign Similarity Matching
4. Entity Extraction
5. LLM Reasoning (Gemini via LangChain)
6. Risk Score Calculation
7. Threat Classification
8. Explainable Verdict

---

## 📂 Project Structure

```
backend/
│
├── main.py
├── config.py
├── database.py
├── security.py
├── schemas.py
│
├── services/
│   ├── detector.py
│   ├── llm.py
│   ├── similarity.py
│   ├── report.py
│   ├── analytics.py
│   ├── memory.py
│   └── seed.py
│
├── routes/
│   ├── auth.py
│   ├── analyze.py
│   ├── analytics.py
│   └── chat.py
│
├── scripts/
│   ├── generate_dataset.py
│   └── evaluate.py
│
└── data/
```

---

## 🛠 Tech Stack

### Backend

- Python
- FastAPI
- MongoDB
- Pydantic
- JWT Authentication
- bcrypt

### AI

- Google Gemini
- LangChain
- Rule-based NLP
- TF-IDF Similarity Matching

---

## 📊 Synthetic Dataset

The project includes utilities for generating realistic datasets containing:

- Scam Messages
- Complaint Records
- Fraud Hotspots
- State Statistics
- Scam Campaign Library

---

## 🔐 Authentication

- User Registration
- Login
- JWT Token Generation
- Password Hashing
- Protected Endpoints

---

## 📈 APIs

Current backend includes APIs for:

- Authentication
- Scam Analysis
- Analytics
- AI Chat
- Report Generation

---

## ⚙️ Getting Started

### Clone Repository

```bash
git clone https://github.com/<your-username>/SentinelAI.git
cd SentinelAI
```

### Create Virtual Environment

```bash
python -m venv venv
```

Windows

```bash
venv\Scripts\activate
```

Linux / macOS

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure Environment

Create a `.env` file and configure:

```env
MONGODB_URI=
JWT_SECRET=
GOOGLE_API_KEY=
```

### Run the Server

```bash
uvicorn main:app --reload
```

---

## 🎯 Future Work

- React Dashboard
- Interactive Analytics
- India Heat Map
- Complaint Visualization
- Threat Timeline
- Advanced AI Agents
- Mobile Responsive UI

---

## 🏆 Hackathon

Developed for:

**ET AI Hackathon 2026**

Problem Statement:

> AI for Digital Public Safety: Defeating Counterfeiting, Fraud & Digital Arrest Scams.

---

## 📄 License

This project was developed as a hackathon prototype for educational and demonstration purposes.
