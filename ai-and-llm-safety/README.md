# Secure RAG Chatbot with OWASP LLM Top 10 Security

A production-ready RAG (Retrieval-Augmented Generation) chatbot with comprehensive security controls based on the OWASP LLM Top 10 (2025) threat model.

## Features

### 🔐 Security Implementations

| OWASP Category | Protection |
|----------------|------------|
| **LLM01: Prompt Injection** | 17+ regex patterns blocking instruction overrides, jailbreaks, delimiter injection |
| **LLM02: Insecure Output** | HTML escaping, XSS filtering, content sanitization |
| **LLM06: Sensitive Info Disclosure** | PII detection (email, phone, SSN, credit cards, API keys) |
| **LLM08: Excessive Agency** | Tool registry, human-in-the-loop approval, rate limiting, audit logging |

### 🛠️ Tech Stack

- **LLM**: Ollama (gemma4:e4b)
- **Embeddings**: nomic-embed-text
- **Vector Store**: ChromaDB
- **API**: FastAPI
- **UI**: Streamlit
- **Testing**: Custom test harness + garak

## Project Structure

```
phase1_chatbot/
├── src/
│   ├── config.py              # Configuration & hardened system prompts
│   ├── models.py              # Ollama/OpenAI clients
│   ├── embed.py               # ChromaDB vector store
│   ├── retrieve.py            # Similarity search
│   ├── generate.py            # RAG pipeline with guardrails
│   ├── chat.py                # Chat session management
│   ├── guardrails.py          # Input/output guardrails
│   ├── input_validation.py    # Regex-based input validation
│   ├── pii_detection.py       # PII detection & redaction
│   └── tool_security.py       # LLM08 tool use controls
├── ui/
│   ├── app.py                 # Streamlit web UI
│   └── cli.py                 # CLI interface
├── api/
│   └── main.py                # FastAPI REST API
├── docs/                      # Documentation
│   ├── SECURITY_TESTING_METHODOLOGY.md
│   └── SECURITY_TEST_REPORT.md
├── phase2_threat_model/       # Security analysis
│   ├── threat_model.md        # OWASP LLM Top 10 analysis
│   └── red_team/              # Test suites
│       ├── llm_security_test_harness.py  # 110+ test cases
│       └── test_guardrails_only.py        # Guardrail verification
└── requirements.txt
```

## Quick Start

### Prerequisites

- Python 3.10+
- Ollama installed with gemma4:e4b model

### Installation

```bash
# Clone and navigate to project
cd phase1_chatbot

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### Run the Chatbot

**CLI Interface:**
```bash
python ui/cli.py
```

**Web UI (Streamlit):**
```bash
streamlit run ui/app.py
```

**REST API:**
```bash
uvicorn api.main:app --reload
# API available at http://localhost:8000
```

## Security Testing

### Run Test Suite

```bash
# Test guardrails
python src/test_guardrails.py

# Test tool security
python src/test_tool_security.py

# Run full test harness
python phase2_threat_model/red_team/test_guardrails_only.py
```

### Test Results

- **Attack Attempts Blocked**: 5/5 (100%)
- **Normal Inputs Allowed**: 3/3 (100%)
- **110+ Test Cases** across 8 security categories
- **Overall Risk Rating**: LOW

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/chat` | Send a chat message |
| POST | `/ingest` | Ingest documents |
| GET | `/health` | Health check |

### Example Request

```bash
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello", "session_id": "user123"}'
```

## Documentation

- [Security Testing Methodology](docs/SECURITY_TESTING_METHODOLOGY.md) - Complete testing framework
- [Security Test Report](docs/SECURITY_TEST_REPORT.md) - Test results and findings
- [Threat Model](phase2_threat_model/threat_model.md) - OWASP LLM Top 10 analysis

## Key Security Features

### Input Guardrails
- Instruction override detection
- Jailbreak pattern blocking (DAN, EvilBot, etc.)
- System prompt extraction prevention
- Delimiter injection filtering

### Output Filtering
- HTML escaping for XSS prevention
- PII detection and redaction
- Dangerous content filtering

### Tool Security (LLM08)
- Risk-based tool classification (Low/Medium/High/Critical)
- Human-in-the-loop approval for sensitive operations
- Rate limiting per tool
- Sequence allowlisting
- Parameter validation (blocks path traversal, command injection)
- Comprehensive audit logging

## OWASP LLM Top 10 Coverage

| # | Category | Status |
|---|----------|--------|
| LLM01 | Prompt Injection | ✅ |
| LLM02 | Insecure Output Handling | ✅ |
| LLM03 | Training Data Poisoning | ℹ️ Out of scope |
| LLM04 | Model Denial of Service | ✅ |
| LLM05 | Supply Chain | ⚠️ Manual review |
| LLM06 | Sensitive Information Disclosure | ✅ |
| LLM07 | Insecure Plugin Design | ✅ |
| LLM08 | Excessive Agency | ✅ |
| LLM09 | Overreliance | ⚠️ Recommendations |
| LLM10 | Model Theft | ℹ️ Out of scope |

## License

MIT License

## Acknowledgments

- [OWASP LLM Top 10 (2025)](https://owasp.org/www-project-llm-top-10/)
- [garak](https://github.com/NVIDIA/garak) - LLM vulnerability scanner
- [Ollama](https://ollama.ai/) - Local LLM runtime
