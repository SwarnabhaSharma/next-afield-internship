# OWASP LLM Top 10 Threat Model: RAG Chatbot

**Project:** RAG-based Chatbot with Ollama (gemma4:e4b) + ChromaDB  
**Date:** April 2026  
**Analyst:** Security Assessment  
**Target:** phase1_chatbot

---

## 1. Executive Summary

This document presents a comprehensive threat model for a RAG (Retrieval-Augmented Generation) chatbot system. The system architecture consists of:

- **LLM Backend:** Ollama (gemma4:e4b) local model
- **Embedding Model:** nomic-embed-text
- **Vector Database:** ChromaDB (persistent, local)
- **Interface:** CLI + Streamlit web UI
- **Document Store:** Local filesystem (docs/)

The threat model follows the OWASP LLM Top 10 (2025) framework, mapping each vulnerability to specific attack vectors against the RAG architecture.

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER INPUT                               │
│              (Chat messages, document uploads)                  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      INPUT HANDLING                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   CLI UI    │  │ Streamlit   │  │  Document Ingestion     │ │
│  │  (cli.py)   │  │   (app.py)  │  │    (ingest.py)          │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    RAG PIPELINE                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   Embed     │  │  ChromaDB   │  │      Retrieve           │ │
│  │  (embed.py) │  │  (vector)   │  │    (retrieve.py)        │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
│                           │                                     │
│                           ▼                                     │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    GENERATE                                 ││
│  │               (generate.py + gemma4:e4b)                    ││
│  └─────────────────────────────────────────────────────────────┘│
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      LLM RESPONSE                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. OWASP LLM Top 10 Threat Analysis

### LLM01: Prompt Injection

| Attribute | Details |
|-----------|---------|
| **Description** | Attacker manipulates LLM through malicious prompts |
| **OWASP Mapping** | SQLi analogy - user input reaches interpreter |
| **Attack Vector** | Direct: malicious user prompt / Indirect: poisoned context |
| **Target Component** | generate.py, models.py (LLM prompt construction) |
| **Severity** | CRITICAL |
| **Likelihood** | HIGH |

**Attack Scenarios:**
1. Direct prompt injection via chat input
2. Context poisoning via RAG retrieval
3. System prompt override attempts

**Test:** `red_team/test_llm01_prompt_injection.py`

---

### LLM02: Insecure Output Handling

| Attribute | Details |
|-----------|---------|
| **Description** | LLM output rendered without sanitization |
| **OWASP Mapping** | XSS analogy - LLM output rendered as HTML |
| **Attack Vector** | Malicious code in LLM response executed by UI |
| **Target Component** | app.py (Streamlit rendering), cli.py (print output) |
| **Severity** | HIGH |
| **Likelihood** | MEDIUM |

**Attack Scenarios:**
1. XSS via LLM-generated HTML/JavaScript
2. Command injection via tool use
3. Path traversal in file operations

**Test:** `red_team/test_llm02_insecure_output.py`

---

### LLM03: Training Data Poisoning

| Attribute | Details |
|-----------|---------|
| **Description** | Corrupted training/injection data affects model behavior |
| **Attack Vector** | Malicious documents in docs/ directory |
| **Target Component** | ingest.py (document loading), ChromaDB (vector store) |
| **Severity** | HIGH |
| **Likelihood** | MEDIUM (single-user) / HIGH (multi-user) |

**Attack Scenarios:**
1. Inject false information into knowledge base
2. Create misleading context for RAG retrieval
3. Embed hidden instructions in documents

**Test:** `red_team/test_llm03_training_data_poisoning.py`

---

### LLM04: Model Denial of Service

| Attribute | Details |
|-----------|---------|
| **Description** | Resource exhaustion through malicious inputs |
| **Attack Vector** | Token amplification, infinite loops, excessive retrieval |
| **Target Component** | generate.py, embed.py, ChromaDB |
| **Severity** | HIGH |
| **Likelihood** | MEDIUM |

**Attack Scenarios:**
1. Extremely long inputs causing token explosion
2. Repeated queries overwhelming the LLM
3. Large document uploads causing memory exhaustion

**Test:** `red_team/test_llm04_model_dos.py`

---

### LLM05: Supply Chain Vulnerabilities

| Attribute | Details |
|-----------|---------|
| **Description** | Compromised dependencies, models, or services |
| **Attack Vector** | Vulnerable Python packages, malicious models |
| **Target Component** | requirements.txt, Ollama models, LangChain |
| **Severity** | HIGH |
| **Likelihood** | LOW-MEDIUM |

**Attack Scenarios:**
1. Compromised pip dependencies
2. Malicious model weights
3. Vulnerable LangChain versions

**Test:** `red_team/test_llm05_supply_chain.py`

---

### LLM06: Sensitive Information Disclosure

| Attribute | Details |
|-----------|---------|
| **Description** | Unauthorized access to sensitive data via RAG |
| **Attack Vector** | Query manipulation to retrieve sensitive documents |
| **Target Component** | retrieve.py, ChromaDB, docs/ |
| **Severity** | CRITICAL |
| **Likelihood** | MEDIUM |

**Attack Scenarios:**
1. Prompt injection to extract training data
2. Cross-user data leakage (if multi-user)
3. Retrieval of documents outside user's permissions

**Test:** `red_team/test_llm06_sensitive_info_disclosure.py`

---

### LLM07: Insecure Plugin Design

| Attribute | Details |
|-----------|---------|
| **Description** | LLM extensions with excessive permissions |
| **Attack Vector** | Tool/function calls with insufficient validation |
| **Target Component** | Future plugin system |
| **Severity** | HIGH |
| **Likelihood** | LOW (not currently implemented) |

**Note:** This threat is NOT APPLICABLE to current implementation as no plugin/tool system exists.

---

### LLM08: Excessive Agency

| Attribute | Details |
|-----------|---------|
| **Description** | LLM takes unauthorized autonomous actions |
| **Attack Vector** | Model performs actions beyond intended scope |
| **Target Component** | generate.py (response generation) |
| **Severity** | HIGH |
| **Likelihood** | LOW |

**Attack Scenarios:**
1. LLM recommends destructive actions
2. Unauthorized file modifications
3. External system interactions

**Test:** `red_team/test_llm08_excessive_agency.py`

---

### LLM09: Overreliance

| Attribute | Details |
|-----------|---------|
| **Description** | Users trust LLM output without verification |
| **Attack Vector** | Hallucinated facts, incorrect code, misleading info |
| **Target Component** | generate.py, entire user-facing interface |
| **Severity** | MEDIUM |
| **Likelihood** | HIGH |

**Attack Scenarios:**
1. Hallucinated information presented as fact
2. Insecure code generated without warnings
3. False confidence in LLM responses

**Test:** `red_team/test_llm09_overreliance.py`

---

### LLM10: Model Theft

| Attribute | Details |
|-----------|---------|
| **Description** | Unauthorized extraction of model or training data |
| **Attack Vector** | Query-based extraction attacks |
| **Target Component** | Ollama model weights, embedding data |
| **Severity** | HIGH |
| **Likelihood** | LOW |

**Attack Scenarios:**
1. Model weight extraction via repeated queries
2. Training data extraction from RAG system
3. Model cloning through API access

**Test:** `red_team/test_llm10_model_theft.py`

---

## 4. Risk Summary Matrix

| Threat | Severity | Likelihood | Risk Score | Status |
|--------|----------|------------|------------|--------|
| LLM01 Prompt Injection | CRITICAL | HIGH | 12/12 | Not Mitigated |
| LLM02 Insecure Output | HIGH | MEDIUM | 8/12 | Partially Mitigated |
| LLM03 Training Data Poisoning | HIGH | MEDIUM | 8/12 | Not Mitigated |
| LLM04 Model DoS | HIGH | MEDIUM | 8/12 | Not Mitigated |
| LLM05 Supply Chain | HIGH | LOW-MEDIUM | 6/12 | Not Mitigated |
| LLM06 Sensitive Info Disclosure | CRITICAL | MEDIUM | 10/12 | Not Mitigated |
| LLM07 Insecure Plugin | HIGH | N/A | N/A | Not Applicable |
| LLM08 Excessive Agency | HIGH | LOW | 5/12 | Not Mitigated |
| LLM09 Overreliance | MEDIUM | HIGH | 7/12 | Partially Mitigated |
| LLM10 Model Theft | HIGH | LOW | 5/12 | Not Mitigated |

---

## 5. Recommended Priority

1. **LLM01** - Implement input validation and prompt sanitization
2. **LLM06** - Add document access controls
3. **LLM02** - Add output sanitization
4. **LLM03** - Document validation and verification
5. **LLM04** - Add rate limiting and input constraints

---

## 6. Test Execution

Run all red team tests:
```bash
cd phase2_threat_model/red_team
pytest *.py -v
```

Individual test execution:
```bash
pytest test_llm01_prompt_injection.py -v
```

---

**Document Version:** 1.0  
**Next Review:** After mitigations implemented