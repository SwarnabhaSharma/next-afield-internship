# SOAR Playbook Runbook

---

## Overview

This runbook documents the automated SOAR (Security Orchestration, Automation and Response) playbooks deployed in this SOC project. The playbooks receive alerts from Kibana, enrich Indicators of Compromise (IOCs) with threat intelligence, log enriched alerts to Elasticsearch, and notify the security team.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           KIBANA SIEM                                │
│                    Detection Rules + Webhook Actions                 │
│                                                                     
│  Rule fires → Webhook POST → http://192.168.56.104:8000/webhook/*  │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                │ HTTP POST (JSON payload)
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   FASTAPI SOAR SERVICE                              │
│                   (Ubuntu VM: Port 8000)                           │
│                                                                      │
│  /webhook/phishing ──→ Phishing Playbook                           │
│  /webhook/malware  ──→ Malware Playbook                            │
│                                                                      │
│  Playbooks:                                                         │
│    1. Extract IOCs (URLs, IPs, Hashes)                             │
│    2. VirusTotal enrichment                                         │
│    3. AbuseIPDB enrichment (phishing only)                          │
│    4. Log to Elasticsearch                                          │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                │ Index enriched alert
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     ELASTICSEARCH                                    │
│                  (Ubuntu VM: Port 9200)                            │
│                                                                      │
│  Index: soar-alerts-YYYY.MM.DD                                     │
│  View in Kibana: Discover > soar-alerts-*                           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

### Software Requirements
- Python 3.10+
- FastAPI
- Uvicorn
- Elasticsearch Python client
- VirusTotal API key (free tier: 500 lookups/day)
- AbuseIPDB API key (free tier: 500 lookups/day)

### System Requirements
- Ubuntu VM running Elasticsearch and Kibana
- Windows machine with Winlogbeat shipping logs
- Network connectivity: Windows ↔ Ubuntu (ports 9200, 5601, 8000)

---

## Installation

### Step 1: Create Project Directory
```bash
mkdir -p ~/soc_soar
cd ~/soc_soar
```

### Step 2: Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn requests pydantic python-dotenv elasticsearch
```

### Step 3: Create Project Structure
```bash
mkdir -p playbooks integrations data runbooks
touch playbooks/__init__.py integrations/__init__.py
```

### Step 4: Configure Environment
Create `~/soc_soar/.env`:
```env
ES_HOST=http://localhost:9200
ES_USER=elastic
ES_PASSWORD=<your_elastic_password>
VIRUSTOTAL_API_KEY=<your_vt_api_key>
ABUSEIPDB_API_KEY=<your_abuseipdb_api_key>
WEBHOOK_SECRET=mysecretkey123
```

---

## Starting the Service

### Step 1: Activate Virtual Environment
```bash
source ~/soc_soar/venv/bin/activate
cd ~/soc_soar
```

### Step 2: Start FastAPI Service
```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

### Step 3: Verify Service is Running
```bash
curl http://localhost:8000/health
```
Expected response: `{"status":"healthy","service":"SOAR Playbooks","version":"1.0.0"}`

---

## Service Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/health` | Health check | None |
| POST | `/webhook/phishing` | Phishing alert playbook | `X-Webhook-Secret` header |
| POST | `/webhook/malware` | Malware alert playbook | `X-Webhook-Secret` header |
| GET | `/alerts` | View recent logged alerts | None |

---

## Testing the Service

### Test Health Endpoint
```bash
curl http://localhost:8000/health
```

### Test Phishing Webhook
```bash
curl -X POST http://localhost:8000/webhook/phishing -H "Content-Type: application/json" -H "X-Webhook-Secret: mysecretkey123" -d '{"alert": {"alert_id": "test-001", "rule_name": "Phishing Alert", "severity": "high", "host": "WORKSTATION-05", "user": "jdoe", "timestamp": "2026-04-17T13:45:00Z", "iocs": {"urls": ["https://suspicious-site.com/login"], "ips": ["8.8.8.8"], "hashes": []}, "kibana_url": "http://192.168.56.104:5601/app/security/alerts/test-001"}}'
```

### Test Malware Webhook
```bash
curl -X POST http://localhost:8000/webhook/malware -H "Content-Type: application/json" -H "X-Webhook-Secret: mysecretkey123" -d '{"alert": {"alert_id": "test-002", "rule_name": "Malware Detected", "severity": "critical", "host": "WORKSTATION-07", "user": "admin", "timestamp": "2026-04-17T14:00:00Z", "iocs": {"urls": [], "ips": [], "hashes": ["d41d8cd98f00b204e9800998ecf8427e"]}, "kibana_url": "http://192.168.56.104:5601/app/security/alerts/test-002"}}'
```

### View Logged Alerts
```bash
curl http://localhost:8000/alerts
```

---

## Kibana Webhook Configuration

### Step 1: Access Kibana Rules
1. Open Kibana: `http://192.168.56.104:5601`
2. Login as `elastic`
3. Go to **Security > Rules > Detection rules (SIEM)**

### Step 2: Configure Webhook for a Rule
1. Select a rule (e.g., Phishing Alert)
2. Click **Edit**
3. Under **Actions**, click **Add action**
4. Select **Webhook**
5. Configure:
   - **Name:** `SOAR Phishing Playbook`
   - **URL:** `http://192.168.56.104:8000/webhook/phishing`
   - **Method:** `POST`
   - **Headers:**
     - `Content-Type: application/json`
     - `X-Webhook-Secret: mysecretkey123`
   - **Body:**
     ```json
     {
       "alert": {
         "alert_id": "{{alert.id}}",
         "rule_name": "{{rule.name}}",
         "severity": "{{rule.severity}}",
         "host": "{{context.hosts[0].name}}",
         "user": "{{context.user.name}}",
         "timestamp": "{{@timestamp}}",
         "iocs": {
           "urls": {{context.iocs.url_list}},
           "ips": {{context.iocs.ip_list}},
           "hashes": {{context.iocs.file_hash_list}}
         },
         "kibana_url": "{{rule.url}}"
       }
     }
     ```
6. Save

### Step 3: Repeat for Malware Rules
Use `/webhook/malware` endpoint for malware detection rules.

---

## Playbook Details

### Phishing Playbook

**Trigger:** Kibana phishing detection rule fires

**Steps:**
1. Extract IOCs (URLs, IPs, Hashes)
2. Check URLs against VirusTotal (15 second wait for analysis)
3. Check IPs against VirusTotal + AbuseIPDB
4. Determine threat level:
   - CRITICAL: Score ≥ 70
   - HIGH: Score 40-69
   - MEDIUM: Score 15-39
   - LOW: Score 5-14
   - INFO: Score < 5
5. Log enriched alert to Elasticsearch
6. Return results to Kibana

**IOC Fields:**
- `urls`: Array of URLs from the alert
- `ips`: Array of IP addresses from the alert
- `hashes`: Array of file hashes (typically empty for phishing)

---

### Malware Playbook

**Trigger:** Kibana malware detection rule fires

**Steps:**
1. Extract IOCs (file hashes)
2. Check hashes against VirusTotal
3. Determine threat level and incident priority:
   - P1 CRITICAL: ≥50 detections
   - P2 HIGH: 20-49 detections
   - P2 MEDIUM: 10-19 detections
   - P3 LOW/INFO: <10 detections
4. Log enriched alert to Elasticsearch
5. Return results to Kibana

**IOC Fields:**
- `urls`: Array of URLs (typically empty for malware)
- `ips`: Array of IPs (typically empty for malware)
- `hashes`: Array of MD5/SHA1/SHA256 hashes

---

## Viewing Enriched Alerts

### In Kibana
1. Go to **Discover**
2. Select index pattern: `soar-alerts-*`
3. View enriched alert documents with VT scores

### Via API
```bash
curl http://localhost:8000/alerts
```

### JSON Fallback (if ES unavailable)
```bash
cat ~/soc_soar/data/alerts.json
```

---

## Alert Triage Workflow

### Step 1: Receive Alert
- Alert appears in Kibana: **Security > Alerts**
- Alert is automatically enriched by SOAR playbook
- VT and AbuseIPDB scores added to alert document

### Step 2: Triage Questions
1. **Is it a True Positive (TP) or False Positive (FP)?**
2. **Is there a known-bad IOC?** (Check VT score ≥ 70 = likely malicious)
3. **What has this host done recently?** (Check Timeline in Kibana)
4. **Is this normal for this user's role?** (Check user baseline)

### Step 3: Enrichment Review
- **VirusTotal Score:** 0/90 = clean, 70+/90 = highly malicious
- **AbuseIPDB Confidence:** 0-100% (≥75% = likely malicious)
- **File Details:** Check file name, size, type

### Step 4: Decision
| Decision | When | Action |
|----------|------|--------|
| Close FP | Benign activity confirmed | Add reason note, close alert |
| Escalate TP | Confirmed attack | Create Case, notify incident response |
| Monitor | Partial evidence | Keep open, add notes, watch for more alerts |

### Step 5: Document
- Add comments to every alert (TP, FP, or Monitor)
- Include triage decision and reasoning
- Note any IOCs blocked or actions taken

---

## SLA Guidelines

| Severity | Response Time | Example |
|----------|---------------|---------|
| CRITICAL (P1) | < 15 minutes | Ransomware, confirmed breach |
| HIGH (P2) | < 1 hour | Active malware, credential theft |
| MEDIUM | < 4 hours | Phishing attempt, suspicious activity |
| LOW | < 24 hours | Policy violation, informational |

---

## Troubleshooting

### Service Won't Start
- **Cause:** Port 8000 already in use
- **Fix:** Change port with `uvicorn main:app --port 8001`

### 401 Unauthorized
- **Cause:** Wrong or missing `X-Webhook-Secret` header
- **Fix:** Ensure header matches `WEBHOOK_SECRET` in `.env`

### VirusTotal Errors
- **Cause:** Rate limited (4 requests/minute on free tier)
- **Fix:** Wait 60 seconds, then retry

### Elasticsearch Connection Failed
- **Cause:** Wrong ES credentials or ES not running
- **Fix:** Check `ES_HOST`, `ES_USER`, `ES_PASSWORD` in `.env`

### Alerts Not Appearing in Kibana
- **Cause:** Index pattern not created
- **Fix:** Go to **Stack Management > Index Patterns > Create index pattern** with `soar-alerts-*`

---

## API Keys Required

### VirusTotal
1. Register at https://www.virustotal.com
2. Free tier: 500 lookups/day, 4 lookups/minute
3. Get API key from Profile > API key

### AbuseIPDB
1. Register at https://www.abuseipdb.com
2. Free tier: 500 lookups/day
3. Get API key from Profile > API

---

## Security Considerations

1. **Webhook Secret:** Change `mysecretkey123` to a strong random string in `.env`
2. **Elasticsearch Password:** Use a strong password, never commit `.env` to version control
3. **Firewall:** Only allow ports 9200, 5601, 8000 from trusted networks
4. **API Keys:** Never expose API keys in logs or screenshots

---

## File Structure

```
~/soc_soar/
├── main.py                      # FastAPI entry point
├── .env                         # API keys and secrets
├── playbooks/
│   ├── __init__.py
│   ├── phishing.py              # Phishing playbook
│   └── malware.py               # Malware playbook
├── integrations/
│   ├── __init__.py
│   ├── virustotal.py            # VirusTotal API client
│   ├── abuseipdb.py             # AbuseIPDB API client
│   └── elasticsearch.py         # ES logging + JSON fallback
├── data/
│   └── alerts.json              # JSON fallback (if ES unavailable)
└── runbooks/
    └── SOAR_RUNBOOK.md          # This documentation
```

---

## Playbook Code Summary

### Phishing Playbook (`playbooks/phishing.py`)
```python
async def run_phishing_playbook(alert_data):
    # 1. Extract IOCs (URLs, IPs, hashes)
    # 2. Check URLs against VirusTotal
    # 3. Check IPs against VirusTotal + AbuseIPDB
    # 4. Determine threat level (CRITICAL/HIGH/MEDIUM/LOW/INFO)
    # 5. Log to Elasticsearch
    # 6. Return enriched results
```

### Malware Playbook (`playbooks/malware.py`)
```python
async def run_malware_playbook(alert_data):
    # 1. Extract IOCs (file hashes)
    # 2. Check hashes against VirusTotal
    # 3. Determine threat level and incident priority (P1/P2/P3)
    # 4. Log to Elasticsearch
    # 5. Return enriched results
```

---

## IOC Enrichment Flow

### For Phishing Alerts
```
URL → VirusTotal URL Scanner → Detection Count
IP  → VirusTotal IP Check    → Detection Count
     → AbuseIPDB Check       → Confidence Score
```

### For Malware Alerts
```
Hash → VirusTotal File Lookup → Detection Count
                                → File Details
                                → Detection Names
```

---

## Threat Level Classification

### VirusTotal Scoring
| Score Range | Threat Level | Action |
|------------|--------------|--------|
| ≥70 | CRITICAL | Immediate response |
| 40-69 | HIGH | Urgent investigation |
| 15-39 | MEDIUM | Standard investigation |
| 5-14 | LOW | Review when possible |
| <5 | INFO | Document and monitor |

### Malware Incident Priority
| Detections | Priority | Response Time |
|-----------|----------|---------------|
| ≥50 | P1 CRITICAL | < 15 minutes |
| 20-49 | P2 HIGH | < 1 hour |
| 10-19 | P2 MEDIUM | < 4 hours |
| <10 | P3 LOW | < 24 hours |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-17 | Initial release |

---

## Contact & Support

For issues or questions:
1. Check service logs in the terminal running `uvicorn`
2. Review `/alerts` endpoint for logged errors
3. Check Elasticsearch logs: `sudo journalctl -u elasticsearch`
