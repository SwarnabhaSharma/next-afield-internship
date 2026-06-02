"""
SOC SOAR Playbooks - FastAPI Entry Point
Receives webhook alerts from Kibana and triggers playbooks
"""

import os
import logging
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
from dotenv import load_dotenv
import json

load_dotenv()

from playbooks.phishing import run_phishing_playbook
from playbooks.malware import run_malware_playbook

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SOC SOAR Playbooks",
    description="Automated playbook service for SOC alert enrichment",
    version="1.0.0"
)


class IOCModel(BaseModel):
    urls: Optional[List[str]] = []
    ips: Optional[List[str]] = []
    hashes: Optional[List[str]] = []


class KibanaAlert(BaseModel):
    alert_id: str
    rule_name: str
    severity: str
    host: Optional[str] = None
    user: Optional[str] = None
    timestamp: str
    iocs: IOCModel
    kibana_url: Optional[str] = None
    description: Optional[str] = None


class WebhookPayload(BaseModel):
    alert: KibanaAlert


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "SOAR Playbooks",
        "version": "1.0.0"
    }


@app.post("/webhook/phishing")
async def phishing_webhook(
    request: Request,
    x_webhook_secret: Optional[str] = Header(None)
):
    expected_secret = os.getenv("WEBHOOK_SECRET", "mysecretkey123")
    if x_webhook_secret != expected_secret:
        logger.warning("Invalid webhook secret received!")
        raise HTTPException(status_code=401, detail="Invalid webhook secret")

    try:
        body = await request.json()
        logger.info(f"Received phishing webhook: {json.dumps(body, indent=2)}")

        alert_data = body.get("alert", body)

        result = await run_phishing_playbook(alert_data)

        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": "Phishing playbook executed",
                "result": result
            }
        )
    except Exception as e:
        logger.error(f"Error running phishing playbook: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(e)}
        )


@app.post("/webhook/malware")
async def malware_webhook(
    request: Request,
    x_webhook_secret: Optional[str] = Header(None)
):
    expected_secret = os.getenv("WEBHOOK_SECRET", "mysecretkey123")
    if x_webhook_secret != expected_secret:
        logger.warning("Invalid webhook secret received!")
        raise HTTPException(status_code=401, detail="Invalid webhook secret")

    try:
        body = await request.json()
        logger.info(f"Received malware webhook: {json.dumps(body, indent=2)}")

        alert_data = body.get("alert", body)

        result = await run_malware_playbook(alert_data)

        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": "Malware playbook executed",
                "result": result
            }
        )
    except Exception as e:
        logger.error(f"Error running malware playbook: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(e)}
        )


@app.get("/alerts")
async def get_alerts():
    try:
        from integrations.elasticsearch import get_recent_alerts
        alerts = get_recent_alerts(limit=50)
        return {
            "status": "success",
            "count": len(alerts),
            "alerts": alerts
        }
    except Exception as e:
        logger.error(f"Error fetching alerts: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(e)}
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)