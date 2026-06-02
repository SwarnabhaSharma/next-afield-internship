"""
Elasticsearch Integration
Logs enriched alerts to Elasticsearch for persistence and querying
Falls back to JSON file if ES is unavailable
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, List
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASSWORD = os.getenv("ES_PASSWORD", "")
ES_INDEX_PREFIX = "soar-alerts"


def get_es_client():
    """
    Create and return an Elasticsearch client
    """
    try:
        from elasticsearch import Elasticsearch
        
        es = Elasticsearch(
            [ES_HOST],
            basic_auth=(ES_USER, ES_PASSWORD),
            verify_certs=False,
            ssl_show_warn=False,
            request_timeout=30
        )
        return es
    except Exception as e:
        logger.error(f"Error creating ES client: {str(e)}")
        return None


async def log_alert(alert_data: Dict[str, Any]) -> bool:
    """
    Log an enriched alert to Elasticsearch
    """
    try:
        es = get_es_client()
        
        if not es:
            logger.warning("ES client not available, using JSON fallback")
            await log_alert_to_json(alert_data)
            return True
        
        index_name = f"{ES_INDEX_PREFIX}-{datetime.utcnow().strftime('%Y.%m.%d')}"
        
        result = es.index(
            index=index_name,
            document=alert_data
        )
        
        logger.info(f"Alert logged to ES index {index_name}: {result.get('result', 'unknown')}")
        return True
        
    except Exception as e:
        logger.error(f"Error logging alert to ES: {str(e)}")
        try:
            await log_alert_to_json(alert_data)
        except Exception as json_error:
            logger.error(f"JSON fallback also failed: {str(json_error)}")
        return False


async def log_alert_to_json(alert_data: Dict[str, Any]) -> bool:
    """
    Fallback: Log alert to a JSON file if Elasticsearch is unavailable
    """
    json_file = os.path.join(
        os.path.dirname(__file__), 
        "..", 
        "data", 
        "alerts.json"
    )
    
    os.makedirs(os.path.dirname(json_file), exist_ok=True)
    
    try:
        with open(json_file, "r") as f:
            alerts = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        alerts = []
    
    alerts.append({
        "logged_at": datetime.utcnow().isoformat(),
        **alert_data
    })
    
    with open(json_file, "w") as f:
        json.dump(alerts, f, indent=2, default=str)
    
    logger.info(f"Alert logged to JSON file: {json_file}")
    return True


def get_recent_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Retrieve recent alerts from Elasticsearch (or JSON fallback)
    """
    try:
        es = get_es_client()
        
        if not es:
            return get_recent_alerts_from_json(limit)
        
        search_body = {
            "query": {"match_all": {}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": limit
        }
        
        result = es.search(
            index=f"{ES_INDEX_PREFIX}-*",
            body=search_body
        )
        
        alerts = [hit["_source"] for hit in result.get("hits", {}).get("hits", [])]
        return alerts
        
    except Exception as e:
        logger.error(f"Error fetching alerts from ES: {str(e)}")
        return get_recent_alerts_from_json(limit)


def get_recent_alerts_from_json(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Fallback: Read alerts from JSON file
    """
    json_file = os.path.join(
        os.path.dirname(__file__), 
        "..", 
        "data", 
        "alerts.json"
    )
    
    try:
        with open(json_file, "r") as f:
            alerts = json.load(f)
        
        return alerts[-limit:][::-1] if alerts else []
        
    except (FileNotFoundError, json.JSONDecodeError):
        return []
