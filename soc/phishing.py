"""
Phishing Playbook
- Extracts IOCs (URLs, IPs) from phishing alerts
- Enriches with VirusTotal and AbuseIPDB
- Logs to Elasticsearch
"""

import os
import logging
from datetime import datetime
from typing import Dict, Any, List
from dotenv import load_dotenv

load_dotenv()

from integrations.virustotal import check_url, check_ip
from integrations.abuseipdb import check_ip as abuseipdb_check_ip
from integrations.elasticsearch import log_alert

logger = logging.getLogger(__name__)


async def run_phishing_playbook(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main phishing playbook execution
    
    Args:
        alert_data: Alert payload from Kibana webhook
        
    Returns:
        Dictionary with playbook execution results
    """
    playbook_start = datetime.utcnow()
    logger.info(f"Starting phishing playbook for alert: {alert_data.get('alert_id', 'unknown')}")
    
    # Extract IOCs from the alert
    iocs = alert_data.get("iocs", {})
    urls = iocs.get("urls", []) if isinstance(iocs, dict) else []
    ips = iocs.get("ips", []) if isinstance(iocs, dict) else []
    hashes = iocs.get("hashes", []) if isinstance(iocs, dict) else []
    
    # Initialize results structure
    results = {
        "alert_id": alert_data.get("alert_id", "unknown"),
        "rule_name": alert_data.get("rule_name", "Unknown Rule"),
        "severity": alert_data.get("severity", "unknown"),
        "host": alert_data.get("host", "unknown"),
        "user": alert_data.get("user", "unknown"),
        "timestamp": alert_data.get("timestamp", datetime.utcnow().isoformat()),
        "kibana_url": alert_data.get("kibana_url", ""),
        "description": alert_data.get("description", ""),
        "playbook": "phishing",
        "iocs": {
            "urls": urls,
            "ips": ips,
            "hashes": hashes
        },
        "enrichment": {
            "virustotal": {"urls": [], "ips": []},
            "abuseipdb": []
        },
        "threat_level": "UNKNOWN",
        "enrichment_time_ms": 0,
        "status": "pending"
    }
    
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "")
    
    # Check URLs against VirusTotal
    url_results = []
    for url in urls:
        if url and vt_key:
            try:
                vt_result = await check_url(vt_key, url)
                url_results.append(vt_result)
                logger.info(f"VT URL result for {url}: {vt_result.get('positives', 0)}/{vt_result.get('total', 0)}")
            except Exception as e:
                logger.error(f"Error checking URL {url}: {str(e)}")
                url_results.append({"url": url, "error": str(e), "status": "error"})
        else:
            if not url:
                url_results.append({"url": "empty", "skipped": "no_url"})
            elif not vt_key:
                url_results.append({"url": url, "skipped": "no_vt_api_key"})
    
    results["enrichment"]["virustotal"]["urls"] = url_results
    
    # Check IPs against VirusTotal AND AbuseIPDB
    ip_results = []
    abuseipdb_results = []
    
    for ip in ips:
        if ip and vt_key:
            try:
                vt_result = await check_ip(vt_key, ip)
                ip_results.append(vt_result)
                logger.info(f"VT IP result for {ip}: {vt_result.get('positives', 0)}/{vt_result.get('total', 0)}")
            except Exception as e:
                logger.error(f"Error checking IP {ip} on VT: {str(e)}")
                ip_results.append({"ip": ip, "error": str(e), "status": "error"})
        else:
            if not vt_key:
                ip_results.append({"ip": ip, "skipped": "no_vt_api_key"})
        
        if ip and abuseipdb_key:
            try:
                abuse_result = await abuseipdb_check_ip(abuseipdb_key, ip)
                abuseipdb_results.append(abuse_result)
                logger.info(f"AbuseIPDB result for {ip}: {abuse_result.get('ip_address', 'unknown')}")
            except Exception as e:
                logger.error(f"Error checking IP {ip} on AbuseIPDB: {str(e)}")
                abuseipdb_results.append({"ip_address": ip, "error": str(e), "status": "error"})
        else:
            if not abuseipdb_key:
                abuseipdb_results.append({"ip_address": ip, "skipped": "no_abuseipdb_api_key"})
    
    results["enrichment"]["virustotal"]["ips"] = ip_results
    results["enrichment"]["abuseipdb"] = abuseipdb_results
    
    # Calculate enrichment time
    playbook_end = datetime.utcnow()
    enrichment_time = (playbook_end - playbook_start).total_seconds() * 1000
    results["enrichment_time_ms"] = enrichment_time
    
    # Determine threat level based on VT scores
    max_url_score = 0
    if url_results:
        url_scores = [r.get("positives", 0) for r in url_results if r.get("positives")]
        max_url_score = max(url_scores) if url_scores else 0
    
    max_ip_score = 0
    if ip_results:
        ip_scores = [r.get("positives", 0) for r in ip_results if r.get("positives")]
        max_ip_score = max(ip_scores) if ip_scores else 0
    
    max_abuseipdb_score = 0
    if abuseipdb_results:
        abuse_scores = [r.get("abuse_confidence_score", 0) for r in abuseipdb_results if r.get("abuse_confidence_score")]
        max_abuseipdb_score = max(abuse_scores) if abuse_scores else 0
    
    max_score = max(max_url_score, max_ip_score, max_abuseipdb_score)
    
    if max_score >= 70:
        results["threat_level"] = "CRITICAL"
    elif max_score >= 40:
        results["threat_level"] = "HIGH"
    elif max_score >= 15:
        results["threat_level"] = "MEDIUM"
    elif max_score >= 5:
        results["threat_level"] = "LOW"
    else:
        results["threat_level"] = "INFO"
    
    # Log to Elasticsearch (or JSON fallback)
    try:
        await log_alert(results)
        results["status"] = "logged"
        logger.info(f"Alert {results['alert_id']} logged successfully")
    except Exception as e:
        logger.error(f"Error logging alert to ES: {str(e)}")
        results["status"] = "log_failed"
    
    playbook_complete = datetime.utcnow()
    total_time = (playbook_complete - playbook_start).total_seconds() * 1000
    results["total_playbook_time_ms"] = total_time
    
    logger.info(
        f"Phishing playbook complete for {alert_data.get('alert_id')}: "
        f"{results['threat_level']} threat level, "
        f"{len(urls)} URLs, {len(ips)} IPs enriched in {total_time:.0f}ms"
    )
    
    return results