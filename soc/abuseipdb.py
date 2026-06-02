"""
AbuseIPDB API Integration
Provides function to check IP addresses for abuse reports
"""

import os
import logging
from typing import Dict, Any
import requests

logger = logging.getLogger(__name__)

ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"


async def check_ip(abuseipdb_api_key: str, ip_address: str) -> Dict[str, Any]:
    """
    Check an IP address against AbuseIPDB
    """
    try:
        url = f"{ABUSEIPDB_BASE_URL}/check"
        headers = {
            "Key": abuseipdb_api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            
            return {
                "ip_address": data.get("ipAddress", ip_address),
                "ip_version": data.get("ipVersion", 4),
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", "Unknown"),
                "usage_type": data.get("usageType", "Unknown"),
                "is_whitelisted": data.get("isWhitelisted", False),
                "country_code": data.get("countryCode", "Unknown"),
                "region_name": data.get("regionName", "Unknown"),
                "city": data.get("city", "Unknown"),
                "is_proxy": data.get("isProxy", False),
                "is_vpn": data.get("isVpn", False),
                "is_tor": data.get("isTor", False),
                "is_hosting_provider": data.get("isHostingProvider", False),
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "last_reported_at": data.get("lastReportedAt", ""),
                "status": "complete"
            }
        
        if response.status_code == 429:
            logger.warning(f"AbuseIPDB rate limited for {ip_address}")
            return {
                "ip_address": ip_address,
                "abuse_confidence_score": 0,
                "error": "Rate limited by AbuseIPDB",
                "status": "rate_limited"
            }
        
        logger.warning(f"AbuseIPDB check failed for {ip_address}: HTTP {response.status_code}")
        return {
            "ip_address": ip_address,
            "abuse_confidence_score": 0,
            "error": f"AbuseIPDB returned HTTP {response.status_code}",
            "status": "error"
        }
        
    except Exception as e:
        logger.error(f"Error checking IP {ip_address}: {str(e)}")
        return {
            "ip_address": ip_address,
            "abuse_confidence_score": 0,
            "error": str(e),
            "status": "error"
        }