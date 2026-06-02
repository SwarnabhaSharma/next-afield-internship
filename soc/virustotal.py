"""
VirusTotal API Integration
Provides functions to check URLs, IPs, and file hashes against VirusTotal
"""

import os
import logging
import asyncio
from typing import Dict, Any
import requests

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


async def check_url(vt_api_key: str, url: str) -> Dict[str, Any]:
    """
    Check a URL against VirusTotal
    """
    try:
        submit_url = f"{VT_BASE_URL}/urls"
        payload = {"url": url}
        headers = {
            "x-apikey": vt_api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        response = requests.post(submit_url, data=payload, headers=headers, timeout=30)
        
        if response.status_code == 200:
            analysis_id = response.json().get("data", {}).get("id", "")
            
            if analysis_id:
                logger.info(f"Waiting 15s for VT to analyze URL: {url}")
                await asyncio.sleep(15)
                
                result_url = f"{VT_BASE_URL}/analyses/{analysis_id}"
                result_response = requests.get(result_url, headers=headers, timeout=30)
                
                if result_response.status_code == 200:
                    result_data = result_response.json().get("data", {}).get("attributes", {})
                    stats = result_data.get("stats", {})
                    
                    return {
                        "url": url,
                        "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
                        "total": stats.get("harmless", 0) + stats.get("undetected", 0) + stats.get("malicious", 0) + stats.get("suspicious", 0),
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "permalink": f"https://www.virustotal.com/gui/url/{analysis_id}",
                        "scan_date": result_data.get("date", ""),
                        "status": "complete"
                    }
        
        logger.warning(f"VT URL check failed for {url}: HTTP {response.status_code}")
        return {
            "url": url,
            "positives": 0,
            "total": 0,
            "error": f"VT returned HTTP {response.status_code}",
            "status": "error"
        }
        
    except requests.exceptions.Timeout:
        logger.error(f"VT URL check timed out for {url}")
        return {
            "url": url,
            "positives": 0,
            "total": 0,
            "error": "Request timed out",
            "status": "error"
        }
    except Exception as e:
        logger.error(f"Error checking URL {url}: {str(e)}")
        return {
            "url": url,
            "positives": 0,
            "total": 0,
            "error": str(e),
            "status": "error"
        }


async def check_ip(vt_api_key: str, ip_address: str) -> Dict[str, Any]:
    """
    Check an IP address against VirusTotal
    """
    try:
        url = f"{VT_BASE_URL}/ip_addresses/{ip_address}"
        headers = {"x-apikey": vt_api_key}
        
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            
            last_analysis_stats = data.get("last_analysis_stats", {})
            last_analysis_results = data.get("last_analysis_results", {})
            
            malicious_count = sum(
                1 for r in last_analysis_results.values() 
                if r.get("category") == "malicious"
            )
            suspicious_count = sum(
                1 for r in last_analysis_results.values() 
                if r.get("category") == "suspicious"
            )
            
            return {
                "ip": ip_address,
                "positives": malicious_count + suspicious_count,
                "total": len(last_analysis_results),
                "country": data.get("country", "Unknown"),
                "as_owner": data.get("as_owner", "Unknown"),
                "network": data.get("network", "Unknown"),
                "malicious": malicious_count,
                "suspicious": suspicious_count,
                "reputation": data.get("reputation", 0),
                "permalink": f"https://www.virustotal.com/gui/ip-address/{ip_address}",
                "status": "complete"
            }
        
        logger.warning(f"VT IP check failed for {ip_address}: HTTP {response.status_code}")
        return {
            "ip": ip_address,
            "positives": 0,
            "total": 0,
            "error": f"VT returned HTTP {response.status_code}",
            "status": "error"
        }
        
    except Exception as e:
        logger.error(f"Error checking IP {ip_address}: {str(e)}")
        return {
            "ip": ip_address,
            "positives": 0,
            "total": 0,
            "error": str(e),
            "status": "error"
        }


async def check_hash(vt_api_key: str, file_hash: str) -> Dict[str, Any]:
    """
    Check a file hash against VirusTotal
    """
    try:
        url = f"{VT_BASE_URL}/files/{file_hash}"
        headers = {"x-apikey": vt_api_key}
        
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            
            last_analysis_stats = data.get("last_analysis_stats", {})
            last_analysis_results = data.get("last_analysis_results", {})
            
            detections = []
            for engine_name, result in last_analysis_results.items():
                if result.get("category") in ["malicious", "suspicious"]:
                    detections.append({
                        "engine": engine_name,
                        "result": result.get("result", ""),
                        "method": result.get("method", ""),
                        "engine_version": result.get("engine_version", "")
                    })
            
            names = data.get("names", [])
            meaningful_name = data.get("meaningful_name", names[0] if names else "Unknown")
            
            return {
                "hash": file_hash,
                "positives": last_analysis_stats.get("malicious", 0) + last_analysis_stats.get("suspicious", 0),
                "total": len(last_analysis_results),
                "malicious": last_analysis_stats.get("malicious", 0),
                "suspicious": last_analysis_stats.get("suspicious", 0),
                "undetected": last_analysis_stats.get("undetected", 0),
                "harmless": last_analysis_stats.get("harmless", 0),
                "type_label": data.get("type_description", "Unknown"),
                "file_name": meaningful_name,
                "file_size": data.get("size", 0),
                "detections": detections[:10],
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
                "status": "complete"
            }
        
        logger.warning(f"VT hash check failed for {file_hash[:16]}...: HTTP {response.status_code}")
        return {
            "hash": file_hash,
            "positives": 0,
            "total": 0,
            "error": f"VT returned HTTP {response.status_code}",
            "status": "error"
        }
        
    except Exception as e:
        logger.error(f"Error checking hash {file_hash[:16]}...: {str(e)}")
        return {
            "hash": file_hash,
            "positives": 0,
            "total": 0,
            "error": str(e),
            "status": "error"
        }