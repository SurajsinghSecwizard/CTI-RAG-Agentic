import logging
import requests
import time
from typing import Dict, Any, Optional
import redis
import json

import config

logger = logging.getLogger(__name__)

class ToolsRouter:
    """Router for external threat intelligence API calls"""
    
    def __init__(self):
        self.config_instance = config.Config()
        
        # Initialize Redis for caching (optional for local development)
        self.redis_client = None
        if self.config_instance.REDIS_URL and self.config_instance.REDIS_URL != "redis://localhost:6379":
            try:
                self.redis_client = redis.from_url(self.config_instance.REDIS_URL)
                self.redis_client.ping()  # Test connection
                logger.info("✅ Redis connection established")
            except Exception as e:
                logger.warning(f"Redis connection failed: {e}")
                self.redis_client = None
        else:
            logger.info("ℹ️ Redis not configured, caching disabled")
        
        # API rate limiting
        self.rate_limits = {
            "virustotal": {"calls": 0, "last_reset": time.time(), "limit": 4},  # 4 calls per minute
            "abuse_ch": {"calls": 0, "last_reset": time.time(), "limit": 10}    # 10 calls per minute
        }
    
    def query_virustotal(self, hash_value: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal for hash information"""
        try:
            # Check if API key is configured
            if not self.config_instance.VIRUSTOTAL_API_KEY or self.config_instance.VIRUSTOTAL_API_KEY == "your_virustotal_api_key":
                logger.warning("VirusTotal API key not configured, skipping query")
                return {
                    "hash": hash_value,
                    "positives": 0,
                    "total": 0,
                    "file_type": "",
                    "file_size": 0,
                    "first_seen": "",
                    "last_seen": "",
                    "note": "API key not configured"
                }
            
            # Check cache first
            cache_key = f"vt:{hash_value}"
            if self.redis_client:
                cached = self.redis_client.get(cache_key)
                if cached:
                    return json.loads(cached)
            
            # Check rate limit
            if not self._check_rate_limit("virustotal"):
                logger.warning("VirusTotal rate limit exceeded")
                return None
            
            # Make API call
            headers = {
                "x-apikey": self.config_instance.VIRUSTOTAL_API_KEY
            }
            
            url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract relevant information
                result = {
                    "hash": hash_value,
                    "positives": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
                    "total": sum(data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).values()),
                    "file_type": data.get("data", {}).get("attributes", {}).get("type_description", ""),
                    "file_size": data.get("data", {}).get("attributes", {}).get("size", 0),
                    "first_seen": data.get("data", {}).get("attributes", {}).get("first_submission_date", ""),
                    "last_seen": data.get("data", {}).get("attributes", {}).get("last_analysis_date", "")
                }
                
                # Cache result for 1 hour
                if self.redis_client:
                    self.redis_client.setex(cache_key, 3600, json.dumps(result))
                
                return result
            elif response.status_code == 401:
                logger.error("VirusTotal API authentication failed - check API key")
                return {
                    "hash": hash_value,
                    "positives": 0,
                    "total": 0,
                    "file_type": "",
                    "file_size": 0,
                    "first_seen": "",
                    "last_seen": "",
                    "note": "Authentication failed"
                }
            else:
                logger.warning(f"VirusTotal API returned status {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"VirusTotal query failed: {e}")
            return None
    
    def query_abuse_ch(self, url: str) -> Optional[Dict[str, Any]]:
        """Query Abuse.ch for URL information"""
        try:
            # Check if API key is configured
            if not self.config_instance.ABUSE_CH_API_KEY or self.config_instance.ABUSE_CH_API_KEY == "your_abuse_ch_api_key":
                logger.warning("Abuse.ch API key not configured, skipping query")
                return {
                    "url": url,
                    "malicious": False,
                    "confidence": 0,
                    "note": "API key not configured"
                }
            
            # Check cache first
            cache_key = f"abuse:{url}"
            if self.redis_client:
                cached = self.redis_client.get(cache_key)
                if cached:
                    return json.loads(cached)
            
            # Check rate limit
            if not self._check_rate_limit("abuse_ch"):
                logger.warning("Abuse.ch rate limit exceeded")
                return None
            
            # Make API call
            headers = {
                "API-Key": self.config_instance.ABUSE_CH_API_KEY
            }
            
            # Note: This is a placeholder - Abuse.ch doesn't have a public API for URL checking
            # You would need to implement the actual API call based on their documentation
            logger.info(f"Abuse.ch URL check for: {url}")
            
            # Placeholder result
            result = {
                "url": url,
                "malicious": False,
                "confidence": 0,
                "note": "API not implemented"
            }
            
            # Cache result for 1 hour
            if self.redis_client:
                self.redis_client.setex(cache_key, 3600, json.dumps(result))
            
            return result
                
        except Exception as e:
            logger.error(f"Abuse.ch query failed: {e}")
            return None
    
    def query_shodan(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query Shodan for IP information"""
        # Placeholder for Shodan integration
        return None
    
    def query_mitre_attack(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Query MITRE ATT&CK for technique information"""
        try:
            # Check cache first
            cache_key = f"mitre:{technique_id}"
            if self.redis_client:
                cached = self.redis_client.get(cache_key)
                if cached:
                    return json.loads(cached)
            
            # Make API call to MITRE ATT&CK
            url = f"https://attack.mitre.org/api/techniques/{technique_id}/"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                result = {
                    "technique_id": technique_id,
                    "name": data.get("name", ""),
                    "description": data.get("description", ""),
                    "tactics": data.get("tactics", []),
                    "platforms": data.get("platforms", []),
                    "permissions_required": data.get("permissions_required", []),
                    "data_sources": data.get("data_sources", []),
                    "defense_bypassed": data.get("defense_bypassed", [])
                }
                
                # Cache result for 24 hours (MITRE data doesn't change often)
                if self.redis_client:
                    self.redis_client.setex(cache_key, 86400, json.dumps(result))
                
                return result
            else:
                logger.warning(f"MITRE ATT&CK API returned status {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"MITRE ATT&CK query failed: {e}")
            return None
    
    def _check_rate_limit(self, service: str) -> bool:
        """Check if we're within rate limits for a service"""
        if service not in self.rate_limits:
            return True
        
        limit_info = self.rate_limits[service]
        current_time = time.time()
        
        # Reset counter if more than 1 minute has passed
        if current_time - limit_info["last_reset"] > 60:
            limit_info["calls"] = 0
            limit_info["last_reset"] = current_time
        
        # Check if we're under the limit
        if limit_info["calls"] < limit_info["limit"]:
            limit_info["calls"] += 1
            return True
        
        return False
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        if not self.redis_client:
            return {"status": "not_configured"}
        
        try:
            info = self.redis_client.info()
            return {
                "status": "connected",
                "used_memory": info.get("used_memory", 0),
                "connected_clients": info.get("connected_clients", 0),
                "total_commands_processed": info.get("total_commands_processed", 0)
            }
        except Exception as e:
            return {"status": "error", "error": str(e)} 