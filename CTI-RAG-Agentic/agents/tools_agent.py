"""
Tools Agent - Handles external API calls and enrichment

Responsibilities:
- VirusTotal API calls for IOC enrichment
- Abuse.ch API calls for domain/IP status
- Shodan API calls for infrastructure intelligence
- MITRE ATT&CK API calls for TTP mapping
- Rate limiting and caching
"""

import logging
import asyncio
import aiohttp
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json

from .base_agent import BaseAgent
from services.tools_router import ToolsRouter

logger = logging.getLogger(__name__)

class ToolsAgent(BaseAgent):
    """Agent responsible for external API calls and enrichment"""
    
    def __init__(self, config):
        super().__init__("Tools", config)
        self.tools_router = ToolsRouter()
        self.session = None
        
        # API endpoints and rate limits
        self.apis = {
            "virustotal": {
                "base_url": "https://www.virustotal.com/vtapi/v2",
                "rate_limit": 4,  # requests per minute
                "last_request": None
            },
            "abusech": {
                "base_url": "https://urlhaus-api.abuse.ch/v1",
                "rate_limit": 10,
                "last_request": None
            },
            "shodan": {
                "base_url": "https://api.shodan.io",
                "rate_limit": 1,
                "last_request": None
            },
            "mitre": {
                "base_url": "https://attack.mitre.org/api",
                "rate_limit": 10,
                "last_request": None
            }
        }
        
    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute tools task"""
        try:
            task_type = task.get("type", "ioc_enrichment")
            
            if task_type == "ioc_enrichment":
                return await self._enrich_iocs(task)
            elif task_type == "domain_lookup":
                return await self._lookup_domain(task)
            elif task_type == "ip_lookup":
                return await self._lookup_ip(task)
            elif task_type == "hash_lookup":
                return await self._lookup_hash(task)
            elif task_type == "ttp_mapping":
                return await self._map_ttp(task)
            elif task_type == "infrastructure_intel":
                return await self._get_infrastructure_intel(task)
            else:
                raise ValueError(f"Unknown tools task type: {task_type}")
                
        except Exception as e:
            logger.error(f"Tools agent execution failed: {e}")
            self.log_action("execution_failed", {"error": str(e)})
            raise
    
    async def _enrich_iocs(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich IOCs with external intelligence"""
        self.log_action("starting_ioc_enrichment", task)
        
        try:
            iocs = task.get("iocs", [])
            enrichment_types = task.get("enrichment_types", ["all"])
            
            enriched_iocs = []
            
            for ioc in iocs:
                ioc_type = ioc.get("type")
                ioc_value = ioc.get("value")
                
                if not ioc_type or not ioc_value:
                    continue
                
                enrichment_result = await self._enrich_single_ioc(
                    ioc_type, ioc_value, enrichment_types
                )
                
                enriched_ioc = {
                    **ioc,
                    "enrichment": enrichment_result,
                    "enriched_at": datetime.utcnow().isoformat()
                }
                enriched_iocs.append(enriched_ioc)
            
            result = {
                "task_type": "ioc_enrichment",
                "total_iocs": len(iocs),
                "enriched_iocs": len(enriched_iocs),
                "enrichment_types": enrichment_types,
                "enriched_data": enriched_iocs,
                "completed_at": datetime.utcnow().isoformat()
            }
            
            self.log_action("completed_ioc_enrichment", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to enrich IOCs: {e}")
            raise
    
    async def _enrich_single_ioc(self, ioc_type: str, ioc_value: str, enrichment_types: List[str]) -> Dict[str, Any]:
        """Enrich a single IOC"""
        enrichment_result = {}
        
        try:
            if ioc_type == "ip_address":
                if "all" in enrichment_types or "abusech" in enrichment_types:
                    abuse_result = await self._check_abusech_ip(ioc_value)
                    enrichment_result["abusech"] = abuse_result
                
                if "all" in enrichment_types or "shodan" in enrichment_types:
                    shodan_result = await self._check_shodan_ip(ioc_value)
                    enrichment_result["shodan"] = shodan_result
            
            elif ioc_type == "domain":
                if "all" in enrichment_types or "abusech" in enrichment_types:
                    abuse_result = await self._check_abusech_domain(ioc_value)
                    enrichment_result["abusech"] = abuse_result
            
            elif ioc_type == "file_hash":
                if "all" in enrichment_types or "virustotal" in enrichment_types:
                    vt_result = await self._check_virustotal_hash(ioc_value)
                    enrichment_result["virustotal"] = vt_result
            
        except Exception as e:
            logger.error(f"Failed to enrich {ioc_type}:{ioc_value}: {e}")
            enrichment_result["error"] = str(e)
        
        return enrichment_result
    
    async def _lookup_domain(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Lookup domain information"""
        self.log_action("starting_domain_lookup", task)
        
        try:
            domain = task.get("domain")
            if not domain:
                raise ValueError("Domain must be specified")
            
            result = {
                "domain": domain,
                "abusech_status": await self._check_abusech_domain(domain),
                "looked_up_at": datetime.utcnow().isoformat()
            }
            
            self.log_action("completed_domain_lookup", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to lookup domain: {e}")
            raise
    
    async def _lookup_ip(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Lookup IP address information"""
        self.log_action("starting_ip_lookup", task)
        
        try:
            ip_address = task.get("ip_address")
            if not ip_address:
                raise ValueError("IP address must be specified")
            
            result = {
                "ip_address": ip_address,
                "abusech_status": await self._check_abusech_ip(ip_address),
                "shodan_info": await self._check_shodan_ip(ip_address),
                "looked_up_at": datetime.utcnow().isoformat()
            }
            
            self.log_action("completed_ip_lookup", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to lookup IP: {e}")
            raise
    
    async def _lookup_hash(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Lookup file hash information"""
        self.log_action("starting_hash_lookup", task)
        
        try:
            file_hash = task.get("file_hash")
            if not file_hash:
                raise ValueError("File hash must be specified")
            
            result = {
                "file_hash": file_hash,
                "virustotal_info": await self._check_virustotal_hash(file_hash),
                "looked_up_at": datetime.utcnow().isoformat()
            }
            
            self.log_action("completed_hash_lookup", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to lookup hash: {e}")
            raise
    
    async def _map_ttp(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Map TTP to MITRE ATT&CK framework"""
        self.log_action("starting_ttp_mapping", task)
        
        try:
            ttp_id = task.get("ttp_id")
            if not ttp_id:
                raise ValueError("TTP ID must be specified")
            
            mitre_info = await self._get_mitre_ttp_info(ttp_id)
            
            result = {
                "ttp_id": ttp_id,
                "mitre_info": mitre_info,
                "mapped_at": datetime.utcnow().isoformat()
            }
            
            self.log_action("completed_ttp_mapping", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to map TTP: {e}")
            raise
    
    async def _get_infrastructure_intel(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Get infrastructure intelligence"""
        self.log_action("starting_infrastructure_intel", task)
        
        try:
            target = task.get("target")  # IP, domain, or ASN
            intel_type = task.get("intel_type", "all")
            
            result = {
                "target": target,
                "intel_type": intel_type,
                "shodan_data": None,
                "abusech_data": None,
                "gathered_at": datetime.utcnow().isoformat()
            }
            
            if intel_type in ["all", "shodan"]:
                result["shodan_data"] = await self._check_shodan_ip(target)
            
            if intel_type in ["all", "abusech"]:
                result["abusech_data"] = await self._check_abusech_ip(target)
            
            self.log_action("completed_infrastructure_intel", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to get infrastructure intel: {e}")
            raise
    
    async def _check_virustotal_hash(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash on VirusTotal"""
        try:
            await self._rate_limit("virustotal")
            
            # Use your existing ToolsRouter
            result = self.tools_router.lookup_hash(file_hash)
            
            self._update_rate_limit("virustotal")
            return result
            
        except Exception as e:
            logger.error(f"VirusTotal lookup failed for {file_hash}: {e}")
            return {"error": str(e)}
    
    async def _check_abusech_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain on Abuse.ch"""
        try:
            await self._rate_limit("abusech")
            
            # Use your existing ToolsRouter
            result = self.tools_router.lookup_domain(domain)
            
            self._update_rate_limit("abusech")
            return result
            
        except Exception as e:
            logger.error(f"Abuse.ch domain lookup failed for {domain}: {e}")
            return {"error": str(e)}
    
    async def _check_abusech_ip(self, ip_address: str) -> Dict[str, Any]:
        """Check IP address on Abuse.ch"""
        try:
            await self._rate_limit("abusech")
            
            # Use your existing ToolsRouter
            result = self.tools_router.lookup_ip(ip_address)
            
            self._update_rate_limit("abusech")
            return result
            
        except Exception as e:
            logger.error(f"Abuse.ch IP lookup failed for {ip_address}: {e}")
            return {"error": str(e)}
    
    async def _check_shodan_ip(self, ip_address: str) -> Dict[str, Any]:
        """Check IP address on Shodan"""
        try:
            await self._rate_limit("shodan")
            
            # This would use Shodan API
            # For now, return mock data
            result = {
                "ports": [80, 443, 22],
                "hostnames": [],
                "org": "Unknown",
                "os": "Unknown",
                "last_update": datetime.utcnow().isoformat()
            }
            
            self._update_rate_limit("shodan")
            return result
            
        except Exception as e:
            logger.error(f"Shodan lookup failed for {ip_address}: {e}")
            return {"error": str(e)}
    
    async def _get_mitre_ttp_info(self, ttp_id: str) -> Dict[str, Any]:
        """Get MITRE ATT&CK TTP information"""
        try:
            await self._rate_limit("mitre")
            
            # This would use MITRE ATT&CK API
            # For now, return mock data
            result = {
                "technique_id": ttp_id,
                "name": f"Technique {ttp_id}",
                "description": f"Description for {ttp_id}",
                "tactic": "Initial Access",
                "platforms": ["Windows", "Linux"],
                "data_sources": ["Process monitoring", "Network monitoring"]
            }
            
            self._update_rate_limit("mitre")
            return result
            
        except Exception as e:
            logger.error(f"MITRE lookup failed for {ttp_id}: {e}")
            return {"error": str(e)}
    
    async def _rate_limit(self, api_name: str):
        """Check and enforce rate limits"""
        api_config = self.apis.get(api_name)
        if not api_config:
            return
        
        last_request = api_config.get("last_request")
        rate_limit = api_config.get("rate_limit", 1)
        
        if last_request:
            time_since_last = datetime.utcnow() - last_request
            min_interval = 60.0 / rate_limit  # seconds between requests
            
            if time_since_last.total_seconds() < min_interval:
                wait_time = min_interval - time_since_last.total_seconds()
                logger.info(f"Rate limiting {api_name}, waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
    
    def _update_rate_limit(self, api_name: str):
        """Update last request time for rate limiting"""
        if api_name in self.apis:
            self.apis[api_name]["last_request"] = datetime.utcnow()
    
    async def get_api_status(self) -> Dict[str, Any]:
        """Get status of all APIs"""
        status = {}
        
        for api_name, api_config in self.apis.items():
            last_request = api_config.get("last_request")
            status[api_name] = {
                "rate_limit": api_config.get("rate_limit"),
                "last_request": last_request.isoformat() if last_request else None,
                "available": True  # Would check actual API availability
            }
        
        return status
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
            self.session = None 