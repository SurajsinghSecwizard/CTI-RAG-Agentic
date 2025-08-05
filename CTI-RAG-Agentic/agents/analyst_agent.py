"""
Analyst Agent - Handles threat analysis and report generation

Responsibilities:
- Perform threat intelligence analysis
- Generate threat briefs and reports
- Extract IOCs and TTPs
- Map to MITRE ATT&CK framework
- Build and maintain threat actor knowledge base
- Provide actionable insights
- Incrementally update threat actor profiles with new intelligence
"""

import logging
import json
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
import asyncio

from .base_agent import BaseAgent
from services.rag_service import RAGService
from services.azure_search import AzureSearchService
from models import ThreatBrief, IOCEnrichment, IOCType, DiamondModelProfile, ThreatActorProfileUpdate
from utils.error_handler import (
    safe_agent_execution,
    safe_search_result_access,
    validate_profile_data,
    safe_metadata_extraction,
    SearchResultError,
    ProfileUpdateError
)

logger = logging.getLogger(__name__)

class AnalystAgent(BaseAgent):
    """Agent responsible for threat analysis and report generation"""
    
    def __init__(self, config):
        super().__init__("Analyst", config)
        self.rag_service = RAGService()
        self.search_service = AzureSearchService()
        
        # Analysis capabilities
        self.analysis_types = [
            "threat_brief", "ioc_extraction", "ttp_analysis",
            "campaign_timeline", "actor_profile", "risk_assessment",
            "knowledge_base_build", "actor_profile_update", "incremental_update"
        ]
        
        # Track analysis results for incremental updates
        self.analysis_memory = {}
        
    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute analysis task with automatic incremental updates"""
        try:
            analysis_type = task.get("type", "threat_brief")
            threat_actor = task.get("threat_actor")
            
            # Execute the analysis
            if analysis_type == "threat_brief":
                result = await self._generate_threat_brief(task)
            elif analysis_type == "ioc_extraction":
                result = await self._extract_iocs(task)
            elif analysis_type == "ttp_analysis":
                result = await self._analyze_ttps(task)
            elif analysis_type == "campaign_timeline":
                result = await self._generate_timeline(task)
            elif analysis_type == "actor_profile":
                result = await self._generate_actor_profile(task)
            elif analysis_type == "risk_assessment":
                result = await self._assess_risk(task)
            elif analysis_type == "knowledge_base_build":
                result = await self._build_knowledge_base(task)
            elif analysis_type == "actor_profile_update":
                result = await self._update_actor_profile(task)
            elif analysis_type == "incremental_update":
                result = await self._incremental_profile_update(task)
            elif analysis_type == "qa_rag":
                result = await self._answer_question_rag(task)
            elif analysis_type == "diamond_analysis":
                result = await self._analyze_threat_actor_diamond(task)
            else:
                raise ValueError(f"Unknown analysis type: {analysis_type}")
            
            # Store analysis result in memory for incremental updates
            if threat_actor:
                if threat_actor not in self.analysis_memory:
                    self.analysis_memory[threat_actor] = []
                self.analysis_memory[threat_actor].append({
                    "analysis_type": analysis_type,
                    "result": result,
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            # Automatically trigger incremental update if this is a new analysis
            if analysis_type not in ["incremental_update", "actor_profile_update", "qa_rag"] and threat_actor:
                await self._auto_incremental_update(threat_actor, result)
            
            return result
                
        except Exception as e:
            logger.error(f"Analyst agent execution failed: {e}")
            self.log_action("execution_failed", {"error": str(e)})
            raise
    
    async def _generate_threat_brief(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive threat brief"""
        self.log_action("starting_threat_brief_generation", task)
        
        try:
            # Extract parameters
            threat_actor = task.get("threat_actor")
            time_window = task.get("time_window", {})
            output_format = task.get("output_format", "json")
            
            # Create ThreatQuery object
            from models import ThreatQuery
            query = ThreatQuery(
                analyst_name="System Analyst",
                focus_actor=threat_actor,
                time_window=f"{time_window.get('start', '2025-01-01')}/{time_window.get('end', '2025-12-31')}",
                need=["latest TTPs", "notable campaigns", "IOCs list", "MITRE mapping"],
                format="attack_brief"
            )
            
            # Generate threat brief using RAG service
            brief = self.rag_service.generate_threat_brief(query)
            
            result = {
                "analysis_type": "threat_brief",
                "threat_actor": threat_actor,
                "time_window": time_window,
                "brief": brief.dict() if brief else None,
                "confidence_score": brief.confidence_score if brief else 0.0,
                "generated_at": datetime.utcnow().isoformat()
            }
            
            self.log_action("completed_threat_brief_generation", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to generate threat brief: {e}")
            raise
    
    async def _extract_iocs(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Extract IOCs from threat intelligence"""
        self.log_action("starting_ioc_extraction", task)
        
        try:
            # Extract parameters
            threat_actor = task.get("threat_actor")
            ioc_types = task.get("ioc_types", ["all"])
            time_window = task.get("time_window", {})
            
            # Search for relevant documents
            documents = await self._search_documents(threat_actor, time_window)
            
            # Extract IOCs from documents
            iocs = []
            for doc in documents:
                doc_iocs = self._extract_iocs_from_text(doc.content, ioc_types)
                iocs.extend(doc_iocs)
            
            # Deduplicate and enrich IOCs
            unique_iocs = self._deduplicate_iocs(iocs)
            enriched_iocs = await self._enrich_iocs(unique_iocs)
            
            result = {
                "analysis_type": "ioc_extraction",
                "threat_actor": threat_actor,
                "ioc_types": ioc_types,
                "total_iocs": len(enriched_iocs),
                "iocs_by_type": self._group_iocs_by_type(enriched_iocs),
                "extracted_at": datetime.utcnow().isoformat()
            }
            
            self.log_action("completed_ioc_extraction", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to extract IOCs: {e}")
            raise
    
    async def _analyze_ttps(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze TTPs and map to MITRE ATT&CK"""
        self.log_action("starting_ttp_analysis", task)
        
        try:
            threat_actor = task.get("threat_actor")
            time_window = task.get("time_window", {})
            
            # Search for relevant documents
            documents = await self._search_documents(threat_actor, time_window)
            
            # Extract and analyze TTPs
            ttps = []
            for doc in documents:
                doc_ttps = self._extract_ttps_from_text(doc.content)
                ttps.extend(doc_ttps)
            
            # Map to MITRE ATT&CK
            mapped_ttps = await self._map_to_mitre_attack(ttps)
            
            result = {
                "analysis_type": "ttp_analysis",
                "threat_actor": threat_actor,
                "total_ttps": len(mapped_ttps),
                "tactics_covered": self._get_tactics_covered(mapped_ttps),
                "ttp_details": mapped_ttps,
                "analyzed_at": datetime.utcnow().isoformat()
            }
            
            self.log_action("completed_ttp_analysis", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to analyze TTPs: {e}")
            raise
    
    async def _generate_timeline(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Generate campaign timeline"""
        self.log_action("starting_timeline_generation", task)
        
        try:
            threat_actor = task.get("threat_actor")
            time_window = task.get("time_window", {})
            
            # Get threat brief first
            brief_task = {
                "type": "threat_brief",
                "threat_actor": threat_actor,
                "time_window": time_window
            }
            brief_result = await self._generate_threat_brief(brief_task)
            
            timeline = brief_result.get("brief", {}).get("campaign_timeline", [])
            
            result = {
                "analysis_type": "campaign_timeline",
                "threat_actor": threat_actor,
                "timeline_events": timeline,
                "total_events": len(timeline),
                "generated_at": datetime.utcnow().isoformat()
            }
            
            self.log_action("completed_timeline_generation", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to generate timeline: {e}")
            raise
    
    async def _generate_actor_profile(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive actor profile"""
        self.log_action("starting_actor_profile_generation", task)
        
        try:
            threat_actor = task.get("threat_actor")
            
            # Generate multiple analyses
            brief_result = await self._generate_threat_brief({
                "type": "threat_brief",
                "threat_actor": threat_actor
            })
            
            ioc_result = await self._extract_iocs({
                "type": "ioc_extraction",
                "threat_actor": threat_actor
            })
            
            ttp_result = await self._analyze_ttps({
                "type": "ttp_analysis",
                "threat_actor": threat_actor
            })
            
            profile = {
                "actor_name": threat_actor,
                "executive_summary": brief_result.get("brief", {}).get("executive_summary"),
                "key_ttps": ttp_result.get("ttp_details", []),
                "notable_iocs": ioc_result.get("iocs_by_type", {}),
                "campaign_timeline": brief_result.get("brief", {}).get("campaign_timeline", []),
                "risk_level": self._calculate_risk_level(ttp_result, ioc_result),
                "last_updated": datetime.utcnow().isoformat()
            }
            
            result = {
                "analysis_type": "actor_profile",
                "threat_actor": threat_actor,
                "profile": profile,
                "generated_at": datetime.utcnow().isoformat()
            }
            
            self.log_action("completed_actor_profile_generation", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to generate actor profile: {e}")
            raise
    
    async def _assess_risk(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risk level based on threat intelligence"""
        self.log_action("starting_risk_assessment", task)
        
        try:
            threat_actor = task.get("threat_actor")
            
            # Get actor profile
            profile_result = await self._generate_actor_profile({
                "type": "actor_profile",
                "threat_actor": threat_actor
            })
            
            profile = profile_result.get("profile", {})
            
            # Calculate risk factors
            risk_factors = {
                "ttp_complexity": len(profile.get("key_ttps", [])),
                "ioc_volume": sum(len(iocs) for iocs in profile.get("notable_iocs", {}).values()),
                "campaign_activity": len(profile.get("campaign_timeline", [])),
                "target_sophistication": self._assess_target_sophistication(profile)
            }
            
            overall_risk = self._calculate_overall_risk(risk_factors)
            
            result = {
                "analysis_type": "risk_assessment",
                "threat_actor": threat_actor,
                "risk_level": overall_risk,
                "risk_factors": risk_factors,
                "recommendations": self._generate_risk_recommendations(overall_risk, risk_factors),
                "assessed_at": datetime.utcnow().isoformat()
            }
            
            self.log_action("completed_risk_assessment", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to assess risk: {e}")
            raise
    
    async def _search_documents(self, threat_actor: str, time_window: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search for relevant documents"""
        try:
            query = f"{threat_actor} threat intelligence"
            documents = self.search_service.search_documents(
                query=query,
                top_k=20,
                filters=time_window
            )
            return documents
        except Exception as e:
            logger.error(f"Failed to search documents: {e}")
            return []
    
    def _extract_iocs_from_text(self, text: str, ioc_types: List[str]) -> List[Dict[str, Any]]:
        """Extract IOCs from text using regex patterns"""
        iocs = []
        
        # IP addresses
        if "all" in ioc_types or "ip" in ioc_types:
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ips = re.findall(ip_pattern, text)
            for ip in ips:
                iocs.append({"type": "ip_address", "value": ip, "confidence": 0.8})
        
        # Domains
        if "all" in ioc_types or "domain" in ioc_types:
            domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            domains = re.findall(domain_pattern, text)
            for domain in domains:
                iocs.append({"type": "domain", "value": domain, "confidence": 0.7})
        
        # File hashes (MD5, SHA1, SHA256)
        if "all" in ioc_types or "hash" in ioc_types:
            hash_patterns = [
                r'\b[a-fA-F0-9]{32}\b',  # MD5
                r'\b[a-fA-F0-9]{40}\b',  # SHA1
                r'\b[a-fA-F0-9]{64}\b'   # SHA256
            ]
            for pattern in hash_patterns:
                hashes = re.findall(pattern, text)
                for hash_val in hashes:
                    iocs.append({"type": "file_hash", "value": hash_val, "confidence": 0.9})
        
        return iocs
    
    def _extract_ttps_from_text(self, text: str) -> List[Dict[str, Any]]:
        """Extract TTPs from text"""
        ttps = []
        
        # MITRE ATT&CK pattern matching
        ttp_pattern = r'T\d{4}(?:\.\d{3})?'
        ttp_matches = re.findall(ttp_pattern, text)
        
        for ttp_id in ttp_matches:
            ttps.append({
                "mitre_id": ttp_id,
                "description": f"Technique {ttp_id} identified",
                "confidence": 0.8
            })
        
        return ttps
    
    def _deduplicate_iocs(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate IOCs"""
        seen = set()
        unique_iocs = []
        
        for ioc in iocs:
            key = f"{ioc['type']}:{ioc['value']}"
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)
        
        return unique_iocs
    
    async def _enrich_iocs(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich IOCs with additional context"""
        # This would integrate with your Tools Agent for enrichment
        # For now, return as-is
        return iocs
    
    async def _map_to_mitre_attack(self, ttps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map TTPs to MITRE ATT&CK framework"""
        # This would use MITRE ATT&CK API or local mapping
        # For now, return as-is
        return ttps
    
    def _group_iocs_by_type(self, iocs: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Group IOCs by type"""
        grouped = {}
        for ioc in iocs:
            ioc_type = ioc["type"]
            if ioc_type not in grouped:
                grouped[ioc_type] = []
            grouped[ioc_type].append(ioc["value"])
        return grouped
    
    def _get_tactics_covered(self, ttps: List[Dict[str, Any]]) -> List[str]:
        """Get MITRE ATT&CK tactics covered"""
        tactics = set()
        for ttp in ttps:
            mitre_id = ttp.get("mitre_id", "")
            if mitre_id:
                tactic = mitre_id.split(".")[0]
                tactics.add(tactic)
        return list(tactics)
    
    def _calculate_risk_level(self, ttp_result: Dict[str, Any], ioc_result: Dict[str, Any]) -> str:
        """Calculate risk level based on TTPs and IOCs"""
        ttp_count = len(ttp_result.get("ttp_details", []))
        ioc_count = sum(len(iocs) for iocs in ioc_result.get("iocs_by_type", {}).values())
        
        if ttp_count > 10 or ioc_count > 50:
            return "HIGH"
        elif ttp_count > 5 or ioc_count > 20:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _assess_target_sophistication(self, profile: Dict[str, Any]) -> int:
        """Assess target sophistication level"""
        # Simple heuristic based on TTP complexity
        ttps = profile.get("key_ttps", [])
        return min(len(ttps), 10)  # Scale 0-10
    
    def _calculate_overall_risk(self, risk_factors: Dict[str, Any]) -> str:
        """Calculate overall risk level"""
        total_score = sum(risk_factors.values())
        
        if total_score > 20:
            return "CRITICAL"
        elif total_score > 15:
            return "HIGH"
        elif total_score > 10:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_risk_recommendations(self, risk_level: str, risk_factors: Dict[str, Any]) -> List[str]:
        """Generate risk mitigation recommendations"""
        recommendations = []
        
        if risk_level in ["HIGH", "CRITICAL"]:
            recommendations.extend([
                "Implement enhanced monitoring and detection capabilities",
                "Conduct threat hunting exercises",
                "Review and update security controls",
                "Consider threat intelligence sharing with trusted partners"
            ])
        
        if risk_factors.get("ttp_complexity", 0) > 5:
            recommendations.append("Focus on advanced threat detection and response")
        
        if risk_factors.get("ioc_volume", 0) > 30:
            recommendations.append("Implement automated IOC blocking and monitoring")
        
        return recommendations 
    
    async def _build_knowledge_base(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Build comprehensive threat actor knowledge base"""
        self.log_action("starting_knowledge_base_build", task)
        
        try:
            threat_actor = task.get("threat_actor")
            time_window = task.get("time_window", {})
            
            # Search for all relevant documents
            documents = await self._search_documents(threat_actor, time_window)
            
            # Extract comprehensive intelligence
            iocs = await self._extract_iocs({
                "threat_actor": threat_actor,
                "ioc_types": ["all"],
                "time_window": time_window
            })
            
            ttps = await self._analyze_ttps({
                "threat_actor": threat_actor,
                "time_window": time_window
            })
            
            timeline = await self._generate_timeline({
                "threat_actor": threat_actor,
                "time_window": time_window
            })
            
            # Build comprehensive profile
            profile = await self._generate_actor_profile({
                "threat_actor": threat_actor,
                "time_window": time_window
            })
            
            # Create knowledge base entry
            knowledge_entry = {
                "threat_actor": threat_actor,
                "profile": profile.get("profile", {}),
                "iocs": iocs.get("iocs_by_type", {}),
                "ttps": ttps.get("ttp_details", []),
                "timeline": timeline.get("timeline_events", []),
                "risk_assessment": await self._assess_risk({
                    "threat_actor": threat_actor
                }),
                "last_updated": datetime.utcnow().isoformat(),
                "document_count": len(documents),
                "intelligence_sources": list(set([doc.get("source", "Unknown") for doc in documents]))
            }
            
            # Store in knowledge base (Azure Search)
            await self._store_knowledge_base_entry(knowledge_entry)
            
            result = {
                "analysis_type": "knowledge_base_build",
                "threat_actor": threat_actor,
                "knowledge_entry": knowledge_entry,
                "status": "completed",
                "generated_at": datetime.utcnow().isoformat()
            }
            
            self.log_action("completed_knowledge_base_build", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to build knowledge base: {e}")
            raise
    
    async def _update_actor_profile(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing threat actor profile with new intelligence"""
        self.log_action("starting_actor_profile_update", task)
        
        try:
            threat_actor = task.get("threat_actor")
            time_window = task.get("time_window", {})
            
            # Get existing profile
            existing_profile = await self._get_existing_profile(threat_actor)
            
            # Get new intelligence
            new_intelligence = await self._build_knowledge_base(task)
            
            # Merge with existing profile
            updated_profile = self._merge_profiles(existing_profile, new_intelligence)
            
            # Store updated profile
            await self._store_knowledge_base_entry(updated_profile)
            
            result = {
                "analysis_type": "actor_profile_update",
                "threat_actor": threat_actor,
                "updated_profile": updated_profile,
                "new_intelligence": new_intelligence,
                "status": "completed",
                "updated_at": datetime.utcnow().isoformat()
            }
            
            self.log_action("completed_actor_profile_update", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to update actor profile: {e}")
            raise
    
    async def _store_knowledge_base_entry(self, knowledge_entry: Dict[str, Any]) -> bool:
        """Store knowledge base entry in Azure Search"""
        try:
            # Extract threat actor name from the knowledge entry
            threat_actor = None
            
            # Try different possible locations for threat_actor
            if 'threat_actor' in knowledge_entry:
                threat_actor = knowledge_entry['threat_actor']
            elif 'data' in knowledge_entry and 'threat_actor' in knowledge_entry['data']:
                threat_actor = knowledge_entry['data']['threat_actor']
            elif 'profile' in knowledge_entry and 'threat_actor' in knowledge_entry['profile']:
                threat_actor = knowledge_entry['profile']['threat_actor']
            else:
                # Try to extract from content or title
                content = str(knowledge_entry.get('content', ''))
                if 'Threat Actor:' in content:
                    threat_actor = content.split('Threat Actor:')[1].split()[0]
                else:
                    threat_actor = "Unknown"
            
            # Create a document for the knowledge base
            doc_id = f"kb_{threat_actor.lower().replace(' ', '_').replace('-', '_')}"
            
            # Create CTIDocument object
            from models import CTIDocument, ConfidenceLevel
            
            # Extract operations from the knowledge entry
            operations = []
            if 'profile' in knowledge_entry:
                operations = knowledge_entry['profile'].get('primary_operations', [])
            elif 'data' in knowledge_entry and 'profile' in knowledge_entry['data']:
                operations = knowledge_entry['data']['profile'].get('primary_operations', [])
            
            # Extract geographic focus
            geo_focus = []
            if 'profile' in knowledge_entry:
                geo_focus = knowledge_entry['profile'].get('geographic_focus', [])
            elif 'data' in knowledge_entry and 'profile' in knowledge_entry['data']:
                geo_focus = knowledge_entry['data']['profile'].get('geographic_focus', [])
            
            search_doc = CTIDocument(
                doc_id=doc_id,
                title=f"Threat Actor Profile: {threat_actor}",
                content=self._generate_knowledge_content(knowledge_entry),
                date_pub=datetime.utcnow(),
                source="knowledge_base",
                threat_actor=threat_actor,
                operation=", ".join(operations),
                mitre_id=self._extract_mitre_ids(knowledge_entry),
                ioc_type=None,  # Will be set by Azure Search service
                geo_scope=", ".join(geo_focus),
                confidence=ConfidenceLevel.HIGH,
                language="en",
                content_vector=None  # Will be generated by Azure Search service
            )
            
            # Upload to Azure Search
            success = self.search_service.upload_documents([search_doc])
            
            if success:
                logger.info(f"Successfully stored knowledge base entry for {threat_actor}")
                return True
            else:
                logger.error(f"Failed to store knowledge base entry for {threat_actor}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to store knowledge base entry: {e}")
            return False
    
    def _generate_knowledge_content(self, knowledge_entry: Dict[str, Any]) -> str:
        """Generate searchable content from knowledge entry"""
        content_parts = []
        
        # Profile information
        profile = knowledge_entry.get('profile', {})
        if profile:
            content_parts.append(f"Threat Actor: {knowledge_entry['threat_actor']}")
            content_parts.append(f"Alias: {', '.join(profile.get('aliases', []))}")
            content_parts.append(f"Description: {profile.get('description', 'No description available')}")
            content_parts.append(f"Geographic Focus: {', '.join(profile.get('geographic_focus', []))}")
            content_parts.append(f"Primary Operations: {', '.join(profile.get('primary_operations', []))}")
        
        # TTPs
        ttps = knowledge_entry.get('ttps', [])
        if ttps:
            ttp_ids = [ttp.get('mitre_id', '') for ttp in ttps if ttp.get('mitre_id')]
            content_parts.append(f"MITRE ATT&CK Techniques: {', '.join(ttp_ids)}")
        
        # IOCs
        iocs = knowledge_entry.get('iocs', {})
        if iocs:
            for ioc_type, ioc_list in iocs.items():
                if ioc_list:
                    content_parts.append(f"{ioc_type.upper()} IOCs: {', '.join(ioc_list[:10])}")  # Limit to first 10
        
        # Timeline
        timeline = knowledge_entry.get('timeline', [])
        if timeline:
            recent_events = timeline[-5:]  # Last 5 events
            for event in recent_events:
                content_parts.append(f"Recent Activity: {event.get('event', '')}")
        
        return " ".join(content_parts)
    
    def _extract_mitre_ids(self, knowledge_entry: Dict[str, Any]) -> str:
        """Extract MITRE ATT&CK IDs from knowledge entry"""
        ttps = knowledge_entry.get('ttps', [])
        mitre_ids = []
        
        for ttp in ttps:
            mitre_id = ttp.get('mitre_id')
            if mitre_id:
                mitre_ids.append(mitre_id)
        
        return ', '.join(mitre_ids) if mitre_ids else None
    
    async def _get_existing_profile(self, threat_actor: str) -> Dict[str, Any]:
        """Get existing threat actor profile from knowledge base"""
        try:
            logger.info(f"Searching for existing profile for threat actor: {threat_actor}")
            
            # Search for existing profile
            results = self.search_service.search_documents(
                query=f"Threat Actor Profile: {threat_actor}",
                top_k=1,
                filters=f"source eq 'knowledge_base' and threat_actor eq '{threat_actor}'"
            )
            
            if results and len(results) > 0:
                # Convert SearchResult object to dictionary using safe access
                search_result = results[0]
                
                # Use safe metadata extraction
                expected_fields = ["threat_actor", "source", "date_pub", "mitre_id", "confidence"]
                metadata = safe_metadata_extraction(search_result, expected_fields)
                
                # Build profile data with safe access
                profile_data = {
                    "threat_actor": metadata.get("threat_actor", threat_actor),
                    "title": safe_search_result_access(search_result, 'title', 'Unknown'),
                    "content": safe_search_result_access(search_result, 'content', ''),
                    "score": safe_search_result_access(search_result, 'score', 0.0),
                    "doc_id": safe_search_result_access(search_result, 'doc_id', 'unknown'),
                    "metadata": metadata
                }
                
                # Validate profile data
                if not validate_profile_data(profile_data):
                    logger.warning(f"Profile data validation failed for {threat_actor}")
                    # Use fallback data
                    profile_data["threat_actor"] = threat_actor
                
                # Try to parse profile data from content
                try:
                    content = safe_search_result_access(search_result, 'content', '')
                    if "{" in content and "}" in content:
                        import json
                        # Extract JSON-like content
                        content_start = content.find("{")
                        content_end = content.rfind("}") + 1
                        if content_start >= 0 and content_end > content_start:
                            json_content = content[content_start:content_end]
                            parsed_data = json.loads(json_content)
                            profile_data.update(parsed_data)
                            logger.info(f"Successfully parsed JSON profile data for {threat_actor}")
                except Exception as parse_error:
                    logger.warning(f"Failed to parse profile content as JSON for {threat_actor}: {parse_error}")
                    # Continue with basic profile data
                
                logger.info(f"Successfully retrieved existing profile for {threat_actor}")
                return {"existing_profile": True, "data": profile_data}
            else:
                logger.info(f"No existing profile found for {threat_actor}")
                return {"existing_profile": False, "data": {}}
                
        except Exception as e:
            logger.error(f"Failed to get existing profile for {threat_actor}: {e}")
            raise SearchResultError(f"Failed to get existing profile for {threat_actor}", 
                                 agent="Analyst", 
                                 task_type="profile_retrieval",
                                 context={"threat_actor": threat_actor})
    
    def _merge_profiles(self, existing_profile: Dict[str, Any], new_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Merge existing profile with new intelligence"""
        merged = existing_profile.get("data", {}).copy()
        
        # Merge IOCs
        existing_iocs = merged.get("iocs", {})
        new_iocs = new_intelligence.get("knowledge_entry", {}).get("iocs", {})
        
        for ioc_type, ioc_list in new_iocs.items():
            if ioc_type not in existing_iocs:
                existing_iocs[ioc_type] = []
            existing_iocs[ioc_type].extend(ioc_list)
            # Remove duplicates
            existing_iocs[ioc_type] = list(set(existing_iocs[ioc_type]))
        
        merged["iocs"] = existing_iocs
        
        # Merge TTPs
        existing_ttps = merged.get("ttps", [])
        new_ttps = new_intelligence.get("knowledge_entry", {}).get("ttps", [])
        
        # Add new TTPs that don't exist
        existing_ttp_ids = {ttp.get("mitre_id") for ttp in existing_ttps}
        for ttp in new_ttps:
            if ttp.get("mitre_id") not in existing_ttp_ids:
                existing_ttps.append(ttp)
        
        merged["ttps"] = existing_ttps
        
        # Update timeline
        existing_timeline = merged.get("timeline", [])
        new_timeline = new_intelligence.get("knowledge_entry", {}).get("timeline", [])
        existing_timeline.extend(new_timeline)
        
        # Sort by date and remove duplicates
        timeline_dict = {}
        for event in existing_timeline:
            key = f"{event.get('date', '')}_{event.get('event', '')}"
            timeline_dict[key] = event
        
        merged["timeline"] = sorted(timeline_dict.values(), key=lambda x: x.get('date', ''))
        
        # Update last updated timestamp
        merged["last_updated"] = datetime.utcnow().isoformat()
        
        return merged 

    async def _auto_incremental_update(self, threat_actor: str, analysis_result: Dict[str, Any]):
        """Automatically update threat actor profile with new analysis results"""
        try:
            logger.info(f"Auto-updating profile for {threat_actor} with new analysis results")
            
            # Extract intelligence from analysis result
            new_intelligence = self._extract_intelligence_from_analysis(analysis_result)
            
            if new_intelligence:
                # Get existing profile
                existing_profile = await self._get_existing_profile(threat_actor)
                
                # Merge with existing profile
                updated_profile = self._merge_profiles_intelligently(existing_profile, new_intelligence)
                
                # Store updated profile
                await self._store_knowledge_base_entry(updated_profile)
                
                logger.info(f"Successfully auto-updated profile for {threat_actor}")
                
        except Exception as e:
            logger.error(f"Failed to auto-update profile for {threat_actor}: {e}")
    
    def _extract_intelligence_from_analysis(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract intelligence from analysis result for profile update"""
        intelligence = {
            "iocs": {},
            "ttps": [],
            "timeline": [],
            "risk_assessment": {},
            "last_analysis": datetime.utcnow().isoformat()
        }
        
        analysis_type = analysis_result.get("analysis_type")
        
        if analysis_type == "ioc_extraction":
            # Extract IOCs
            iocs_by_type = analysis_result.get("iocs_by_type", {})
            for ioc_type, ioc_list in iocs_by_type.items():
                intelligence["iocs"][ioc_type] = ioc_list
        
        elif analysis_type == "ttp_analysis":
            # Extract TTPs
            ttp_details = analysis_result.get("ttp_details", [])
            intelligence["ttps"] = ttp_details
        
        elif analysis_type == "campaign_timeline":
            # Extract timeline
            timeline = analysis_result.get("timeline", [])
            intelligence["timeline"] = timeline
        
        elif analysis_type == "risk_assessment":
            # Extract risk assessment
            risk_factors = analysis_result.get("risk_factors", {})
            intelligence["risk_assessment"] = risk_factors
        
        elif analysis_type == "threat_brief":
            # Extract from threat brief
            brief = analysis_result.get("brief", {})
            if brief:
                # Extract IOCs from brief
                brief_iocs = brief.get("iocs", [])
                for ioc in brief_iocs:
                    ioc_type = ioc.get("type", "unknown")
                    if ioc_type not in intelligence["iocs"]:
                        intelligence["iocs"][ioc_type] = []
                    intelligence["iocs"][ioc_type].append(ioc.get("value", ""))
                
                # Extract TTPs from brief
                tactics_techniques = brief.get("tactics_techniques", [])
                for technique in tactics_techniques:
                    intelligence["ttps"].append({
                        "technique": technique,
                        "source": "threat_brief"
                    })
                
                # Extract timeline from brief
                campaign_timeline = brief.get("campaign_timeline", [])
                intelligence["timeline"].extend(campaign_timeline)
        
        return intelligence
    
    def _merge_profiles_intelligently(self, existing_profile: Dict[str, Any], new_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Intelligently merge new intelligence with existing profile"""
        merged = existing_profile.get("data", {}).copy()
        
        # Merge IOCs with deduplication
        existing_iocs = merged.get("iocs", {})
        new_iocs = new_intelligence.get("iocs", {})
        
        for ioc_type, ioc_list in new_iocs.items():
            if ioc_type not in existing_iocs:
                existing_iocs[ioc_type] = []
            
            # Add new IOCs and remove duplicates
            existing_iocs[ioc_type].extend(ioc_list)
            existing_iocs[ioc_type] = list(set(existing_iocs[ioc_type]))
            
            # Limit to reasonable number per type
            existing_iocs[ioc_type] = existing_iocs[ioc_type][:50]
        
        merged["iocs"] = existing_iocs
        
        # Merge TTPs with deduplication
        existing_ttps = merged.get("ttps", [])
        new_ttps = new_intelligence.get("ttps", [])
        
        # Create set of existing TTP IDs for deduplication
        existing_ttp_ids = set()
        for ttp in existing_ttps:
            if isinstance(ttp, dict):
                existing_ttp_ids.add(ttp.get("mitre_id", ttp.get("technique", "")))
            else:
                existing_ttp_ids.add(str(ttp))
        
        # Add new TTPs that don't exist
        for ttp in new_ttps:
            if isinstance(ttp, dict):
                ttp_id = ttp.get("mitre_id", ttp.get("technique", ""))
            else:
                ttp_id = str(ttp)
            
            if ttp_id not in existing_ttp_ids:
                existing_ttps.append(ttp)
                existing_ttp_ids.add(ttp_id)
        
        merged["ttps"] = existing_ttps
        
        # Merge timeline with deduplication
        existing_timeline = merged.get("timeline", [])
        new_timeline = new_intelligence.get("timeline", [])
        
        # Create timeline deduplication key
        timeline_dict = {}
        for event in existing_timeline + new_timeline:
            if isinstance(event, dict):
                key = f"{event.get('date', '')}_{event.get('event', '')}"
                timeline_dict[key] = event
            else:
                timeline_dict[str(event)] = {"event": str(event), "date": datetime.utcnow().isoformat()}
        
        # Sort by date
        merged["timeline"] = sorted(
            timeline_dict.values(), 
            key=lambda x: x.get('date', ''),
            reverse=True
        )[:20]  # Keep last 20 events
        
        # Merge risk assessment
        existing_risk = merged.get("risk_assessment", {})
        new_risk = new_intelligence.get("risk_assessment", {})
        merged["risk_assessment"] = {**existing_risk, **new_risk}
        
        # Update analysis history
        analysis_history = merged.get("analysis_history", [])
        analysis_history.append({
            "analysis_type": new_intelligence.get("last_analysis_type", "unknown"),
            "timestamp": new_intelligence.get("last_analysis"),
            "intelligence_added": {
                "iocs_added": sum(len(ioc_list) for ioc_list in new_intelligence.get("iocs", {}).values()),
                "ttps_added": len(new_intelligence.get("ttps", [])),
                "timeline_events_added": len(new_intelligence.get("timeline", []))
            }
        })
        
        # Keep last 10 analysis records
        merged["analysis_history"] = analysis_history[-10:]
        
        # Update last updated timestamp
        merged["last_updated"] = datetime.utcnow().isoformat()
        
        return merged
    
    async def _incremental_profile_update(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Perform incremental profile update based on accumulated analysis memory"""
        self.log_action("starting_incremental_profile_update", task)
        
        try:
            threat_actor = task.get("threat_actor")
            
            if not threat_actor or threat_actor not in self.analysis_memory:
                return {
                    "analysis_type": "incremental_update",
                    "threat_actor": threat_actor,
                    "status": "no_analysis_data",
                    "message": "No analysis data available for incremental update"
                }
            
            # Get all analysis results for this threat actor
            analysis_results = self.analysis_memory[threat_actor]
            
            # Aggregate intelligence from all analyses
            aggregated_intelligence = self._aggregate_analysis_intelligence(analysis_results)
            
            # Get existing profile
            existing_profile = await self._get_existing_profile(threat_actor)
            
            # Merge with existing profile
            updated_profile = self._merge_profiles_intelligently(existing_profile, aggregated_intelligence)
            
            # Store updated profile
            await self._store_knowledge_base_entry(updated_profile)
            
            result = {
                "analysis_type": "incremental_update",
                "threat_actor": threat_actor,
                "analyses_processed": len(analysis_results),
                "intelligence_added": aggregated_intelligence,
                "updated_profile": updated_profile,
                "status": "completed",
                "updated_at": datetime.utcnow().isoformat()
            }
            
            self.log_action("completed_incremental_profile_update", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to perform incremental profile update: {e}")
            raise
    
    def _aggregate_analysis_intelligence(self, analysis_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate intelligence from multiple analysis results"""
        aggregated = {
            "iocs": {},
            "ttps": [],
            "timeline": [],
            "risk_assessment": {},
            "analysis_count": len(analysis_results),
            "last_analysis": datetime.utcnow().isoformat()
        }
        
        for analysis in analysis_results:
            analysis_result = analysis.get("result", {})
            intelligence = self._extract_intelligence_from_analysis(analysis_result)
            
            # Aggregate IOCs
            for ioc_type, ioc_list in intelligence.get("iocs", {}).items():
                if ioc_type not in aggregated["iocs"]:
                    aggregated["iocs"][ioc_type] = []
                aggregated["iocs"][ioc_type].extend(ioc_list)
            
            # Aggregate TTPs
            aggregated["ttps"].extend(intelligence.get("ttps", []))
            
            # Aggregate timeline
            aggregated["timeline"].extend(intelligence.get("timeline", []))
            
            # Aggregate risk assessment
            aggregated["risk_assessment"].update(intelligence.get("risk_assessment", {}))
        
        # Deduplicate aggregated data
        for ioc_type in aggregated["iocs"]:
            aggregated["iocs"][ioc_type] = list(set(aggregated["iocs"][ioc_type]))
        
        # Deduplicate TTPs
        ttp_ids = set()
        unique_ttps = []
        for ttp in aggregated["ttps"]:
            if isinstance(ttp, dict):
                ttp_id = ttp.get("mitre_id", ttp.get("technique", ""))
            else:
                ttp_id = str(ttp)
            
            if ttp_id not in ttp_ids:
                unique_ttps.append(ttp)
                ttp_ids.add(ttp_id)
        
        aggregated["ttps"] = unique_ttps
        
        return aggregated 

    async def _answer_question_rag(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Answer questions using RAG system with citations"""
        self.log_action("starting_qa_rag", task)
        
        try:
            # Extract parameters
            question = task.get("question")
            max_results = task.get("max_results", 10)
            confidence_threshold = task.get("confidence_threshold", 0.7)
            output_format = task.get("output_format", "Auto")
            filters = task.get("filters", {})
            
            logger.info(f"Q&A RAG - Question: {question}")
            logger.info(f"Q&A RAG - Max results: {max_results}")
            logger.info(f"Q&A RAG - Filters: {filters}")
            
            # Build search query with filters
            search_query = self._build_search_query(question, filters)
            logger.info(f"Q&A RAG - Search query: {search_query}")
            
            # Search for relevant documents
            search_results = await self._search_documents_qa(search_query, max_results, filters)
            logger.info(f"Q&A RAG - Found {len(search_results)} search results")
            
            if not search_results:
                logger.warning("Q&A RAG - No search results found")
                return {
                    "answer": "I couldn't find any relevant information to answer your question. Please try rephrasing or broadening your search.",
                    "citations": [],
                    "sources": [],
                    "confidence": 0.0,
                    "generated_at": datetime.utcnow().isoformat()
                }
            
            # Generate answer using RAG
            answer, confidence = await self._generate_rag_answer(question, search_results, output_format)
            logger.info(f"Q&A RAG - Generated answer with confidence: {confidence}")
            
            # Extract citations
            citations = self._extract_citations(search_results)
            logger.info(f"Q&A RAG - Extracted {len(citations)} citations")
            
            # Check if this is a threat actor profile question and update profile
            threat_actor = self._extract_threat_actor_from_question(question)
            if threat_actor:
                logger.info(f"Q&A RAG - Detected threat actor: {threat_actor}")
                await self._update_threat_actor_profile_from_qa(threat_actor, search_results, question)
            
            # Filter by confidence threshold
            if confidence < confidence_threshold:
                answer = f"I found some information, but I'm not very confident in the answer (confidence: {confidence:.2f}). Here's what I found:\n\n{answer}"
            
            result = {
                "answer": answer,
                "citations": citations,
                "sources": search_results,
                "confidence": confidence,
                "generated_at": datetime.utcnow().isoformat()
            }
            
            self.log_action("completed_qa_rag", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to answer question with RAG: {e}")
            raise

    def _extract_threat_actor_from_question(self, question: str) -> Optional[str]:
        """Extract threat actor name from question"""
        # Common threat actors to look for
        threat_actors = [
            "APT29", "APT28", "APT41", "FIN7", "Lazarus", "Volt Typhoon",
            "Cozy Bear", "Fancy Bear", "CozyDuke", "The Dukes", "Carbanak",
            "BlackCat", "OCTO TEMPEST", "LUMMA STEALER"
        ]
        
        question_lower = question.lower()
        for actor in threat_actors:
            if actor.lower() in question_lower:
                return actor
        
        return None

    async def _update_threat_actor_profile_from_qa(self, threat_actor: str, search_results: List[Dict[str, Any]], question: str):
        """Update threat actor profile based on Q&A results"""
        try:
            logger.info(f"Updating threat actor profile for {threat_actor}")
            
            # Get existing profile
            existing_profile = await self._get_existing_diamond_profile(threat_actor)
            
            # Analyze search results for Diamond Model components
            diamond_analysis = await self._analyze_diamond_model_components(search_results, threat_actor)
            
            # Calculate delta and update profile
            if existing_profile:
                delta_updates = self._calculate_profile_delta(existing_profile, diamond_analysis)
                updated_profile = self._merge_diamond_profiles(existing_profile, diamond_analysis)
            else:
                # Create new profile
                updated_profile = self._create_new_diamond_profile(threat_actor, diamond_analysis)
                delta_updates = []
            
            # Store updated profile
            await self._store_diamond_profile(updated_profile)
            
            # Log delta updates
            if delta_updates:
                logger.info(f"Profile updates for {threat_actor}: {len(delta_updates)} changes")
                for update in delta_updates:
                    logger.info(f"  - {update.update_type}: {update.component_type} - {update.component_id}")
            
        except Exception as e:
            logger.error(f"Failed to update threat actor profile: {e}")

    async def _analyze_diamond_model_components(self, search_results: List[Dict[str, Any]], threat_actor: str) -> Dict[str, Any]:
        """Analyze search results to extract Diamond Model components"""
        try:
            analysis = {
                "adversary": None,
                "infrastructure": [],
                "victims": [],
                "capabilities": []
            }
            
            for result in search_results:
                content = result.get("content", "")
                title = result.get("title", "")
                source = result.get("source", "")
                
                # Extract adversary information
                if not analysis["adversary"]:
                    adversary_info = self._extract_adversary_info(content, title, threat_actor)
                    if adversary_info:
                        analysis["adversary"] = adversary_info
                
                # Extract infrastructure (IOCs)
                infrastructure_items = self._extract_infrastructure_info(content, source)
                analysis["infrastructure"].extend(infrastructure_items)
                
                # Extract victim information
                victim_info = self._extract_victim_info(content, title)
                if victim_info:
                    analysis["victims"].append(victim_info)
                
                # Extract capabilities (TTPs)
                capability_info = self._extract_capability_info(content, title)
                if capability_info:
                    analysis["capabilities"].append(capability_info)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Failed to analyze Diamond Model components: {e}")
            return {"adversary": None, "infrastructure": [], "victims": [], "capabilities": []}

    def _extract_adversary_info(self, content: str, title: str, threat_actor: str) -> Optional[Dict[str, Any]]:
        """Extract adversary information from content"""
        try:
            # Extract aliases
            aliases = self._extract_aliases(content, threat_actor)
            
            # Extract motivation
            motivation = self._extract_motivation(content)
            
            # Extract capabilities
            capabilities = self._extract_capabilities(content)
            
            # Extract country of origin
            country = self._extract_country_of_origin(content)
            
            # Extract sophistication level
            sophistication = self._extract_sophistication_level(content)
            
            if any([aliases, motivation, capabilities, country, sophistication]):
                return {
                    "id": f"adv_{threat_actor.lower()}",
                    "name": threat_actor,
                    "description": f"Threat actor {threat_actor}",
                    "aliases": aliases,
                    "motivation": motivation,
                    "capabilities": capabilities,
                    "country_of_origin": country,
                    "sophistication_level": sophistication,
                    "threat_level": self._assess_threat_level(content),
                    "confidence": "medium",
                    "sources": []
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to extract adversary info: {e}")
            return None

    def _extract_infrastructure_info(self, content: str, source: str) -> List[Dict[str, Any]]:
        """Extract infrastructure (IOCs) from content"""
        infrastructure = []
        
        try:
            # Extract IP addresses
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ips = re.findall(ip_pattern, content)
            for ip in ips:
                infrastructure.append({
                    "id": f"inf_ip_{ip.replace('.', '_')}",
                    "name": f"IP Address: {ip}",
                    "description": f"IP address {ip}",
                    "ioc_type": "ip",
                    "value": ip,
                    "category": "network",
                    "subcategory": "ip_address",
                    "confidence": "medium",
                    "sources": [source]
                })
            
            # Extract domains
            domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            domains = re.findall(domain_pattern, content)
            for domain in domains:
                if not domain.startswith('www.'):
                    infrastructure.append({
                        "id": f"inf_domain_{domain.replace('.', '_')}",
                        "name": f"Domain: {domain}",
                        "description": f"Domain {domain}",
                        "ioc_type": "domain",
                        "value": domain,
                        "category": "network",
                        "subcategory": "domain",
                        "confidence": "medium",
                        "sources": [source]
                    })
            
            # Extract hashes
            hash_pattern = r'\b[A-Fa-f0-9]{32,64}\b'
            hashes = re.findall(hash_pattern, content)
            for hash_val in hashes:
                infrastructure.append({
                    "id": f"inf_hash_{hash_val}",
                    "name": f"Hash: {hash_val[:8]}...",
                    "description": f"File hash {hash_val}",
                    "ioc_type": "hash",
                    "value": hash_val,
                    "category": "file",
                    "subcategory": "hash",
                    "confidence": "medium",
                    "sources": [source]
                })
            
        except Exception as e:
            logger.error(f"Failed to extract infrastructure info: {e}")
        
        return infrastructure

    def _extract_victim_info(self, content: str, title: str) -> Optional[Dict[str, Any]]:
        """Extract victim information from content"""
        try:
            # Extract sector information
            sectors = self._extract_sectors(content)
            
            # Extract geography
            geography = self._extract_geography(content)
            
            if sectors or geography:
                return {
                    "id": f"victim_{len(sectors)}_{len(geography)}",
                    "name": "Target Organization",
                    "description": "Victim organization",
                    "sector": sectors[0] if sectors else "",
                    "industry": sectors[0] if sectors else "",
                    "geography": geography[0] if geography else "",
                    "target_type": "primary",
                    "confidence": "medium",
                    "sources": []
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to extract victim info: {e}")
            return None

    def _extract_capability_info(self, content: str, title: str) -> Optional[Dict[str, Any]]:
        """Extract capability (TTP) information from content"""
        try:
            # Extract MITRE ATT&CK techniques
            mitre_pattern = r'T\d{4}(?:\.\d{3})?'
            mitre_techniques = re.findall(mitre_pattern, content)
            
            # Extract tools and malware
            tools = self._extract_tools(content)
            malware = self._extract_malware(content)
            
            if mitre_techniques or tools or malware:
                return {
                    "id": f"cap_{len(mitre_techniques)}_{len(tools)}",
                    "name": "Technical Capability",
                    "description": "Technical capabilities and TTPs",
                    "mitre_technique": mitre_techniques[0] if mitre_techniques else "",
                    "mitre_tactic": self._map_technique_to_tactic(mitre_techniques[0]) if mitre_techniques else "",
                    "tools_used": tools,
                    "malware_families": malware,
                    "attack_vectors": self._extract_attack_vectors(content),
                    "complexity_level": self._assess_complexity(content),
                    "confidence": "medium",
                    "sources": []
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to extract capability info: {e}")
            return None

    # Helper methods for extraction
    def _extract_aliases(self, content: str, threat_actor: str) -> List[str]:
        """Extract aliases for threat actor"""
        aliases = []
        # Look for common alias patterns
        alias_patterns = [
            rf'{threat_actor}[^a-zA-Z0-9]*\(([^)]+)\)',
            rf'also known as[^.]*{threat_actor}[^.]*',
            rf'{threat_actor}[^.]*alias[^.]*'
        ]
        
        for pattern in alias_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            aliases.extend(matches)
        
        return list(set(aliases))

    def _extract_motivation(self, content: str) -> str:
        """Extract motivation from content"""
        motivation_keywords = [
            "financial gain", "espionage", "cybercrime", "hacktivism",
            "state-sponsored", "political", "economic", "military"
        ]
        
        for keyword in motivation_keywords:
            if keyword.lower() in content.lower():
                return keyword
        
        return ""

    def _extract_capabilities(self, content: str) -> List[str]:
        """Extract capabilities from content"""
        capabilities = []
        capability_keywords = [
            "spear phishing", "malware", "ransomware", "data theft",
            "persistence", "lateral movement", "privilege escalation"
        ]
        
        for keyword in capability_keywords:
            if keyword.lower() in content.lower():
                capabilities.append(keyword)
        
        return capabilities

    def _extract_country_of_origin(self, content: str) -> Optional[str]:
        """Extract country of origin"""
        countries = ["Russia", "China", "North Korea", "Iran", "United States"]
        
        for country in countries:
            if country.lower() in content.lower():
                return country
        
        return None

    def _extract_sophistication_level(self, content: str) -> str:
        """Extract sophistication level"""
        if any(word in content.lower() for word in ["advanced", "sophisticated", "complex"]):
            return "high"
        elif any(word in content.lower() for word in ["basic", "simple", "rudimentary"]):
            return "low"
        else:
            return "medium"

    def _assess_threat_level(self, content: str) -> str:
        """Assess threat level"""
        if any(word in content.lower() for word in ["critical", "high", "severe"]):
            return "high"
        elif any(word in content.lower() for word in ["low", "minimal", "minor"]):
            return "low"
        else:
            return "medium"

    def _extract_sectors(self, content: str) -> List[str]:
        """Extract target sectors"""
        sectors = ["healthcare", "finance", "technology", "government", "energy", "education"]
        found_sectors = []
        
        for sector in sectors:
            if sector.lower() in content.lower():
                found_sectors.append(sector)
        
        return found_sectors

    def _extract_geography(self, content: str) -> List[str]:
        """Extract geographic information"""
        countries = ["United States", "Europe", "Asia", "Russia", "China", "North Korea"]
        found_geography = []
        
        for country in countries:
            if country.lower() in content.lower():
                found_geography.append(country)
        
        return found_geography

    def _extract_tools(self, content: str) -> List[str]:
        """Extract tools from content"""
        tools = []
        tool_keywords = [
            "Cobalt Strike", "Metasploit", "PowerShell", "Python", "C++",
            "Mimikatz", "BloodHound", "Empire", "Covenant"
        ]
        
        for tool in tool_keywords:
            if tool.lower() in content.lower():
                tools.append(tool)
        
        return tools

    def _extract_malware(self, content: str) -> List[str]:
        """Extract malware families"""
        malware = []
        malware_keywords = [
            "Emotet", "TrickBot", "Ryuk", "REvil", "Conti", "LockBit",
            "WannaCry", "NotPetya", "Stuxnet", "Duqu"
        ]
        
        for malware_family in malware_keywords:
            if malware_family.lower() in content.lower():
                malware.append(malware_family)
        
        return malware

    def _extract_attack_vectors(self, content: str) -> List[str]:
        """Extract attack vectors"""
        vectors = []
        vector_keywords = [
            "phishing", "spear phishing", "watering hole", "supply chain",
            "zero-day", "social engineering", "credential stuffing"
        ]
        
        for vector in vector_keywords:
            if vector.lower() in content.lower():
                vectors.append(vector)
        
        return vectors

    def _assess_complexity(self, content: str) -> str:
        """Assess attack complexity"""
        if any(word in content.lower() for word in ["advanced", "sophisticated", "complex"]):
            return "high"
        elif any(word in content.lower() for word in ["basic", "simple"]):
            return "low"
        else:
            return "medium"

    def _map_technique_to_tactic(self, technique: str) -> str:
        """Map MITRE technique to tactic"""
        tactic_mapping = {
            "T1001": "Command and Control",
            "T1003": "Credential Access",
            "T1005": "Defense Evasion",
            "T1012": "Discovery",
            "T1018": "Discovery",
            "T1021": "Lateral Movement",
            "T1027": "Defense Evasion",
            "T1033": "Discovery",
            "T1047": "Execution",
            "T1053": "Execution",
            "T1055": "Defense Evasion",
            "T1059": "Execution",
            "T1069": "Discovery",
            "T1071": "Command and Control",
            "T1074": "Collection",
            "T1078": "Initial Access",
            "T1082": "Discovery",
            "T1083": "Discovery",
            "T1090": "Command and Control",
            "T1098": "Persistence"
        }
        
        return tactic_mapping.get(technique, "Unknown")

    async def _get_existing_diamond_profile(self, threat_actor: str) -> Optional[Dict[str, Any]]:
        """Get existing Diamond Model profile"""
        try:
            # This would typically query a database or storage
            # For now, return None to create new profile
            return None
        except Exception as e:
            logger.error(f"Failed to get existing profile: {e}")
            return None

    def _calculate_profile_delta(self, existing_profile: Dict[str, Any], new_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Calculate delta between existing and new profile"""
        delta_updates = []
        
        try:
            # Compare adversary information
            if new_analysis["adversary"] and existing_profile.get("adversary"):
                old_adv = existing_profile["adversary"]
                new_adv = new_analysis["adversary"]
                
                # Check for new aliases
                new_aliases = set(new_adv.get("aliases", [])) - set(old_adv.get("aliases", []))
                if new_aliases:
                    delta_updates.append({
                        "update_type": "new_component",
                        "component_type": "adversary",
                        "component_id": "aliases",
                        "old_value": list(old_adv.get("aliases", [])),
                        "new_value": list(new_adv.get("aliases", [])),
                        "confidence_change": 0.1
                    })
            
            # Compare infrastructure
            existing_infrastructure = {inf["value"]: inf for inf in existing_profile.get("infrastructure", [])}
            new_infrastructure = {inf["value"]: inf for inf in new_analysis.get("infrastructure", [])}
            
            for value, new_inf in new_infrastructure.items():
                if value not in existing_infrastructure:
                    delta_updates.append({
                        "update_type": "new_component",
                        "component_type": "infrastructure",
                        "component_id": new_inf["id"],
                        "old_value": None,
                        "new_value": new_inf,
                        "confidence_change": 0.05
                    })
            
            # Compare capabilities
            existing_capabilities = {cap["mitre_technique"]: cap for cap in existing_profile.get("capabilities", [])}
            new_capabilities = {cap["mitre_technique"]: cap for cap in new_analysis.get("capabilities", [])}
            
            for technique, new_cap in new_capabilities.items():
                if technique not in existing_capabilities:
                    delta_updates.append({
                        "update_type": "new_component",
                        "component_type": "capability",
                        "component_id": new_cap["id"],
                        "old_value": None,
                        "new_value": new_cap,
                        "confidence_change": 0.1
                    })
            
        except Exception as e:
            logger.error(f"Failed to calculate profile delta: {e}")
        
        return delta_updates

    def _merge_diamond_profiles(self, existing_profile: Dict[str, Any], new_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Merge new analysis into existing profile"""
        try:
            merged_profile = existing_profile.copy()
            
            # Merge adversary information
            if new_analysis["adversary"]:
                if "adversary" not in merged_profile:
                    merged_profile["adversary"] = new_analysis["adversary"]
                else:
                    # Merge aliases
                    existing_aliases = set(merged_profile["adversary"].get("aliases", []))
                    new_aliases = set(new_analysis["adversary"].get("aliases", []))
                    merged_profile["adversary"]["aliases"] = list(existing_aliases | new_aliases)
            
            # Merge infrastructure
            existing_infrastructure = {inf["value"]: inf for inf in merged_profile.get("infrastructure", [])}
            for new_inf in new_analysis.get("infrastructure", []):
                if new_inf["value"] not in existing_infrastructure:
                    merged_profile.setdefault("infrastructure", []).append(new_inf)
            
            # Merge capabilities
            existing_capabilities = {cap["mitre_technique"]: cap for cap in merged_profile.get("capabilities", [])}
            for new_cap in new_analysis.get("capabilities", []):
                if new_cap["mitre_technique"] not in existing_capabilities:
                    merged_profile.setdefault("capabilities", []).append(new_cap)
            
            # Update metadata
            merged_profile["updated_at"] = datetime.utcnow().isoformat()
            merged_profile["source_count"] = merged_profile.get("source_count", 0) + len(new_analysis.get("infrastructure", []))
            
            return merged_profile
            
        except Exception as e:
            logger.error(f"Failed to merge profiles: {e}")
            return existing_profile

    def _create_new_diamond_profile(self, threat_actor: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Create new Diamond Model profile"""
        try:
            profile = {
                "threat_actor_id": threat_actor.lower().replace(" ", "_"),
                "primary_name": threat_actor,
                "aliases": [],
                "adversary": analysis.get("adversary"),
                "infrastructure": analysis.get("infrastructure", []),
                "victims": analysis.get("victims", []),
                "capabilities": analysis.get("capabilities", []),
                "relationships": {},
                "attack_chains": [],
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat(),
                "confidence_score": 0.5,
                "source_count": len(analysis.get("infrastructure", [])),
                "last_analysis": datetime.utcnow().isoformat(),
                "analysis_delta": {},
                "intelligence_gaps": []
            }
            
            return profile
            
        except Exception as e:
            logger.error(f"Failed to create new profile: {e}")
            return {}

    async def _store_diamond_profile(self, profile: Dict[str, Any]):
        """Store Diamond Model profile in Azure AI Search"""
        try:
            threat_actor = profile.get('primary_name', 'Unknown')
            logger.info(f"Storing Diamond Model profile for {threat_actor}")
            
            # Create a comprehensive profile document for Azure Search
            profile_content = self._generate_diamond_profile_content(profile)
            
            # Create CTIDocument for Azure Search
            from models import CTIDocument, ConfidenceLevel, IOCType
            
            # Extract operations and geographic focus
            operations = []
            geo_focus = []
            
            # Extract from capabilities
            capabilities = profile.get('capabilities', [])
            for cap in capabilities:
                if cap.get('tactic'):
                    operations.append(cap['tactic'])
            
            # Extract from victims
            victims = profile.get('victims', [])
            for victim in victims:
                if victim.get('geography'):
                    geo_focus.extend(victim['geography'])
                if victim.get('sector'):
                    operations.append(victim['sector'])
            
            # Extract from adversary
            adversary = profile.get('adversary', {})
            if adversary.get('country_of_origin'):
                geo_focus.append(adversary['country_of_origin'])
            
            # Create unique document ID
            doc_id = f"DIAMOND_PROFILE_{threat_actor.replace(' ', '_').replace('-', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            
            # Create the document
            profile_doc = CTIDocument(
                doc_id=doc_id,
                title=f"Diamond Model Profile: {threat_actor}",
                content=profile_content,
                date_pub=datetime.utcnow(),
                source="diamond_model_analysis",
                threat_actor=threat_actor,
                operation=", ".join(list(set(operations))),
                mitre_id=self._extract_mitre_ids_from_profile(profile),
                ioc_type=IOCType.HASH,  # Default to hash for profile documents
                geo_scope=", ".join(list(set(geo_focus))),
                confidence=ConfidenceLevel.HIGH,
                language="en",
                content_vector=None  # Will be generated by Azure Search service
            )
            
            # Upload to Azure Search
            success = self.search_service.upload_documents([profile_doc])
            
            if success:
                logger.info(f"✅ Successfully stored Diamond Model profile for {threat_actor}")
                logger.info(f"  📊 Infrastructure: {len(profile.get('infrastructure', []))} items")
                logger.info(f"  ⚡ Capabilities: {len(profile.get('capabilities', []))} items")
                logger.info(f"  🎯 Victims: {len(profile.get('victims', []))} items")
                logger.info(f"  🎯 Adversary: {adversary.get('name', 'Unknown')}")
                return True
            else:
                logger.error(f"❌ Failed to store Diamond Model profile for {threat_actor}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to store Diamond Model profile: {e}")
            return False
    
    def _generate_diamond_profile_content(self, profile: Dict[str, Any]) -> str:
        """Generate comprehensive content for Diamond Model profile"""
        threat_actor = profile.get('primary_name', 'Unknown')
        
        # Adversary section
        adversary = profile.get('adversary', {})
        adversary_section = f"""
## Adversary Information
- **Name**: {adversary.get('name', 'Unknown')}
- **Aliases**: {', '.join(adversary.get('aliases', []))}
- **Motivation**: {adversary.get('motivation', 'Unknown')}
- **Country of Origin**: {adversary.get('country_of_origin', 'Unknown')}
- **Sophistication Level**: {adversary.get('sophistication_level', 'Unknown')}
"""
        
        # Infrastructure section
        infrastructure = profile.get('infrastructure', [])
        infrastructure_section = f"""
## Infrastructure
- **Total IOCs**: {len(infrastructure)} items
"""
        if infrastructure:
            by_type = {}
            for item in infrastructure:
                ioc_type = item.get('type', 'Unknown')
                if ioc_type not in by_type:
                    by_type[ioc_type] = []
                by_type[ioc_type].append(item.get('value', 'Unknown'))
            
            for ioc_type, values in by_type.items():
                infrastructure_section += f"- **{ioc_type}**: {len(values)} items\n"
        
        # Victims section
        victims = profile.get('victims', [])
        victims_section = f"""
## Victims
- **Total Victims**: {len(victims)} items
"""
        if victims:
            by_sector = {}
            by_geography = {}
            for victim in victims:
                sector = victim.get('sector', 'Unknown')
                geography = victim.get('geography', ['Unknown'])
                
                if sector not in by_sector:
                    by_sector[sector] = 0
                by_sector[sector] += 1
                
                for geo in geography:
                    if geo not in by_geography:
                        by_geography[geo] = 0
                    by_geography[geo] += 1
            
            victims_section += "- **By Sector**:\n"
            for sector, count in by_sector.items():
                victims_section += f"  - {sector}: {count} victims\n"
            
            victims_section += "- **By Geography**:\n"
            for geo, count in by_geography.items():
                victims_section += f"  - {geo}: {count} victims\n"
        
        # Capabilities section
        capabilities = profile.get('capabilities', [])
        capabilities_section = f"""
## Capabilities
- **Total Capabilities**: {len(capabilities)} items
"""
        if capabilities:
            by_tactic = {}
            tools = []
            malware = []
            
            for cap in capabilities:
                tactic = cap.get('tactic', 'Unknown')
                if tactic not in by_tactic:
                    by_tactic[tactic] = 0
                by_tactic[tactic] += 1
                
                if cap.get('tools'):
                    tools.extend(cap['tools'])
                if cap.get('malware'):
                    malware.extend(cap['malware'])
            
            capabilities_section += "- **By Tactic**:\n"
            for tactic, count in by_tactic.items():
                capabilities_section += f"  - {tactic}: {count} capabilities\n"
            
            if tools:
                capabilities_section += f"- **Tools Used**: {', '.join(list(set(tools)))}\n"
            if malware:
                capabilities_section += f"- **Malware Families**: {', '.join(list(set(malware)))}\n"
        
        # Metadata section
        metadata_section = f"""
## Profile Metadata
- **Created**: {profile.get('created_at', 'Unknown')}
- **Last Updated**: {profile.get('updated_at', 'Unknown')}
- **Confidence Score**: {profile.get('confidence_score', 0):.2f}
- **Source Count**: {profile.get('source_count', 0)} intelligence sources
- **Analysis Delta**: {len(profile.get('analysis_delta', {}))} changes tracked
"""
        
        # Combine all sections
        full_content = f"""# Diamond Model Profile: {threat_actor}

{adversary_section}

{infrastructure_section}

{victims_section}

{capabilities_section}

{metadata_section}

---
*This profile was generated using Diamond Model analysis and stored in the threat intelligence knowledge base.*
"""
        
        return full_content
    
    def _extract_mitre_ids_from_profile(self, profile: Dict[str, Any]) -> str:
        """Extract MITRE ATT&CK IDs from Diamond Model profile"""
        mitre_ids = set()
        
        # Extract from capabilities
        capabilities = profile.get('capabilities', [])
        for cap in capabilities:
            if cap.get('mitre_id'):
                mitre_ids.add(cap['mitre_id'])
        
        # Extract from infrastructure (if any have MITRE mappings)
        infrastructure = profile.get('infrastructure', [])
        for item in infrastructure:
            if item.get('mitre_id'):
                mitre_ids.add(item['mitre_id'])
        
        return ", ".join(sorted(mitre_ids)) if mitre_ids else "T1078"  # Default to T1078 if none found

    def _build_search_query(self, question: str, filters: Dict[str, Any]) -> str:
        """Build search query with filters"""
        query = question
        
        # Add time filter
        time_filter = filters.get("time_filter", "All Time")
        if time_filter != "All Time":
            query += f" {time_filter}"
        
        # Add source filter
        source_filter = filters.get("source_filter", [])
        if source_filter:
            sources_str = ", ".join(source_filter)
            query += f" sources: {sources_str}"
        
        # Add actor filter
        actor_filter = filters.get("actor_filter", [])
        if actor_filter:
            actors_str = ", ".join(actor_filter)
            query += f" threat actors: {actors_str}"
        
        return query
    
    async def _search_documents_qa(self, query: str, max_results: int, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search documents for Q&A with filters"""
        try:
            # Build Azure Search filter string
            filter_parts = []
            
            # Add time filter
            time_filter = filters.get("time_filter", "All Time")
            if time_filter != "All Time":
                # Convert time filter to date range
                from datetime import datetime, timedelta
                now = datetime.utcnow()
                
                if time_filter == "Last 30 Days":
                    start_date = (now - timedelta(days=30)).isoformat()
                elif time_filter == "Last 90 Days":
                    start_date = (now - timedelta(days=90)).isoformat()
                elif time_filter == "Last 6 Months":
                    start_date = (now - timedelta(days=180)).isoformat()
                elif time_filter == "Last Year":
                    start_date = (now - timedelta(days=365)).isoformat()
                else:
                    start_date = None
                
                if start_date:
                    filter_parts.append(f"date_pub ge '{start_date}'")
            
            # Add source filter
            source_filter = filters.get("source_filter", [])
            if source_filter:
                source_conditions = [f"source eq '{source}'" for source in source_filter]
                filter_parts.append(f"({' or '.join(source_conditions)})")
            
            # Add actor filter
            actor_filter = filters.get("actor_filter", [])
            if actor_filter:
                actor_conditions = [f"threat_actor eq '{actor}'" for actor in actor_filter]
                filter_parts.append(f"({' or '.join(actor_conditions)})")
            
            # Combine filters
            azure_filter = None
            if filter_parts:
                azure_filter = " and ".join(filter_parts)
                logger.info(f"Using Azure Search filter: {azure_filter}")
            
            # Search using Azure Search with correct parameters
            search_results = self.search_service.search_documents(
                query=query,
                top_k=max_results,
                filters=azure_filter
            )
            
            # Convert SearchResult objects to dictionaries for Q&A processing
            results = []
            for result in search_results:
                result_dict = {
                    "doc_id": result.doc_id,
                    "title": result.title,
                    "content": result.content,
                    "score": result.score,
                    "source": result.metadata.get("source", "Unknown"),
                    "date": result.metadata.get("date_pub", "Unknown"),
                    "threat_actor": result.metadata.get("threat_actor", "Unknown")
                }
                results.append(result_dict)
            
            logger.info(f"Q&A search returned {len(results)} results for query: {query}")
            return results
            
        except Exception as e:
            logger.error(f"Failed to search documents for Q&A: {e}")
            return []
    
    async def _generate_rag_answer(self, question: str, search_results: List[Dict[str, Any]], output_format: str) -> tuple[str, float]:
        """Generate answer using RAG with specified output format"""
        try:
            # Prepare context from search results
            context = self._prepare_context_from_results(search_results)
            
            # Build prompt based on output format
            prompt = self._build_qa_prompt(question, context, output_format)
            
            # Generate answer using RAG service
            answer = await self.rag_service.generate_answer(prompt, context)
            
            # Calculate confidence based on source relevance
            confidence = self._calculate_answer_confidence(search_results)
            
            return answer, confidence
            
        except Exception as e:
            logger.error(f"Failed to generate RAG answer: {e}")
            return "I encountered an error while generating the answer.", 0.0
    
    def _prepare_context_from_results(self, search_results: List[Dict[str, Any]]) -> str:
        """Prepare context from search results"""
        context_parts = []
        
        for i, result in enumerate(search_results, 1):
            content = result.get("content", "")
            title = result.get("title", f"Document {i}")
            source = result.get("source", "Unknown")
            date = result.get("date", "Unknown")
            
            context_part = f"Document {i} ({source}, {date}):\n{content}\n"
            context_parts.append(context_part)
        
        return "\n".join(context_parts)
    
    def _build_qa_prompt(self, question: str, context: str, output_format: str) -> str:
        """Build prompt for Q&A with specific output format"""
        base_prompt = f"""
You are a threat intelligence analyst. Answer the following question based on the provided context.

Question: {question}

Context:
{context}

Please provide a comprehensive answer with the following requirements:
1. Base your answer only on the provided context
2. If the context doesn't contain enough information, say so
3. Include specific details and examples from the context
4. Be clear and professional in your response
"""

        # Add format-specific instructions
        if output_format == "Markdown":
            base_prompt += "\nFormat your response in Markdown with proper headings, bullet points, and emphasis."
        elif output_format == "JSON":
            base_prompt += "\nFormat your response as a JSON object with 'answer' and 'key_points' fields."
        elif output_format == "Bullet Points":
            base_prompt += "\nFormat your response as bullet points with clear, concise statements."
        elif output_format == "Executive Summary":
            base_prompt += "\nFormat your response as an executive summary with key findings and implications."
        
        return base_prompt
    
    def _extract_citations(self, search_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract citations from search results"""
        citations = []
        
        for result in search_results:
            citation = {
                "title": result.get("title", "Untitled"),
                "source": result.get("source", "Unknown"),
                "date": result.get("date", "Unknown"),
                "relevance_score": result.get("score", 0.0),
                "excerpt": result.get("content", "")[:200] + "..." if len(result.get("content", "")) > 200 else result.get("content", "")
            }
            citations.append(citation)
        
        return citations
    
    def _calculate_answer_confidence(self, search_results: List[Dict[str, Any]]) -> float:
        """Calculate confidence based on search result relevance"""
        if not search_results:
            return 0.0
        
        # Calculate average relevance score
        scores = [result.get("score", 0.0) for result in search_results]
        avg_score = sum(scores) / len(scores)
        
        # Adjust confidence based on number of results and their quality
        num_results = len(search_results)
        if num_results >= 5:
            confidence_boost = 0.1
        elif num_results >= 3:
            confidence_boost = 0.05
        else:
            confidence_boost = 0.0
        
        confidence = min(avg_score + confidence_boost, 1.0)
        return confidence 

    async def _analyze_threat_actor_diamond(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat actor using Diamond Model framework"""
        self.log_action("starting_diamond_analysis", task)
        
        try:
            # Extract parameters
            threat_actor = task.get("threat_actor")
            time_window = task.get("time_window", "All Time")
            include_delta = task.get("include_delta", True)
            
            if not threat_actor:
                raise ValueError("Threat actor name is required for Diamond Model analysis")
            
            logger.info(f"Diamond Analysis - Threat Actor: {threat_actor}")
            logger.info(f"Diamond Analysis - Time Window: {time_window}")
            
            # Search for relevant documents
            search_results = await self._search_documents_by_actor(threat_actor, time_window)
            logger.info(f"Diamond Analysis - Found {len(search_results)} documents")
            
            if not search_results:
                return {
                    "threat_actor": threat_actor,
                    "diamond_model": None,
                    "delta_analysis": None,
                    "confidence": 0.0,
                    "message": f"No documents found for {threat_actor}",
                    "generated_at": datetime.utcnow().isoformat()
                }
            
            # Analyze Diamond Model components
            diamond_analysis = await self._analyze_diamond_model_components(search_results, threat_actor)
            
            # Get existing profile for delta analysis
            existing_profile = await self._get_existing_diamond_profile(threat_actor)
            delta_analysis = None
            
            if include_delta and existing_profile:
                delta_analysis = self._calculate_profile_delta(existing_profile, diamond_analysis)
                logger.info(f"Diamond Analysis - Found {len(delta_analysis)} delta updates")
            
            # Create or update profile
            if existing_profile:
                updated_profile = self._merge_diamond_profiles(existing_profile, diamond_analysis)
            else:
                updated_profile = self._create_new_diamond_profile(threat_actor, diamond_analysis)
            
            # Store updated profile
            await self._store_diamond_profile(updated_profile)
            
            # Format Diamond Model output
            diamond_output = self._format_diamond_model_output(updated_profile)
            
            result = {
                "threat_actor": threat_actor,
                "diamond_model": diamond_output,
                "delta_analysis": delta_analysis,
                "confidence": updated_profile.get("confidence_score", 0.0),
                "source_count": updated_profile.get("source_count", 0),
                "last_updated": updated_profile.get("updated_at"),
                "generated_at": datetime.utcnow().isoformat()
            }
            
            self.log_action("completed_diamond_analysis", result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to analyze threat actor with Diamond Model: {e}")
            raise

    async def _search_documents_by_actor(self, threat_actor: str, time_window: str) -> List[Dict[str, Any]]:
        """Search documents by threat actor with time filtering"""
        try:
            # Build search parameters
            search_params = {
                "query": threat_actor,
                "top_k": 20,
                "filters": f"threat_actor eq '{threat_actor}'"
            }
            
            # Add time filter if specified
            if time_window != "All Time":
                from datetime import datetime, timedelta
                now = datetime.utcnow()
                
                if time_window == "Last 30 Days":
                    start_date = (now - timedelta(days=30)).isoformat()
                elif time_window == "Last 90 Days":
                    start_date = (now - timedelta(days=90)).isoformat()
                elif time_window == "Last 6 Months":
                    start_date = (now - timedelta(days=180)).isoformat()
                elif time_window == "Last Year":
                    start_date = (now - timedelta(days=365)).isoformat()
                else:
                    start_date = None
                
                if start_date:
                    search_params["filters"] += f" and date_pub ge '{start_date}'"
            
            # Search using Azure Search
            search_results = self.search_service.search_documents(**search_params)
            
            # Convert to dictionary format
            results = []
            for result in search_results:
                result_dict = {
                    "doc_id": result.doc_id,
                    "title": result.title,
                    "content": result.content,
                    "score": result.score,
                    "source": result.metadata.get("source", "Unknown"),
                    "date": result.metadata.get("date_pub", "Unknown"),
                    "threat_actor": result.metadata.get("threat_actor", "Unknown")
                }
                results.append(result_dict)
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to search documents by actor: {e}")
            return []

    def _format_diamond_model_output(self, profile: Dict[str, Any]) -> Dict[str, Any]:
        """Format Diamond Model profile for output"""
        try:
            formatted = {
                "threat_actor_id": profile.get("threat_actor_id"),
                "primary_name": profile.get("primary_name"),
                "aliases": profile.get("aliases", []),
                
                # Adversary component
                "adversary": {
                    "name": profile.get("adversary", {}).get("name", ""),
                    "aliases": profile.get("adversary", {}).get("aliases", []),
                    "motivation": profile.get("adversary", {}).get("motivation", ""),
                    "capabilities": profile.get("adversary", {}).get("capabilities", []),
                    "country_of_origin": profile.get("adversary", {}).get("country_of_origin"),
                    "sophistication_level": profile.get("adversary", {}).get("sophistication_level", "medium"),
                    "threat_level": profile.get("adversary", {}).get("threat_level", "medium")
                },
                
                # Infrastructure components
                "infrastructure": {
                    "total_count": len(profile.get("infrastructure", [])),
                    "by_type": self._group_infrastructure_by_type(profile.get("infrastructure", [])),
                    "recent_additions": profile.get("infrastructure", [])[-5:] if profile.get("infrastructure") else []
                },
                
                # Victim components
                "victims": {
                    "total_count": len(profile.get("victims", [])),
                    "by_sector": self._group_victims_by_sector(profile.get("victims", [])),
                    "by_geography": self._group_victims_by_geography(profile.get("victims", []))
                },
                
                # Capability components
                "capabilities": {
                    "total_count": len(profile.get("capabilities", [])),
                    "by_mitre_tactic": self._group_capabilities_by_tactic(profile.get("capabilities", [])),
                    "tools_used": self._extract_all_tools(profile.get("capabilities", [])),
                    "malware_families": self._extract_all_malware(profile.get("capabilities", []))
                },
                
                # Metadata
                "metadata": {
                    "created_at": profile.get("created_at"),
                    "updated_at": profile.get("updated_at"),
                    "confidence_score": profile.get("confidence_score", 0.0),
                    "source_count": profile.get("source_count", 0),
                    "intelligence_gaps": profile.get("intelligence_gaps", [])
                }
            }
            
            return formatted
            
        except Exception as e:
            logger.error(f"Failed to format Diamond Model output: {e}")
            return {}

    def _group_infrastructure_by_type(self, infrastructure: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group infrastructure by IOC type"""
        grouped = {}
        for inf in infrastructure:
            ioc_type = inf.get("ioc_type", "unknown")
            if ioc_type not in grouped:
                grouped[ioc_type] = []
            grouped[ioc_type].append(inf)
        return grouped

    def _group_victims_by_sector(self, victims: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group victims by sector"""
        grouped = {}
        for victim in victims:
            sector = victim.get("sector", "unknown")
            if sector not in grouped:
                grouped[sector] = []
            grouped[sector].append(victim)
        return grouped

    def _group_victims_by_geography(self, victims: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group victims by geography"""
        grouped = {}
        for victim in victims:
            geography = victim.get("geography", "unknown")
            if geography not in grouped:
                grouped[geography] = []
            grouped[geography].append(victim)
        return grouped

    def _group_capabilities_by_tactic(self, capabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group capabilities by MITRE tactic"""
        grouped = {}
        for cap in capabilities:
            tactic = cap.get("mitre_tactic", "unknown")
            if tactic not in grouped:
                grouped[tactic] = []
            grouped[tactic].append(cap)
        return grouped

    def _extract_all_tools(self, capabilities: List[Dict[str, Any]]) -> List[str]:
        """Extract all tools from capabilities"""
        tools = set()
        for cap in capabilities:
            tools.update(cap.get("tools_used", []))
        return list(tools)

    def _extract_all_malware(self, capabilities: List[Dict[str, Any]]) -> List[str]:
        """Extract all malware families from capabilities"""
        malware = set()
        for cap in capabilities:
            malware.update(cap.get("malware_families", []))
        return list(malware)