import logging
import json
import re
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
import openai
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_core.documents import Document

import config
from models import ThreatQuery, ThreatBrief, SearchResult, IOCEnrichment, IOCType
from services.azure_search import AzureSearchService
from services.tools_router import ToolsRouter

logger = logging.getLogger(__name__)

class RAGService:
    """RAG service for threat intelligence analysis using Azure AI Search only"""
    
    def __init__(self):
        self.config_instance = config.Config()
        self.search_service = AzureSearchService()
        self.tools_router = ToolsRouter()
        
        # Initialize embeddings (for possible future use, not for local vector store)
        try:
            self.embeddings = OpenAIEmbeddings(
                openai_api_key=self.config_instance.OPENAI_API_KEY,
                openai_api_base=self.config_instance.OPENAI_API_BASE,
                model="text-embedding-ada-002"
            )
        except Exception as e:
            logger.warning(f"Failed to initialize OpenAI embeddings: {e}")
            self.embeddings = None
        
        # Text splitter for chunking
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=self.config_instance.CHUNK_SIZE,
            chunk_overlap=self.config_instance.CHUNK_OVERLAP,
            length_function=len,
        )

    def generate_threat_brief(self, query: ThreatQuery) -> ThreatBrief:
        """Generate a comprehensive threat intelligence brief"""
        try:
            # Step 1: Retrieve relevant documents
            search_results = self._retrieve_documents(query)
            if not search_results:
                return self._generate_empty_brief(query)
            # Step 2: Extract and enrich IOCs
            iocs = self._extract_and_enrich_iocs(search_results)
            # Step 3: Generate brief using GPT-4o
            brief = self._generate_brief_with_gpt(query, search_results, iocs)
            return brief
        except Exception as e:
            logger.error(f"Failed to generate threat brief: {e}")
            return self._generate_error_brief(query, str(e))

    def _retrieve_documents(self, query: ThreatQuery) -> List[SearchResult]:
        """Retrieve relevant documents using Azure AI Search only"""
        try:
            if self.search_service is None:
                logger.error("Azure Search service is not available. Check your configuration.")
                return []
            return self._retrieve_from_azure_search(query)
        except Exception as e:
            logger.error(f"Document retrieval failed: {e}")
            return []

    def _retrieve_from_azure_search(self, query: ThreatQuery) -> List[SearchResult]:
        """Retrieve documents from Azure AI Search"""
        try:
            # Build search query
            search_terms = []
            if query.focus_actor:
                search_terms.append(query.focus_actor)
            for need in query.need:
                if "TTP" in need or "tactic" in need:
                    search_terms.append("MITRE ATT&CK")
                if "IOC" in need or "indicator" in need:
                    search_terms.append("indicator compromise")
                if "campaign" in need:
                    search_terms.append("campaign operation")
            search_query = " ".join(search_terms)
            filters = None
            if query.time_window:
                start_date, end_date = query.time_window.split("/")
                # Convert to ISO 8601 datetime strings for Azure Search
                if len(start_date) == 10:
                    start_date_iso = f"{start_date}T00:00:00Z"
                else:
                    start_date_iso = start_date
                if len(end_date) == 10:
                    end_date_iso = f"{end_date}T23:59:59Z"
                else:
                    end_date_iso = end_date
                # Use simple string comparison for date filtering (date_pub is now String type)
                filters = (
                    f"date_pub ge '{start_date_iso}' and date_pub le '{end_date_iso}'"
                )
            
            # Search with semantic ranking
            results = self.search_service.search(
                query=search_query,
                top_k=self.config_instance.TOP_K_RETRIEVAL,
                filters=filters,
                semantic_ranking=True
            )
            
            return results
        except Exception as e:
            logger.error(f"Azure Search retrieval failed: {e}")
            return []

    def _extract_and_enrich_iocs(self, search_results: List[SearchResult]) -> List[Dict[str, Any]]:
        """Extract and enrich IOCs from search results"""
        iocs = []
        
        for result in search_results:
            # Extract IOCs from content
            content = result.content.lower()
            
            # IP addresses
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, content)
            for ip in ips:
                if self._validate_ioc(IOCType.IP, ip):
                    iocs.append({
                        "type": "ip",
                        "value": ip,
                        "source": result.title,
                        "confidence": 0.8
                    })
            
            # Domains
            domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            domains = re.findall(domain_pattern, content)
            for domain in domains:
                if self._validate_ioc(IOCType.DOMAIN, domain):
                    iocs.append({
                        "type": "domain",
                        "value": domain,
                        "source": result.title,
                        "confidence": 0.7
                    })
            
            # File hashes (MD5, SHA1, SHA256)
            hash_patterns = [
                r'\b[a-fA-F0-9]{32}\b',  # MD5
                r'\b[a-fA-F0-9]{40}\b',  # SHA1
                r'\b[a-fA-F0-9]{64}\b'   # SHA256
            ]
            for pattern in hash_patterns:
                hashes = re.findall(pattern, content)
                for hash_val in hashes:
                    if self._validate_ioc(IOCType.HASH, hash_val):
                        iocs.append({
                            "type": "hash",
                            "value": hash_val,
                            "source": result.title,
                            "confidence": 0.9
                        })
        
        # Enrich IOCs with external data
        enriched_iocs = []
        for ioc in iocs:
            enriched_ioc = self._enrich_ioc(ioc)
            enriched_iocs.append(enriched_ioc)
        
        # Deduplicate
        return self._deduplicate_iocs(enriched_iocs)

    def _validate_ioc(self, ioc_type: IOCType, value: str) -> bool:
        """Validate IOC format"""
        if ioc_type == IOCType.IP:
            # Basic IP validation
            parts = value.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        elif ioc_type == IOCType.DOMAIN:
            # Basic domain validation
            return '.' in value and len(value) > 3
        elif ioc_type == IOCType.HASH:
            # Hash validation
            return len(value) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in value)
        return False

    def _enrich_ioc(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich IOC with external threat intelligence"""
        try:
            if ioc["type"] == "hash":
                # Query VirusTotal for hash information
                vt_result = self.tools_router.query_virustotal(ioc["value"])
                if vt_result:
                    ioc["virustotal"] = vt_result
            elif ioc["type"] == "domain":
                # Query Abuse.ch for domain information
                abuse_result = self.tools_router.query_abuse_ch(ioc["value"])
                if abuse_result:
                    ioc["abuse_ch"] = abuse_result
        except Exception as e:
            logger.warning(f"Failed to enrich IOC {ioc['value']}: {e}")
        
        return ioc

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

    def _generate_brief_with_gpt(self, query: ThreatQuery, search_results: List[SearchResult], iocs: List[Dict[str, Any]]) -> ThreatBrief:
        """Generate threat brief using GPT-4o"""
        try:
            # Prepare context
            context = self._prepare_context(search_results, iocs)
            
            # Create prompt
            prompt = f"""
            Generate a comprehensive threat intelligence brief based on the following query and retrieved information.
            
            Query: {query.query}
            Focus Actor: {query.focus_actor or 'Not specified'}
            Time Window: {query.time_window or 'Not specified'}
            Specific Needs: {', '.join(query.need) if query.need else 'Not specified'}
            
            Retrieved Information:
            {context}
            
            Please provide:
            1. Executive Summary (2-3 sentences)
            2. Key Findings (bullet points)
            3. Threat Actor Analysis (if applicable)
            4. TTPs Identified (if applicable)
            5. IOCs and Indicators (with confidence levels)
            6. Recommendations
            7. Risk Assessment
            
            Format the response as a structured threat intelligence brief.
            """
            
            # Initialize OpenAI client
            client = openai.AzureOpenAI(
                api_key=self.config_instance.AZURE_OPENAI_API_KEY,
                azure_endpoint=self.config_instance.AZURE_OPENAI_ENDPOINT,
                api_version=self.config_instance.AZURE_OPENAI_API_VERSION
            )
            
            # Generate response
            response = client.chat.completions.create(
                model=self.config_instance.AZURE_OPENAI_DEPLOYMENT_NAME,
                messages=[
                    {"role": "system", "content": "You are a senior threat intelligence analyst. Provide comprehensive, accurate, and actionable threat intelligence briefs."},
                    {"role": "user", "content": prompt}
                ],
                temperature=self.config_instance.TEMPERATURE,
                max_tokens=self.config_instance.MAX_TOKENS
            )
            
            brief_content = response.choices[0].message.content
            
            # Parse the brief content
            return ThreatBrief(
                query_id=query.query_id,
                query=query.query,
                content=brief_content,
                search_results=search_results,
                iocs=iocs,
                generated_at=datetime.now().isoformat(),
                confidence=0.8
            )
            
        except Exception as e:
            logger.error(f"Failed to generate brief with GPT: {e}")
            return self._generate_error_brief(query, f"GPT generation failed: {str(e)}")

    def _prepare_context(self, search_results: List[SearchResult], iocs: List[Dict[str, Any]]) -> str:
        """Prepare context from search results and IOCs"""
        context_parts = []
        
        # Add search results
        for i, result in enumerate(search_results[:5], 1):  # Limit to top 5 results
            context_parts.append(f"Document {i}: {result.title}")
            context_parts.append(f"Content: {result.content[:500]}...")  # Truncate long content
            context_parts.append("")
        
        # Add IOCs
        if iocs:
            context_parts.append("Indicators of Compromise (IOCs):")
            for ioc in iocs:
                context_parts.append(f"- {ioc['type'].upper()}: {ioc['value']} (Confidence: {ioc['confidence']})")
                if 'virustotal' in ioc:
                    vt = ioc['virustotal']
                    context_parts.append(f"  VirusTotal: {vt['positives']}/{vt['total']} detections")
                if 'abuse_ch' in ioc:
                    context_parts.append(f"  Abuse.ch: {ioc['abuse_ch']['malicious']}")
            context_parts.append("")
        
        return "\n".join(context_parts)

    def _generate_empty_brief(self, query: ThreatQuery) -> ThreatBrief:
        """Generate empty brief when no results found"""
        return ThreatBrief(
            query_id=query.query_id,
            query=query.query,
            content="No relevant threat intelligence information found for the given query. Please try different search terms or expand your search criteria.",
            search_results=[],
            iocs=[],
            generated_at=datetime.now().isoformat(),
            confidence=0.0
        )

    def _generate_error_brief(self, query: ThreatQuery, error: str) -> ThreatBrief:
        """Generate error brief"""
        return ThreatBrief(
            query_id=query.query_id,
            query=query.query,
            content=f"Error generating threat brief: {error}. Please check your configuration and try again.",
            search_results=[],
            iocs=[],
            generated_at=datetime.now().isoformat(),
            confidence=0.0
        )

    async def generate_answer(self, prompt: str, context: str) -> str:
        """Generate answer using GPT-4o"""
        try:
            client = openai.AzureOpenAI(
                api_key=self.config_instance.AZURE_OPENAI_API_KEY,
                azure_endpoint=self.config_instance.AZURE_OPENAI_ENDPOINT,
                api_version=self.config_instance.AZURE_OPENAI_API_VERSION
            )
            
            response = client.chat.completions.create(
                model=self.config_instance.AZURE_OPENAI_DEPLOYMENT_NAME,
                messages=[
                    {"role": "system", "content": "You are a helpful threat intelligence assistant. Answer questions based on the provided context."},
                    {"role": "user", "content": f"Context: {context}\n\nQuestion: {prompt}"}
                ],
                temperature=0.1,
                max_tokens=1000
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"Failed to generate answer: {e}")
            return f"Error generating answer: {str(e)}" 