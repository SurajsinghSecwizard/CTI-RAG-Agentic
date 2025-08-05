import logging
import requests
import feedparser
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
import hashlib
import re
from urllib.parse import urlparse
import json

from models import CTIDocument, IOCType, ConfidenceLevel
import config
from .data_source_manager import DataSourceManager, DataSource

logger = logging.getLogger(__name__)

class DocumentIngestionService:
    """Service for ingesting CTI documents from various sources"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CTI-RAG-Agent/1.0 (Threat Intelligence Bot)'
        })
        self.data_source_manager = DataSourceManager()
    
    def scrape_rss_feed(self, source: DataSource) -> List[CTIDocument]:
        """Scrape RSS feed from a data source"""
        try:
            feed = feedparser.parse(source.feed_url)
            
            documents = []
            for entry in feed.entries[:source.max_posts]:
                try:
                    # Extract content
                    content = self._extract_blog_content(entry.link)
                    if not content:
                        continue
                    
                    # Extract threat actor from title/content
                    threat_actor = self._extract_threat_actor(entry.title, content)
                    
                    # Generate document ID
                    doc_id = f"{source.label[:2].upper()}_{datetime.now().strftime('%Y_%m_%d')}_{hashlib.md5(entry.link.encode()).hexdigest()[:8]}"
                    
                    # Handle missing published_parsed
                    if entry.published_parsed:
                        date_pub = datetime(*entry.published_parsed[:6])
                    else:
                        date_pub = datetime.now()
                    
                    doc = CTIDocument(
                        doc_id=doc_id,
                        title=entry.title,
                        content=content,
                        date_pub=date_pub,
                        source=source.label,
                        threat_actor=threat_actor,
                        confidence=ConfidenceLevel.HIGH,
                        language="en"
                    )
                    documents.append(doc)
                    
                except Exception as e:
                    logger.error(f"Failed to process {source.label} entry: {e}")
                    continue
            
            logger.info(f"Successfully scraped {len(documents)} {source.label} documents")
            return documents
            
        except Exception as e:
            logger.error(f"Failed to scrape {source.label} blog: {e}")
            return []
    
    def scrape_crowdstrike_blog(self, max_posts: int = 50) -> List[CTIDocument]:
        """Scrape CrowdStrike blog posts"""
        source = self.data_source_manager.get_source("CrowdStrike")
        if source:
            source.max_posts = max_posts
            return self.scrape_rss_feed(source)
        else:
            # Fallback to hardcoded method
            return self._scrape_crowdstrike_legacy(max_posts)
    
    def _scrape_crowdstrike_legacy(self, max_posts: int = 50) -> List[CTIDocument]:
        """Legacy CrowdStrike scraping method"""
        try:
            url = "https://www.crowdstrike.com/blog/feed/"
            feed = feedparser.parse(url)
            
            documents = []
            for entry in feed.entries[:max_posts]:
                try:
                    # Extract content
                    content = self._extract_blog_content(entry.link)
                    if not content:
                        continue
                    
                    # Extract threat actor from title/content
                    threat_actor = self._extract_threat_actor(entry.title, content)
                    
                    # Generate document ID
                    doc_id = f"CS_{datetime.now().strftime('%Y_%m_%d')}_{hashlib.md5(entry.link.encode()).hexdigest()[:8]}"
                    
                    # Handle missing published_parsed
                    if entry.published_parsed:
                        date_pub = datetime(*entry.published_parsed[:6])
                    else:
                        date_pub = datetime.now()
                    
                    doc = CTIDocument(
                        doc_id=doc_id,
                        title=entry.title,
                        content=content,
                        date_pub=date_pub,
                        source="CrowdStrike",
                        threat_actor=threat_actor,
                        confidence=ConfidenceLevel.HIGH,
                        language="en"
                    )
                    documents.append(doc)
                    
                except Exception as e:
                    logger.error(f"Failed to process CrowdStrike entry: {e}")
                    continue
            
            logger.info(f"Successfully scraped {len(documents)} CrowdStrike documents")
            return documents
            
        except Exception as e:
            logger.error(f"Failed to scrape CrowdStrike blog: {e}")
            return []
    
    def scrape_mandiant_blog(self, max_posts: int = 50) -> List[CTIDocument]:
        """Scrape Mandiant blog posts"""
        source = self.data_source_manager.get_source("Mandiant")
        if source:
            source.max_posts = max_posts
            return self.scrape_rss_feed(source)
        else:
            # Fallback to hardcoded method
            return self._scrape_mandiant_legacy(max_posts)
    
    def _scrape_mandiant_legacy(self, max_posts: int = 50) -> List[CTIDocument]:
        """Legacy Mandiant scraping method"""
        try:
            url = "https://www.mandiant.com/resources/blog/feed"
            feed = feedparser.parse(url)
            
            documents = []
            for entry in feed.entries[:max_posts]:
                try:
                    # Extract content
                    content = self._extract_blog_content(entry.link)
                    if not content:
                        continue
                    
                    # Extract threat actor
                    threat_actor = self._extract_threat_actor(entry.title, content)
                    
                    # Generate document ID
                    doc_id = f"MD_{datetime.now().strftime('%Y_%m_%d')}_{hashlib.md5(entry.link.encode()).hexdigest()[:8]}"
                    
                    # Handle missing published_parsed
                    if entry.published_parsed:
                        date_pub = datetime(*entry.published_parsed[:6])
                    else:
                        date_pub = datetime.now()
                    
                    doc = CTIDocument(
                        doc_id=doc_id,
                        title=entry.title,
                        content=content,
                        date_pub=date_pub,
                        source="Mandiant",
                        threat_actor=threat_actor,
                        confidence=ConfidenceLevel.HIGH,
                        language="en"
                    )
                    documents.append(doc)
                    
                except Exception as e:
                    logger.error(f"Failed to process Mandiant entry: {e}")
                    continue
            
            logger.info(f"Successfully scraped {len(documents)} Mandiant documents")
            return documents
            
        except Exception as e:
            logger.error(f"Failed to scrape Mandiant blog: {e}")
            return []
    
    def scrape_microsoft_security(self, max_posts: int = 50) -> List[CTIDocument]:
        """Scrape Microsoft Security blog posts"""
        source = self.data_source_manager.get_source("Microsoft Defender")
        if source:
            source.max_posts = max_posts
            return self.scrape_rss_feed(source)
        else:
            # Fallback to hardcoded method
            return self._scrape_microsoft_legacy(max_posts)
    
    def _scrape_microsoft_legacy(self, max_posts: int = 50) -> List[CTIDocument]:
        """Legacy Microsoft Security scraping method"""
        try:
            url = "https://www.microsoft.com/en-us/security/blog/feed/"
            feed = feedparser.parse(url)
            
            documents = []
            for entry in feed.entries[:max_posts]:
                try:
                    # Extract content
                    content = self._extract_blog_content(entry.link)
                    if not content:
                        continue
                    
                    # Extract threat actor
                    threat_actor = self._extract_threat_actor(entry.title, content)
                    
                    # Generate document ID
                    doc_id = f"MS_{datetime.now().strftime('%Y_%m_%d')}_{hashlib.md5(entry.link.encode()).hexdigest()[:8]}"
                    
                    # Handle missing published_parsed
                    if entry.published_parsed:
                        date_pub = datetime(*entry.published_parsed[:6])
                    else:
                        date_pub = datetime.now()
                    
                    doc = CTIDocument(
                        doc_id=doc_id,
                        title=entry.title,
                        content=content,
                        date_pub=date_pub,
                        source="Microsoft Security",
                        threat_actor=threat_actor,
                        confidence=ConfidenceLevel.HIGH,
                        language="en"
                    )
                    documents.append(doc)
                    
                except Exception as e:
                    logger.error(f"Failed to process Microsoft entry: {e}")
                    continue
            
            logger.info(f"Successfully scraped {len(documents)} Microsoft Security documents")
            return documents
            
        except Exception as e:
            logger.error(f"Failed to scrape Microsoft Security blog: {e}")
            return []
    
    def scrape_sophos_blog(self, max_posts: int = 50) -> List[CTIDocument]:
        """Scrape Sophos blog posts"""
        source = self.data_source_manager.get_source("Sophos")
        if source:
            source.max_posts = max_posts
            return self.scrape_rss_feed(source)
        return []
    
    def scrape_trend_micro_blog(self, max_posts: int = 50) -> List[CTIDocument]:
        """Scrape Trend Micro blog posts"""
        source = self.data_source_manager.get_source("Trend Micro")
        if source:
            source.max_posts = max_posts
            return self.scrape_rss_feed(source)
        return []
    
    def scrape_bitdefender_blog(self, max_posts: int = 50) -> List[CTIDocument]:
        """Scrape Bitdefender blog posts"""
        source = self.data_source_manager.get_source("Bitdefender")
        if source:
            source.max_posts = max_posts
            return self.scrape_rss_feed(source)
        return []
    
    def scrape_trellix_blog(self, max_posts: int = 50) -> List[CTIDocument]:
        """Scrape Trellix (McAfee) blog posts"""
        source = self.data_source_manager.get_source("Trellix (McAfee)")
        if source:
            source.max_posts = max_posts
            return self.scrape_rss_feed(source)
        return []
    
    def scrape_kaspersky_blog(self, max_posts: int = 50) -> List[CTIDocument]:
        """Scrape Kaspersky blog posts"""
        source = self.data_source_manager.get_source("Kaspersky")
        if source:
            source.max_posts = max_posts
            return self.scrape_rss_feed(source)
        return []
    
    def scrape_symantec_blog(self, max_posts: int = 50) -> List[CTIDocument]:
        """Scrape Symantec blog posts"""
        source = self.data_source_manager.get_source("Symantec (Broadcom)")
        if source:
            source.max_posts = max_posts
            return self.scrape_rss_feed(source)
        return []
    
    def scrape_eset_blog(self, max_posts: int = 50) -> List[CTIDocument]:
        """Scrape ESET blog posts"""
        source = self.data_source_manager.get_source("ESET")
        if source:
            source.max_posts = max_posts
            return self.scrape_rss_feed(source)
        return []
    
    def scrape_sentinelone_blog(self, max_posts: int = 50) -> List[CTIDocument]:
        """Scrape SentinelOne blog posts"""
        source = self.data_source_manager.get_source("SentinelOne")
        if source:
            source.max_posts = max_posts
            return self.scrape_rss_feed(source)
        return []
    
    def scrape_abuse_ch_iocs(self) -> List[CTIDocument]:
        """Scrape Abuse.ch IOC feeds"""
        try:
            # Abuse.ch URLhaus feed
            urlhaus_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
            
            response = self.session.get(urlhaus_url)
            if response.status_code != 200:
                logger.error(f"Failed to fetch Abuse.ch data: {response.status_code}")
                return []
            
            # Parse CSV content
            lines = response.text.split('\n')
            documents = []
            
            for line in lines[1:]:  # Skip header
                if not line.strip():
                    continue
                
                try:
                    parts = line.split(',')
                    if len(parts) >= 4:
                        url = parts[2].strip('"')
                        malware = parts[3].strip('"')
                        date_added = parts[4].strip('"')
                        
                        # Generate document ID
                        doc_id = f"AB_{datetime.now().strftime('%Y_%m_%d')}_{hashlib.md5(url.encode()).hexdigest()[:8]}"
                        
                        content = f"Malicious URL: {url}\nMalware: {malware}\nDate Added: {date_added}"
                        
                        doc = CTIDocument(
                            doc_id=doc_id,
                            title=f"Abuse.ch IOC - {malware}",
                            content=content,
                            date_pub=datetime.strptime(date_added, "%Y-%m-%d %H:%M:%S UTC"),
                            source="Abuse.ch",
                            ioc_type=IOCType.URL,
                            confidence=ConfidenceLevel.MEDIUM,
                            language="en"
                        )
                        documents.append(doc)
                        
                except Exception as e:
                    logger.error(f"Failed to process Abuse.ch line: {e}")
                    continue
            
            logger.info(f"Successfully scraped {len(documents)} Abuse.ch IOCs")
            return documents
            
        except Exception as e:
            logger.error(f"Failed to scrape Abuse.ch: {e}")
            return []
    
    def _extract_blog_content(self, url: str) -> Optional[str]:
        """Extract main content from blog post URL"""
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code != 200:
                return None
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()
            
            # Try to find main content area
            content_selectors = [
                'article',
                '.post-content',
                '.entry-content',
                '.blog-post-content',
                'main',
                '.content'
            ]
            
            content = None
            for selector in content_selectors:
                content_elem = soup.select_one(selector)
                if content_elem:
                    content = content_elem.get_text(separator=' ', strip=True)
                    break
            
            if not content:
                # Fallback to body text
                content = soup.get_text(separator=' ', strip=True)
            
            # Clean up content
            content = re.sub(r'\s+', ' ', content)
            content = content[:10000]  # Limit length
            
            return content if len(content) > 100 else None
            
        except Exception as e:
            logger.error(f"Failed to extract content from {url}: {e}")
            return None
    
    def _extract_threat_actor(self, title: str, content: str) -> Optional[str]:
        """Extract threat actor from title and content"""
        # Common threat actor patterns
        actor_patterns = [
            r'\b(APT\d+)\b',
            r'\b(FIN\d+)\b',
            r'\b(Lazarus)\b',
            r'\b(Volt Typhoon)\b',
            r'\b(Carbanak)\b',
            r'\b(Emotet)\b',
            r'\b(TrickBot)\b',
            r'\b(Ryuk)\b',
            r'\b(REvil)\b',
            r'\b(Conti)\b'
        ]
        
        # Search in title first, then content
        text_to_search = f"{title} {content}"
        
        for pattern in actor_patterns:
            match = re.search(pattern, text_to_search, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def ingest_all_sources(self) -> List[CTIDocument]:
        """Ingest documents from all configured sources"""
        all_documents = []
        
        # Get all enabled sources from the data source manager
        sources = self.data_source_manager.get_sources(enabled_only=True)
        
        for source in sources:
            try:
                if source.source_type == "rss":
                    documents = self.scrape_rss_feed(source)
                    all_documents.extend(documents)
                    logger.info(f"Ingested {len(documents)} documents from {source.label}")
                elif source.source_type == "csv":
                    # Handle CSV sources like Abuse.ch
                    if source.label == "Abuse.ch":
                        documents = self.scrape_abuse_ch_iocs()
                        all_documents.extend(documents)
                        logger.info(f"Ingested {len(documents)} documents from {source.label}")
                else:
                    logger.warning(f"Unsupported source type for {source.label}: {source.source_type}")
                    
            except Exception as e:
                logger.error(f"Failed to ingest from {source.label}: {e}")
                continue
        
        logger.info(f"Total documents ingested: {len(all_documents)}")
        return all_documents
    
    def ingest_specific_source(self, source_label: str) -> List[CTIDocument]:
        """Ingest documents from a specific source"""
        source = self.data_source_manager.get_source(source_label)
        if not source:
            logger.error(f"Source {source_label} not found")
            return []
        
        if not source.enabled:
            logger.warning(f"Source {source_label} is disabled")
            return []
        
        try:
            if source.source_type == "rss":
                documents = self.scrape_rss_feed(source)
                logger.info(f"Ingested {len(documents)} documents from {source.label}")
                return documents
            elif source.source_type == "csv":
                if source.label == "Abuse.ch":
                    documents = self.scrape_abuse_ch_iocs()
                    logger.info(f"Ingested {len(documents)} documents from {source.label}")
                    return documents
            else:
                logger.warning(f"Unsupported source type for {source.label}: {source.source_type}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to ingest from {source.label}: {e}")
            return []
    
    def get_available_sources(self) -> List[Dict[str, Any]]:
        """Get list of available data sources"""
        sources = self.data_source_manager.get_sources(enabled_only=False)
        return [
            {
                "label": source.label,
                "feed_url": source.feed_url,
                "source_type": source.source_type,
                "enabled": source.enabled,
                "max_posts": source.max_posts,
                "priority": source.priority
            }
            for source in sources
        ] 