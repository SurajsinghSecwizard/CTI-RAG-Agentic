"""
Data Source Manager - Handles CTI data source configuration and management

Responsibilities:
- Load data sources from TSV files
- Manage source configurations
- Provide source metadata
- Support dynamic source addition
"""

import csv
import logging
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import json

logger = logging.getLogger(__name__)

@dataclass
class DataSource:
    """Represents a CTI data source"""
    label: str
    feed_url: str
    source_type: str = "rss"
    enabled: bool = True
    max_posts: int = 50
    priority: int = 1
    last_updated: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

class DataSourceManager:
    """Manages CTI data sources from configuration files"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = config_dir
        self.sources: Dict[str, DataSource] = {}
        self.sources_file = os.path.join(config_dir, "data_sources.tsv")
        self.backup_file = os.path.join(config_dir, "AV_EDR_Vendors.tsv")
        
        # Load sources on initialization
        self.load_sources()
    
    def load_sources(self) -> None:
        """Load data sources from TSV file"""
        try:
            # Try to load from the main sources file first
            if os.path.exists(self.sources_file):
                self._load_from_tsv(self.sources_file)
            elif os.path.exists(self.backup_file):
                # Fallback to the AV_EDR_Vendors.tsv file
                self._load_from_tsv(self.backup_file)
                # Create the main sources file from the backup
                self._create_main_sources_file()
            else:
                logger.warning("No data sources file found. Creating default sources.")
                self._create_default_sources()
                
        except Exception as e:
            logger.error(f"Failed to load data sources: {e}")
            self._create_default_sources()
    
    def _load_from_tsv(self, file_path: str) -> None:
        """Load sources from TSV file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f, delimiter='\t')
                
                for row in reader:
                    label = row.get('Label', '').strip()
                    feed_url = row.get('Feed URL', '').strip()
                    
                    if label and feed_url:
                        # Determine source type based on URL
                        source_type = self._determine_source_type(feed_url)
                        
                        source = DataSource(
                            label=label,
                            feed_url=feed_url,
                            source_type=source_type,
                            enabled=True,
                            max_posts=50,
                            priority=1
                        )
                        
                        self.sources[label] = source
                        
            logger.info(f"Loaded {len(self.sources)} data sources from {file_path}")
            
        except Exception as e:
            logger.error(f"Failed to load sources from {file_path}: {e}")
            raise
    
    def _determine_source_type(self, url: str) -> str:
        """Determine the type of data source based on URL"""
        url_lower = url.lower()
        
        if 'feed' in url_lower or 'rss' in url_lower:
            return "rss"
        elif 'api' in url_lower:
            return "api"
        elif 'csv' in url_lower or 'download' in url_lower:
            return "csv"
        else:
            return "web"
    
    def _create_main_sources_file(self) -> None:
        """Create the main sources file from backup"""
        try:
            if not os.path.exists(self.config_dir):
                os.makedirs(self.config_dir)
            
            with open(self.sources_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, delimiter='\t')
                writer.writerow(['Label', 'Feed URL', 'Source Type', 'Enabled', 'Max Posts', 'Priority'])
                
                for source in self.sources.values():
                    writer.writerow([
                        source.label,
                        source.feed_url,
                        source.source_type,
                        source.enabled,
                        source.max_posts,
                        source.priority
                    ])
            
            logger.info(f"Created main sources file: {self.sources_file}")
            
        except Exception as e:
            logger.error(f"Failed to create main sources file: {e}")
    
    def _create_default_sources(self) -> None:
        """Create default data sources if no file exists"""
        default_sources = [
            DataSource("CrowdStrike", "https://www.crowdstrike.com/blog/feed/", "rss"),
            DataSource("Microsoft Defender", "https://www.microsoft.com/en-us/security/blog/feed/", "rss"),
            DataSource("Mandiant", "https://www.mandiant.com/resources/blog/feed", "rss"),
            DataSource("Abuse.ch", "https://urlhaus.abuse.ch/downloads/csv_recent/", "csv")
        ]
        
        for source in default_sources:
            self.sources[source.label] = source
        
        logger.info("Created default data sources")
    
    def get_sources(self, enabled_only: bool = True) -> List[DataSource]:
        """Get all data sources"""
        if enabled_only:
            return [source for source in self.sources.values() if source.enabled]
        return list(self.sources.values())
    
    def get_source(self, label: str) -> Optional[DataSource]:
        """Get a specific data source by label"""
        return self.sources.get(label)
    
    def add_source(self, source: DataSource) -> bool:
        """Add a new data source"""
        try:
            self.sources[source.label] = source
            self._save_sources()
            logger.info(f"Added new data source: {source.label}")
            return True
        except Exception as e:
            logger.error(f"Failed to add data source {source.label}: {e}")
            return False
    
    def update_source(self, label: str, **kwargs) -> bool:
        """Update an existing data source"""
        if label not in self.sources:
            logger.error(f"Source {label} not found")
            return False
        
        try:
            source = self.sources[label]
            for key, value in kwargs.items():
                if hasattr(source, key):
                    setattr(source, key, value)
            
            self._save_sources()
            logger.info(f"Updated data source: {label}")
            return True
        except Exception as e:
            logger.error(f"Failed to update data source {label}: {e}")
            return False
    
    def remove_source(self, label: str) -> bool:
        """Remove a data source"""
        try:
            if label in self.sources:
                del self.sources[label]
                self._save_sources()
                logger.info(f"Removed data source: {label}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove data source {label}: {e}")
            return False
    
    def enable_source(self, label: str) -> bool:
        """Enable a data source"""
        return self.update_source(label, enabled=True)
    
    def disable_source(self, label: str) -> bool:
        """Disable a data source"""
        return self.update_source(label, enabled=False)
    
    def get_source_stats(self) -> Dict[str, Any]:
        """Get statistics about data sources"""
        total_sources = len(self.sources)
        enabled_sources = len([s for s in self.sources.values() if s.enabled])
        
        source_types = {}
        for source in self.sources.values():
            source_type = source.source_type
            source_types[source_type] = source_types.get(source_type, 0) + 1
        
        return {
            "total_sources": total_sources,
            "enabled_sources": enabled_sources,
            "disabled_sources": total_sources - enabled_sources,
            "source_types": source_types,
            "last_updated": datetime.utcnow().isoformat()
        }
    
    def _save_sources(self) -> None:
        """Save sources to TSV file"""
        try:
            if not os.path.exists(self.config_dir):
                os.makedirs(self.config_dir)
            
            with open(self.sources_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, delimiter='\t')
                writer.writerow(['Label', 'Feed URL', 'Source Type', 'Enabled', 'Max Posts', 'Priority'])
                
                for source in self.sources.values():
                    writer.writerow([
                        source.label,
                        source.feed_url,
                        source.source_type,
                        source.enabled,
                        source.max_posts,
                        source.priority
                    ])
            
            logger.info(f"Saved {len(self.sources)} sources to {self.sources_file}")
            
        except Exception as e:
            logger.error(f"Failed to save sources: {e}")
    
    def export_sources(self, file_path: str) -> bool:
        """Export sources to a file"""
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, delimiter='\t')
                writer.writerow(['Label', 'Feed URL', 'Source Type', 'Enabled', 'Max Posts', 'Priority'])
                
                for source in self.sources.values():
                    writer.writerow([
                        source.label,
                        source.feed_url,
                        source.source_type,
                        source.enabled,
                        source.max_posts,
                        source.priority
                    ])
            
            logger.info(f"Exported sources to {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export sources: {e}")
            return False
    
    def import_sources(self, file_path: str) -> bool:
        """Import sources from a file"""
        try:
            self._load_from_tsv(file_path)
            self._save_sources()
            logger.info(f"Imported sources from {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import sources: {e}")
            return False 