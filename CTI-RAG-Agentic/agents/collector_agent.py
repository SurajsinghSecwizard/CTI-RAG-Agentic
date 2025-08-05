"""
Collector Agent - Handles threat intelligence ingestion and processing

Responsibilities:
- Fetch documents from various CTI sources
- Process and normalize documents
- Generate embeddings
- Upload to Azure Search
- Handle duplicates and updates
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json

from .base_agent import BaseAgent
from services.document_ingestion import DocumentIngestionService
from services.azure_search import AzureSearchService
from services.data_source_manager import DataSourceManager, DataSource
from models import CTIDocument

logger = logging.getLogger(__name__)

class CollectorAgent(BaseAgent):
    """Agent responsible for collecting and ingesting threat intelligence"""
    
    def __init__(self, config):
        super().__init__("Collector", config)
        self.ingestion_service = DocumentIngestionService()
        self.search_service = AzureSearchService()
        self.data_source_manager = DataSourceManager()
        
        # Get sources from data source manager
        self.sources = [source.label for source in self.data_source_manager.get_sources(enabled_only=True)]
        
    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute collection task"""
        try:
            task_type = task.get("type", "full_ingestion")
            
            if task_type == "full_ingestion":
                return await self._full_ingestion(task)
            elif task_type == "incremental_ingestion":
                return await self._incremental_ingestion(task)
            elif task_type == "source_ingestion":
                return await self._source_ingestion(task)
            elif task_type == "add_source":
                return await self._add_source(task)
            elif task_type == "update_source":
                return await self._update_source(task)
            elif task_type == "remove_source":
                return await self._remove_source(task)
            else:
                raise ValueError(f"Unknown task type: {task_type}")
                
        except Exception as e:
            logger.error(f"Collector agent execution failed: {e}")
            self.log_action("execution_failed", {"error": str(e)})
            raise
    
    async def _full_ingestion(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Perform full ingestion from all sources"""
        self.log_action("starting_full_ingestion", task)
        
        results = {
            "total_documents": 0,
            "sources_processed": [],
            "errors": [],
            "start_time": datetime.utcnow().isoformat()
        }
        
        # Get all enabled sources
        sources = self.data_source_manager.get_sources(enabled_only=True)
        
        for source in sources:
            try:
                source_result = await self._ingest_source(source.label, task)
                results["sources_processed"].append(source_result)
                results["total_documents"] += source_result.get("documents_ingested", 0)
                
            except Exception as e:
                error_msg = f"Failed to ingest {source.label}: {e}"
                logger.error(error_msg)
                results["errors"].append(error_msg)
        
        results["end_time"] = datetime.utcnow().isoformat()
        self.log_action("completed_full_ingestion", results)
        
        return results
    
    async def _incremental_ingestion(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Perform incremental ingestion (last 24 hours)"""
        self.log_action("starting_incremental_ingestion", task)
        
        # Set time window for incremental ingestion
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)
        
        task["time_window"] = {
            "start": start_time.isoformat(),
            "end": end_time.isoformat()
        }
        
        return await self._full_ingestion(task)
    
    async def _source_ingestion(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest from a specific source"""
        source_label = task.get("source")
        if not source_label:
            raise ValueError("Source must be specified for source_ingestion")
        
        self.log_action("starting_source_ingestion", {"source": source_label})
        
        try:
            result = await self._ingest_source(source_label, task)
            self.log_action("completed_source_ingestion", result)
            return result
            
        except Exception as e:
            logger.error(f"Source ingestion failed for {source_label}: {e}")
            self.log_action("source_ingestion_failed", {"source": source_label, "error": str(e)})
            raise
    
    async def _add_source(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Add a new data source"""
        try:
            source_data = task.get("source_data", {})
            source = DataSource(
                label=source_data["label"],
                feed_url=source_data["feed_url"],
                source_type=source_data.get("source_type", "rss"),
                enabled=source_data.get("enabled", True),
                max_posts=source_data.get("max_posts", 50),
                priority=source_data.get("priority", 1)
            )
            
            success = self.data_source_manager.add_source(source)
            
            result = {
                "action": "add_source",
                "source_label": source.label,
                "success": success,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            if success:
                self.log_action("source_added", result)
                # Update sources list
                self.sources = [s.label for s in self.data_source_manager.get_sources(enabled_only=True)]
            else:
                self.log_action("source_add_failed", result)
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to add source: {e}")
            return {
                "action": "add_source",
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def _update_source(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing data source"""
        try:
            source_label = task.get("source_label")
            updates = task.get("updates", {})
            
            success = self.data_source_manager.update_source(source_label, **updates)
            
            result = {
                "action": "update_source",
                "source_label": source_label,
                "updates": updates,
                "success": success,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            if success:
                self.log_action("source_updated", result)
            else:
                self.log_action("source_update_failed", result)
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to update source: {e}")
            return {
                "action": "update_source",
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def _remove_source(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Remove a data source"""
        try:
            source_label = task.get("source_label")
            
            success = self.data_source_manager.remove_source(source_label)
            
            result = {
                "action": "remove_source",
                "source_label": source_label,
                "success": success,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            if success:
                self.log_action("source_removed", result)
                # Update sources list
                self.sources = [s.label for s in self.data_source_manager.get_sources(enabled_only=True)]
            else:
                self.log_action("source_remove_failed", result)
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to remove source: {e}")
            return {
                "action": "remove_source",
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def _ingest_source(self, source_label: str, task: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest documents from a specific source"""
        start_time = datetime.utcnow()
        
        # Fetch documents from source
        documents = await self._fetch_documents(source_label, task)
        
        if not documents:
            return {
                "source": source_label,
                "documents_ingested": 0,
                "processing_time": (datetime.utcnow() - start_time).total_seconds(),
                "status": "no_documents"
            }
        
        # Process and upload documents
        processed_docs = await self._process_documents(documents)
        uploaded_count = await self._upload_documents(processed_docs)
        
        result = {
            "source": source_label,
            "documents_fetched": len(documents),
            "documents_processed": len(processed_docs),
            "documents_ingested": uploaded_count,
            "processing_time": (datetime.utcnow() - start_time).total_seconds(),
            "status": "success"
        }
        
        self.log_action("source_ingestion_completed", result)
        return result
    
    async def _fetch_documents(self, source_label: str, task: Dict[str, Any]) -> List[CTIDocument]:
        """Fetch documents from a specific source"""
        try:
            # Use the ingestion service to fetch from specific source
            documents = self.ingestion_service.ingest_specific_source(source_label)
            return documents
            
        except Exception as e:
            logger.error(f"Failed to fetch documents from {source_label}: {e}")
            raise
    
    async def _process_documents(self, documents: List[CTIDocument]) -> List[CTIDocument]:
        """Process documents (generate embeddings, normalize, etc.)"""
        processed_docs = []
        
        for doc in documents:
            try:
                # Generate embeddings if not present
                if not doc.content_vector:
                    # This would use your existing embedding generation
                    # For now, we'll skip this step
                    pass
                
                processed_docs.append(doc)
                
            except Exception as e:
                logger.error(f"Failed to process document {doc.doc_id}: {e}")
                continue
        
        return processed_docs
    
    async def _upload_documents(self, documents: List[CTIDocument]) -> int:
        """Upload documents to Azure Search"""
        try:
            success = self.search_service.upload_documents(documents)
            if success:
                return len(documents)
            else:
                logger.error("Failed to upload documents to Azure Search")
                return 0
                
        except Exception as e:
            logger.error(f"Failed to upload documents: {e}")
            return 0
    
    def get_ingestion_stats(self) -> Dict[str, Any]:
        """Get ingestion statistics"""
        try:
            stats = self.search_service.get_index_stats()
            source_stats = self.data_source_manager.get_source_stats()
            
            return {
                "total_documents": stats.get("document_count", 0),
                "storage_size": stats.get("storage_size", 0),
                "last_ingestion": self.get_state("last_ingestion_time"),
                "sources_configured": len(self.sources),
                "sources_enabled": source_stats.get("enabled_sources", 0),
                "sources_disabled": source_stats.get("disabled_sources", 0),
                "source_types": source_stats.get("source_types", {}),
                "available_sources": self.ingestion_service.get_available_sources()
            }
        except Exception as e:
            logger.error(f"Failed to get ingestion stats: {e}")
            return {"error": str(e)}
    
    def get_source_management_info(self) -> Dict[str, Any]:
        """Get information for source management"""
        try:
            sources = self.data_source_manager.get_sources(enabled_only=False)
            return {
                "total_sources": len(sources),
                "sources": [
                    {
                        "label": source.label,
                        "feed_url": source.feed_url,
                        "source_type": source.source_type,
                        "enabled": source.enabled,
                        "max_posts": source.max_posts,
                        "priority": source.priority,
                        "last_updated": source.last_updated.isoformat() if source.last_updated else None
                    }
                    for source in sources
                ]
            }
        except Exception as e:
            logger.error(f"Failed to get source management info: {e}")
            return {"error": str(e)} 