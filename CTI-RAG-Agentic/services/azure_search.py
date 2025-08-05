import os
import json
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from azure.search.documents.indexes import SearchIndexClient
from azure.search.documents.indexes.models import (
    SearchIndex, 
    SearchField, 
    SearchFieldDataType, 
    VectorSearch,
    VectorSearchProfile,
    VectorSearchAlgorithmKind
)
# Vector import is only needed for production Azure Search
# For local development with FAISS, this is not required
try:
    from azure.search.documents.models import Vector
except ImportError:
    Vector = None  # Fallback for local development

import config
from models import CTIDocument, SearchResult

logger = logging.getLogger(__name__)

class AzureSearchService:
    """Azure AI Search service for CTI document storage and retrieval"""
    
    def __init__(self):
        self.endpoint = config.Config.AZURE_SEARCH_ENDPOINT
        self.key = config.Config.AZURE_SEARCH_KEY
        self.index_name = os.getenv("AZURE_SEARCH_INDEX_NAME", "cti-kb-index")
        
        # Initialize clients
        self.credential = AzureKeyCredential(self.key)
        self.search_client = SearchClient(
            endpoint=self.endpoint,
            index_name=self.index_name,
            credential=self.credential
        )
        self.index_client = SearchIndexClient(
            endpoint=self.endpoint,
            credential=self.credential
        )
    
    def create_index(self) -> bool:
        """Create the CTI knowledge base index"""
        try:
            # Define search fields
            fields = [
                SearchField(name="doc_id", type=SearchFieldDataType.String, key=True),
                SearchField(name="title", type=SearchFieldDataType.String, searchable=True),
                SearchField(name="content", type=SearchFieldDataType.String, searchable=True),
                SearchField(name="date_pub", type=SearchFieldDataType.String, filterable=True, sortable=True),
                SearchField(name="source", type=SearchFieldDataType.String, filterable=True, facetable=True),
                SearchField(name="threat_actor", type=SearchFieldDataType.String, filterable=True, searchable=True),
                SearchField(name="operation", type=SearchFieldDataType.String, searchable=True),
                SearchField(name="mitre_id", type=SearchFieldDataType.String, filterable=True),
                SearchField(name="ioc_type", type=SearchFieldDataType.String, filterable=True),
                SearchField(name="geo_scope", type=SearchFieldDataType.String, filterable=True),
                SearchField(name="confidence", type=SearchFieldDataType.String, filterable=True),
                SearchField(name="language", type=SearchFieldDataType.String, filterable=True),
                SearchField(name="content_vector", type=SearchFieldDataType.Collection(SearchFieldDataType.Single), 
                          vector_search_dimensions=1536, vector_search_profile_name="my-vector-config")
            ]
            
            # Vector search configuration
            vector_search = VectorSearch(
                profiles=[
                    VectorSearchProfile(
                        name="my-vector-config",
                        algorithm_configuration_name="my-algorithms-config"
                    )
                ],
                algorithms=[
                    {
                        "name": "my-algorithms-config",
                        "kind": VectorSearchAlgorithmKind.HNSW,
                        "parameters": {
                            "m": 4,
                            "efConstruction": 400,
                            "efSearch": 500,
                            "metric": "cosine"
                        }
                    }
                ]
            )
            
            # Create index
            index = SearchIndex(
                name=self.index_name,
                fields=fields,
                vector_search=vector_search
            )
            
            self.index_client.create_or_update_index(index)
            logger.info(f"Successfully created/updated index: {self.index_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create index: {e}")
            return False
    
    def upload_documents(self, documents: List[CTIDocument]) -> bool:
        """Upload documents to Azure Search"""
        try:
            # Convert documents to search format
            search_docs = []
            for doc in documents:
                # Generate a default vector if content_vector is None
                content_vector = doc.content_vector
                if content_vector is None:
                    # Create a default vector of 1536 zeros (same as OpenAI embeddings)
                    content_vector = [0.0] * 1536
                
                search_doc = {
                    "doc_id": doc.doc_id,
                    "title": doc.title,
                    "content": doc.content,
                    "date_pub": doc.date_pub.isoformat(),
                    "source": doc.source,
                    "threat_actor": doc.threat_actor,
                    "operation": doc.operation,
                    "mitre_id": doc.mitre_id,
                    "ioc_type": doc.ioc_type.value if doc.ioc_type else None,
                    "geo_scope": doc.geo_scope,
                    "confidence": doc.confidence.value,
                    "language": doc.language,
                    "content_vector": content_vector
                }
                search_docs.append(search_doc)
            
            # Upload in batches
            batch_size = 1000
            for i in range(0, len(search_docs), batch_size):
                batch = search_docs[i:i + batch_size]
                result = self.search_client.upload_documents(batch)
                logger.info(f"Uploaded batch {i//batch_size + 1}: {len(batch)} documents")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to upload documents: {e}")
            return False
    
    def search_documents(
        self, 
        query: str, 
        top_k: int = 10,
        filters: Optional[str] = None,
        vector_query: Optional[List[float]] = None
    ) -> List[SearchResult]:
        """Search documents using hybrid search (keyword + vector)"""
        try:
            search_options = {
                "top": top_k,
                "include_total_count": True
            }
            
            # Add filters if provided
            if filters:
                search_options["filter"] = filters
                logger.info(f"Using filter: {filters}")
            else:
                logger.info("No filters applied")
            
            # Add vector search if provided and Vector class is available
            if vector_query and Vector is not None:
                search_options["vector_queries"] = [
                    Vector(value=vector_query, k_nearest_neighbors=top_k, fields="content_vector")
                ]
            
            logger.info(f"Searching with query: '{query}', options: {search_options}")
            
            # Perform search
            results = self.search_client.search(query, **search_options)
            
            # Convert to SearchResult objects
            search_results = []
            for result in results:
                # Handle both dictionary-like and object-like results
                try:
                    # Try dictionary access first
                    doc_id = result.get("doc_id") if hasattr(result, 'get') else getattr(result, 'doc_id', None)
                    title = result.get("title") if hasattr(result, 'get') else getattr(result, 'title', None)
                    content = result.get("content") if hasattr(result, 'get') else getattr(result, 'content', None)
                    score = result.get("@search.score") if hasattr(result, 'get') else getattr(result, '@search.score', 0.0)
                    
                    # Extract metadata safely
                    metadata = {}
                    for field in ["date_pub", "source", "threat_actor", "mitre_id", "confidence"]:
                        if hasattr(result, 'get'):
                            metadata[field] = result.get(field)
                        else:
                            metadata[field] = getattr(result, field, None)
                    
                    search_result = SearchResult(
                        doc_id=doc_id,
                        title=title,
                        content=content,
                        score=score,
                        metadata=metadata
                    )
                    search_results.append(search_result)
                except Exception as e:
                    logger.warning(f"Failed to process search result: {e}")
                    continue
            
            logger.info(f"Search returned {len(search_results)} results")
            return search_results
            
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []
    
    def search_by_actor(
        self, 
        actor: str, 
        time_window: Optional[str] = None,
        top_k: int = 20
    ) -> List[SearchResult]:
        """Search documents by threat actor with optional time filtering"""
        try:
            # Build filter
            filters = f"threat_actor eq '{actor}'"
            
            if time_window:
                start_date, end_date = time_window.split("/")
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
                filters += f" and date_pub ge '{start_date_iso}' and date_pub le '{end_date_iso}'"
            
            return self.search_documents(
                query=actor,
                top_k=top_k,
                filters=filters
            )
            
        except Exception as e:
            logger.error(f"Actor search failed: {e}")
            return []
    
    def get_index_stats(self) -> Dict[str, Any]:
        """Get index statistics"""
        try:
            stats = self.index_client.get_index_statistics(self.index_name)
            # Use attribute access if available, else fallback to dict keys
            document_count = getattr(stats, 'document_count', None) or stats.get('document_count')
            storage_size = getattr(stats, 'storage_size', None) or stats.get('storage_size')
            logger.info(f"Index stats - document_count: {document_count}, storage_size: {storage_size}")
            return {
                "document_count": document_count,
                "storage_size": storage_size,
                "index_name": self.index_name
            }
        except Exception as e:
            logger.error(f"Failed to get index stats: {e}")
            return {} 