"""
Maintainer Agent - Manages system health and optimization

Responsibilities:
- Monitor system health and performance
- Optimize Azure Search index
- Manage storage and cleanup
- Alert on issues
- Performance tuning
"""

import logging
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json

from .base_agent import BaseAgent
from services.azure_search import AzureSearchService
from services.document_ingestion import DocumentIngestionService

logger = logging.getLogger(__name__)

class MaintainerAgent(BaseAgent):
    """Agent responsible for system maintenance and optimization"""
    
    def __init__(self, config):
        super().__init__("Maintainer", config)
        self.search_service = AzureSearchService()
        self.ingestion_service = DocumentIngestionService()
        
        # Maintenance schedules
        self.maintenance_tasks = {
            "health_check": {"interval_hours": 1, "last_run": None},
            "index_optimization": {"interval_hours": 24, "last_run": None},
            "storage_cleanup": {"interval_hours": 168, "last_run": None},  # Weekly
            "performance_analysis": {"interval_hours": 6, "last_run": None}
        }
        
        # Health thresholds
        self.thresholds = {
            "max_document_count": 100000,
            "max_storage_size_mb": 1000,
            "max_response_time_ms": 5000,
            "min_uptime_percentage": 99.5
        }
        
    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute maintenance task"""
        try:
            task_type = task.get("type", "health_check")
            
            if task_type == "health_check":
                return await self._health_check(task)
            elif task_type == "index_optimization":
                return await self._optimize_index(task)
            elif task_type == "storage_cleanup":
                return await self._cleanup_storage(task)
            elif task_type == "performance_analysis":
                return await self._analyze_performance(task)
            elif task_type == "scheduled_maintenance":
                return await self._scheduled_maintenance(task)
            else:
                raise ValueError(f"Unknown maintenance task type: {task_type}")
                
        except Exception as e:
            logger.error(f"Maintainer agent execution failed: {e}")
            self.log_action("execution_failed", {"error": str(e)})
            raise
    
    async def _health_check(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive health check"""
        self.log_action("starting_health_check", task)
        
        try:
            health_status = {
                "timestamp": datetime.utcnow().isoformat(),
                "overall_status": "healthy",
                "components": {},
                "alerts": [],
                "recommendations": []
            }
            
            # Check Azure Search health
            search_health = await self._check_search_health()
            health_status["components"]["azure_search"] = search_health
            
            # Check ingestion health
            ingestion_health = await self._check_ingestion_health()
            health_status["components"]["ingestion"] = ingestion_health
            
            # Check storage health
            storage_health = await self._check_storage_health()
            health_status["components"]["storage"] = storage_health
            
            # Check performance health
            performance_health = await self._check_performance_health()
            health_status["components"]["performance"] = performance_health
            
            # Determine overall status
            overall_status = self._determine_overall_status(health_status["components"])
            health_status["overall_status"] = overall_status
            
            # Generate alerts and recommendations
            health_status["alerts"] = self._generate_alerts(health_status["components"])
            health_status["recommendations"] = self._generate_recommendations(health_status["components"])
            
            self.log_action("completed_health_check", health_status)
            return health_status
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            raise
    
    async def _optimize_index(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Azure Search index"""
        self.log_action("starting_index_optimization", task)
        
        try:
            optimization_result = {
                "timestamp": datetime.utcnow().isoformat(),
                "optimizations_performed": [],
                "performance_improvements": {},
                "errors": []
            }
            
            # Get current index stats
            current_stats = self.search_service.get_index_stats()
            
            # Check if optimization is needed
            if self._needs_index_optimization(current_stats):
                try:
                    # Perform index optimization
                    # This would call Azure Search optimization APIs
                    optimization_result["optimizations_performed"].append("index_optimization")
                    
                    # Get stats after optimization
                    new_stats = self.search_service.get_index_stats()
                    
                    # Calculate improvements
                    optimization_result["performance_improvements"] = {
                        "storage_reduction_mb": current_stats.get("storage_size", 0) - new_stats.get("storage_size", 0),
                        "document_count_change": new_stats.get("document_count", 0) - current_stats.get("document_count", 0)
                    }
                    
                except Exception as e:
                    optimization_result["errors"].append(f"Index optimization failed: {e}")
            else:
                optimization_result["optimizations_performed"].append("no_optimization_needed")
            
            self.log_action("completed_index_optimization", optimization_result)
            return optimization_result
            
        except Exception as e:
            logger.error(f"Index optimization failed: {e}")
            raise
    
    async def _cleanup_storage(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Clean up storage and remove old data"""
        self.log_action("starting_storage_cleanup", task)
        
        try:
            cleanup_result = {
                "timestamp": datetime.utcnow().isoformat(),
                "cleanup_actions": [],
                "storage_freed_mb": 0,
                "documents_removed": 0,
                "errors": []
            }
            
            # Get current storage stats
            current_stats = self.search_service.get_index_stats()
            
            # Check for old documents (older than 90 days)
            cutoff_date = datetime.utcnow() - timedelta(days=90)
            
            try:
                # This would query for old documents and remove them
                # For now, we'll simulate the process
                old_docs_count = 0  # Would be actual count
                cleanup_result["documents_removed"] = old_docs_count
                cleanup_result["cleanup_actions"].append("removed_old_documents")
                
            except Exception as e:
                cleanup_result["errors"].append(f"Document cleanup failed: {e}")
            
            # Clean up temporary files
            try:
                # This would clean up temporary ingestion files
                cleanup_result["cleanup_actions"].append("cleaned_temp_files")
                
            except Exception as e:
                cleanup_result["errors"].append(f"Temp file cleanup failed: {e}")
            
            self.log_action("completed_storage_cleanup", cleanup_result)
            return cleanup_result
            
        except Exception as e:
            logger.error(f"Storage cleanup failed: {e}")
            raise
    
    async def _analyze_performance(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze system performance"""
        self.log_action("starting_performance_analysis", task)
        
        try:
            performance_result = {
                "timestamp": datetime.utcnow().isoformat(),
                "metrics": {},
                "bottlenecks": [],
                "optimization_opportunities": []
            }
            
            # Analyze search performance
            search_metrics = await self._analyze_search_performance()
            performance_result["metrics"]["search"] = search_metrics
            
            # Analyze ingestion performance
            ingestion_metrics = await self._analyze_ingestion_performance()
            performance_result["metrics"]["ingestion"] = ingestion_metrics
            
            # Analyze storage performance
            storage_metrics = await self._analyze_storage_performance()
            performance_result["metrics"]["storage"] = storage_metrics
            
            # Identify bottlenecks
            performance_result["bottlenecks"] = self._identify_bottlenecks(performance_result["metrics"])
            
            # Generate optimization opportunities
            performance_result["optimization_opportunities"] = self._generate_optimization_opportunities(
                performance_result["metrics"]
            )
            
            self.log_action("completed_performance_analysis", performance_result)
            return performance_result
            
        except Exception as e:
            logger.error(f"Performance analysis failed: {e}")
            raise
    
    async def _scheduled_maintenance(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Run scheduled maintenance tasks"""
        self.log_action("starting_scheduled_maintenance", task)
        
        try:
            maintenance_result = {
                "timestamp": datetime.utcnow().isoformat(),
                "tasks_executed": [],
                "results": {}
            }
            
            current_time = datetime.utcnow()
            
            # Check which maintenance tasks are due
            for task_name, task_config in self.maintenance_tasks.items():
                last_run = task_config.get("last_run")
                interval = timedelta(hours=task_config.get("interval_hours", 24))
                
                if not last_run or (current_time - last_run) >= interval:
                    try:
                        # Execute the maintenance task
                        task_result = await self.execute({"type": task_name})
                        maintenance_result["results"][task_name] = task_result
                        maintenance_result["tasks_executed"].append(task_name)
                        
                        # Update last run time
                        self.maintenance_tasks[task_name]["last_run"] = current_time
                        
                    except Exception as e:
                        logger.error(f"Scheduled maintenance task {task_name} failed: {e}")
                        maintenance_result["results"][task_name] = {"error": str(e)}
            
            self.log_action("completed_scheduled_maintenance", maintenance_result)
            return maintenance_result
            
        except Exception as e:
            logger.error(f"Scheduled maintenance failed: {e}")
            raise
    
    async def _check_search_health(self) -> Dict[str, Any]:
        """Check Azure Search health"""
        try:
            stats = self.search_service.get_index_stats()
            
            return {
                "status": "healthy",
                "document_count": stats.get("document_count", 0),
                "storage_size_mb": stats.get("storage_size", 0),
                "index_exists": True,
                "last_updated": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "last_updated": datetime.utcnow().isoformat()
            }
    
    async def _check_ingestion_health(self) -> Dict[str, Any]:
        """Check ingestion system health"""
        try:
            # This would check ingestion service health
            return {
                "status": "healthy",
                "last_ingestion": self.get_state("last_ingestion_time"),
                "sources_available": True,
                "last_updated": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "last_updated": datetime.utcnow().isoformat()
            }
    
    async def _check_storage_health(self) -> Dict[str, Any]:
        """Check storage health"""
        try:
            stats = self.search_service.get_index_stats()
            storage_size_mb = stats.get("storage_size", 0)
            
            return {
                "status": "healthy" if storage_size_mb < self.thresholds["max_storage_size_mb"] else "warning",
                "storage_size_mb": storage_size_mb,
                "storage_utilization_percent": (storage_size_mb / self.thresholds["max_storage_size_mb"]) * 100,
                "last_updated": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "last_updated": datetime.utcnow().isoformat()
            }
    
    async def _check_performance_health(self) -> Dict[str, Any]:
        """Check performance health"""
        try:
            # This would measure actual performance metrics
            return {
                "status": "healthy",
                "avg_response_time_ms": 250,
                "uptime_percentage": 99.9,
                "last_updated": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "last_updated": datetime.utcnow().isoformat()
            }
    
    def _determine_overall_status(self, components: Dict[str, Any]) -> str:
        """Determine overall system status"""
        unhealthy_count = 0
        warning_count = 0
        
        for component_name, component_status in components.items():
            status = component_status.get("status", "unknown")
            if status == "unhealthy":
                unhealthy_count += 1
            elif status == "warning":
                warning_count += 1
        
        if unhealthy_count > 0:
            return "unhealthy"
        elif warning_count > 0:
            return "warning"
        else:
            return "healthy"
    
    def _generate_alerts(self, components: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate alerts based on component status"""
        alerts = []
        
        for component_name, component_status in components.items():
            status = component_status.get("status", "unknown")
            
            if status == "unhealthy":
                alerts.append({
                    "level": "critical",
                    "component": component_name,
                    "message": f"{component_name} is unhealthy",
                    "timestamp": datetime.utcnow().isoformat()
                })
            elif status == "warning":
                alerts.append({
                    "level": "warning",
                    "component": component_name,
                    "message": f"{component_name} needs attention",
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        return alerts
    
    def _generate_recommendations(self, components: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on component status"""
        recommendations = []
        
        # Storage recommendations
        storage = components.get("storage", {})
        if storage.get("status") == "warning":
            recommendations.append("Consider cleaning up old documents to reduce storage usage")
        
        # Performance recommendations
        performance = components.get("performance", {})
        if performance.get("avg_response_time_ms", 0) > self.thresholds["max_response_time_ms"]:
            recommendations.append("Consider optimizing search queries or scaling resources")
        
        return recommendations
    
    def _needs_index_optimization(self, stats: Dict[str, Any]) -> bool:
        """Determine if index optimization is needed"""
        document_count = stats.get("document_count", 0)
        storage_size = stats.get("storage_size", 0)
        
        # Optimize if document count is high or storage is large
        return document_count > 10000 or storage_size > 500
    
    async def _analyze_search_performance(self) -> Dict[str, Any]:
        """Analyze search performance metrics"""
        # This would collect actual search performance data
        return {
            "avg_query_time_ms": 150,
            "queries_per_minute": 25,
            "cache_hit_rate": 0.85,
            "index_fragmentation": 0.1
        }
    
    async def _analyze_ingestion_performance(self) -> Dict[str, Any]:
        """Analyze ingestion performance metrics"""
        # This would collect actual ingestion performance data
        return {
            "documents_per_hour": 100,
            "avg_processing_time_ms": 2000,
            "success_rate": 0.98,
            "error_rate": 0.02
        }
    
    async def _analyze_storage_performance(self) -> Dict[str, Any]:
        """Analyze storage performance metrics"""
        # This would collect actual storage performance data
        return {
            "storage_utilization": 0.65,
            "growth_rate_mb_per_day": 50,
            "compression_ratio": 0.8,
            "backup_size_mb": 200
        }
    
    def _identify_bottlenecks(self, metrics: Dict[str, Any]) -> List[str]:
        """Identify performance bottlenecks"""
        bottlenecks = []
        
        search_metrics = metrics.get("search", {})
        if search_metrics.get("avg_query_time_ms", 0) > 1000:
            bottlenecks.append("Slow search queries")
        
        ingestion_metrics = metrics.get("ingestion", {})
        if ingestion_metrics.get("avg_processing_time_ms", 0) > 5000:
            bottlenecks.append("Slow document processing")
        
        storage_metrics = metrics.get("storage", {})
        if storage_metrics.get("storage_utilization", 0) > 0.8:
            bottlenecks.append("High storage utilization")
        
        return bottlenecks
    
    def _generate_optimization_opportunities(self, metrics: Dict[str, Any]) -> List[str]:
        """Generate optimization opportunities"""
        opportunities = []
        
        search_metrics = metrics.get("search", {})
        if search_metrics.get("cache_hit_rate", 0) < 0.8:
            opportunities.append("Increase search result caching")
        
        ingestion_metrics = metrics.get("ingestion", {})
        if ingestion_metrics.get("success_rate", 0) < 0.95:
            opportunities.append("Improve ingestion error handling")
        
        storage_metrics = metrics.get("storage", {})
        if storage_metrics.get("compression_ratio", 0) < 0.7:
            opportunities.append("Optimize storage compression")
        
        return opportunities 