"""
Agentic CTI RAG System - Main Orchestrator

This module provides the main interface for the multi-agent CTI system,
coordinating all agents and providing a unified API for threat intelligence operations.
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json

import config
from agents import CoordinatorAgent, CollectorAgent, AnalystAgent, ToolsAgent, MaintainerAgent

logger = logging.getLogger(__name__)

class AgenticCTISystem:
    """Main orchestrator for the agentic CTI RAG system"""
    
    def __init__(self, config: config.Config):
        self.config = config
        self.coordinator = CoordinatorAgent(config)
        self.is_initialized = False
        
    async def initialize(self):
        """Initialize the agentic system"""
        try:
            logger.info("🤖 Initializing Agentic CTI System...")
            
            # Initialize coordinator (which initializes all other agents)
            await self.coordinator.execute({"type": "agent_status"})
            
            self.is_initialized = True
            logger.info("✅ Agentic CTI System initialized successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize Agentic CTI System: {e}")
            raise
    
    async def run_threat_analysis_workflow(self, threat_actor: str, analysis_types: List[str] = None) -> Dict[str, Any]:
        """Run a comprehensive threat analysis workflow"""
        if not self.is_initialized:
            await self.initialize()
        
        try:
            logger.info(f"🎯 Starting threat analysis workflow for {threat_actor}")
            
            # Create workflow
            workflow_task = await self.coordinator.create_threat_analysis_workflow(
                threat_actor=threat_actor,
                analysis_types=analysis_types
            )
            
            # Execute workflow
            result = await self.coordinator.execute(workflow_task)
            
            logger.info(f"✅ Threat analysis workflow completed for {threat_actor}")
            return result
            
        except Exception as e:
            logger.error(f"❌ Threat analysis workflow failed for {threat_actor}: {e}")
            raise
    
    async def get_agent_status(self) -> Dict[str, Any]:
        """Get status of all agents"""
        if not self.is_initialized:
            await self.initialize()
        
        return await self.coordinator.execute({"type": "agent_status"})
    
    async def run_ingestion_workflow(self, sources: List[str] = None) -> Dict[str, Any]:
        """Run document ingestion workflow"""
        if not self.is_initialized:
            await self.initialize()
        
        try:
            logger.info("📥 Starting ingestion workflow")
            
            workflow_task = {
                "type": "workflow",
                "workflow_id": f"ingestion_{datetime.utcnow().timestamp()}",
                "steps": [
                    {
                        "agent": "collector",
                        "task_type": "full_ingestion",
                        "parameters": {
                            "sources": sources or ["all"]
                        }
                    }
                ]
            }
            
            result = await self.coordinator.execute(workflow_task)
            
            logger.info("✅ Ingestion workflow completed")
            return result
            
        except Exception as e:
            logger.error(f"❌ Ingestion workflow failed: {e}")
            raise
    
    async def run_maintenance_workflow(self) -> Dict[str, Any]:
        """Run system maintenance workflow"""
        if not self.is_initialized:
            await self.initialize()
        
        try:
            logger.info("🔧 Starting maintenance workflow")
            
            workflow_task = {
                "type": "workflow",
                "workflow_id": f"maintenance_{datetime.utcnow().timestamp()}",
                "steps": [
                    {
                        "agent": "maintainer",
                        "task_type": "scheduled_maintenance",
                        "parameters": {}
                    }
                ]
            }
            
            result = await self.coordinator.execute(workflow_task)
            
            logger.info("✅ Maintenance workflow completed")
            return result
            
        except Exception as e:
            logger.error(f"❌ Maintenance workflow failed: {e}")
            raise
    
    async def enrich_iocs(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Enrich IOCs using the Tools agent"""
        if not self.is_initialized:
            await self.initialize()
        
        try:
            logger.info(f"🔍 Enriching {len(iocs)} IOCs")
            
            workflow_task = {
                "type": "workflow",
                "workflow_id": f"ioc_enrichment_{datetime.utcnow().timestamp()}",
                "steps": [
                    {
                        "agent": "tools",
                        "task_type": "ioc_enrichment",
                        "parameters": {
                            "iocs": iocs,
                            "enrichment_types": ["virustotal", "abusech"]
                        }
                    }
                ]
            }
            
            result = await self.coordinator.execute(workflow_task)
            
            logger.info("✅ IOC enrichment completed")
            return result
            
        except Exception as e:
            logger.error(f"❌ IOC enrichment failed: {e}")
            raise
    
    async def generate_threat_brief(self, threat_actor: str, time_window: Dict[str, str] = None) -> Dict[str, Any]:
        """Generate threat brief using the Analyst agent"""
        if not self.is_initialized:
            await self.initialize()
        
        try:
            logger.info(f"📋 Generating threat brief for {threat_actor}")
            
            workflow_task = {
                "type": "workflow",
                "workflow_id": f"threat_brief_{threat_actor}_{datetime.utcnow().timestamp()}",
                "steps": [
                    {
                        "agent": "analyst",
                        "task_type": "threat_brief",
                        "parameters": {
                            "threat_actor": threat_actor,
                            "time_window": time_window or {
                                "start": (datetime.utcnow() - timedelta(days=90)).isoformat(),
                                "end": datetime.utcnow().isoformat()
                            }
                        }
                    }
                ]
            }
            
            result = await self.coordinator.execute(workflow_task)
            
            logger.info("✅ Threat brief generated")
            return result
            
        except Exception as e:
            logger.error(f"❌ Threat brief generation failed: {e}")
            raise
    
    async def monitor_system_health(self) -> Dict[str, Any]:
        """Monitor system health using the Maintainer agent"""
        if not self.is_initialized:
            await self.initialize()
        
        try:
            logger.info("🏥 Monitoring system health")
            
            workflow_task = {
                "type": "workflow",
                "workflow_id": f"health_check_{datetime.utcnow().timestamp()}",
                "steps": [
                    {
                        "agent": "maintainer",
                        "task_type": "health_check",
                        "parameters": {}
                    }
                ]
            }
            
            result = await self.coordinator.execute(workflow_task)
            
            logger.info("✅ System health check completed")
            return result
            
        except Exception as e:
            logger.error(f"❌ System health check failed: {e}")
            raise
    
    async def get_workflow_status(self) -> Dict[str, Any]:
        """Get status of active workflows"""
        if not self.is_initialized:
            await self.initialize()
        
        return await self.coordinator.execute({"type": "workflow_monitoring"})
    
    async def optimize_resources(self, apply_optimizations: bool = False) -> Dict[str, Any]:
        """Optimize system resources"""
        if not self.is_initialized:
            await self.initialize()
        
        return await self.coordinator.execute({
            "type": "resource_optimization",
            "apply_optimizations": apply_optimizations
        })
    
    async def cleanup(self):
        """Cleanup system resources"""
        try:
            await self.coordinator.cleanup()
            logger.info("🧹 Agentic CTI System cleanup completed")
        except Exception as e:
            logger.error(f"❌ Cleanup failed: {e}")

# Global system instance
_agentic_system = None

async def get_agentic_system() -> AgenticCTISystem:
    """Get or create the global agentic system instance"""
    global _agentic_system
    
    if _agentic_system is None:
        config_instance = config.Config()
        _agentic_system = AgenticCTISystem(config_instance)
        await _agentic_system.initialize()
    
    return _agentic_system

async def shutdown_agentic_system():
    """Shutdown the global agentic system"""
    global _agentic_system
    
    if _agentic_system is not None:
        await _agentic_system.cleanup()
        _agentic_system = None 