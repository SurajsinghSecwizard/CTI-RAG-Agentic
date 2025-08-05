"""
Coordinator Agent - Orchestrates workflow and communication between agents

Responsibilities:
- Coordinate multi-agent workflows
- Manage task distribution and routing
- Handle agent communication
- Monitor workflow progress
- Optimize resource allocation
"""

import logging
import asyncio
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
import json
from dataclasses import dataclass
from enum import Enum

from .base_agent import BaseAgent
from .collector_agent import CollectorAgent
from .analyst_agent import AnalystAgent
from .tools_agent import ToolsAgent
from .maintainer_agent import MaintainerAgent

logger = logging.getLogger(__name__)

class WorkflowStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class WorkflowTask:
    id: str
    agent: str
    task_type: str
    parameters: Dict[str, Any]
    status: WorkflowStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class CoordinatorAgent(BaseAgent):
    """Agent responsible for orchestrating multi-agent workflows"""
    
    def __init__(self, config):
        super().__init__("Coordinator", config)
        
        # Initialize other agents
        self.agents = {
            "collector": CollectorAgent(config),
            "analyst": AnalystAgent(config),
            "tools": ToolsAgent(config),
            "maintainer": MaintainerAgent(config)
        }
        
        # Workflow management
        self.active_workflows = {}
        self.workflow_history = []
        self.task_queue = asyncio.Queue()
        
        # Performance tracking
        self.agent_performance = {}
        self.resource_usage = {}
        
    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute coordination task"""
        try:
            task_type = task.get("type", "workflow")
            
            if task_type == "workflow":
                return await self._execute_workflow(task)
            elif task_type == "agent_status":
                return await self._get_agent_status(task)
            elif task_type == "resource_optimization":
                return await self._optimize_resources(task)
            elif task_type == "workflow_monitoring":
                return await self._monitor_workflows(task)
            else:
                raise ValueError(f"Unknown coordination task type: {task_type}")
                
        except Exception as e:
            logger.error(f"Coordinator agent execution failed: {e}")
            self.log_action("execution_failed", {"error": str(e)})
            raise
    
    async def _execute_workflow(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a multi-agent workflow"""
        self.log_action("starting_workflow_execution", task)
        
        try:
            workflow_id = task.get("workflow_id", f"workflow_{datetime.utcnow().timestamp()}")
            workflow_steps = task.get("steps", [])
            
            # Create workflow
            workflow = {
                "id": workflow_id,
                "status": WorkflowStatus.RUNNING,
                "steps": workflow_steps,
                "created_at": datetime.utcnow(),
                "results": {},
                "errors": []
            }
            
            self.active_workflows[workflow_id] = workflow
            
            # Execute workflow steps
            for i, step in enumerate(workflow_steps):
                try:
                    step_result = await self._execute_workflow_step(step, workflow_id)
                    workflow["results"][f"step_{i}"] = step_result
                    
                    # Check if step result should trigger next steps
                    if step.get("condition"):
                        if not self._evaluate_condition(step["condition"], step_result):
                            logger.info(f"Workflow {workflow_id} stopped at step {i} due to condition")
                            break
                    
                except Exception as e:
                    error_msg = f"Step {i} failed: {e}"
                    logger.error(error_msg)
                    workflow["errors"].append(error_msg)
                    workflow["status"] = WorkflowStatus.FAILED
                    break
            
            # Finalize workflow
            if workflow["status"] == WorkflowStatus.RUNNING:
                workflow["status"] = WorkflowStatus.COMPLETED
                workflow["completed_at"] = datetime.utcnow()
            
            # Move to history
            self.workflow_history.append(workflow)
            if workflow_id in self.active_workflows:
                del self.active_workflows[workflow_id]
            
            result = {
                "workflow_id": workflow_id,
                "status": workflow["status"].value,
                "steps_completed": len(workflow["results"]),
                "total_steps": len(workflow_steps),
                "errors": workflow["errors"],
                "execution_time": (workflow.get("completed_at", datetime.utcnow()) - workflow["created_at"]).total_seconds(),
                "results": workflow["results"]  # Include the actual results
            }
            
            self.log_action("completed_workflow_execution", result)
            return result
            
        except Exception as e:
            logger.error(f"Workflow execution failed: {e}")
            raise
    
    async def _execute_workflow_step(self, step: Dict[str, Any], workflow_id: str) -> Dict[str, Any]:
        """Execute a single workflow step"""
        agent_name = step.get("agent")
        task_type = step.get("task_type")
        parameters = step.get("parameters", {})
        
        if agent_name not in self.agents:
            raise ValueError(f"Unknown agent: {agent_name}")
        
        agent = self.agents[agent_name]
        
        # Add workflow context to parameters
        parameters["workflow_id"] = workflow_id
        
        # Execute the task
        start_time = datetime.utcnow()
        result = await agent.execute({
            "type": task_type,
            **parameters
        })
        execution_time = (datetime.utcnow() - start_time).total_seconds()
        
        # Track performance
        self._track_agent_performance(agent_name, execution_time, result)
        
        return {
            "agent": agent_name,
            "task_type": task_type,
            "result": result,
            "execution_time": execution_time,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _evaluate_condition(self, condition: Dict[str, Any], step_result: Dict[str, Any]) -> bool:
        """Evaluate workflow condition"""
        condition_type = condition.get("type")
        
        if condition_type == "success":
            return step_result.get("result", {}).get("status") != "failed"
        elif condition_type == "threshold":
            threshold = condition.get("threshold")
            value = step_result.get("result", {}).get(condition.get("field"))
            operator = condition.get("operator", ">=")
            
            if operator == ">=":
                return value >= threshold
            elif operator == "<=":
                return value <= threshold
            elif operator == "==":
                return value == threshold
            else:
                return True
        
        return True
    
    async def _get_agent_status(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Get status of all agents"""
        self.log_action("getting_agent_status", task)
        
        try:
            status = {
                "timestamp": datetime.utcnow().isoformat(),
                "agents": {}
            }
            
            # Add coordinator's own status
            status["agents"]["coordinator"] = {
                "health": self.health_check(),
                "memory_size": len(self.get_memory()),
                "state_keys": list(self.state.keys()),
                "performance": self.agent_performance.get("coordinator", {}),
                "managed_agents": len(self.agents),
                "active_workflows": len(self.active_workflows),
                "workflow_history": len(self.workflow_history)
            }
            
            # Add managed agents status
            for agent_name, agent in self.agents.items():
                agent_status = {
                    "health": agent.health_check(),
                    "memory_size": len(agent.get_memory()),
                    "state_keys": list(agent.state.keys()),
                    "performance": self.agent_performance.get(agent_name, {})
                }
                status["agents"][agent_name] = agent_status
            
            self.log_action("completed_agent_status_check", status)
            return status
            
        except Exception as e:
            logger.error(f"Failed to get agent status: {e}")
            raise
    
    async def _optimize_resources(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize resource allocation across agents"""
        self.log_action("starting_resource_optimization", task)
        
        try:
            optimization_result = {
                "timestamp": datetime.utcnow().isoformat(),
                "optimizations": [],
                "resource_usage": self._calculate_resource_usage(),
                "recommendations": []
            }
            
            # Analyze agent performance
            performance_analysis = self._analyze_agent_performance()
            
            # Generate optimization recommendations
            recommendations = self._generate_resource_recommendations(performance_analysis)
            optimization_result["recommendations"] = recommendations
            
            # Apply optimizations if requested
            if task.get("apply_optimizations", False):
                applied_optimizations = await self._apply_optimizations(recommendations)
                optimization_result["optimizations"] = applied_optimizations
            
            self.log_action("completed_resource_optimization", optimization_result)
            return optimization_result
            
        except Exception as e:
            logger.error(f"Resource optimization failed: {e}")
            raise
    
    async def _monitor_workflows(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Monitor active workflows"""
        self.log_action("starting_workflow_monitoring", task)
        
        try:
            monitoring_result = {
                "timestamp": datetime.utcnow().isoformat(),
                "active_workflows": len(self.active_workflows),
                "workflow_history": len(self.workflow_history),
                "active_workflow_details": [],
                "performance_metrics": self._calculate_workflow_metrics()
            }
            
            # Get details of active workflows
            for workflow_id, workflow in self.active_workflows.items():
                workflow_detail = {
                    "id": workflow_id,
                    "status": workflow["status"].value,
                    "steps_completed": len(workflow["results"]),
                    "total_steps": len(workflow["steps"]),
                    "created_at": workflow["created_at"].isoformat(),
                    "execution_time": (datetime.utcnow() - workflow["created_at"]).total_seconds()
                }
                monitoring_result["active_workflow_details"].append(workflow_detail)
            
            self.log_action("completed_workflow_monitoring", monitoring_result)
            return monitoring_result
            
        except Exception as e:
            logger.error(f"Workflow monitoring failed: {e}")
            raise
    
    def _track_agent_performance(self, agent_name: str, execution_time: float, result: Dict[str, Any]):
        """Track agent performance metrics"""
        if agent_name not in self.agent_performance:
            self.agent_performance[agent_name] = {
                "total_executions": 0,
                "total_execution_time": 0,
                "success_count": 0,
                "error_count": 0,
                "avg_execution_time": 0
            }
        
        perf = self.agent_performance[agent_name]
        perf["total_executions"] += 1
        perf["total_execution_time"] += execution_time
        perf["avg_execution_time"] = perf["total_execution_time"] / perf["total_executions"]
        
        if result.get("status") == "success":
            perf["success_count"] += 1
        else:
            perf["error_count"] += 1
    
    def _calculate_resource_usage(self) -> Dict[str, Any]:
        """Calculate current resource usage"""
        total_memory = sum(len(agent.get_memory()) for agent in self.agents.values())
        total_state_keys = sum(len(agent.state.keys()) for agent in self.agents.values())
        
        return {
            "total_memory_entries": total_memory,
            "total_state_keys": total_state_keys,
            "active_workflows": len(self.active_workflows),
            "agent_count": len(self.agents)
        }
    
    def _analyze_agent_performance(self) -> Dict[str, Any]:
        """Analyze agent performance patterns"""
        analysis = {}
        
        for agent_name, perf in self.agent_performance.items():
            if perf["total_executions"] > 0:
                success_rate = perf["success_count"] / perf["total_executions"]
                analysis[agent_name] = {
                    "success_rate": success_rate,
                    "avg_execution_time": perf["avg_execution_time"],
                    "total_executions": perf["total_executions"],
                    "efficiency_score": success_rate / max(perf["avg_execution_time"], 1)
                }
        
        return analysis
    
    def _generate_resource_recommendations(self, performance_analysis: Dict[str, Any]) -> List[str]:
        """Generate resource optimization recommendations"""
        recommendations = []
        
        for agent_name, analysis in performance_analysis.items():
            if analysis["success_rate"] < 0.8:
                recommendations.append(f"Improve error handling for {agent_name} agent")
            
            if analysis["avg_execution_time"] > 10:
                recommendations.append(f"Optimize performance for {agent_name} agent")
            
            if analysis["efficiency_score"] < 0.1:
                recommendations.append(f"Review {agent_name} agent implementation")
        
        return recommendations
    
    async def _apply_optimizations(self, recommendations: List[str]) -> List[str]:
        """Apply resource optimizations"""
        applied = []
        
        for recommendation in recommendations:
            try:
                # This would implement actual optimizations
                # For now, we'll just log them
                logger.info(f"Applied optimization: {recommendation}")
                applied.append(recommendation)
                
            except Exception as e:
                logger.error(f"Failed to apply optimization '{recommendation}': {e}")
        
        return applied
    
    def _calculate_workflow_metrics(self) -> Dict[str, Any]:
        """Calculate workflow performance metrics"""
        if not self.workflow_history:
            return {}
        
        total_workflows = len(self.workflow_history)
        completed_workflows = len([w for w in self.workflow_history if w["status"] == WorkflowStatus.COMPLETED])
        failed_workflows = len([w for w in self.workflow_history if w["status"] == WorkflowStatus.FAILED])
        
        avg_execution_time = 0
        if completed_workflows > 0:
            total_time = sum(
                (w.get("completed_at", datetime.utcnow()) - w["created_at"]).total_seconds()
                for w in self.workflow_history
                if w["status"] == WorkflowStatus.COMPLETED
            )
            avg_execution_time = total_time / completed_workflows
        
        return {
            "total_workflows": total_workflows,
            "completed_workflows": completed_workflows,
            "failed_workflows": failed_workflows,
            "success_rate": completed_workflows / total_workflows if total_workflows > 0 else 0,
            "avg_execution_time": avg_execution_time
        }
    
    async def create_threat_analysis_workflow(self, threat_actor: str, analysis_types: List[str] = None) -> Dict[str, Any]:
        """Create a comprehensive threat analysis workflow"""
        if analysis_types is None:
            analysis_types = ["threat_brief", "ioc_extraction", "ttp_analysis", "risk_assessment"]
        
        workflow_steps = []
        
        # Step 1: Collect latest intelligence
        workflow_steps.append({
            "agent": "collector",
            "task_type": "incremental_ingestion",
            "parameters": {
                "sources": ["all"],
                "time_window": {
                    "start": (datetime.utcnow() - timedelta(days=30)).isoformat(),
                    "end": datetime.utcnow().isoformat()
                }
            }
        })
        
        # Step 2: Generate threat brief
        if "threat_brief" in analysis_types:
            workflow_steps.append({
                "agent": "analyst",
                "task_type": "threat_brief",
                "parameters": {
                    "threat_actor": threat_actor,
                    "time_window": {
                        "start": (datetime.utcnow() - timedelta(days=90)).isoformat(),
                        "end": datetime.utcnow().isoformat()
                    }
                }
            })
        
        # Step 3: Extract IOCs
        if "ioc_extraction" in analysis_types:
            workflow_steps.append({
                "agent": "analyst",
                "task_type": "ioc_extraction",
                "parameters": {
                    "threat_actor": threat_actor,
                    "ioc_types": ["all"]
                }
            })
            
            # Step 3.1: Enrich IOCs
            workflow_steps.append({
                "agent": "tools",
                "task_type": "ioc_enrichment",
                "parameters": {
                    "enrichment_types": ["virustotal", "abusech"]
                },
                "condition": {
                    "type": "success",
                    "depends_on": "ioc_extraction"
                }
            })
        
        # Step 4: Analyze TTPs
        if "ttp_analysis" in analysis_types:
            workflow_steps.append({
                "agent": "analyst",
                "task_type": "ttp_analysis",
                "parameters": {
                    "threat_actor": threat_actor
                }
            })
        
        # Step 5: Risk assessment
        if "risk_assessment" in analysis_types:
            workflow_steps.append({
                "agent": "analyst",
                "task_type": "risk_assessment",
                "parameters": {
                    "threat_actor": threat_actor
                }
            })
        
        return {
            "type": "workflow",
            "workflow_id": f"threat_analysis_{threat_actor}_{datetime.utcnow().timestamp()}",
            "steps": workflow_steps
        }
    
    async def cleanup(self):
        """Cleanup coordinator resources"""
        for agent in self.agents.values():
            if hasattr(agent, 'cleanup'):
                await agent.cleanup() 