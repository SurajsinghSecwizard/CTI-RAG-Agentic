"""
Base Agent Class for CTI RAG System

Provides common functionality for all agents including:
- OpenAI client management
- Logging and monitoring
- Error handling
- State management
"""

import logging
import json
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime
import openai
from openai import AzureOpenAI

import config
from models import CTIDocument, ThreatBrief, IOCEnrichment

logger = logging.getLogger(__name__)

class BaseAgent(ABC):
    """Base class for all CTI agents"""
    
    def __init__(self, name: str, config: config.Config):
        self.name = name
        self.config_instance = config
        self.openai_client = self._init_openai_client()
        self.state = {}
        self.memory = []
        
        logger.info(f"🤖 Initialized {self.name} agent")
    
    def _init_openai_client(self) -> AzureOpenAI:
        """Initialize OpenAI client for Azure"""
        try:
            return AzureOpenAI(
                azure_endpoint=self.config_instance.AZURE_OPENAI_ENDPOINT,
                api_key=self.config_instance.AZURE_OPENAI_API_KEY,
                api_version=self.config_instance.AZURE_OPENAI_API_VERSION
            )
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")
            raise
    
    def log_action(self, action: str, details: Dict[str, Any] = None):
        """Log agent actions for monitoring"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "agent": self.name,
            "action": action,
            "details": details or {}
        }
        self.memory.append(log_entry)
        logger.info(f"🤖 {self.name}: {action}")
    
    def get_memory(self) -> List[Dict[str, Any]]:
        """Get agent's memory/action history"""
        return self.memory
    
    def clear_memory(self):
        """Clear agent's memory"""
        self.memory.clear()
        logger.info(f"🧹 {self.name}: Memory cleared")
    
    @abstractmethod
    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute agent's primary task - must be implemented by subclasses"""
        pass
    
    def update_state(self, key: str, value: Any):
        """Update agent's internal state"""
        self.state[key] = value
        logger.debug(f"📝 {self.name}: State updated - {key}: {value}")
    
    def get_state(self, key: str) -> Any:
        """Get value from agent's state"""
        return self.state.get(key)
    
    def health_check(self) -> Dict[str, Any]:
        """Check agent's health status"""
        return {
            "agent": self.name,
            "status": "healthy",
            "memory_size": len(self.memory),
            "state_keys": list(self.state.keys()),
            "timestamp": datetime.utcnow().isoformat()
        } 