"""
Comprehensive Error Handling for Agentic CTI System

This module provides robust error handling utilities for the multi-agent system,
ensuring graceful degradation and proper error reporting.
"""

import logging
import traceback
from typing import Dict, Any, Optional, Callable
from functools import wraps
from datetime import datetime

logger = logging.getLogger(__name__)

class AgenticError(Exception):
    """Base exception for agentic system errors"""
    def __init__(self, message: str, agent: str = None, task_type: str = None, context: Dict[str, Any] = None):
        super().__init__(message)
        self.agent = agent
        self.task_type = task_type
        self.context = context or {}
        self.timestamp = datetime.utcnow()

class SearchResultError(AgenticError):
    """Error related to SearchResult object handling"""
    pass

class ProfileUpdateError(AgenticError):
    """Error related to profile updates"""
    pass

class APIError(AgenticError):
    """Error related to external API calls"""
    pass

class DataValidationError(AgenticError):
    """Error related to data validation"""
    pass

def safe_agent_execution(agent_name: str = None):
    """
    Decorator for safe agent execution with comprehensive error handling
    
    Args:
        agent_name: Name of the agent for logging
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            agent = agent_name or func.__name__
            start_time = datetime.utcnow()
            
            try:
                logger.info(f"🔄 {agent} starting execution")
                result = await func(*args, **kwargs)
                execution_time = (datetime.utcnow() - start_time).total_seconds()
                logger.info(f"✅ {agent} completed successfully in {execution_time:.2f}s")
                return result
                
            except SearchResultError as e:
                logger.error(f"🔍 {agent} SearchResult error: {e}")
                return {
                    "status": "error",
                    "error_type": "search_result",
                    "message": str(e),
                    "agent": agent,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
            except ProfileUpdateError as e:
                logger.error(f"📊 {agent} Profile update error: {e}")
                return {
                    "status": "error",
                    "error_type": "profile_update",
                    "message": str(e),
                    "agent": agent,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
            except APIError as e:
                logger.error(f"🌐 {agent} API error: {e}")
                return {
                    "status": "error",
                    "error_type": "api",
                    "message": str(e),
                    "agent": agent,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
            except DataValidationError as e:
                logger.error(f"📋 {agent} Data validation error: {e}")
                return {
                    "status": "error",
                    "error_type": "validation",
                    "message": str(e),
                    "agent": agent,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
            except Exception as e:
                logger.error(f"❌ {agent} Unexpected error: {e}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                return {
                    "status": "error",
                    "error_type": "unexpected",
                    "message": str(e),
                    "agent": agent,
                    "timestamp": datetime.utcnow().isoformat(),
                    "traceback": traceback.format_exc()
                }
                
        return wrapper
    return decorator

def safe_search_result_access(search_result, field_name: str, default_value=None):
    """
    Safely access SearchResult object fields
    
    Args:
        search_result: SearchResult object
        field_name: Name of the field to access
        default_value: Default value if field doesn't exist
        
    Returns:
        Field value or default value
    """
    try:
        if hasattr(search_result, field_name):
            return getattr(search_result, field_name, default_value)
        elif hasattr(search_result, 'metadata') and search_result.metadata:
            return search_result.metadata.get(field_name, default_value)
        else:
            return default_value
    except Exception as e:
        logger.warning(f"Failed to access field '{field_name}' from SearchResult: {e}")
        return default_value

def validate_profile_data(profile_data: Dict[str, Any]) -> bool:
    """
    Validate profile data structure
    
    Args:
        profile_data: Profile data to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        required_fields = ["threat_actor"]
        for field in required_fields:
            if field not in profile_data or not profile_data[field]:
                logger.warning(f"Missing required field: {field}")
                return False
        return True
    except Exception as e:
        logger.error(f"Profile data validation failed: {e}")
        return False

def safe_metadata_extraction(search_result, expected_fields: list) -> Dict[str, Any]:
    """
    Safely extract metadata from SearchResult object
    
    Args:
        search_result: SearchResult object
        expected_fields: List of expected field names
        
    Returns:
        Dictionary with extracted metadata
    """
    metadata = {}
    
    try:
        # Try to get metadata from SearchResult object
        if hasattr(search_result, 'metadata') and search_result.metadata:
            for field in expected_fields:
                metadata[field] = search_result.metadata.get(field)
        else:
            # Fallback: try to extract from content
            content = getattr(search_result, 'content', '')
            for field in expected_fields:
                # Simple content parsing for common fields
                if field == 'threat_actor' and 'Threat Actor:' in content:
                    try:
                        threat_actor = content.split('Threat Actor:')[1].split()[0]
                        metadata[field] = threat_actor
                    except Exception:
                        metadata[field] = None
                else:
                    metadata[field] = None
                    
    except Exception as e:
        logger.warning(f"Failed to extract metadata: {e}")
        for field in expected_fields:
            metadata[field] = None
            
    return metadata

def handle_api_error(error: Exception, api_name: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Handle API errors gracefully
    
    Args:
        error: The exception that occurred
        api_name: Name of the API
        context: Additional context
        
    Returns:
        Error response dictionary
    """
    error_response = {
        "status": "error",
        "api": api_name,
        "error_type": type(error).__name__,
        "message": str(error),
        "timestamp": datetime.utcnow().isoformat(),
        "context": context or {}
    }
    
    if "401" in str(error):
        error_response["error_type"] = "authentication"
        error_response["message"] = f"{api_name} API authentication failed - check API key"
    elif "404" in str(error):
        error_response["error_type"] = "not_found"
        error_response["message"] = f"{api_name} API resource not found"
    elif "429" in str(error):
        error_response["error_type"] = "rate_limit"
        error_response["message"] = f"{api_name} API rate limit exceeded"
    
    logger.error(f"🌐 {api_name} API error: {error_response}")
    return error_response

def log_system_health(component: str, status: str, details: Dict[str, Any] = None):
    """
    Log system health information
    
    Args:
        component: Component name
        status: Health status (healthy, warning, error)
        details: Additional details
    """
    health_log = {
        "component": component,
        "status": status,
        "timestamp": datetime.utcnow().isoformat(),
        "details": details or {}
    }
    
    if status == "healthy":
        logger.info(f"✅ {component} health check passed")
    elif status == "warning":
        logger.warning(f"⚠️ {component} health check warning: {details}")
    elif status == "error":
        logger.error(f"❌ {component} health check failed: {details}")
    
    return health_log

def create_error_context(agent: str, task_type: str, parameters: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Create error context for better debugging
    
    Args:
        agent: Agent name
        task_type: Task type
        parameters: Task parameters
        
    Returns:
        Error context dictionary
    """
    return {
        "agent": agent,
        "task_type": task_type,
        "parameters": parameters or {},
        "timestamp": datetime.utcnow().isoformat(),
        "system_info": {
            "python_version": "3.9+",
            "platform": "agentic_cti_system"
        }
    } 