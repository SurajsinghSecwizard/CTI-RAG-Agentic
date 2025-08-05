"""
Utilities for the Agentic CTI System
"""

from .error_handler import (
    AgenticError,
    SearchResultError,
    ProfileUpdateError,
    APIError,
    DataValidationError,
    safe_agent_execution,
    safe_search_result_access,
    validate_profile_data,
    safe_metadata_extraction,
    handle_api_error,
    log_system_health,
    create_error_context
)

__all__ = [
    'AgenticError',
    'SearchResultError', 
    'ProfileUpdateError',
    'APIError',
    'DataValidationError',
    'safe_agent_execution',
    'safe_search_result_access',
    'validate_profile_data',
    'safe_metadata_extraction',
    'handle_api_error',
    'log_system_health',
    'create_error_context'
] 