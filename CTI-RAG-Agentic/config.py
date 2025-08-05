import os
from dotenv import load_dotenv
from typing import Optional

# Load environment variables
load_dotenv()

class Config:
    """Application configuration class"""
    
    # OpenAI Configuration (from .env file)
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_API_BASE: str = os.getenv("OPENAI_API_BASE", "")
    OPENAI_API_VERSION: str = os.getenv("OPENAI_API_VERSION", "2024-12-01-preview")
    OPENAI_DEPLOYMENT_NAME: str = os.getenv("OPENAI_DEPLOYMENT_NAME", "gpt-4o")
    
    # Azure OpenAI Configuration (mapped from .env variables)
    AZURE_OPENAI_ENDPOINT: str = os.getenv("OPENAI_API_BASE", "")  # Map from OPENAI_API_BASE
    AZURE_OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")    # Map from OPENAI_API_KEY
    AZURE_OPENAI_API_VERSION: str = os.getenv("OPENAI_API_VERSION", "2024-12-01-preview")
    AZURE_OPENAI_DEPLOYMENT_NAME: str = os.getenv("OPENAI_DEPLOYMENT_NAME", "gpt-4o")
    
    # Azure Configuration
    AZURE_SEARCH_ENDPOINT: str = os.getenv("AZURE_SEARCH_ENDPOINT", "")
    AZURE_SEARCH_KEY: str = os.getenv("AZURE_SEARCH_KEY", "")
    AZURE_SEARCH_INDEX_NAME: str = os.getenv("AZURE_SEARCH_INDEX_NAME", "cti-kb-index")
    
    # Azure Storage
    AZURE_STORAGE_CONNECTION_STRING: str = os.getenv("AZURE_STORAGE_CONNECTION_STRING", "")
    AZURE_STORAGE_CONTAINER_NAME: str = os.getenv("AZURE_STORAGE_CONTAINER_NAME", "cti-documents")
    
    # External APIs
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSE_CH_API_KEY: str = os.getenv("ABUSE_CH_API_KEY", "")
    
    # Redis Configuration
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    # Application Settings
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    MAX_TOKENS: int = int(os.getenv("MAX_TOKENS", "4000"))
    TEMPERATURE: float = float(os.getenv("TEMPERATURE", "0.1"))
    
    # RAG Settings
    CHUNK_SIZE: int = 400
    CHUNK_OVERLAP: int = 50
    TOP_K_RETRIEVAL: int = 10
    
    # Vector Store Configuration (local vector store removed)
    # USE_LOCAL_VECTORSTORE: bool = os.getenv("USE_LOCAL_VECTORSTORE", "true").lower() == "true"
    # LOCAL_VECTORSTORE_PATH: str = os.getenv("LOCAL_VECTORSTORE_PATH", "./vectorstore")
    
    # Sample threat actors for testing
    SAMPLE_ACTORS = [
        "FIN7", "APT29", "Lazarus", "Volt Typhoon", "APT41", 
        "APT28", "APT1", "Carbanak", "Cobalt Strike", "Emotet"
    ]
    
    def __init__(self):
        """Initialize config instance - this allows instantiation without breaking existing functionality"""
        # This method allows the class to be instantiated
        # All configuration values are accessed as class attributes
        pass
    
    @classmethod
    def validate(cls) -> bool:
        """Validate required configuration"""
        required_vars = [
            "OPENAI_API_KEY",      # Required for Azure OpenAI
            "OPENAI_API_BASE"      # Required for Azure OpenAI endpoint
        ]
        
        # For local development, Azure Search is optional
        # if not cls.USE_LOCAL_VECTORSTORE:
        #     required_vars.extend([
        #         "AZURE_SEARCH_ENDPOINT", 
        #         "AZURE_SEARCH_KEY"
        #     ])
        
        missing_vars = []
        for var in required_vars:
            if not getattr(cls, var):
                missing_vars.append(var)
        
        if missing_vars:
            print(f"Missing required environment variables: {missing_vars}")
            return False
        
        return True

# No module-level instance needed - we'll use config.Config() directly 