from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class IOCType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    CVE = "cve"

class ConfidenceLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class DiamondModelComponent(BaseModel):
    """Base class for Diamond Model components"""
    id: str
    name: str
    description: str
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    sources: List[str] = []
    metadata: Dict[str, Any] = {}

class Adversary(DiamondModelComponent):
    """Diamond Model: Adversary component"""
    aliases: List[str] = []
    motivation: str = ""
    capabilities: List[str] = []
    resources: List[str] = []
    sophistication_level: str = "medium"
    country_of_origin: Optional[str] = None
    threat_level: str = "medium"

class Infrastructure(DiamondModelComponent):
    """Diamond Model: Infrastructure component"""
    ioc_type: IOCType
    value: str
    category: str = ""
    subcategory: str = ""
    enrichment_data: Dict[str, Any] = {}
    reputation_score: Optional[float] = None
    detection_rate: Optional[float] = None

class Victim(DiamondModelComponent):
    """Diamond Model: Victim component"""
    sector: str = ""
    industry: str = ""
    geography: str = ""
    organization_size: str = ""
    target_type: str = ""  # primary, secondary, tertiary
    attack_surface: List[str] = []

class Capability(DiamondModelComponent):
    """Diamond Model: Capability component"""
    mitre_technique: str = ""
    mitre_tactic: str = ""
    mitre_subtechnique: Optional[str] = None
    tools_used: List[str] = []
    malware_families: List[str] = []
    attack_vectors: List[str] = []
    complexity_level: str = "medium"

class DiamondModelProfile(BaseModel):
    """Complete Diamond Model threat actor profile"""
    threat_actor_id: str
    primary_name: str
    aliases: List[str] = []
    
    # Diamond Model Components
    adversary: Adversary
    infrastructure: List[Infrastructure] = []
    victims: List[Victim] = []
    capabilities: List[Capability] = []
    
    # Relationships and Connections
    relationships: Dict[str, List[str]] = {}  # component_id -> related_component_ids
    attack_chains: List[Dict[str, Any]] = []
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    confidence_score: float = 0.0
    source_count: int = 0
    
    # Analysis metadata
    last_analysis: Optional[datetime] = None
    analysis_delta: Dict[str, Any] = {}  # Track changes between analyses
    intelligence_gaps: List[str] = []

class ThreatActorProfileUpdate(BaseModel):
    """Delta update for threat actor profile"""
    threat_actor_id: str
    update_type: str  # "new_component", "updated_component", "new_relationship", "intelligence_gap"
    component_type: str  # "adversary", "infrastructure", "victim", "capability"
    component_id: str
    old_value: Optional[Dict[str, Any]] = None
    new_value: Optional[Dict[str, Any]] = None
    confidence_change: float = 0.0
    source_count_change: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    analysis_session_id: str = ""

class ThreatQuery(BaseModel):
    """Threat intelligence query model"""
    query_id: Optional[str] = None
    analyst_name: str
    focus_actor: Optional[str] = None
    time_window: Optional[str] = None
    need: List[str] = []
    format: str = "attack_brief"
    
    class Config:
        json_schema_extra = {
            "example": {
                "analyst_name": "Aditi",
                "focus_actor": "FIN7",
                "time_window": "2025-06-01/2025-07-12",
                "need": ["latest TTPs", "notable campaigns", "IOCs list", "MITRE mapping"],
                "format": "attack_brief"
            }
        }

class ThreatBrief(BaseModel):
    """Threat intelligence brief model"""
    threat_actor: Optional[str] = None
    executive_summary: str
    tactics_techniques: List[str] = []
    iocs: List[Dict[str, Any]] = []
    campaign_timeline: List[Dict[str, Any]] = []
    confidence_score: float = 0.0
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_schema_extra = {
            "example": {
                "executive_summary": "FIN7 has been observed using new BULLETFLAYER loader...",
                "tactics_techniques": [
                    "T1566.001 (Phishing: Spearphishing Attachment)",
                    "T1071.004 (Application Layer Protocol: DNS)"
                ],
                "iocs": [
                    {
                        "type": "hash",
                        "value": "a1b2c3d4e5f6...",
                        "confidence": "high"
                    }
                ],
                "campaign_timeline": [
                    {
                        "date": "2025-06-18",
                        "event": "New BULLETFLAYER loader observed"
                    }
                ],
                "references": ["CS_2025_06_FIN7"],
                "confidence_score": 0.85
            }
        }

class SearchResult(BaseModel):
    """Search result model"""
    doc_id: str
    title: str
    content: str
    score: float
    metadata: Dict[str, Any] = {}

class IOCEnrichment(BaseModel):
    """IOC enrichment model"""
    ioc_type: IOCType
    value: str
    enrichment_data: Dict[str, Any] = {}
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    sources: List[str] = []

class CTIDocument(BaseModel):
    """CTI document model"""
    doc_id: str
    title: str
    content: str
    date_pub: datetime
    source: str
    threat_actor: Optional[str] = None
    operation: Optional[str] = None
    mitre_id: Optional[str] = None
    ioc_type: Optional[IOCType] = None
    geo_scope: Optional[str] = None
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    language: str = "en"
    content_vector: Optional[List[float]] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        } 