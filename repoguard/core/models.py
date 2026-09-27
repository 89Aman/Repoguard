from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class OWASPCategory(str, Enum):
    A01 = "A01:2021 - Broken Access Control"
    A02 = "A02:2021 - Cryptographic Failures"
    A03 = "A03:2021 - Injection"
    A04 = "A04:2021 - Insecure Design"
    A05 = "A05:2021 - Security Misconfiguration"
    A06 = "A06:2021 - Vulnerable and Outdated Components"
    A07 = "A07:2021 - Identification and Authentication Failures"
    A08 = "A08:2021 - Software and Data Integrity Failures"
    A09 = "A09:2021 - Security Logging and Monitoring Failures"
    A10 = "A10:2021 - Server-Side Request Forgery"


class FindingSource(str, Enum):
    DEPENDENCIES = "DEPENDENCIES"
    SAST = "SAST"
    SECRETS = "SECRETS"
    CONFIGURATION = "CONFIGURATION"
    REPO_HYGIENE = "REPO_HYGIENE"
    API_DISCOVERY = "API_DISCOVERY"
    DAST_APP = "DAST_APP"
    DAST_API = "DAST_API"


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    owasp_category: str
    source: FindingSource
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    endpoint: Optional[str] = None
    http_method: Optional[str] = None
    description: str
    offending_snippet: Optional[str] = None
    request_detail: Optional[str] = None
    response_detail: Optional[str] = None
    fix: str


class EndpointAuthStatus(str, Enum):
    PROTECTED = "PROTECTED"
    UNPROTECTED = "UNPROTECTED"
    ALLOW_ANY_DEFAULT = "ALLOW_ANY_DEFAULT"
    PUBLIC = "PUBLIC"


class EndpointInfo(BaseModel):
    path: str
    http_methods: List[str] = Field(default_factory=list)
    handler: str
    auth_classes: List[str] = Field(default_factory=list)
    permission_classes: List[str] = Field(default_factory=list)
    status: EndpointAuthStatus
    is_flagged: bool = False
    notes: str = ""


class ScanSummary(BaseModel):
    target_path: str
    target_url: Optional[str] = None
    scanned_at: str
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    total_endpoints: int = 0
    unprotected_endpoints: int = 0


class ReportData(BaseModel):
    summary: ScanSummary
    findings: List[Finding] = Field(default_factory=list)
    endpoints: List[EndpointInfo] = Field(default_factory=list)
    top_fixes: List[Finding] = Field(default_factory=list)
