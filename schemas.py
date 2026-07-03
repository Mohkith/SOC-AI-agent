"""
All Pydantic models live here — Alert (normalized SIEM alert),
ExtractedIOCs (what indicators this specific alert has),
and EnrichedIOC (threat intel results from AbuseIPDB + VirusTotal).
"""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, computed_field
from sqlmodel import SQLModel, Field as SQLField


class Alert(BaseModel): 

    alert_id: str
    rule_name: str

    siem_source: Literal["splunk", "sentinel"] = "splunk"
    severity: Literal["low", "medium", "high", "critical"] = "medium"

    # structured fields — code branches on these (internal IP check, etc.)
    src_ip: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    username: str | None = None
    hostname: str | None = None
    event_code: str | None = None
    event_count: int | None = None
    timeframe_minutes: int | None = None
    description: str | None = None
    log_snippet: str | None = None

    # escape hatch — every other field Splunk/Sentinel sent, untouched.
    # the LLM sees this in full even though our code doesn't parse it.
    raw_details: dict = Field(default_factory=dict)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    results_link: str | None = None


class ExtractedIOCs(BaseModel):
    """What IOCs (if any) this specific alert actually contains."""

    ips: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    has_network_ioc: bool = False


class AbuseIPresponse(BaseModel):
    ipAddress: str
    abuseConfidenceScore: int
    totalReports: int
    countryCode: str | None = None
    isp: str | None = None


class VTresponse(BaseModel):
    reputation: int
    country: str | None = None
    network: str | None = None
    categories: dict | None = None
    last_analysis_stats: dict | None = None
    last_analysis_results: dict | None = None


class ShodanResponse(BaseModel):
    
    ip_str: str
    ports: list[int] = []
    hostnames: list[str] = []
    org: str | None = None
    os: str | None = None
    data: list[dict] = []          # raw per-service banners (kept minimal in prompt)


class TriageResult(BaseModel):

    verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_INVESTIGATION"]
    confidence: int
    priority: int
    summary: str
    mitre_tactics: list[str] = []
    investigation_queries: list[str] = []
    rule_suggestion: str | None = None


class EnrichedIOC(SQLModel, table=True):

    __tablename__ = "iocs_cached"

    id: int | None = SQLField(default=None)
    ipAddress: str = SQLField(index=True,primary_key=True)

    abuse_score: int = 0
    abuse_total_reports: int = 0
    country: str | None = None
    isp: str | None = None

    vt_reputation: int = 0
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_harmless: int = 0
    vt_network: str | None = None

    enriched_at: datetime = SQLField(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @computed_field
    @property
    def combined_score(self) -> int:
        combined = int((self.abuse_score * 0.7) + (self.vt_malicious * 0.3))
        return min(combined, 100)

    @computed_field
    @property
    def severity(self) -> str:
        if self.combined_score >= 75:
            return "HIGH"
        elif self.combined_score >= 25:
            return "MEDIUM"
        return "LOW"