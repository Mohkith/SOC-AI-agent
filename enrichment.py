"""
Threat intel enrichment — AbuseIPDB + VirusTotal called in parallel,
merged into one EnrichedIOC. This is your existing Phase 1/2 code,
moved into its own module.
"""

import os

import httpx
from dotenv import load_dotenv

from schemas import AbuseIPresponse, EnrichedIOC, VTresponse

load_dotenv()

ABUSEIP_API_KEY = os.getenv("ABUSEIP_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIP_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
VT_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"


async def enrich_abuseipdb(ip_address: str) -> AbuseIPresponse | None:
    if not ABUSEIP_API_KEY:
        print("[AbuseIPDB] skipped — ABUSEIP_API_KEY not set in environment")
        return None

    headers = {"Key": ABUSEIP_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip_address}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                ABUSEIP_BASE_URL, params=params, headers=headers, timeout=10.0
            )
            response.raise_for_status()
    except httpx.TimeoutException as exc:
        print(f"[AbuseIPDB] timed out: {exc}")
        return None
    except httpx.HTTPStatusError as exc:
        print(f"[AbuseIPDB] HTTP {exc.response.status_code}: {exc.response.text}")
        return None

    try:
        return AbuseIPresponse(**response.json()["data"])
    except Exception as exc:
        print(f"[AbuseIPDB] failed to parse response: {exc}")
        return None


async def enrich_virustotal(ip_address: str) -> VTresponse | None:
    if not VT_API_KEY:
        print("[VirusTotal] skipped — VT_API_KEY not set in environment")
        return None

    headers = {"x-apikey": VT_API_KEY, "accept": "application/json"}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                VT_BASE_URL + ip_address, headers=headers, timeout=10.0
            )
            response.raise_for_status()
    except httpx.TimeoutException as exc:
        print(f"[VirusTotal] timed out: {exc}")
        return None
    except httpx.HTTPStatusError as exc:
        print(f"[VirusTotal] HTTP {exc.response.status_code}: {exc.response.text}")
        return None

    try:
        return VTresponse(**response.json()["data"]["attributes"])
    except Exception as exc:
        print(f"[VirusTotal] failed to parse response: {exc}")
        return None


def build_enriched_ioc(
    ip: str,
    abuse_data: AbuseIPresponse | None,
    vt_data: VTresponse | None,
) -> EnrichedIOC:
    stats = vt_data.last_analysis_stats if vt_data and vt_data.last_analysis_stats else {}

    country = (
        (abuse_data.countryCode if abuse_data else None)
        or (vt_data.country if vt_data else None)
    )

    return EnrichedIOC(
        ipAddress=ip,
        abuse_score=abuse_data.abuseConfidenceScore if abuse_data else 0,
        abuse_total_reports=abuse_data.totalReports if abuse_data else 0,
        country=country,
        isp=abuse_data.isp if abuse_data else None,
        vt_reputation=vt_data.reputation if vt_data else 0,
        vt_malicious=stats.get("malicious", 0),
        vt_suspicious=stats.get("suspicious", 0),
        vt_harmless=stats.get("harmless", 0),
        vt_network=vt_data.network if vt_data else None,
    )