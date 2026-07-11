"""
Threat intel enrichment — AbuseIPDB + VirusTotal called in parallel,
merged into one EnrichedIOC.
"""

import os
import base64
from urllib.parse import quote
import httpx
from dotenv import load_dotenv
import json

from schemas import AbuseIPresponse, EnrichedIOC, VTresponse, USresponse, URLEnrichment

load_dotenv()
ABUSEIP_API_KEY = os.getenv("ABUSEIP_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
US_API_KEY = os.getenv("US_API_KEY")
ABUSEIP_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
VT_IP_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
VT_HASH_BASE_URL = "https://www.virustotal.com/api/v3/files/"
VT_DOMAIN_BASE_URL = "https://www.virustotal.com/api/v3/domains/"
VT_URL_BASE_URL = "https://www.virustotal.com/api/v3/urls/"
US_BASE_URL = "https://urlscan.io/api/v1/"


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
                VT_IP_BASE_URL + ip_address, headers=headers, timeout=10.0
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


async def enrich_hash_vt(hash_value: str) -> VTresponse | None:
    if not VT_API_KEY:
        print("[VirusTotal] skipped — VT_API_KEY not set in environment")
        return None

    headers = {"x-apikey": VT_API_KEY, "accept": "application/json"}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                VT_HASH_BASE_URL + hash_value, headers=headers, timeout=10.0
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


async def enrich_domain_VT(domain: str) -> VTresponse | None:
    if not VT_API_KEY:
        print("[VirusTotal] skipped — VT_API_KEY not set in environment")
        return None

    headers = {"x-apikey": VT_API_KEY, "accept": "application/json"}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                VT_DOMAIN_BASE_URL + domain, headers=headers, timeout=10.0
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


async def enrich_virustotal_url(url: str) -> VTresponse | None:
    if not VT_API_KEY:
        print("[VirusTotal] skipped — VT_API_KEY not set in environment")
        return None

    # Encode the URL for VT ID (base64url without padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    headers = {"x-apikey": VT_API_KEY, "accept": "application/json"}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                VT_URL_BASE_URL + url_id, headers=headers, timeout=10.0
            )
            response.raise_for_status()
    except httpx.TimeoutException as exc:
        print(f"[VirusTotal] timed out: {exc}")
        return None
    except httpx.HTTPStatusError as exc:
        print(f"[VirusTotal] HTTP {exc.response.status_code}: {exc.response.text}")
        return None

    try:
        # The response JSON has a "data" object with "attributes"
        return VTresponse(**response.json()["data"]["attributes"])
    except Exception as exc:
        print(f"[VirusTotal] failed to parse response: {exc}")
        return None


async def enrich_urlscan(url: str) -> USresponse | None:
    if not US_API_KEY:
        print("[UrlScan] skipped — US_API_KEY not set in environment")
        return None

    headers = {"API-KEY": US_API_KEY, "Content-Type": "application/json"}
    # URL encode the query parameter
    encoded_url = quote(url, safe='')

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{US_BASE_URL}search/?q={encoded_url}", headers=headers, timeout=10.0
            )
            response.raise_for_status()
    except httpx.TimeoutException as exc:
        print(f"[UrlScan] timed out: {exc}")
        return None
    except httpx.HTTPStatusError as exc:
        print(f"[UrlScan] HTTP {exc.response.status_code}: {exc.response.text}")
        return None

    try:
        data = response.json()
        results = data.get("results", [])
        if not results:
            print(f"[UrlScan] no results found for URL: {url}")
            return None
        # Take the first result (most recent)
        result = results[0]
        verdicts = result.get("verdicts")
        stats = result.get("stats")
        # Extract URL and domain from the result
        url_from_task = result.get("task", {}).get("url")
        url_from_page = result.get("page", {}).get("url")
        url_value = url_from_task or url_from_page or url
        domain = result.get("page", {}).get("domain")

        return USresponse(
            verdicts=verdicts,
            stats=stats,
            url=url_value,
            domain=domain
        )
    except Exception as exc:
        print(f"[UrlScan] failed to parse response: {exc}")
        return None


async def enrich_url(url: str) -> URLEnrichment | None:
    """Enrich a URL with VirusTotal and UrlScan data."""
    if not VT_API_KEY and not US_API_KEY:
        print("[URL Enrichment] skipped — no API keys set")
        return None
    import asyncio
    vt_task = None
    us_task = None
    if VT_API_KEY:
        vt_task = asyncio.create_task(enrich_virustotal_url(url))
    if US_API_KEY:
        us_task = asyncio.create_task(enrich_urlscan(url))
    vt_result = None
    us_result = None
    if vt_task:
        try:
            vt_result = await vt_task
        except Exception as exc:
            print(f"[VT URL] error: {exc}")
    if us_task:
        try:
            us_result = await us_task
        except Exception as exc:
            print(f"[URLScan] error: {exc}")
    if vt_result is None and us_result is None:
        return None
    return URLEnrichment(url=url, vt=vt_result, urlscan=us_result)


def build_enriched_ioc(
    ip: str,
    abuse_data: AbuseIPresponse | None,
    vt_data: VTresponse | None,
    domain: str | None = None,
    domain_vt: VTresponse | None = None,
    hash_value: str | None = None,
    hash_vt: VTresponse | None = None,
    url: str | None = None,
    url_vt: VTresponse | None = None,
) -> EnrichedIOC:
    stats = vt_data.last_analysis_stats if vt_data and vt_data.last_analysis_stats else {}
    domain_stats = domain_vt.last_analysis_stats if domain_vt and domain_vt.last_analysis_stats else {}
    hash_stats = hash_vt.last_analysis_stats if hash_vt and hash_vt.last_analysis_stats else {}
    url_stats = url_vt.last_analysis_stats if url_vt and url_vt.last_analysis_stats else {}

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
        domain_enriched=domain,
        vt_domain_malicious=domain_stats.get("malicious", 0),
        vt_domain_suspicious=domain_stats.get("suspicious", 0),
        vt_domain_harmless=domain_stats.get("harmless", 0),
        hash_enriched=hash_value,
        vt_hash_malicious=hash_stats.get("malicious", 0),
        vt_hash_suspicious=hash_stats.get("suspicious", 0),
        vt_hash_harmless=hash_stats.get("harmless", 0),
        url_enriched=url,
        vt_url_malicious=url_stats.get("malicious", 0),
        vt_url_suspicious=url_stats.get("suspicious", 0),
        vt_url_harmless=url_stats.get("harmless", 0),
    )