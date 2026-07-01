"""
Shodan client — fetches exposure data (open ports, services, known CVEs)
for an IP. Same async/httpx pattern as enrich_abuseipdb / enrich_virustotal
in enrichment.py.
"""

import os

import httpx
from dotenv import load_dotenv

from schemas import ShodanResponse

load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
SHODAN_BASE_URL = "https://api.shodan.io/shodan/host/"


async def enrich_shodan(ip_address: str) -> ShodanResponse | None:
    if not SHODAN_API_KEY:
        print("[Shodan] skipped — SHODAN_API_KEY not set in environment")
        return None

    params = {"key": SHODAN_API_KEY}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                SHODAN_BASE_URL + ip_address, params=params, timeout=10.0
            )
            response.raise_for_status()
    except httpx.TimeoutException as exc:
        print(f"[Shodan] timed out: {exc}")
        return None
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            # Shodan has no data on this IP at all — not an error, just empty
            print(f"[Shodan] no data found for {ip_address}")
            return None
        print(f"[Shodan] HTTP {exc.response.status_code}: {exc.response.text}")
        return None

    raw = response.json()
    try:
        return ShodanResponse(
            ip_str=raw.get("ip_str", ip_address),
            ports=raw.get("ports", []),
            hostnames=raw.get("hostnames", []),
            org=raw.get("org"),
            os=raw.get("os"),
            data=[
                {
                    "port": entry.get("port"),
                    "product": entry.get("product"),
                    "version": entry.get("version"),
                }
                for entry in raw.get("data", [])
            ],
        )
    except Exception as exc:
        print(f"[Shodan] failed to parse response: {exc}")
        return None 