"""
SQLite cache for EnrichedIOC — avoids re-querying AbuseIPDB/VirusTotal
for the same IP within a 24-hour window.
"""

from datetime import datetime, timedelta, timezone
from sqlmodel import Session, SQLModel, create_engine, select

from enrichment import (
    build_enriched_ioc,
    enrich_abuseipdb,
    enrich_virustotal,
    enrich_domain_VT,
    enrich_hash_vt,
    enrich_virustotal_url,
)
from schemas import EnrichedIOC, ExtractedIOCs

engine = create_engine("sqlite:///enriched_iocs.db") # engine tells SQLModel where to store the database, how to connect and what type of database to use. 


def create_db_and_tables() -> None:
    SQLModel.metadata.create_all(engine)             # creates the database and tables based on the defined SQLModel classes.


def get_cached(ip: str) -> EnrichedIOC | None:
    with Session(engine, expire_on_commit=False) as session:
        statement = select(EnrichedIOC).where(EnrichedIOC.ipAddress == ip)
        result = session.exec(statement).first()

        if result is None:
            return None

        age = datetime.now(timezone.utc) - result.enriched_at.replace(tzinfo=timezone.utc)
        if age > timedelta(hours=24):
            session.delete(result)
            session.commit()
            return None

        return result 


def save_ioc(ioc: EnrichedIOC) -> None:
    with Session(engine,expire_on_commit=False) as session:
        session.add(ioc)
        session.commit()
        session.refresh(ioc)

async def enrich_ip_all(iocs: ExtractedIOCs) -> EnrichedIOC:
    """The single entry point everything else calls: cache check, then
    enrich + save on a miss. Enriches IP (AbuseIPDB + VT) plus
    domain, hash, and URL via VT in parallel."""
    import asyncio

    target_ip = iocs.ips[0] if iocs.ips else None

    if target_ip:
        cached = get_cached(target_ip)
        if cached:
            print(f"  [cache hit] {target_ip}")
            return cached

    tasks = {}
    if target_ip:
        tasks["abuse"] = enrich_abuseipdb(target_ip)
        tasks["vt_ip"] = enrich_virustotal(target_ip)
    if iocs.domain:
        tasks["vt_domain"] = enrich_domain_VT(iocs.domain[0])
    if iocs.file_hash:
        tasks["vt_hash"] = enrich_hash_vt(iocs.file_hash[0])
    if iocs.url:
        tasks["vt_url"] = enrich_virustotal_url(iocs.url[0])

    if not tasks:
        placeholder_ip = target_ip or "no-ip"
        return EnrichedIOC(ipAddress=placeholder_ip)

    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    result_map = {}
    for key, val in zip(tasks.keys(), results):
        result_map[key] = val if not isinstance(val, Exception) else None

    abuse_data = result_map.get("abuse")
    vt_data = result_map.get("vt_ip")
    domain_vt = result_map.get("vt_domain")
    hash_vt = result_map.get("vt_hash")
    url_vt = result_map.get("vt_url")

    domain = iocs.domain[0] if iocs.domain else None
    hash_value = iocs.file_hash[0] if iocs.file_hash else None
    url = iocs.url[0] if iocs.url else None

    ioc = build_enriched_ioc(
        ip=target_ip or "no-ip",
        abuse_data=abuse_data,
        vt_data=vt_data,
        domain=domain,
        domain_vt=domain_vt,
        hash_value=hash_value,
        hash_vt=hash_vt,
        url=url,
        url_vt=url_vt,
    )
    save_ioc(ioc)
    return ioc