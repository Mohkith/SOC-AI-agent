"""
SQLite cache for EnrichedIOC — avoids re-querying AbuseIPDB/VirusTotal
for the same IP within a 24-hour window.
"""

from datetime import datetime, timedelta, timezone
from sqlmodel import Session, SQLModel, create_engine, select

from enrichment import build_enriched_ioc, enrich_abuseipdb, enrich_virustotal
from schemas import EnrichedIOC

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

async def enrich_ip_all(ip: str) -> EnrichedIOC:
    """The single entry point everything else calls: cache check, then
    enrich + save on a miss."""
    import asyncio

    cached = get_cached(ip)
    if cached:
        print(f"  [cache hit] {ip}")
        return cached

    abuse_data, vt_data = await asyncio.gather(
        enrich_abuseipdb(ip), enrich_virustotal(ip), return_exceptions=True
    ) # return_exceptions= True allows the function to return exceptions, so that it does not block the execution of other tasks 
    abuse_data = abuse_data if not isinstance(abuse_data, Exception) else None # isintance checks whether a value is of a given type 
    vt_data = vt_data if not isinstance(vt_data, Exception) else None
    
    ioc = build_enriched_ioc(ip, abuse_data, vt_data)
    save_ioc(ioc)
    return ioc