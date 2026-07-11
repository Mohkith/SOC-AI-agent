"""
FastAPI webhook server.Receives the raw payload, converts
it to an Alert, hands off to the LangGraph pipeline, returns the result.

Run with: uvicorn main:app --reload --port 5000
Test with:
  curl -X POST http://localhost:5000/webhook/splunk \
    -H "Content-Type: application/json" \
    -d "Splunk_alert.json"
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from pydantic import ValidationError
from dotenv import load_dotenv

from adapters import from_sentinel, from_splunk
from db import create_db_and_tables
from graph import soc_graph
from schemas import Alert
from slack import send_slack_alert

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(lifespan=lifespan)


@app.post("/webhook/splunk")
async def receive_splunk_alert(request: Request):
    raw_payload = await request.json()

    try:
        alert = from_splunk(raw_payload)
    except (KeyError, ValidationError) as exc:
        print(f"[Splunk] payload validation failed: {exc}")
        if isinstance(exc, ValidationError):
            print(f"[Splunk] validation details: {exc.errors()}")
        raise HTTPException(status_code=400, detail=f"Invalid Splunk payload: {exc}")
    
    return await process_alert(alert)


@app.post("/webhook/sentinel")
async def receive_sentinel_alert(request: Request):
    raw_payload = await request.json()

    try:
        alert = from_sentinel(raw_payload)
    except (KeyError, ValidationError) as exc:
        print(f"[Sentinel] payload validation failed: {exc}")
        if isinstance(exc, ValidationError):
            print(f"[Sentinel] validation details: {exc.errors()}")
        raise HTTPException(status_code=400, detail=f"Invalid Sentinel payload: {exc}")

    return await process_alert(alert)


async def process_alert(alert: Alert) -> dict:
    final_state = await soc_graph.ainvoke({"alert": alert})
    result = final_state["result"]
    enriched = final_state.get("enriched")
    shodan_data = final_state.get("shodan_data")    

    response = {
        "alert_id": alert.alert_id,
        "rule_name": alert.rule_name,
        **result.model_dump(),
        "enrichment": {
            "ip": enriched.ipAddress,
            "abuse_score": enriched.abuse_score,
            "abuse_total_reports": enriched.abuse_total_reports,
            "country": enriched.country,
            "isp": enriched.isp,
            "vt_malicious": enriched.vt_malicious,
            "vt_suspicious": enriched.vt_suspicious,
            "vt_harmless": enriched.vt_harmless,
            "combined_score": enriched.combined_score,
            "severity": enriched.severity,
            "domain": enriched.domain_enriched,
            "vt_domain_malicious": enriched.vt_domain_malicious,
            "vt_domain_suspicious": enriched.vt_domain_suspicious,
            "vt_domain_harmless": enriched.vt_domain_harmless,
            "hash": enriched.hash_enriched,
            "vt_hash_malicious": enriched.vt_hash_malicious,
            "vt_hash_suspicious": enriched.vt_hash_suspicious,
            "vt_hash_harmless": enriched.vt_hash_harmless,
            "url": enriched.url_enriched,
            "vt_url_malicious": enriched.vt_url_malicious,
            "vt_url_suspicious": enriched.vt_url_suspicious,
            "vt_url_harmless": enriched.vt_url_harmless,
        } if enriched else None,
        "shodan_data": {
            "isp": shodan_data.isp,
            "asn": shodan_data.asn,
            "ports": shodan_data.ports,
            "hostnames": shodan_data.hostnames,
            "org": shodan_data.org,
            "os": shodan_data.os,
            "data": shodan_data.data,
        } if shodan_data else None,
    }

    await send_slack_alert(alert, result, enriched)
    return response

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=5000,reload=True, log_level="info")