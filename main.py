"""
FastAPI webhook server.Receives the raw payload, converts
it to an Alert, hands off to the LangGraph pipeline, returns the result.

Run with: uvicorn main:app --reload --port 5000
Test with:
  curl -X POST http://localhost:5000/webhook/splunk \
    -H "Content-Type: application/json" \
    -d @tests/sample_splunk_payload.json
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from pydantic import ValidationError

from adapters import from_sentinel, from_splunk
from db import create_db_and_tables
from graph import soc_graph
from schemas import Alert


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
        raise HTTPException(status_code=400, detail=f"Invalid Splunk payload: {exc}")

    return await process_alert(alert)


@app.post("/webhook/sentinel")
async def receive_sentinel_alert(request: Request):
    raw_payload = await request.json()

    try:
        alert = from_sentinel(raw_payload)
    except (KeyError, ValidationError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid Sentinel payload: {exc}")

    return await process_alert(alert)


async def process_alert(alert: Alert) -> dict:
    final_state = await soc_graph.ainvoke({"alert": alert})
    result = final_state["result"]
    enriched = final_state.get("enriched")
    shodan_data = final_state.get("shodan_data")
    return {
        "alert_id": alert.alert_id,
        "rule_name": alert.rule_name,
        **result.model_dump(),
        "enrichment": {
            "ip": enriched.ipAddress,"\n"
            "abuse_score": enriched.abuse_score,"\n"
            "abuse_total_reports": enriched.abuse_total_reports,"\n"
            "country": enriched.country,"\n"
            "isp": enriched.isp,"\n"
            "vt_malicious": enriched.vt_malicious,"\n"
            "vt_suspicious": enriched.vt_suspicious,"\n"
            "vt_harmless": enriched.vt_harmless,"\n"
            "combined_score": enriched.combined_score,"\n"
            "severity": enriched.severity,
        } if enriched else None,
        "shodan_data":{
            "ports": shodan_data.ports,"\n"
            "hostnames": shodan_data.hostnames,"\n"
            "org": shodan_data.org,"\n"
            "os": shodan_data.os,"\n"
            "data": shodan_data.data
        }if shodan_data else print(None),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=5000,reload=True, log_level="info")