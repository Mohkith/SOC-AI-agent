"""
LangGraph wiring. This is the single place the pipeline's flow is
defined — every node below wraps a function you already wrote in
another file. None of the actual logic lives here, only the wiring.
"""

from typing import TypedDict

from langgraph.graph import END, StateGraph

from decisions import should_query_shodan, is_internal_ip
from db import enrich_ip_all
from ip_utils import extract_iocs
from llm_client import triage_alert
from prompts import build_prompt
from schemas import Alert, EnrichedIOC, ExtractedIOCs, ShodanResponse, TriageResult
from shodan_client import enrich_shodan


class GraphState(TypedDict):
    alert: Alert
    iocs: ExtractedIOCs | None
    enriched: EnrichedIOC | None
    shodan_data: ShodanResponse | None
    prompt: str | None
    result: TriageResult | None


# ---- nodes ----

def extract_iocs_node(state: GraphState) -> dict:
    iocs = extract_iocs(state["alert"])
    return {"iocs": iocs}


async def enrich_node(state: GraphState) -> dict:
    iocs = state["iocs"]
    has_any_ioc = (
        iocs.ips
        or iocs.domain
        or iocs.file_hash
        or iocs.url
    )
    
    if not has_any_ioc:
        return {"enriched": None}

    if iocs.ips and is_internal_ip(iocs.ips[0]):
        print(f"  [skip] {iocs.ips[0]} is internal — skipping IP enrichment")
        if not iocs.domain and not iocs.file_hash and not iocs.url:
            return {"enriched": None}

    enriched = await enrich_ip_all(iocs)
    return {"enriched": enriched}


async def query_shodan_node(state: GraphState) -> dict:
    target_ip = state["iocs"].ips[0]
    shodan_data = await enrich_shodan(target_ip)
    return {"shodan_data": shodan_data}


def build_prompt_node(state: GraphState) -> dict:
    prompt = build_prompt(state["alert"], state.get("enriched"), state.get("shodan_data"))
    return {"prompt": prompt}


async def triage_node(state: GraphState) -> dict:
    result = await triage_alert(state["prompt"])
    return {"result": result}


# ---- conditional edge ----

def shodan_decision(state: GraphState) -> str: 
    """Returns the name of the next node — this IS the branch."""
    if should_query_shodan(state.get("enriched")):
        return "query_shodan"
    return "build_prompt"


# ---- assemble the graph ----

graph = StateGraph(GraphState)

graph.add_node("extract_iocs", extract_iocs_node)
graph.add_node("enrich", enrich_node)
graph.add_node("query_shodan", query_shodan_node)
graph.add_node("build_prompt", build_prompt_node)
graph.add_node("triage", triage_node)

graph.set_entry_point("extract_iocs")
graph.add_edge("extract_iocs", "enrich")

graph.add_conditional_edges(
    "enrich",
    shodan_decision,
    {
        "query_shodan": "query_shodan",
        "build_prompt": "build_prompt",
    },
)

graph.add_edge("query_shodan", "build_prompt")
graph.add_edge("build_prompt", "triage")
graph.add_edge("triage", END)

soc_graph = graph.compile() 


