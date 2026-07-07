<h1>AI SOC Agent</h1>

AI SOC Agent is a FastAPI-based security triage service that receives Splunk and Sentinel alerts, normalizes them into a shared format, extracts IOCs, enriches network indicators, optionally queries Shodan, and returns a structured LLM-assisted triage result.

## Features
- Splunk webhook support
- Sentinel webhook support
- IOC extraction from incoming alerts
- IP enrichment using AbuseIPDB and VirusTotal
- Optional Shodan lookup for exposed hosts
- LLM-based triage verdict generation
- SQLite-backed caching for enriched IPs
- Slack webhook delivery for enriched LLM triage alerts

## Setup
1. Clone the repository.
```bash
git clone https://github.com/Mohkith/SOC-AI-agent.git
cd SOC-AI-agent
```

2. Create and activate a virtual environment.

Windows:
```powershell
python -m venv venv
.\.venv\Scripts\activate
```

macOS or Linux:
```bash
python3 -m venv venv
source .venv/bin/activate
```

3. Install dependencies.
```bash
pip install -r requirements.txt
```

4. Create your environment file.
```bash
copy .env.example .env
```

5. Add your API keys to `.env`.

## Environment Variables
- `ABUSEIP_API_KEY` - AbuseIPDB API key
- `VT_API_KEY` - VirusTotal API key
- `OLLAMA_API_KEY` - Ollama API key
- `SLACK_WEBHOOK_URL` - Slack incoming webhook URL for triage notifications

When `SLACK_WEBHOOK_URL` is set, each processed alert is posted to Slack with the verdict, confidence, priority, summary, and any enrichment context.

## Run the App
```bash
uvicorn main:app --reload --port 5000
```

## Example Request
```bash
curl -X POST http://localhost:5000/webhook/splunk \
	-H "Content-Type: application/json" \
	-d '<splunk alert>  
```

## Project Structure
- `main.py` - FastAPI app and webhook routes
- `graph.py` - LangGraph workflow and branching
- `schemas.py` - Pydantic and SQLModel data models
- `adapters.py` - Splunk and Sentinel payload conversion
- `enrichment.py` - Threat-intel enrichment helpers
- `shodan_client.py` - Shodan lookup logic
- `llm_client.py` - LLM triage request and parsing
- `db.py` - Database setup and IOC cache
- `prompts.py` - Prompt construction helpers
- `decisions.py` - Routing decisions for the graph
- `ip_utils.py` - IP parsing and helper utilities
- `slack.py` - Slack Integration









