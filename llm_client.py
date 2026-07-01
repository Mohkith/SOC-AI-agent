"""
LLM client for Ollama-compatible chat endpoints.

Sends the prompt built by prompts.py, gets text back, and validates it
against TriageResult.

If the model's JSON doesn't validate (rare, but happens), we retry once
with a stricter follow-up instruction before giving up.
"""

import json
import os

import httpx
from dotenv import load_dotenv
from pydantic import ValidationError

from prompts import SYSTEM_PROMPT
from schemas import TriageResult

load_dotenv()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "nemotron-3-super:cloud")
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY")


def _ollama_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if OLLAMA_API_KEY:
        headers["Authorization"] = f"Bearer {OLLAMA_API_KEY}"
    return headers


def _extract_json(text: str) -> str:
    
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    return text.strip()


async def triage_alert(prompt: str) -> TriageResult:
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "options": {"temperature": 0},
    }

    async with httpx.AsyncClient(
        base_url=OLLAMA_BASE_URL,
        headers=_ollama_headers(),
        timeout=120.0,
    ) as client:
        response = await client.post("/api/chat", json=payload)
        response.raise_for_status()
        raw_text = response.json()["message"]["content"]

    try:
        cleaned = _extract_json(raw_text)
        data = json.loads(cleaned)
        return TriageResult(**data)
    except (json.JSONDecodeError, ValidationError) as exc:
        print(f"[LLM] first parse failed: {exc}. Retrying with stricter instruction.")

        retry_payload = {
            "model": OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": raw_text},
                {
                    "role": "user",
                    "content": (
                        "That was not valid JSON matching the required schema. "
                        "Respond with ONLY the JSON object, no markdown fences, "
                        "no preamble, no explanation."
                    ),
                },
            ],
            "stream": False,
            "options": {"temperature": 0},
        }

        async with httpx.AsyncClient(
            base_url=OLLAMA_BASE_URL,
            headers=_ollama_headers(),
            timeout=120.0,
        ) as client:
            retry_response = await client.post("/api/chat", json=retry_payload)
            retry_response.raise_for_status()
            retry_text = retry_response.json()["message"]["content"]

        cleaned = _extract_json(retry_text)
        data = json.loads(cleaned)  # let this raise if it fails twice — surfaces as a 500
        return TriageResult(**data)