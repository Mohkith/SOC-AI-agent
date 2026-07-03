"""
Slack notifications — pushes only the alerts that actually need a human's
attention, formatted so the analyst can act on them quickly.
"""

import os
from dotenv import load_dotenv
import httpx

from schemas import Alert, TriageResult, EnrichedIOC

load_dotenv()

Slack_url = os.getenv("SLACK_WEBHOOK_URL")

Priority_threshold = 60


VERDICT_EMOJI = {
    "TRUE_POSITIVE": "🔴",
    "NEEDS_INVESTIGATION": "🟡",
    "FALSE_POSITIVE": "🟢",
}

def should_notify_slack(result: TriageResult) -> bool:
    if result.verdict == "NEEDS_INVESTIGATION":
        return True
    if result.verdict == "TRUE_POSITIVE" and result.priority >= Priority_threshold:
        return True
    return False

def _build_slack_blocks(alert: Alert, result: TriageResult, enriched: EnrichedIOC | None) -> dict:
    """
    Slack's Block Kit format — richer than plain text, renders as proper
    sections/fields instead of one wall of text.
    """
    emoji = VERDICT_EMOJI.get(result.verdict, "⚪")
 
    fields = [
        {"type": "mrkdwn", "text": f"*Verdict*\n{result.verdict}"},
        {"type": "mrkdwn", "text": f"*Confidence*\n{result.confidence}/100"},
        {"type": "mrkdwn", "text": f"*Priority*\n{result.priority}/100"},
        {"type": "mrkdwn", "text": f"*Source*\n{alert.siem_source}"},
    ]
 
    if alert.src_ip:
        fields.append({"type": "mrkdwn", "text": f"*Source IP*\n`{alert.src_ip}`"})
    if enriched:
        fields.append({
            "type": "mrkdwn",
            "text": f"*Threat Intel*\nAbuse: {enriched.abuse_score} · VT malicious: {enriched.vt_malicious}",
        })
 
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} {alert.rule_name}"},
        },
        {"type": "section", "fields": fields},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Analyst brief*\n{result.summary}"},
        },
    ]
 
    if result.mitre_tactics:
        tactics = ", ".join(f"`{t}`" for t in result.mitre_tactics)
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*MITRE ATT&CK*\n{tactics}"},
        })
 
    if result.investigation_queries:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Next query to run*\n```{result.investigation_queries[0]}```"},
        })
 
    if result.rule_suggestion:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Rule suggestion*\n{result.rule_suggestion}"},
        })
    
    if alert.results_link:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"<{alert.results_link}|Open original alert in {alert.siem_source.title()}>"},
        })  
 
    blocks.append({"type": "divider"})
 
    return {"blocks": blocks}
 
 
async def send_slack_alert(alert: Alert, result: TriageResult, enriched: EnrichedIOC | None) -> None:
    if not Slack_url:
        print("[Slack] skipped — SLACK_WEBHOOK_URL not set in environment")
        return
 
    if not should_notify_slack(result):
        return 
 
    payload = _build_slack_blocks(alert, result, enriched)
 
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(Slack_url, json=payload, timeout=10.0)
            response.raise_for_status()
        print(f"[Slack] notified: {alert.rule_name} ({result.verdict})")
    except httpx.HTTPStatusError as exc:
        print(f"[Slack] failed to send: HTTP {exc.response.status_code}: {exc.response.text}")
    except httpx.TimeoutException:
        print("[Slack] timed out sending notification")