"""
Builds the final text that gets sent to the LLM. This is the convergence
point of the whole pipeline: structured Alert fields (used for code-level
branching upstream) + EnrichedIOC threat intel (if enrichment ran) +
raw_details (everything else Splunk sent, untouched, for the model to read).
"""

import json

from schemas import Alert, EnrichedIOC, ShodanResponse

SYSTEM_PROMPT = """You are a SOC L2 security analyst reviewing an alert escalated by an L1 analyst.

Analyze the alert and any threat intelligence provided below. Return ONLY valid JSON
matching this exact schema, with no other text:

{
  "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE" | "NEEDS_INVESTIGATION",
  "AbuseIPDB_Enrichment": "<include the ABUSEIPDB reports, if no enrichemnt, return 'none'>",
  "Virsutotal_Enrichemnt": "<include the VT reports, if no enrichment, return 'none'>",
  "confidence": <int 0-100>,
  "priority": <int 0-100>,
  "summary": "<2-3 sentence analyst brief; include MITRE ATT&CK IDs and technique names inline when relevant>",
  "next_steps": ["<short analyst action 1>", "<short analyst action 2>", "<short analyst action 3>"],
  "mitre_tactics": ["T1110", "T1078"],
  "investigation_queries": ["<SPL or KQL query string>"],
  "rule_suggestion": "<only if verdict is FALSE_POSITIVE, else  print null>"
}

Summary formatting rules:
- When a MITRE ATT&CK technique is relevant, mention it inline in the summary using the format `Txxxx - Technique Name`.
- Keep the summary to 2-3 sentences, but make sure the ATT&CK technique IDs and names are readable to an analyst.
- If multiple techniques are relevant, include the most important ones rather than listing every possible technique.

Next steps rules:
- Return 2 to 5 concise, practical actions the analyst should take next.
- Phrase each item as a concrete action, such as validate the host/user, check recent logon or process activity, compare with admin change windows, or confirm whether the activity matches expected behavior.
- The steps should help the analyst decide whether this is a true positive or a false positive.
- Keep the items specific to the alert context; do not use generic advice.
- Do not repeat the summary or investigation queries verbatim.

Rules for investigation_queries:
- Only generate concise, analyst-useful queries; prefer 1 to 3 queries total.
- Do not invent an index name. Include `index=` only if it is explicitly present in the alert or raw details.
- If the alert does not provide an index, omit `index=` entirely and write the query using only fields that are actually present.
- Keep each query focused on one purpose, for example: confirm the alert event, check related process activity, or look for the same host/user in a narrow time window.
- Do not chain unrelated searches into one long query.
- Do not repeat the same search with trivial formatting changes.
- For a log-cleared alert, prefer queries centered on the alert's event code, host, user, and nearby activity rather than a broad catch-all search.
- Return EACH query as a SEPARATE string in the list — never combine multiple
  searches into one string with commas.
- Each query must be syntactically valid, runnable SPL on its own.
- Use ONLY real SPL syntax: index, sourcetype, search terms, | stats, | where,
  earliest=-Xm / earliest=-Xh (relative to now, not anchored to a specific
  epoch timestamp).
- Do NOT invent keywords. If unsure of exact SPL syntax for something, use a
  simpler, certainly-correct query rather than a fancier uncertain one.
"""


def build_prompt(
    alert: Alert,
    enriched: EnrichedIOC | None,
    shodan_data: ShodanResponse | None = None,
) -> str:
    parts = [
        "ALERT DETAILS:",
        f"Rule: {alert.rule_name}",
        f"Severity: {alert.severity}",
        f"SIEM source: {alert.siem_source}",
        f"Source IP: {alert.src_ip or 'none'}",
        f"Destination IP: {alert.dest_ip or 'none'}",
        f"Username: {alert.username or 'none'}",
        f"Hostname: {alert.hostname or 'none'}",
        f"Event count: {alert.event_count if alert.event_count is not None else 'n/a'}",
        f"Description: {alert.description or 'none'}",
    ]

    if alert.log_snippet:
        parts.append(f"\nLog sample:\n{alert.log_snippet}")

    if enriched:
        parts.append("\nTHREAT INTEL (source IP is external, enrichment ran):")
        parts.append(f"AbuseIPDB score: {enriched.abuse_score} ({enriched.abuse_total_reports} reports)")
        parts.append(f"VirusTotal malicious flags: {enriched.vt_malicious}")
        parts.append(f"VirusTotal suspicious flags: {enriched.vt_suspicious}")
        parts.append(f"Combined severity: {enriched.severity} ({enriched.combined_score}/100)")
        parts.append(f"Country: {enriched.country or 'unknown'}")
        parts.append(f"ISP: {enriched.isp or 'unknown'}")

        if enriched.domain_enriched:
            parts.append(f"\nDOMAIN ENRICHMENT ({enriched.domain_enriched}):")
            parts.append(f"VT malicious: {enriched.vt_domain_malicious}, suspicious: {enriched.vt_domain_suspicious}, harmless: {enriched.vt_domain_harmless}")

        if enriched.hash_enriched:
            parts.append(f"\nHASH ENRICHMENT ({enriched.hash_enriched}):")
            parts.append(f"VT malicious: {enriched.vt_hash_malicious}, suspicious: {enriched.vt_hash_suspicious}, harmless: {enriched.vt_hash_harmless}")

        if enriched.url_enriched:
            parts.append(f"\nURL ENRICHMENT ({enriched.url_enriched}):")
            parts.append(f"VT malicious: {enriched.vt_url_malicious}, suspicious: {enriched.vt_url_suspicious}, harmless: {enriched.vt_url_harmless}")
    else:
        parts.append("\nTHREAT INTEL: source IP is internal, or no network IOC present — no external reputation data")

    if shodan_data:
        parts.append("\nEXPOSURE DATA (Shodan — queried because reputation data was ambiguous):")
        parts.append(f"Open ports: {shodan_data.ports or 'none detected'}")
        parts.append(f"Hostnames: {shodan_data.hostnames or 'none'}")
        parts.append(f"Organization: {shodan_data.org or 'unknown'}")
        parts.append(f"Operating system: {shodan_data.os or 'unknown'}")
        if shodan_data.data:
            parts.append(f"Services detected: {shodan_data.data}")

    # everything else Splunk/Sentinel sent, that we didn't explicitly parse above
    if alert.raw_details:
        parts.append(f"\nFULL RAW EVENT FIELDS:\n{json.dumps(alert.raw_details, indent=2, default=str)}")

    return "\n".join(parts)