"""
Adapters — one function per SIEM source. Each knows how to dig through
that source's specific (and sometimes deeply nested) raw JSON shape and
produce a clean, normalized Alert object.
"""

from schemas import Alert


def _normalize_severity(value: object) -> str:
    severity = str(value).strip().lower() if value is not None else ""

    aliases = {
        "info": "low",
        "informational": "low",
        "information": "low",
        "notice": "low",
        "moderate": "medium",
        "medium-high": "medium",
        "med": "medium",
        "severe": "critical",
        "critical-high": "critical",
        "urgent": "critical",
    }

    return severity if severity in {"low", "medium", "high", "critical"} else aliases.get(severity, "medium")

def from_splunk(raw: dict) -> Alert:
    
    result = raw.get("result", {})

    src_ip = (
        result.get("Source_Network_Address")
        or result.get("src_ip")
        or result.get("Source_Address")
        or None
    )
    # Splunk sometimes sends "" for empty fields instead of omitting the key
    if src_ip == "":
        src_ip = None

    dest_port = result.get("dest_port") or result.get("Destination_Port")
    try:
        dest_port = int(dest_port) if dest_port not in (None, "") else None
    except (ValueError, TypeError):
        dest_port = None

    return Alert(
        alert_id=raw.get("sid", "unknown-splunk-alert"),
        rule_name=raw.get("search_name", "Unknown Splunk Rule"),
        siem_source="splunk",
        severity=_normalize_severity(
            raw.get("severity")
            or result.get("severity")
            or raw.get("alert_severity")
            or result.get("alert_severity")
        ),
        src_ip=src_ip,
        dest_ip=result.get("dest_ip") or result.get("Destination_Address"),
        dest_port=dest_port,
        username=result.get("Account_Name") or result.get("user"),
        hostname=result.get("ComputerName"),
        event_code=result.get("EventCode"),
        description=raw.get("search_name"),
        log_snippet=result.get("_raw"),
        message= result.get("Message"),
        results_link=raw.get("results_link"),
        raw_details=result,  # keep everything, untouched, for the LLM
    )


def from_sentinel(raw: dict) -> Alert:
    """
    Converts a raw Sentinel incident payload into an Alert.

    Sentinel buries IPs/usernames inside an `entities` list instead of
    flat fields, so we loop through it to pull out what we need.
    """
    src_ip = None
    username = None
    hostname = None

    for entity in raw.get("entities", []):
        entity_type = entity.get("type", "").lower()
        if entity_type == "ip" and src_ip is None:
            src_ip = entity.get("address")
        elif entity_type == "account" and username is None:
            username = entity.get("name")
        elif entity_type == "host" and hostname is None:
            hostname = entity.get("hostName")

    return Alert(
        alert_id=raw.get("id", "unknown-sentinel-alert"),
        rule_name=raw.get("title", "Unknown Sentinel Rule"),
        siem_source="sentinel",
        severity=str(raw.get("severity", "medium")).lower(),
        src_ip=src_ip,
        username=username,
        hostname=hostname,
        description=raw.get("description"),
        message=raw.get("message"),
        raw_details=raw,  # keep everything, untouched, for the LLM
    )