"""
- is_internal_ip():  RFC1918 check, used to decide whether to skip external threat intel enrichment entirely
- should_query_shodan():  determines whether to query Shodan based on enrichment results
"""

from schemas import EnrichedIOC
import ipaddress

def should_query_shodan(enriched: EnrichedIOC | None) -> bool:
    if enriched is None:
        return False
    

    abuse_ambiguity = 25 <= enriched.abuse_score <=75
    vt_ambiguious = (enriched.vt_malicious + enriched.vt_suspicious) < 4 

    return abuse_ambiguity and vt_ambiguious


def is_internal_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True

    return addr.is_private or addr.is_loopback or addr.is_link_local