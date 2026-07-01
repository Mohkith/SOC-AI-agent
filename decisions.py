from schemas import EnrichedIOC

def should_query_shodan(enriched: EnrichedIOC | None) -> bool:
    if enriched is None:
        return False
    

    abuse_ambiguity = 25 <= enriched.abuse_score <=75
    vt_ambiguious = (enriched.vt_malicious + enriched.vt_suspicious) < 4 

    return abuse_ambiguity and vt_ambiguious