"""
Two small, focused utilities:
  - extract_iocs():    figures out what IOCs (if any) THIS alert has
  - is_internal_ip():  RFC1918 check, used to decide whether to skip external threat intel enrichment entirely
""" 

import ipaddress

from schemas import Alert, ExtractedIOCs


def extract_iocs(alert: Alert) -> ExtractedIOCs:
    """
    Not every alert has a network IOC (e.g. a 'security log cleared'
    alert has a hostname but no IP at all). This looks at what THIS
    alert actually populated and reports back what's usable.
    """
    ips = [ip for ip in [alert.src_ip, alert.dest_ip] if ip]
    hostnames = [alert.hostname] if alert.hostname else []
    usernames = [alert.username] if alert.username else []

    return ExtractedIOCs(
        ips=ips,
        hostnames=hostnames,
        usernames=usernames,
        has_network_ioc=len(ips) > 0,
    )


def is_internal_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True

    return addr.is_private or addr.is_loopback or addr.is_link_local