"""
  - extract_iocs():    figures out what IOCs (if any) THIS alert has
""" 

import re
import json

from schemas import Alert, ExtractedIOCs

MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
URL_REGEX = re.compile(r'\bhttps?://[^\s\'\"\]\}]+')
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b')

Noise_Filter={
    "schemas.microsoft.com", "microsoft.com", "w3.org", "localhost", "127.0.0.1"
}
def extract_iocs(alert: Alert) -> ExtractedIOCs:
    """
    Not every alert has a network IOC (e.g. a 'security log cleared'
    alert has a hostname but no IP at all). This looks at what THIS
    alert actually populated and reports back what's usable.
    """


    ips = [ip for ip in [alert.src_ip, alert.dest_ip] if ip]
    hostnames = [alert.hostname] if alert.hostname else []
    usernames = [alert.username] if alert.username else []
    hashes = [alert.FileHash] if alert.FileHash else []
    file_name = [alert.FileName] if alert.FileName else []
    domain = [alert.Domain] if alert.Domain else []
    url = [alert.Url] if alert.Url else []

    search = json.dumps(alert.raw_details)

    if not hashes:
        found_hashes = MD5_REGEX.findall(search) + SHA256_REGEX.findall(search)
        if found_hashes:
            hashes = list(set(found_hashes))

    if not url:
        found_url = URL_REGEX.findall(search)
        clean_url = [curl.strip() for curl in found_url if not any(noise in curl.lower() for noise in Noise_Filter)]
        if clean_url:
            url = clean_url

    if not domain:
        found_domain = DOMAIN_REGEX.findall(search)
        if found_domain:
            c_domain = []
            for d in found_domain:
                if d not in Noise_Filter and not d.endswith(('.exe', '.dll', '.tmp', '.sys')):
                    c_domain.append(d)
            domain = c_domain


    return ExtractedIOCs(
        ips=ips,
        hostnames=hostnames,
        usernames=usernames,
        file_hash=hashes,
        file_name=file_name,
        domain=domain,
        url=url,
        has_network_ioc=len(ips) > 0,
    )

