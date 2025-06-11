# backend/flagged_sites.py
"""
This module contains a list of dummy flagged sites/patterns for demonstration purposes.
It includes general malicious indicators and some simulated telecom-specific exploit patterns.
"""

# Hardcoded list of flagged domains/patterns
FLAGGED_DOMAINS = [
    "malicious.com",
    "phishing.net",
    "suspicious.org",
    "examplebadsite.com",
    "badonionlink.onion",       # Dummy .onion for testing
    "phishing-tor.onion",       # Another dummy .onion
    "evilurl.com/malicious_payload", # Example of a full malicious URL
    "http://insecure.com/login", # Example of an insecure login page
    "telecom-exploit.ru",       # Simulated C2 for telecom attacks
    "ss7-gateway-hack.xyz",     # Simulated SS7 exploit site
    "diameter-vulnerability.info", # Simulated Diameter exploit site
    "api-breach.com",           # Simulated API breach site
    "darkweb.marketplace.onion", # Simulated dark web marketplace
    "exploitdb.com/telecom",    # Link to exploit databases (can be flagged for monitoring)
    "github.com/telecom-backdoor", # Suspicious GitHub repos
]

def is_flagged(domain_or_url):
    """
    Checks if a given domain or full URL contains any of the flagged patterns.
    """
    if not isinstance(domain_or_url, str):
        return False # Ensure it's a string for comparison

    # Normalize input to lowercase for case-insensitive comparison
    input_lower = domain_or_url.lower()
    return any(flagged_pattern.lower() in input_lower for flagged_pattern in FLAGGED_DOMAINS)

def get_flagged_domains():
    """
    Returns the list of currently flagged domains/patterns.
    """
    return sorted(FLAGGED_DOMAINS)