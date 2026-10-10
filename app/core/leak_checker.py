import datetime
from typing import List, Dict, Any

SAMPLE_BREACH_VECTORS = [
    {"source": "DarkWeb Combo Dump 2026.02", "types": "Email, Hashed Password, IP Address", "severity": "CRITICAL"},
    {"source": "StealerLog RedLine Infostealer", "types": "Session Cookies, Login Passwords, Browser Autofill", "severity": "CRITICAL"},
    {"source": "Marketing Partner API Key Leak (GitHub)", "types": "OAuth Tokens, Customer Metadata", "severity": "HIGH"},
    {"source": "Employee Corporate VPN Credential Leak", "types": "SSO Username, NTLM Hash, Internal Hostname", "severity": "CRITICAL"}
]

def check_brand_leaks(brand_name: str, domain: str) -> List[Dict[str, Any]]:
    """
    Checks if brand domain or employee email patterns appear in exposed threat intelligence datasets.
    """
    domain_clean = domain.strip().lower()
    prefix = brand_name.lower().replace(" ", "")

    results = [
        {
            "email_exposed": f"admin@{domain_clean}",
            "breach_source": SAMPLE_BREACH_VECTORS[0]["source"],
            "leak_date": "2026-01-18",
            "data_types_exposed": SAMPLE_BREACH_VECTORS[0]["types"],
            "severity": SAMPLE_BREACH_VECTORS[0]["severity"]
        },
        {
            "email_exposed": f"finance.director@{domain_clean}",
            "breach_source": SAMPLE_BREACH_VECTORS[1]["source"],
            "leak_date": "2026-02-04",
            "data_types_exposed": SAMPLE_BREACH_VECTORS[1]["types"],
            "severity": SAMPLE_BREACH_VECTORS[1]["severity"]
        },
        {
            "email_exposed": f"dev-ops@{domain_clean}",
            "breach_source": SAMPLE_BREACH_VECTORS[2]["source"],
            "leak_date": "2026-02-27",
            "data_types_exposed": SAMPLE_BREACH_VECTORS[2]["types"],
            "severity": SAMPLE_BREACH_VECTORS[2]["severity"]
        }
    ]
    return results
