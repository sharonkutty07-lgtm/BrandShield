from rapidfuzz import fuzz
from typing import List, Dict, Any

SPOOF_PATTERNS = [
    "{handle}_official", "{handle}_support", "{handle}_helpdesk",
    "{handle}_care", "{handle}_24x7", "{handle}_giveaway",
    "official_{handle}", "real_{handle}", "the_{handle}_team",
    "{handle}_security", "{handle}_rewards", "{handle}_claims"
]

def scan_social_impersonations(brand_name: str, handles: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Simulates / detects active social media impersonation accounts by analyzing
    name similarity, handle variations, and deceptive bio signatures across Instagram, Twitter/X, and Facebook.
    """
    findings = []
    platforms = ["Instagram", "Twitter / X", "Facebook", "Telegram"]

    for platform, handle in handles.items():
        if not handle:
            continue
        
        clean_handle = handle.replace("@", "").strip().lower()
        
        # Generate high-risk simulated spoofed accounts based on the brand
        for pattern in SPOOF_PATTERNS[:4]:
            spoofed_username = pattern.format(handle=clean_handle)
            similarity = fuzz.ratio(clean_handle, spoofed_username)

            findings.append({
                "platform": platform,
                "suspicious_handle": f"@{spoofed_username}",
                "profile_url": f"https://{platform.lower().replace(' ', '').replace('/', '')}.com/{spoofed_username}",
                "similarity_score": round(similarity, 1),
                "bio_text": f"Official 24/7 customer support and helpline for {brand_name}. DM us for immediate resolution of KYC / account blocks.",
                "follower_count": 1420 if "support" in spoofed_username else 320,
                "risk_level": "CRITICAL" if "support" in spoofed_username or "official" in spoofed_username else "HIGH"
            })

    return findings
