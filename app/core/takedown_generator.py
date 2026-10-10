import datetime
from typing import Dict, Any

def generate_takedown_notice(
    brand_name: str,
    official_domain: str,
    threat_url: str,
    threat_type: str,
    registrar: str = "Hosting Provider / Abuse Desk",
    sender_name: str = "Brand Protection & Security Operations Center",
    sender_email: str = "abuse-response@brandshield.security",
    custom_notes: str = None
) -> Dict[str, str]:
    """
    Generates a formal, industry-standard Cease & Desist / Domain Takedown Notice
    tailored to the specific brand and malicious host.
    """
    current_time_utc = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Infer abuse desk email
    abuse_email = "abuse@" + (registrar.lower().replace(" ", "").split("/")[0] if registrar else "registrar.com")
    if "cloudflare" in registrar.lower():
        abuse_email = "abuse@cloudflare.com"
    elif "godaddy" in registrar.lower():
        abuse_email = "abuse@godaddy.com"
    elif "namecheap" in registrar.lower():
        abuse_email = "abuse@namecheap.com"
    else:
        abuse_email = "abuse-desk@hosting-provider.net"

    subject = f"[URGENT: TRADEMARK INFRINGEMENT & PHISHING ABUSE NOTICE] Immediate Takedown Request for {threat_url}"

    body = f"""ATTENTION: ABUSE DEPARTMENT & LEGAL COMPLIANCE
RE: FORMAL TAKEDOWN & SUSPENSION REQUEST FOR FRAUDULENT DOMAIN / CONTENT

Date of Notice: {current_time_utc}
Registrar / Host: {registrar}
Abuse Contact: {abuse_email}

Complainant / Trademark Owner:
Organization: {brand_name}
Official Authorized Web Domain: {official_domain}
Authorized Security Representative: {sender_name} ({sender_email})

----------------------------------------------------------------------
1. DETAILS OF THE INFRINGING & MALICIOUS ASSET
----------------------------------------------------------------------
Infringing URL / Host: {threat_url}
Violation Category: {threat_type} (Unauthorized Trademark Spoofing, Phishing & Deceptive Credential Harvesting)
Targeted Entity: {brand_name}

----------------------------------------------------------------------
2. STATEMENT OF FACTS & EVIDENCE
----------------------------------------------------------------------
We have detected that the host/domain referenced above ({threat_url}) is actively engaging in malicious cyber activity, specifically:
1. Impersonating the registered trade identity, brand name, and visual markers of {brand_name}.
2. Misleading consumers and unauthorized harvesting of sensitive credentials/banking/personal data.
3. Violating your Acceptable Use Policy (AUP), Terms of Service, and ICANN Registrar Accreditation Agreement requirements.

Evidence Notes:
{custom_notes if custom_notes else f"The host {threat_url} mimics {brand_name}'s official services without license or authorization. Deceptive authentication pages and typo-squatted variations were confirmed via automated heuristic & threat-scoring validation."}

----------------------------------------------------------------------
3. DEMANDED REMEDIAL ACTION
----------------------------------------------------------------------
Pursuant to international cyber protection statutes, the ICANN Registrar Agreement, and your Terms of Service:
1. IMMEDIATELY SUSPEND DNS resolution and disable the hosting account associated with {threat_url}.
2. Preserve all server access logs, registrant metadata, and associated payment details for potential law enforcement referral.
3. Confirm in writing to {sender_email} when the malicious asset has been neutralized.

----------------------------------------------------------------------
4. DECLARATION & GOOD FAITH CERTIFICATION
----------------------------------------------------------------------
I have a good faith belief that the use of the protected intellectual property and brand identity described above is not authorized by the copyright/trademark owner, its agent, or the law. The information in this notification is accurate, and under penalty of perjury, I am authorized to act on behalf of {brand_name}.

Sincerely,

{sender_name}
BrandShield Security & Fraud Defense Team
On behalf of: {brand_name}
Contact: {sender_email}
"""

    return {
        "recipient_email": abuse_email,
        "subject": subject,
        "letter_body": body,
        "generated_at": current_time_utc
    }
