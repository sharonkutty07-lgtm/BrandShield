# 🏆 BrandShield Hackathon Pitch Deck & Presentation Guide
**HACXLERATE 2026 | Challenge #03: Digital Risk Protection Platform**  
*Powered by Kampus.vc*

---

## ⏱️ 5-Minute Pitch Outline & Speaker Script

### Slide 1: The Problem (0:00 - 0:45)
* **Visual:** Screenshot of real-world fake bank / fintech login page copying legitimate logos.
* **Speaker Script:**  
  > *"Every day, cybercriminals launch attacks that bypass traditional company firewalls completely. They register look-alike domains with one character changed, spin up deceptive phishing portals, launch fake customer care social accounts, and exploit leaked employee credentials.*  
  > *For large tech giants, million-dollar security teams monitor this 24/7. But for small-to-midsize businesses and growing startups, there has been no affordable, automated defense. That’s why we built **BrandShield**."*

---

### Slide 2: The Solution — BrandShield (0:45 - 1:30)
* **Visual:** System Architecture Diagram & Dashboard Overview.
* **Speaker Script:**  
  > *"BrandShield is an autonomous Digital Risk Protection Platform that acts as a 24/7 exterior perimeter defense.*  
  > *1. **Ground Truth Registration**: An organization registers its official domain and social footprint.*  
  > *2. **Active Threat Hunting**: Our engine continuously hunts for homoglyphs, typosquats, and social impersonators using fuzzy text similarity and DNS resolution checks.*  
  > *3. **Explainable URL Risk Scorer**: Evaluates any link on a 0–100 risk scale with transparent diagnostic reasons.*  
  > *4. **1-Click Takedowns**: Automatically generates legally binding Cease & Desist notifications addressed directly to registrar abuse desks."*

---

### Slide 3: Live Demo (1:30 - 3:30)
* **Action 1 (Brand Baseline):** Show `ABC Bank` in Brand Registration with official domain `abcbank.com`.
* **Action 2 (Look-Alike Hunter):** Open Look-Alike Hunter and demonstrate detected variations like `abcbank-secure-netbanking.top` and homoglyphs with 90%+ similarity match.
* **Action 3 (URL Scanner):** Paste `http://abcbank-secure-netbanking.top/login.php` into the scanner. Show the **100/100 CRITICAL PHISHING** score, brand masquerading flag, and lack of SSL diagnostic.
* **Action 4 (Incident Triage & 1-Click Takedown):** Open Incidents tab, click **1-Click Takedown**, preview the auto-addressed notice to `abuse@cloudflare.com`, and move the status from `OPEN` to `RESOLVED`.
* **Action 5 (Audit Report):** Open and display the Executive Security Audit Report.

---

### Slide 4: Business Model & Market Opportunity (3:30 - 4:15)
* **Visual:** Pricing Tiers ($29/mo Starter, $99/mo Pro, $299/mo Enterprise).
* **Speaker Script:**  
  > *"Our business model is a simple, predictable monthly subscription scaled by the number of monitored assets with premium tiers for automated takedown SLAs. Compared to hiring a dedicated SOC analyst ($85k+/yr), BrandShield provides comprehensive brand protection starting at just $29/month."*

---

### Slide 5: Key Differentiators & Roadmap (4:15 - 5:00)
* **Key Differentiators:**
  1. **Explainable AI Risk Scoring**: No black-box scores—clear evidence cards for every risk point.
  2. **1-Click Remediation**: Bridges the gap between alert detection and legal registrar takedowns.
  3. **Zero Setup Friction**: Under 60 seconds from brand entry to full threat discovery.
* **Roadmap:** Telegram/Slack webhook alerts, automated SSL Certificate Transparency (CT) log streaming, and browser extension for everyday consumer protection.

---

## 💡 Top Questions Judges Might Ask & How to Answer

1. **Q: How does the system handle false positives?**  
   * **Answer:** *"We use multi-factor weighting. Similarity score alone doesn't trigger a critical alert; we combine RapidFuzz string proximity, live DNS resolution, presence of deceptive auth keywords, and missing SSL. Furthermore, our analyst workflow allows 1-click classification as `FALSE_POSITIVE`."*

2. **Q: How are takedown notices sent to registrars?**  
   * **Answer:** *"Our takedown generator extracts the hosting registrar and DNS provider from WHOIS/DNS records, maps the correct abuse contact (e.g. `abuse@cloudflare.com`), and formats an ICANN & DMCA compliant Cease & Desist letter containing exact evidence timestamps."*

3. **Q: Is the data compliant with privacy and defensive standards?**  
   * **Answer:** *"Yes. As per the hackathon ethical guidelines, BrandShield is strictly defensive. It only monitors public DNS records, open social profiles, and synthetic/authorized breach telemetry without gathering private personal data."*
