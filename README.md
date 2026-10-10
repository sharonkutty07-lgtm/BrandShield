# 🛡️ BrandShield - Digital Risk Protection Platform

> **HACXLERATE 2026 | Challenge #03: Digital Risk Protection Platform**  
> *Defensive Monitoring, Fake Brand Detection, Phishing URL Scoring & Automated Takedowns.*

---

## 🌟 Overview & Problem Statement

Organizations face sophisticated threats outside their perimeter:
1. **Fake Websites & Look-Alike Domains** mimicking official brand portals to steal login credentials and payment cards.
2. **Deceptive Social Media Profiles** impersonating customer support and executing scam giveaways.
3. **Phishing Links** distributed via SMS/Email targeting everyday consumers.
4. **Credential & Data Leak Exposures** traded on dark web combo lists.

**BrandShield** acts as an autonomous digital defense platform that registers brand assets as the reference ground truth, continuously hunts for impersonators, calculates explainable risk scores (0–100), and empowers security teams with **1-Click Legal Takedown Notices**.

---

## 📐 System Architecture

```
                          ┌────────────────────────────────────────┐
                          │         Modern Cyber Web UI            │
                          │   (Dashboard + Instant URL Scanner)    │
                          └──────────────────┬─────────────────────┘
                                             │ REST API (JSON)
                          ┌──────────────────▼─────────────────────┐
                          │        FastAPI Python Backend          │
                          └──────┬───────────┬───────────┬─────────┘
                                 │           │           │
        ┌────────────────────────┼───────────┴───────────┼────────────────────────┐
        ▼                        ▼                       ▼                        ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│  Look-alike &    │ │    URL Risk &    │ │  Impersonation   │ │  Leak / Breach   │
│  Typosquatting   │ │ Phishing Scorer  │ │ Profile Matcher  │ │     Checker      │
│  (Homoglyphs,    │ │ (Heuristics +    │ │ (Fuzzy text, Bio │ │ (Simulated & API │
│   TLD swaps,     │ │  Domain age &    │ │  similarity,     │ │  credential      │
│   RapidFuzz)     │ │  ML features)    │ │  handles)        │ │  watch)          │
└─────────┬────────┘ └─────────┬────────┘ └─────────┬────────┘ └─────────┬────────┘
          │                    │                    │                    │
          └────────────────────┼────────────────────┴────────────────────┘
                               ▼
            ┌──────────────────────────────────────┐
            │   Risk & Incident Management Core    │
            │  (Severity Scorer: Low/Med/High/Crit)│
            │  Workflow: OPEN ➔ INVESTIGATING ➔    │
            │            RESOLVED                  │
            │  Auto-generated Takedown Notices     │
            │  Executive Audit Reports             │
            └──────────────────┬───────────────────┘
                               ▼
            ┌──────────────────────────────────────┐
            │       SQLite Database Engine         │
            │  (Assets, Incidents, Scans, Logs)    │
            └──────────────────────────────────────┘
```

---

## 🚀 Key Features

### 1. 🏢 Brand Registration (Golden Baseline)
- Add company name, official web domain, security contact, industry vertical, and official social handles (Instagram, Twitter/X, Facebook, LinkedIn).
- Stored in SQLite as the reference ground truth for all threat comparisons.
- Automatically generates initial lookalike permutations and initiates perimeter monitoring upon submission.

### 2. 🌐 Look-Alike & Typosquatting Hunter
- **Homoglyphs**: `kampus.vc` ➔ `karnpus.vc`, `kαmpus.vc`.
- **Combosquatting**: `abcbank-login.com`, `abcbank-kyc-verify.top`.
- **TLD Impersonation**: Swaps TLDs across high-abuse extensions (`.xyz`, `.top`, `.online`, `.club`).
- **RapidFuzz Similarity Matrix**: Scores character proximity to official domain (0–100%).

### 3. 🔍 Intelligent Phishing URL Risk Scorer
- Analyzes any link across structural anomalies:
  - Encryption protocol (HTTP vs HTTPS)
  - Raw IP address in hostname (`http://192.168.1.1/login`)
  - High Shannon Entropy in parameters
  - Brand keyword masquerading (detects if URL claims to be a brand while hosted on unauthorized domain)
  - High-abuse TLDs and deceptive `@` authentication bypass symbols.
- Itemized diagnostic breakdown explaining the exact reason for every risk point.

### 4. 👥 Social Media Impersonation Watch
- Flags unauthorized handles with high fuzzy similarity to official handles.
- Analyzes profile bios for deceptive keywords ("Official 24/7 Support", "Giveaway", "KYC helpdesk").

### 5. ⚖️ Incident Lifecycle & 1-Click Legal Takedown Generator
- State machine: **`OPEN` ➔ `INVESTIGATING` ➔ `RESOLVED` / `FALSE_POSITIVE`**.
- Generates industry-compliant **Cease & Desist / DMCA Takedown Notice** addressed to registrar abuse desks (Namecheap, Cloudflare, GoDaddy, Hostinger).

### 6. 📑 Executive Security Audit Reports
- Formats structured brand risk assessments ready for executive review or PDF export.

---

## 💻 Quick Start & Setup

### Prerequisites
- Python 3.9+ installed.

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Server
```bash
python run.py
```

Open your browser and navigate to:
👉 **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

Interactive Swagger API docs are available at:
👉 **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**

---

## 🎬 5-Step Hackathon Demo Script

1. **Brand Registration**:
   - Open the **Brand Registration** tab.
   - Enter `ABC Bank` with official domain `abcbank.com` and social handles.
   - Click **Save Brand & Launch Threat Discovery**. Notice how 20+ lookalikes and threats are instantly populated.
2. **Look-Alike Hunter**:
   - Open **Look-Alike Hunter** to view detected homoglyphs and combotwinning domains.
   - Click **Escalate** on a suspicious domain to send it directly to SOC triage.
3. **Phishing Link Scanner**:
   - Open **Phishing Link Scanner** and test:  
     `http://abcbank-secure-netbanking.top/login.php`
   - Observe the 95/100 **CRITICAL PHISHING RISK** verdict with the itemized diagnostic reasons.
4. **Incident & 1-Click Takedown**:
   - Open **Incidents & Takedowns**.
   - Click **1-Click Takedown** to review the auto-generated legal notice letter, copy it, or dispatch it to the abuse desk.
   - Move the status from `OPEN` to `RESOLVED`.
5. **Executive Audit Report**:
   - Go to **Brand Registration** and click **Audit Report** on ABC Bank. Print/save the compliance report.


## User Login (local demo)
- Open `http://127.0.0.1:8000/`; signed-out users are sent to `/login`.
- Use `/register` to create an account. Passwords are stored as salted PBKDF2 hashes.
- Set the `BRANDSHIELD_SESSION_SECRET` environment variable to a long random secret before deployment. The included fallback secret is for local demos only.
