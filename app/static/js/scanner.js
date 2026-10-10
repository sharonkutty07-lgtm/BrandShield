// Instant URL Risk Scanner Module

async function handleScanSubmit(event) {
  event.preventDefault();

  const urlInput = document.getElementById("scan-url-input");
  const targetUrl = urlInput.value.trim();
  if (!targetUrl) return;

  const scanBtn = document.getElementById("btn-scan-action");
  const originalText = scanBtn.innerHTML;
  scanBtn.disabled = true;
  scanBtn.innerHTML = "⏳ Scanning Deep Features...";

  try {
    const res = await fetch("/api/scan/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: targetUrl })
    });

    if (!res.ok) {
      showToast("Scan failed. Please check URL format.", "danger");
      return;
    }

    const data = await res.json();
    renderScanResult(data);
    loadRecentScans();

  } catch (err) {
    console.error("Scan error:", err);
    showToast("Network error performing scan.", "danger");
  } finally {
    scanBtn.disabled = false;
    scanBtn.innerHTML = originalText;
  }
}

function renderScanResult(data) {
  const resultCard = document.getElementById("scan-result-card");
  resultCard.classList.add("active");

  const scoreBanner = document.getElementById("score-banner");
  const scoreCircle = document.getElementById("score-circle");
  const verdictBadge = document.getElementById("scan-verdict-badge");
  const verdictTitle = document.getElementById("scan-verdict-title");
  const targetDisplay = document.getElementById("scan-target-display");
  const brandMatchAlert = document.getElementById("scan-brand-match-alert");
  const scoreNumber = document.getElementById("score-number");
  const diagnosticsContainer = document.getElementById("diagnostics-container");
  const recommendationsList = document.getElementById("recommendations-list");

  // Animate Risk Score
  scoreNumber.innerText = data.risk_score;
  targetDisplay.innerText = `${data.target_url} (IP: ${data.ip_address || 'Unresolved'})`;

  // Color classes & verdicts
  scoreBanner.className = "score-banner";
  if (data.risk_score >= 70) {
    scoreBanner.classList.add("danger");
    scoreCircle.style.color = "#ef4444";
    verdictBadge.innerHTML = `<span class="badge badge-critical">CRITICAL PHISHING RISK</span>`;
    verdictTitle.innerText = "🚨 MALICIOUS PHISHING TARGET DETECTED";
    verdictTitle.style.color = "#ef4444";
  } else if (data.risk_score >= 40) {
    scoreBanner.classList.add("warning");
    scoreCircle.style.color = "#f59e0b";
    verdictBadge.innerHTML = `<span class="badge badge-high">SUSPICIOUS LINK</span>`;
    verdictTitle.innerText = "⚠️ HIGH RISK SUSPICIOUS WEB TARGET";
    verdictTitle.style.color = "#f59e0b";
  } else {
    scoreBanner.classList.add("safe");
    scoreCircle.style.color = "#10b981";
    verdictBadge.innerHTML = `<span class="badge badge-safe">CLEAN / LOW RISK</span>`;
    verdictTitle.innerText = "✅ LOW RISK / VERIFIED SAFE STRUCTURE";
    verdictTitle.style.color = "#10b981";
  }

  // Brand Match Notice
  if (data.matched_brand) {
    brandMatchAlert.innerHTML = `🎯 TARGET IMPERSONATION: This link is actively masquerading as <u>${data.matched_brand}</u> without authorized registration!`;
    brandMatchAlert.style.display = "block";
  } else {
    brandMatchAlert.style.display = "none";
  }

  // Render Diagnostics List
  diagnosticsContainer.innerHTML = data.diagnostics.map(diag => {
    const statusClass = diag.status === "DANGER" ? "danger" : diag.status === "WARNING" ? "warning" : "safe";
    const statusBadge = diag.status === "DANGER" ? "badge-critical" : diag.status === "WARNING" ? "badge-medium" : "badge-safe";

    return `
      <div class="diagnostic-item ${statusClass}">
        <div>
          <div class="diag-title">${diag.indicator}</div>
          <div class="diag-sub">Vector Category: ${diag.category}</div>
        </div>
        <div style="display:flex; align-items:center; gap:0.5rem;">
          <span style="font-weight:700; font-size:0.85rem;">+${diag.risk_impact} Risk</span>
          <span class="badge ${statusBadge}">${diag.status}</span>
        </div>
      </div>
    `;
  }).join('');

  // Render Recommendations
  recommendationsList.innerHTML = data.recommendations.map(rec => `<li>${rec}</li>`).join('');

  // Scroll smoothly to results
  resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function loadRecentScans() {
  const tbody = document.getElementById("recent-scans-table-body");
  if (!tbody) return;

  try {
    const res = await fetch("/api/scan/history");
    const scans = await res.json();

    if (scans.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted);">No scan history recorded.</td></tr>`;
      return;
    }

    tbody.innerHTML = scans.map(s => {
      const sevBadge = s.risk_score >= 70 ? "badge-critical" : s.risk_score >= 40 ? "badge-high" : "badge-safe";
      const dateStr = new Date(s.scanned_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

      return `
        <tr>
          <td class="mono-text" style="color:#fff;">${s.target_url}</td>
          <td><strong style="color:${s.risk_score >= 70 ? '#ef4444' : s.risk_score >= 40 ? '#f59e0b' : '#10b981'};">${s.risk_score}/100</strong></td>
          <td><span class="badge ${sevBadge}">${s.risk_level}</span></td>
          <td>${s.matched_brand_name ? `<span class="badge badge-info">${s.matched_brand_name}</span>` : '<span style="color:var(--text-dim);">None</span>'}</td>
          <td style="color:var(--text-muted); font-size:0.75rem;">${dateStr}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error("Error loading scan history:", err);
  }
}
