// Look-Alike & Typosquatting Hunter Module

async function loadLookalikes() {
  const tbody = document.getElementById("lookalikes-table-body");
  tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;">Scanning cyberspace for look-alike domains...</td></tr>`;

  try {
    let url = "/api/lookalikes/";
    if (State.currentBrandId !== "ALL") {
      url += `?brand_id=${State.currentBrandId}`;
    }

    const res = await fetch(url);
    const lookalikes = await res.json();

    if (lookalikes.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No look-alike domains found. Register a brand or enter a custom domain above!</td></tr>`;
      return;
    }

    tbody.innerHTML = lookalikes.map(lk => {
      const sevBadge = lk.risk_level === "CRITICAL" ? "badge-critical" : lk.risk_level === "HIGH" ? "badge-high" : "badge-medium";
      const dnsBadge = lk.dns_status === "ACTIVE" ? "badge-critical" : "badge-info";

      return `
        <tr>
          <td><strong class="mono-text" style="color:#f87171; font-size:0.9rem;">${lk.domain_name}</strong></td>
          <td><span class="badge badge-info">${lk.variation_type}</span></td>
          <td>
            <div style="display:flex; align-items:center; gap:0.5rem;">
              <span style="font-weight:700;">${lk.similarity_score}%</span>
              <div style="flex:1; height:4px; width:60px; background:rgba(255,255,255,0.1); border-radius:2px; overflow:hidden;">
                <div style="height:100%; width:${lk.similarity_score}%; background:var(--accent-cyan);"></div>
              </div>
            </div>
          </td>
          <td><span class="badge ${dnsBadge}">${lk.dns_status}</span></td>
          <td class="mono-text" style="font-size:0.75rem;">${lk.ip_address || 'Unresolved'}</td>
          <td><span class="badge ${sevBadge}">${lk.risk_level}</span></td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="escalateLookalike(${lk.id}, '${lk.domain_name}')">
              🚨 Escalate
            </button>
          </td>
        </tr>
      `;
    }).join('');

  } catch (err) {
    console.error("Error loading lookalikes:", err);
    tbody.innerHTML = `<tr><td colspan="7" style="color:var(--status-critical); text-align:center;">Failed to load lookalike domains.</td></tr>`;
  }
}

async function generateCustomLookalikes() {
  const input = document.getElementById("custom-lookalike-input");
  const domain = input.value.trim();
  if (!domain) {
    showToast("Please enter a domain name to generate look-alikes.", "warning");
    return;
  }

  const tbody = document.getElementById("lookalikes-table-body");
  tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;">Generating algorithmic permutations for '${domain}'...</td></tr>`;

  try {
    const res = await fetch("/api/lookalikes/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: domain, limit: 30, check_dns: false })
    });

    const data = await res.json();
    showToast(`Generated ${data.total_generated} look-alike variations for '${domain}'`, "success");

    tbody.innerHTML = data.variants.map((lk, idx) => {
      const sevBadge = lk.risk_level === "CRITICAL" ? "badge-critical" : lk.risk_level === "HIGH" ? "badge-high" : "badge-medium";
      return `
        <tr>
          <td><strong class="mono-text" style="color:#f87171; font-size:0.9rem;">${lk.domain_name}</strong></td>
          <td><span class="badge badge-info">${lk.variation_type}</span></td>
          <td><span style="font-weight:700;">${lk.similarity_score}%</span></td>
          <td><span class="badge badge-info">${lk.dns_status}</span></td>
          <td class="mono-text" style="font-size:0.75rem;">${lk.ip_address || 'Simulated Check'}</td>
          <td><span class="badge ${sevBadge}">${lk.risk_level}</span></td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="testUrlInScanner('https://${lk.domain_name}')">
              🔍 Test in Scanner
            </button>
          </td>
        </tr>
      `;
    }).join('');

  } catch (err) {
    showToast("Error generating variants.", "danger");
  }
}

async function escalateLookalike(lookalikeId, domainName) {
  try {
    const res = await fetch(`/api/lookalikes/${lookalikeId}/escalate`, { method: "POST" });
    const result = await res.json();

    if (res.ok) {
      showToast(`🚨 Domain '${domainName}' escalated to active incident #${result.incident_id}!`, "success");
      loadDashboardData();
    } else {
      showToast(result.detail || "Escalation failed", "danger");
    }
  } catch (err) {
    showToast("Network error escalating domain.", "danger");
  }
}

function testUrlInScanner(url) {
  showTab("scanner-view");
  const input = document.getElementById("scan-url-input");
  if (input) {
    input.value = url;
    document.getElementById("btn-scan-action").click();
  }
}
