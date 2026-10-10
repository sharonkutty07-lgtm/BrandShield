// Brand Registration & Management Module

async function handleBrandSubmit(event) {
  event.preventDefault();
  
  const submitBtn = document.getElementById("btn-save-brand");
  const originalText = submitBtn.innerHTML;
  submitBtn.disabled = true;
  submitBtn.innerHTML = "⏳ Discovering Threats & Registering...";

  const payload = {
    company_name: document.getElementById("reg-company-name").value.trim(),
    official_domain: document.getElementById("reg-official-domain").value.trim(),
    official_email: document.getElementById("reg-official-email").value.trim() || null,
    industry: document.getElementById("reg-industry").value,
    instagram_handle: document.getElementById("reg-instagram").value.trim() || null,
    twitter_handle: document.getElementById("reg-twitter").value.trim() || null,
    facebook_handle: document.getElementById("reg-facebook").value.trim() || null,
    linkedin_handle: document.getElementById("reg-linkedin").value.trim() || null,
    keywords: document.getElementById("reg-keywords").value.trim() || null
  };

  try {
    const res = await fetch("/api/brands/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const err = await res.json();
      showToast(err.detail || "Failed to register brand.", "danger");
      return;
    }

    const createdBrand = await res.json();
    showToast(`🎉 Brand '${createdBrand.company_name}' successfully registered! 25+ lookalike domains and threat signals generated.`, "success");
    
    // Reset form
    document.getElementById("brand-registration-form").reset();

    // Reload views
    await loadBrandsDropdown();
    await loadBrands();
    loadDashboardData();

  } catch (error) {
    console.error("Error creating brand:", error);
    showToast("Network error registering brand.", "danger");
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = originalText;
  }
}

async function loadBrands() {
  const container = document.getElementById("brands-container");
  container.innerHTML = `<div style="color:var(--text-muted); padding:1rem;">Loading registered brand assets...</div>`;

  try {
    const res = await fetch("/api/brands/");
    const brands = await res.json();

    if (brands.length === 0) {
      container.innerHTML = `
        <div style="grid-column: 1/-1; text-align:center; padding:2rem; background:rgba(255,255,255,0.02); border-radius:var(--radius-md);">
          <p style="color:var(--text-muted); font-size:0.95rem;">No brands registered yet. Use the form above to register your first brand!</p>
        </div>
      `;
      return;
    }

    container.innerHTML = "";
    for (const b of brands) {
      // Fetch details for counts
      const detailRes = await fetch(`/api/brands/${b.id}`);
      const details = await detailRes.json();

      const card = document.createElement("div");
      card.className = "brand-card";
      card.innerHTML = `
        <div class="brand-card-header">
          <div>
            <div class="brand-card-title">${b.company_name}</div>
            <div class="brand-domain-tag">🌐 ${b.official_domain}</div>
          </div>
          <span class="badge badge-safe">PROTECTED</span>
        </div>

        <div style="font-size:0.8rem; color:var(--text-muted);">
          Industry: <strong>${b.industry || 'General'}</strong>
        </div>

        <div class="brand-stats-row">
          <div class="brand-stat-mini">
            <span>Lookalikes</span>
            <strong style="color:var(--accent-cyan);">${details.lookalikes_count || 0}</strong>
          </div>
          <div class="brand-stat-mini">
            <span>Active Incidents</span>
            <strong style="color:var(--status-critical);">${details.incidents_count || 0}</strong>
          </div>
          <div class="brand-stat-mini">
            <span>Fake Profiles</span>
            <strong style="color:var(--status-high);">${details.impersonations_count || 0}</strong>
          </div>
          <div class="brand-stat-mini">
            <span>Exposures</span>
            <strong style="color:var(--status-medium);">${details.leaks_count || 0}</strong>
          </div>
        </div>

        <div style="font-size:0.75rem; color:var(--text-dim); display:flex; gap:0.5rem; flex-wrap:wrap;">
          ${b.instagram_handle ? `<span>📸 @${b.instagram_handle}</span>` : ''}
          ${b.twitter_handle ? `<span>🐦 @${b.twitter_handle}</span>` : ''}
          ${b.facebook_handle ? `<span>👥 /${b.facebook_handle}</span>` : ''}
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:auto; padding-top:0.5rem;">
          <button class="btn btn-secondary btn-sm" onclick="viewBrandAuditReport(${b.id})">📑 Audit Report</button>
          <button class="btn btn-danger btn-sm" onclick="deleteBrand(${b.id}, '${b.company_name}')">🗑️ Delete</button>
        </div>
      `;
      container.appendChild(card);
    }
  } catch (err) {
    console.error("Error fetching brands:", err);
    container.innerHTML = `<div style="color:var(--status-critical);">Failed to load brand assets.</div>`;
  }
}

async function deleteBrand(brandId, name) {
  if (!confirm(`Are you sure you want to remove '${name}' and all associated threat detections?`)) return;

  try {
    const res = await fetch(`/api/brands/${brandId}`, { method: "DELETE" });
    if (res.ok) {
      showToast(`Brand '${name}' removed.`, "info");
      await loadBrandsDropdown();
      await loadBrands();
      loadDashboardData();
    }
  } catch (err) {
    showToast("Failed to delete brand.", "danger");
  }
}

async function viewBrandAuditReport(brandId) {
  const modalContent = document.getElementById("report-modal-content");
  modalContent.innerHTML = `<div style="padding:2rem; text-align:center;">Generating executive security audit report...</div>`;
  openModal("report-modal");

  try {
    const res = await fetch(`/api/reports/brand/${brandId}`);
    if (!res.ok) throw new Error("Report fetch failed");
    const data = await res.json();

    modalContent.innerHTML = `
      <div style="border-bottom: 2px solid var(--accent-cyan); padding-bottom: 1rem; margin-bottom: 1.5rem; display:flex; justify-content:space-between; align-items:flex-end;">
        <div>
          <h2 style="color:#fff; font-size:1.4rem;">DIGITAL BRAND RISK AUDIT</h2>
          <div style="font-size:0.8rem; color:var(--text-muted); font-family:var(--font-mono);">${data.report_metadata.report_id}</div>
        </div>
        <div style="text-align:right; font-size:0.75rem; color:var(--text-muted);">
          <div>Generated: ${data.report_metadata.generated_at}</div>
          <div style="color:var(--accent-cyan); font-weight:600;">${data.report_metadata.compliance_standard}</div>
        </div>
      </div>

      <div style="display:grid; grid-template-columns: 1fr 1fr; gap:1.25rem; margin-bottom:1.5rem;">
        <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-color); padding:1rem; border-radius:var(--radius-sm);">
          <div style="font-size:0.75rem; color:var(--text-muted); text-transform:uppercase;">Target Entity</div>
          <div style="font-size:1.1rem; font-weight:700; color:#fff; margin-top:2px;">${data.brand_summary.company_name}</div>
          <div style="font-size:0.85rem; color:var(--accent-cyan); font-family:var(--font-mono);">${data.brand_summary.official_domain}</div>
          <div style="font-size:0.78rem; color:var(--text-muted); margin-top:4px;">Industry: ${data.brand_summary.industry}</div>
        </div>

        <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-color); padding:1rem; border-radius:var(--radius-sm);">
          <div style="font-size:0.75rem; color:var(--text-muted); text-transform:uppercase;">Overall Threat Rating</div>
          <div style="font-size:1.2rem; font-weight:800; color:var(--status-critical); margin-top:2px;">
            ${data.threat_landscape.overall_health_rating}
          </div>
          <div style="font-size:0.78rem; color:var(--text-muted); margin-top:4px;">
            Active Investigations: <strong>${data.threat_landscape.active_investigations_count}</strong> | Critical Lookalikes: <strong>${data.threat_landscape.critical_lookalikes_count}</strong>
          </div>
        </div>
      </div>

      <h4 style="font-size:0.9rem; color:var(--text-muted); margin-bottom:0.5rem; text-transform:uppercase;">Top Identified Domain Impersonations</h4>
      <table class="custom-table" style="margin-bottom:1.5rem;">
        <thead>
          <tr>
            <th>Lookalike Domain</th>
            <th>Attack Vector</th>
            <th>Match %</th>
            <th>Risk Level</th>
          </tr>
        </thead>
        <tbody>
          ${data.top_lookalikes.map(l => `
            <tr>
              <td class="mono-text" style="color:#f87171;">${l.domain_name}</td>
              <td>${l.variation_type}</td>
              <td>${l.similarity_score}%</td>
              <td><span class="badge ${l.risk_level === 'CRITICAL' ? 'badge-critical' : 'badge-high'}">${l.risk_level}</span></td>
            </tr>
          `).join('')}
        </tbody>
      </table>

      <h4 style="font-size:0.9rem; color:var(--text-muted); margin-bottom:0.5rem; text-transform:uppercase;">Mandatory Remediation Directives</h4>
      <ul style="margin-left:1.5rem; font-size:0.85rem; color:var(--text-main); line-height:1.6;">
        ${data.remediation_actions.map(a => `<li>${a}</li>`).join('')}
      </ul>
    `;
  } catch (err) {
    modalContent.innerHTML = `<div style="color:var(--status-critical); padding:2rem;">Failed to generate report: ${err.message}</div>`;
  }
}
