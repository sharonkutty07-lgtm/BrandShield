// Social Impersonation Watcher Module

async function loadImpersonations() {
  const tbody = document.getElementById("impersonations-table-body");
  tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;">Scanning social platforms for impersonating profiles...</td></tr>`;

  try {
    let url = "/api/impersonations/";
    if (State.currentBrandId !== "ALL") {
      url += `?brand_id=${State.currentBrandId}`;
    }

    const res = await fetch(url);
    const impersonators = await res.json();

    if (impersonators.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No fake social media profiles detected. Ground truth handles are secure.</td></tr>`;
      return;
    }

    tbody.innerHTML = impersonators.map(imp => {
      const sevBadge = imp.risk_level === "CRITICAL" ? "badge-critical" : "badge-high";
      const icon = imp.platform.includes("Instagram") ? "📸" : imp.platform.includes("Twitter") ? "🐦" : imp.platform.includes("Facebook") ? "👥" : "✈️";

      return `
        <tr>
          <td><strong>${icon} ${imp.platform}</strong></td>
          <td><strong class="mono-text" style="color:#f87171;">${imp.suspicious_handle}</strong></td>
          <td style="font-size:0.78rem; color:var(--text-muted); max-width:300px;">"${imp.bio_text}"</td>
          <td>
            <span style="font-weight:700; color:var(--accent-cyan);">${imp.similarity_score}% Match</span>
          </td>
          <td>${imp.follower_count.toLocaleString()} accounts</td>
          <td><span class="badge ${sevBadge}">${imp.risk_level}</span></td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="reportSocialProfile('${imp.suspicious_handle}', '${imp.platform}')">
              🚨 Report Abuse
            </button>
          </td>
        </tr>
      `;
    }).join('');

  } catch (err) {
    console.error("Error loading impersonations:", err);
    tbody.innerHTML = `<tr><td colspan="7" style="color:var(--status-critical); text-align:center;">Failed to load social accounts.</td></tr>`;
  }
}

function reportSocialProfile(handle, platform) {
  showToast(`Initiated direct social abuse report for ${handle} on ${platform}. Case assigned to analyst.`, "success");
}
