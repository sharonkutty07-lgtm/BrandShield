// Incident Lifecycle & Automated Takedown Module

let currentActiveIncidentId = null;
let currentIncidentFilter = "ALL";

function filterIncidents(status) {
  currentIncidentFilter = status;
  loadIncidents();
}

async function loadIncidents() {
  const tbody = document.getElementById("incidents-table-body");
  tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;">Loading security incidents...</td></tr>`;

  try {
    let url = `/api/incidents/?status_filter=${currentIncidentFilter}`;
    if (State.currentBrandId !== "ALL") {
      url += `&brand_id=${State.currentBrandId}`;
    }

    const res = await fetch(url);
    const incidents = await res.json();

    if (incidents.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No incidents found under '${currentIncidentFilter}' status filter.</td></tr>`;
      return;
    }

    tbody.innerHTML = incidents.map(inc => {
      const sevBadge = inc.severity === "CRITICAL" ? "badge-critical" : inc.severity === "HIGH" ? "badge-high" : "badge-medium";
      const statusBadge = inc.status === "OPEN" ? "badge-critical" : inc.status === "INVESTIGATING" ? "badge-high" : inc.status === "RESOLVED" ? "badge-safe" : "badge-info";

      return `
        <tr>
          <td class="mono-text" style="color:var(--text-dim);">#${inc.id}</td>
          <td><strong>${inc.brand_name}</strong></td>
          <td>
            <div style="font-weight:600; color:#fff;">${inc.title}</div>
            <div class="mono-text" style="font-size:0.75rem; color:#f87171; margin-top:2px;">${inc.threat_url}</div>
            <div style="font-size:0.75rem; color:var(--text-muted); margin-top:4px;">${inc.evidence_notes || ''}</div>
          </td>
          <td><span class="badge ${sevBadge}">${inc.severity} (${inc.risk_score}%)</span></td>
          <td>
            <select class="form-select" style="padding:0.25rem 0.5rem; font-size:0.75rem;" onchange="updateIncidentStatus(${inc.id}, this.value)">
              <option value="OPEN" ${inc.status === 'OPEN' ? 'selected' : ''}>🔴 OPEN</option>
              <option value="INVESTIGATING" ${inc.status === 'INVESTIGATING' ? 'selected' : ''}>🟡 INVESTIGATING</option>
              <option value="RESOLVED" ${inc.status === 'RESOLVED' ? 'selected' : ''}>🟢 RESOLVED</option>
              <option value="FALSE_POSITIVE" ${inc.status === 'FALSE_POSITIVE' ? 'selected' : ''}>⚪ FALSE POSITIVE</option>
            </select>
          </td>
          <td>
            ${inc.takedown_sent 
              ? `<span class="badge badge-safe">✅ NOTICE SENT</span>` 
              : `<span class="badge badge-medium">PENDING</span>`}
          </td>
          <td>
            <button class="btn btn-primary btn-sm" onclick="triggerTakedownModal(${inc.id})">
              ${inc.takedown_sent ? '📄 View Notice' : '⚡ 1-Click Takedown'}
            </button>
          </td>
        </tr>
      `;
    }).join('');

  } catch (err) {
    console.error("Error loading incidents:", err);
    tbody.innerHTML = `<tr><td colspan="7" style="color:var(--status-critical); text-align:center;">Failed to load incidents.</td></tr>`;
  }
}

async function updateIncidentStatus(incidentId, newStatus) {
  try {
    const res = await fetch(`/api/incidents/${incidentId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus, notes: `Status manually changed in SOC portal to ${newStatus}` })
    });

    if (res.ok) {
      showToast(`Incident #${incidentId} transitioned to ${newStatus}`, "success");
      loadDashboardData();
    } else {
      showToast("Failed to update status", "danger");
    }
  } catch (err) {
    showToast("Network error updating incident status.", "danger");
  }
}

async function triggerTakedownModal(incidentId) {
  currentActiveIncidentId = incidentId;
  openModal("takedown-modal");

  const recipientDiv = document.getElementById("takedown-recipient-email");
  const subjectDiv = document.getElementById("takedown-subject");
  const bodyPre = document.getElementById("takedown-body-text");

  recipientDiv.innerText = "Resolving abuse desk for registrar...";
  subjectDiv.innerText = "Generating formal cease and desist notice...";
  bodyPre.innerText = "Generating legal takedown notice template...";

  try {
    const res = await fetch(`/api/incidents/${incidentId}/takedown`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ incident_id: incidentId })
    });

    if (!res.ok) {
      throw new Error("Failed to generate takedown notice");
    }

    const data = await res.json();
    recipientDiv.innerText = data.recipient_email;
    subjectDiv.innerText = data.subject;
    bodyPre.innerText = data.letter_body;

    // Refresh incidents table to reflect takedown status
    loadIncidents();
    loadDashboardData();

  } catch (err) {
    bodyPre.innerText = `Error generating takedown letter: ${err.message}`;
  }
}

function copyTakedownText() {
  const bodyText = document.getElementById("takedown-body-text").innerText;
  navigator.clipboard.writeText(bodyText).then(() => {
    showToast("📋 Legal takedown letter copied to clipboard!", "success");
  }).catch(() => {
    showToast("Please copy text manually.", "info");
  });
}

function simulateTakedownDispatch() {
  const recipient = document.getElementById("takedown-recipient-email").innerText;
  showToast(`⚡ Notice dispatched via automated SMTP abuse gateway to [${recipient}]! Ticket #SOC-${Math.floor(Math.random()*90000+10000)} opened with registrar.`, "success");
  closeModal("takedown-modal");
  
  if (currentActiveIncidentId) {
    updateIncidentStatus(currentActiveIncidentId, "INVESTIGATING");
    loadIncidents();
  }
}
