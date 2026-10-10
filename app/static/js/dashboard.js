// Dashboard Analytics & Threat Feed Module

let severityChartInstance = null;
let categoryChartInstance = null;

async function loadDashboardData() {
  try {
    const res = await fetch("/api/dashboard/summary");
    if (!res.ok) return;
    const data = await res.json();

    // Update KPI Stat Counters
    document.getElementById("stat-brands").innerText = data.monitored_brands_count;
    document.getElementById("stat-incidents").innerText = data.active_incidents_count;
    document.getElementById("stat-threats").innerText = data.total_threats_detected;
    document.getElementById("stat-resolved").innerText = data.resolved_incidents_count;

    // Render Charts
    renderSeverityChart(data.severity_breakdown);
    renderCategoryChart(data.threat_types_breakdown);

    // Render Recent Incidents Table
    renderRecentIncidents(data.recent_incidents);

  } catch (err) {
    console.error("Error loading dashboard metrics:", err);
  }
}

function renderSeverityChart(severities) {
  const ctx = document.getElementById("severityChart");
  if (!ctx) return;

  const labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const counts = [
    severities["CRITICAL"] || 0,
    severities["HIGH"] || 0,
    severities["MEDIUM"] || 0,
    severities["LOW"] || 0
  ];

  if (severityChartInstance) {
    severityChartInstance.data.datasets[0].data = counts;
    severityChartInstance.update();
    return;
  }

  severityChartInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: labels,
      datasets: [{
        data: counts,
        backgroundColor: [
          "#ef4444", // Critical Red
          "#f97316", // High Orange
          "#f59e0b", // Medium Amber
          "#10b981"  // Low Green
        ],
        borderWidth: 0,
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "right",
          labels: {
            color: "#9ca3af",
            font: { family: "Inter", size: 12 }
          }
        }
      },
      cutout: "70%"
    }
  });
}

function renderCategoryChart(categories) {
  const ctx = document.getElementById("categoryChart");
  if (!ctx) return;

  const labels = Object.keys(categories);
  const data = Object.values(categories);

  if (categoryChartInstance) {
    categoryChartInstance.data.labels = labels;
    categoryChartInstance.data.datasets[0].data = data;
    categoryChartInstance.update();
    return;
  }

  categoryChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Detected Vectors",
        data: data,
        backgroundColor: "rgba(6, 182, 212, 0.7)",
        borderColor: "#06b6d4",
        borderWidth: 1,
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          ticks: { color: "#9ca3af", font: { family: "Inter", size: 11 } },
          grid: { display: false }
        },
        y: {
          ticks: { color: "#9ca3af", font: { family: "Inter", size: 11 }, precision: 0 },
          grid: { color: "rgba(255, 255, 255, 0.05)" }
        }
      }
    }
  });
}

function renderRecentIncidents(incidents) {
  const tbody = document.getElementById("dashboard-recent-incidents-body");
  if (!tbody) return;

  if (!incidents || incidents.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">No active security incidents detected. Clean perimeter!</td></tr>`;
    return;
  }

  tbody.innerHTML = incidents.map(inc => {
    const sevBadge = inc.severity === "CRITICAL" ? "badge-critical" : inc.severity === "HIGH" ? "badge-high" : "badge-medium";
    const statusBadge = inc.status === "OPEN" ? "badge-critical" : inc.status === "INVESTIGATING" ? "badge-high" : "badge-safe";

    return `
      <tr>
        <td><strong>${inc.brand_name}</strong></td>
        <td>
          <div style="font-weight:600; color:#fff;">${inc.title}</div>
          <div class="mono-text" style="font-size:0.75rem; color:#f87171;">${inc.threat_url}</div>
        </td>
        <td><span class="badge badge-info">${inc.threat_type}</span></td>
        <td><span class="badge ${sevBadge}">${inc.severity} (${inc.risk_score}%)</span></td>
        <td><span class="badge ${statusBadge}">${inc.status}</span></td>
        <td>
          <button class="btn btn-primary btn-sm" onclick="triggerTakedownModal(${inc.id})">
            ${inc.takedown_sent ? '📄 View Notice' : '⚡ Takedown'}
          </button>
        </td>
      </tr>
    `;
  }).join('');
}
