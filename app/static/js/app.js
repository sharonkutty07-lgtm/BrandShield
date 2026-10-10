// Global Application State
const State = {
  currentBrandId: "ALL",
  brands: [],
  activeTab: "dashboard-view"
};

// Navigation Tab Switcher
function showTab(tabId) {
  State.activeTab = tabId;

  // Update nav links
  document.querySelectorAll(".nav-item").forEach(el => {
    if (el.getAttribute("data-target") === tabId) {
      el.classList.add("active");
    } else {
      el.classList.remove("active");
    }
  });

  // Update views
  document.querySelectorAll(".view-section").forEach(sec => {
    if (sec.id === tabId) {
      sec.classList.add("active");
    } else {
      sec.classList.remove("active");
    }
  });

  // Update page heading
  const headings = {
    "dashboard-view": { title: "Threat Intelligence Dashboard", sub: "Continuous external threat monitoring and proactive digital risk defense" },
    "brands-view": { title: "Brand Registration & Asset Matrix", sub: "Establish your protected trademark ground truth and official perimeter" },
    "lookalikes-view": { title: "Look-Alike & Typosquatting Hunter", sub: "Proactive tracking of homoglyphs, TLD swaps, and combotwinning domains" },
    "scanner-view": { title: "Phishing Link & URL Risk Scanner", sub: "Instant heuristic, entropy, and brand impersonation diagnostic engine" },
    "impersonations-view": { title: "Social Impersonation Watch", sub: "Monitoring deceptive brand profiles across Instagram, Twitter/X, and Facebook" },
    "incidents-view": { title: "Incident Lifecycle & Takedown Desk", sub: "Triage threats and generate legally binding Cease & Desist notifications" },
    "pricing-view": { title: "Transparent Security Subscription & ROI Model", sub: "Defensive Digital Risk Protection accessible for growing businesses" }
  };

  if (headings[tabId]) {
    document.getElementById("page-heading").innerText = headings[tabId].title;
    document.getElementById("page-subheading").innerText = headings[tabId].sub;
  }

  // Trigger data refreshes for the active tab
  if (tabId === "dashboard-view") loadDashboardData();
  if (tabId === "brands-view") loadBrands();
  if (tabId === "lookalikes-view") loadLookalikes();
  if (tabId === "impersonations-view") loadImpersonations();
  if (tabId === "incidents-view") loadIncidents();
  if (tabId === "scanner-view") loadRecentScans();
  if (tabId === "pricing-view" && typeof updatePricingCalculator === 'function') updatePricingCalculator();
}

// Global Toast Notifications
function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  const toast = document.createElement("div");
  toast.className = "toast";
  
  const icon = type === "success" ? "✅" : type === "danger" ? "🚨" : type === "warning" ? "⚠️" : "🛡️";
  toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
  
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Modal Helpers
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.add("active");
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.remove("active");
}

// Initialize Application on DOM Ready
document.addEventListener("DOMContentLoaded", () => {
  // Setup tab click listeners
  document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      const target = item.getAttribute("data-target");
      if (target) showTab(target);
    });
  });

  // Setup Global Brand Selector
  const selector = document.getElementById("global-brand-filter");
  selector.addEventListener("change", (e) => {
    State.currentBrandId = e.target.value;
    showToast(`Filtering data by: ${e.target.options[e.target.selectedIndex].text}`, "info");
    
    // Refresh currently open tab
    showTab(State.activeTab);
  });

  // Initial Data Load
  loadBrandsDropdown();
  loadDashboardData();
});

// Load Brands into the Global Header Dropdown
async function loadBrandsDropdown() {
  try {
    const res = await fetch("/api/brands/");
    if (!res.ok) return;
    const brands = await res.json();
    State.brands = brands;

    const selector = document.getElementById("global-brand-filter");
    selector.innerHTML = `<option value="ALL">All Monitored Brands</option>`;
    brands.forEach(b => {
      selector.innerHTML += `<option value="${b.id}">${b.company_name} (${b.official_domain})</option>`;
    });
  } catch (err) {
    console.error("Error loading brands dropdown:", err);
  }
}
