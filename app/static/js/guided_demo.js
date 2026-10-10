// Interactive Guided Pitch Demo Module

const DemoSteps = [
  {
    stepNumber: "Step 1 of 5",
    title: "1. The Threat: Real-World Brand Impersonation Scam",
    desc: "Attackers register fake look-alike websites copying brand logins (e.g. ABC Bank NetBanking) to steal consumer passwords, OTPs, and credit cards.",
    tab: "dashboard-view",
    action: () => {
      showToast("Step 1: Scammers launch targeted campaigns outside the company's internal firewall.", "info");
    }
  },
  {
    stepNumber: "Step 2 of 5",
    title: "2. Brand Registration: Establish Protected Perimeter",
    desc: "The organization enters its official company name, verified domains, and social handles into BrandShield to establish the golden ground truth baseline.",
    tab: "brands-view",
    action: () => {
      showToast("Step 2: Brand baseline registered. Continuous discovery engines triggered!", "success");
    }
  },
  {
    stepNumber: "Step 3 of 5",
    title: "3. Autonomous Look-Alike & Typosquatting Hunter",
    desc: "BrandShield hunts for homoglyphs, dropped letters, combosquatting ('brand-login.xyz'), and abusive TLDs using RapidFuzz character similarity.",
    tab: "lookalikes-view",
    action: () => {
      showToast("Step 3: 20+ deceptive domains detected with 85%+ similarity scores.", "warning");
    }
  },
  {
    stepNumber: "Step 4 of 5",
    title: "4. Explainable Phishing Link Risk Scoring",
    desc: "When users or security teams paste a suspicious URL, BrandShield inspects entropy, lack of SSL, brand mismatch, and returns an explainable 0-100 risk score.",
    tab: "scanner-view",
    action: () => {
      const input = document.getElementById("scan-url-input");
      if (input) {
        input.value = "http://abcbank-secure-netbanking.top/login.php";
        document.getElementById("btn-scan-action").click();
      }
    }
  },
  {
    stepNumber: "Step 5 of 5",
    title: "5. Rapid Incident Triage & 1-Click Legal Takedown",
    desc: "The security analyst moves threats from OPEN ➔ INVESTIGATING ➔ RESOLVED, and generates an automated Cease & Desist / DMCA notice pre-addressed to registrar abuse desks.",
    tab: "incidents-view",
    action: () => {
      showToast("Step 5: 1-Click Takedown notice generated for Cloudflare / Namecheap abuse desks!", "success");
      setTimeout(() => triggerTakedownModal(1), 700);
    }
  }
];

let currentStepIndex = 0;

function startGuidedDemo() {
  currentStepIndex = 0;
  const bar = document.getElementById("demo-guide-bar");
  if (bar) bar.classList.add("active");
  renderDemoStep(currentStepIndex);
}

function nextDemoStep() {
  if (currentStepIndex < DemoSteps.length - 1) {
    currentStepIndex++;
    renderDemoStep(currentStepIndex);
  } else {
    stopGuidedDemo();
    showTab("pricing-view");
    showToast("🎉 Demo Complete! Here is the commercial subscription & ROI model.", "success");
  }
}

function prevDemoStep() {
  if (currentStepIndex > 0) {
    currentStepIndex--;
    renderDemoStep(currentStepIndex);
  }
}

function stopGuidedDemo() {
  const bar = document.getElementById("demo-guide-bar");
  if (bar) bar.classList.remove("active");
}

function renderDemoStep(index) {
  const step = DemoSteps[index];
  document.getElementById("demo-badge").innerText = step.stepNumber;
  document.getElementById("demo-title").innerText = step.title;
  document.getElementById("demo-desc").innerText = step.desc;

  // Switch tab
  showTab(step.tab);

  // Execute step action
  if (step.action) step.action();

  // Update button labels
  const nextBtn = document.getElementById("demo-next-btn");
  if (index === DemoSteps.length - 1) {
    nextBtn.innerText = "Finish & View Pricing ➔";
  } else {
    nextBtn.innerText = "Next Step ➔";
  }
}
