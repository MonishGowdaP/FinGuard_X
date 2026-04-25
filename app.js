const state = {
  decisionStartedAt: Date.now(),
  freezeActive: false,
  behaviorSamples: [],
  preGeneratedScams: [],
  currentScam: null,
  linkedGuardian: null,
  authorityReports: load("authorityReports", []),
  hvm: load("hvm", {
    panicProne: 0.62,
    authorityTrust: 0.74,
    reactionSpeed: 0.68,
    susceptibility: 0.59,
    simulations: 0,
  }),
  pipeline: null,
  classifierThreshold: 0.65,
  scamSeedsFromDatasets: [],
  legitSeedsFromDatasets: [],
  simulationSource: "merged",
  decisionStartedAtMs: 0,
  decisionTimerId: null,
  freezeTimerId: null,
  attempts: { safe: 0, scam: 0 },
  recentAttempts: [],
  storyModeRunning: false,
  pressureWindowMs: 15000,
};

const socketBus = new EventTarget();
const FALLBACK_PRESSURE_THRESHOLD = 0.75;
const SCAM_LIBRARY = [
  {
    title: "UPI Freeze Alert",
    amount: 5000,
    source: "SBI Security Desk",
    message:
      "URGENT: Your UPI access will be blocked in 4 minutes. Pay verification hold amount immediately to retain service.",
  },
  {
    title: "KYC Expiry Warning",
    amount: 2999,
    source: "Axis KYC Cell",
    message:
      "KYC expired. Account will be suspended today. Complete instant re-activation fee now.",
  },
  {
    title: "Reward Transfer Trap",
    amount: 1500,
    source: "UPI Cashback Center",
    message:
      "You won a priority reward. To release funds now, pay refundable processing amount first.",
  },
];
const LEGIT_LIBRARY = [
  {
    title: "Routine Utility Payment",
    amount: 1240,
    source: "Registered Utility Portal",
    message:
      "Your monthly electricity bill is ready. Review invoice details and pay before due date to avoid late fee.",
  },
  {
    title: "Card Statement Reminder",
    amount: 2875,
    source: "Verified Card Services",
    message:
      "Your card statement is generated. Please verify your transactions and pay the outstanding amount through the official app.",
  },
  {
    title: "Subscription Renewal Notice",
    amount: 499,
    source: "Trusted Subscription Provider",
    message:
      "Your annual subscription renews tomorrow. Confirm plan details and complete payment if you want to continue service.",
  },
];
const DATASET_INSIGHTS = {
  source: "payment_fraud.csv",
  total: 39221,
  fraud: 560,
  fraudRate: 1.43,
  paymentMethod: [
    { label: "creditcard", total: 28004, fraud: 410, fraudRate: 1.46 },
    { label: "paypal", total: 9303, fraud: 129, fraudRate: 1.39 },
    { label: "storecredit", total: 1914, fraud: 21, fraudRate: 1.1 },
  ],
  category: [
    { label: "(blank)", total: 95, fraud: 8, fraudRate: 8.42 },
    { label: "shopping", total: 13328, fraud: 199, fraudRate: 1.49 },
    { label: "electronics", total: 12834, fraud: 176, fraudRate: 1.37 },
    { label: "food", total: 12964, fraud: 177, fraudRate: 1.37 },
  ],
  weekend: [
    { label: "(blank)", total: 560, fraud: 560, fraudRate: 100 },
    { label: "0", total: 19348, fraud: 0, fraudRate: 0 },
    { label: "1", total: 19313, fraud: 0, fraudRate: 0 },
  ],
};

boot();

function boot() {
  warmupScams();
  bindUI();
  renderDatasetInsights();
  renderHvm();
  renderAttemptChart();
  showNextScam();
  startBehaviorTracker();
  listenSocketEvents();
  setActiveFeaturePanel(null);
  document.body.classList.remove("menu-open");
  appendEvent("System ready. Behavioral tracking active.", "INFO");
}

function bindUI() {
  $("#payNowBtn").addEventListener("click", onPayNow);
  $("#verifyBtn").addEventListener("click", () => {
    stopReactionTimer();
    appendEvent("User paused and chose to verify source.", "SAFE");
    state.attempts.safe += 1;
    pushAttemptResult(false);
    updateHvmFromRecentAttempts();
    renderAttemptChart();
    renderHvm();
  });
  $("#demoModeBtn").addEventListener("click", runDemoMode);
  $("#storyModeBtn").addEventListener("click", runStoryMode);
  $("#resetBtn").addEventListener("click", () => location.reload());
  $("#classifyBtn").addEventListener("click", classifyPastedMessage);
  $("#linkGuardianBtn").addEventListener("click", linkGuardian);
  $("#runPipelineBtn").addEventListener("click", runDataPipeline);
  $("#csvFileInput").addEventListener("change", onCsvFileSelected);
  $("#thresholdSlider").addEventListener("input", onThresholdChanged);
  $("#simulationSource").addEventListener("change", onSimulationSourceChanged);
  $("#pressureWindow").addEventListener("change", onPressureWindowChanged);
  $("#menuToggleBtn").addEventListener("click", toggleFeatureMenu);
  document.querySelectorAll(".menu-item").forEach((btn) => {
    btn.addEventListener("click", () => setActiveFeaturePanel(btn.dataset.panel));
  });
}

function warmupScams() {
  const { scams, legit } = getSimulationScamPool();
  const balancedPool = buildBalancedSimulationPool(scams, legit);
  state.preGeneratedScams = balancedPool.map((entry) => ({
    ...entry,
    isScam: typeof entry.isScam === "boolean" ? entry.isScam : true,
    dna: scoreScamDna(entry.message),
  }));
}

function getSimulationScamPool() {
  const scamBase = state.scamSeedsFromDatasets.length
    ? [...SCAM_LIBRARY, ...state.scamSeedsFromDatasets]
    : [...SCAM_LIBRARY];
  const legitBase = state.legitSeedsFromDatasets.length
    ? [...LEGIT_LIBRARY, ...state.legitSeedsFromDatasets]
    : [...LEGIT_LIBRARY];

  if (state.simulationSource === "payment-only") {
    return {
      scams: scamBase.map((entry) => ({ ...entry, isScam: true })),
      legit: legitBase.map((entry) => ({ ...entry, isScam: false })),
    };
  }
  if (state.simulationSource === "text-only") {
    return {
      scams: (state.scamSeedsFromDatasets.length ? state.scamSeedsFromDatasets : SCAM_LIBRARY).map(
        (entry) => ({ ...entry, isScam: true })
      ),
      legit: (state.legitSeedsFromDatasets.length ? state.legitSeedsFromDatasets : LEGIT_LIBRARY).map(
        (entry) => ({ ...entry, isScam: false })
      ),
    };
  }
  return {
    scams: scamBase.map((entry) => ({ ...entry, isScam: true })),
    legit: legitBase.map((entry) => ({ ...entry, isScam: false })),
  };
}

function buildBalancedSimulationPool(scams, legit) {
  const scamList = scams || [];
  const legitList = legit || [];
  if (!scamList.length && !legitList.length) return [];
  if (!scamList.length) return [...legitList];
  if (!legitList.length) return [...scamList];

  const targetPerSide = Math.max(scamList.length, legitList.length);
  const balanced = [];
  for (let i = 0; i < targetPerSide; i += 1) {
    balanced.push({ ...scamList[i % scamList.length], isScam: true });
    balanced.push({ ...legitList[i % legitList.length], isScam: false });
  }
  for (let i = balanced.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [balanced[i], balanced[j]] = [balanced[j], balanced[i]];
  }
  return balanced.slice(0, 80);
}

function showNextScam() {
  if (!state.preGeneratedScams.length) warmupScams();
  state.currentScam =
    state.preGeneratedScams[
      Math.floor(Math.random() * state.preGeneratedScams.length)
    ];
  state.decisionStartedAt = Date.now();
  state.decisionStartedAtMs = performance.now();
  $("#decisionClock").textContent = "Decision timer started now.";
  $("#scamCard").innerHTML = `
    <p><strong>${state.currentScam.source}</strong></p>
    <h3>${state.currentScam.title}</h3>
    <p>${state.currentScam.message}</p>
    <p><strong>${
      state.currentScam.isScam
        ? `Pay INR ${state.currentScam.amount} immediately`
        : `Payment request INR ${state.currentScam.amount} (verify normally before paying)`
    }</strong></p>
  `;
  renderDna(state.currentScam.dna);
  startReactionTimer();
}

function startReactionTimer() {
  stopReactionTimer();
  state.decisionTimerId = setInterval(() => {
    const elapsedMs = Math.max(0, performance.now() - state.decisionStartedAtMs);
    const elapsedSeconds = formatSecondsFromMs(elapsedMs);
    const riskPulse =
      elapsedMs > state.pressureWindowMs ? "High pressure window" : "Cognitive window";
    const pressureWindowSeconds = formatSecondsFromMs(state.pressureWindowMs);
    $("#msCounter").textContent = `Reaction timer: ${elapsedSeconds}s | ${riskPulse} (${pressureWindowSeconds}s)`;
  }, 50);
}

function stopReactionTimer() {
  if (!state.decisionTimerId) return;
  clearInterval(state.decisionTimerId);
  state.decisionTimerId = null;
}

function startBehaviorTracker() {
  let lastClickAt = Date.now();
  let scrollStops = 0;
  let isScrolling = false;

  window.addEventListener("click", () => {
    const now = Date.now();
    const tapSpeed = 1000 / Math.max(100, now - lastClickAt);
    lastClickAt = now;
    state.behaviorSamples.push({ tapSpeed, at: now });
  });

  window.addEventListener("scroll", () => {
    isScrolling = true;
    clearTimeout(window.__scrollStopTimeout);
    window.__scrollStopTimeout = setTimeout(() => {
      if (isScrolling) {
        scrollStops += 1;
        isScrolling = false;
      }
    }, 180);
  });

  setInterval(() => {
    const now = Date.now();
    const elapsed = (now - state.decisionStartedAt) / 1000;
    const recentTaps = state.behaviorSamples.slice(-5);
    const avgTapSpeed =
      recentTaps.reduce((sum, s) => sum + s.tapSpeed, 0) /
        Math.max(1, recentTaps.length) || 0;
    const hesitation = Math.min(1, scrollStops / 3);
    const pressure = computePressure(avgTapSpeed, hesitation, elapsed);

    socketBus.dispatchEvent(
      new CustomEvent("behavior:sample", {
        detail: {
          avgTapSpeed,
          hesitation,
          elapsed,
          pressure,
          level: pressure >= FALLBACK_PRESSURE_THRESHOLD ? "HIGH" : "LOW",
        },
      })
    );
  }, 2000);
}

function listenSocketEvents() {
  socketBus.addEventListener("behavior:sample", (evt) => {
    const sample = evt.detail;
    appendEvent(
      `Behavior sample -> tap:${sample.avgTapSpeed.toFixed(2)} hesitation:${sample.hesitation.toFixed(
        2
      )} decision:${sample.elapsed.toFixed(1)}s pressure:${sample.pressure.toFixed(
        2
      )}`
      ,
      "METRIC"
    );
    if (sample.level === "HIGH" && !state.freezeActive) {
      const adjustedRisk = adjustRiskByThreshold(sample.pressure);
      socketBus.dispatchEvent(
        new CustomEvent("freeze:trigger", {
          detail: {
            risk: adjustedRisk,
            reason: "Behavior matches scam victim pressure pattern.",
          },
        })
      );
    }
  });

  socketBus.addEventListener("freeze:trigger", (evt) => {
    showFreezeOverlay(evt.detail.risk, evt.detail.reason, evt.detail.pressureWindowMs);
    maybeAlertGuardian(evt.detail.risk);
  });
}

function onPayNow() {
  triggerPaymentFeedback();
  syncPressureWindowFromUI();
  const elapsedMs = Math.max(0, performance.now() - state.decisionStartedAtMs);
  const elapsedSeconds = formatSecondsFromMs(elapsedMs);
  const elapsed = elapsedMs / 1000;
  const fastDecisionPenalty = elapsed < 4 ? 0.3 : 0.1;
  const dnaPressure =
    ((state.currentScam?.dna?.urgency || 0) +
      (state.currentScam?.dna?.authority || 0) +
      (state.currentScam?.dna?.fear || 0)) /
    3;
  const reactionPressure = clamp01(
    (state.pressureWindowMs - elapsedMs) / Math.max(1, state.pressureWindowMs)
  );
  const risk = clamp01(
    state.hvm.susceptibility * 0.35 +
      fastDecisionPenalty * 0.25 +
      dnaPressure * 0.25 +
      reactionPressure * 0.15
  );
  const adjustedRisk = adjustRiskByThreshold(risk);
  stopReactionTimer();
  $("#decisionClock").textContent = `Pay action at ${elapsedSeconds}s. Interception running.`;
  appendEvent(
    `Pay intent captured at ${elapsedSeconds}s. Interception check running.`,
    "METRIC"
  );
  // For demo reliability, payment intent always routes through freeze flow.
  socketBus.dispatchEvent(
    new CustomEvent("freeze:trigger", {
      detail: {
        risk: Math.max(55, adjustedRisk),
        reason: "Payment decision occurred under urgency pressure.",
        pressureWindowMs: state.pressureWindowMs,
      },
    })
  );
}

function showFreezeOverlay(riskScore, reason, pressureWindowMs = state.pressureWindowMs) {
  if (state.freezeActive) return;
  state.freezeActive = true;
  document.body.classList.add("freeze-locked");
  if (state.freezeTimerId) {
    clearInterval(state.freezeTimerId);
    state.freezeTimerId = null;
  }
  const root = $("#freezeRoot");
  const overlayPressureWindowMs = normalizePressureWindowMs(pressureWindowMs, state.pressureWindowMs);
  const pressureWindowSeconds = formatSecondsFromMs(overlayPressureWindowMs);
  const freezeStartedAtMs = performance.now();
  const freezeEndsAtMs = freezeStartedAtMs + overlayPressureWindowMs;
  root.innerHTML = `
    <div class="freeze-overlay">
      <div class="freeze-card">
        <button id="freezeCloseBtn" class="freeze-close hidden" aria-label="Close freeze popup">x</button>
        <h2>Decision Intercepted</h2>
        <p>${reason}</p>
        <p>Risk score: <strong>${riskScore}%</strong></p>
        <p>Pressure window: <strong>${pressureWindowSeconds}s</strong></p>
        <p>You are likely not thinking clearly right now.</p>
        <p class="countdown" id="freezeCountdown">${pressureWindowSeconds}s</p>
        <button id="pauseVerifyNow" class="primary">Pause & Verify</button>
      </div>
    </div>
  `;
  $("#pauseVerifyNow").addEventListener("click", () => {
    appendEvent("User selected Pause & Verify inside freeze.", "FREEZE");
    resolveSimulation(false);
  });
  $("#freezeCloseBtn").addEventListener("click", () => {
    appendEvent("Freeze popup closed after pressure window crossed.", "FREEZE");
    resolveSimulation(false);
  });

  state.freezeTimerId = setInterval(() => {
    const remainingMs = Math.max(0, freezeEndsAtMs - performance.now());
    const el = $("#freezeCountdown");
    if (el) el.textContent = `${formatSecondsFromMs(remainingMs)}s`;
    const elapsedMs = Math.max(0, performance.now() - freezeStartedAtMs);
    if (elapsedMs >= overlayPressureWindowMs) $("#freezeCloseBtn")?.classList.remove("hidden");
    if (remainingMs <= 0) {
      clearInterval(state.freezeTimerId);
      state.freezeTimerId = null;
      promptTimedOutPaymentChoice();
    }
  }, 50);
}

function promptTimedOutPaymentChoice() {
  const root = $("#freezeRoot");
  if (!root) return;
  root.innerHTML = `
    <div class="freeze-overlay">
      <div class="freeze-card report-card">
        <h2>Pressure Window Ended</h2>
        <p>The decision timer ended. Do you want to proceed with this payment now?</p>
        <div class="actions">
          <button id="proceedPaymentBtn" class="danger">Proceed & Pay</button>
          <button id="abortPaymentBtn">Abort Payment</button>
        </div>
      </div>
    </div>
  `;
  $("#proceedPaymentBtn").addEventListener("click", () => {
    const isScam = isCurrentTransactionScam();
    showPaymentSuccessPopup(() => {
      resolveSimulation({
        isScam,
        source: "timeout-proceed",
      });
    });
  });
  $("#abortPaymentBtn").addEventListener("click", () => {
    showPaymentDeclinedPopup(() => {
      resolveSimulation({
        isScam: false,
        source: "timeout-abort",
      });
    });
  });
}

function showPaymentSuccessPopup(onDone) {
  const root = $("#freezeRoot");
  if (!root) {
    if (onDone) onDone();
    return;
  }
  root.innerHTML = `
    <div class="freeze-overlay">
      <div class="freeze-card payment-success-card">
        <div class="success-checkmark">✓</div>
        <h2>PAYMENT SUCCESSFUL</h2>
        <button id="paymentDoneBtn" class="primary">Done</button>
      </div>
    </div>
  `;
  $("#paymentDoneBtn").addEventListener("click", () => {
    if (onDone) onDone();
  });
}

function showPaymentDeclinedPopup(onClose) {
  const root = $("#freezeRoot");
  if (!root) {
    if (onClose) onClose();
    return;
  }
  root.innerHTML = `
    <div class="freeze-overlay">
      <div class="freeze-card payment-success-card">
        <div class="decline-cross">✕</div>
        <h2>PAYMENT DECLINED</h2>
        <button id="paymentCloseBtn">Close</button>
      </div>
    </div>
  `;
  $("#paymentCloseBtn").addEventListener("click", () => {
    if (onClose) onClose();
  });
}

function resolveSimulation(result) {
  if (state.freezeTimerId) {
    clearInterval(state.freezeTimerId);
    state.freezeTimerId = null;
  }
  $("#freezeRoot").innerHTML = "";
  state.freezeActive = false;
  document.body.classList.remove("freeze-locked");
  const elapsed = ((Date.now() - state.decisionStartedAt) / 1000).toFixed(1);
  const reactionMs = Math.max(0, performance.now() - state.decisionStartedAtMs);
  stopReactionTimer();
  const isScam = typeof result === "boolean" ? result : Boolean(result?.isScam);
  const resultSource = typeof result === "object" ? result?.source : null;

  if (isScam) {
    appendEvent(
      `Reveal -> AI scam simulation. Victim would lose INR ${state.currentScam.amount} in ${elapsed}s.`
      ,
      "ALERT"
    );
    state.attempts.scam += 1;
    pushAttemptResult(true, reactionMs);
    updateHvmFromRecentAttempts();
    renderAttemptChart();
    renderHvm();
    promptAuthoritySubmission(
      buildAuthorityReportRecord(reactionMs, elapsed),
      () => showNextScam()
    );
    return;
  } else {
    if (resultSource === "timeout-proceed") {
      appendEvent("Transaction review result: payment appears LEGIT and was completed.", "SAFE");
    } else if (resultSource === "timeout-abort") {
      appendEvent("Payment aborted after timeout. No transaction submitted.", "SAFE");
    } else {
      appendEvent("Reveal -> User interrupted the scam before loss.", "SAFE");
    }
    state.attempts.safe += 1;
    pushAttemptResult(false, reactionMs);
  }
  updateHvmFromRecentAttempts();
  renderAttemptChart();
  renderHvm();
  showNextScam();
}

function isCurrentTransactionScam() {
  const scam = state.currentScam || {};
  if (typeof scam.isScam === "boolean") return scam.isScam;
  if (typeof scam.label === "number") return scam.label === 1;
  const dna = scam.dna || scoreScamDna(scam.message || "");
  const dnaRisk = clamp01((dna.urgency + dna.authority + dna.fear + dna.reward * 0.5) / 3.5);
  const amountRisk = clamp01((toNumber(scam.amount) - 1000) / 9000);
  const blended = clamp01(dnaRisk * 0.65 + amountRisk * 0.2 + state.hvm.susceptibility * 0.15);
  return blended >= state.classifierThreshold;
}

function buildAuthorityReportRecord(reactionMs, elapsedSeconds) {
  const scam = state.currentScam || {};
  return {
    id: `TX-${Date.now()}`,
    submittedAt: new Date().toISOString(),
    source: scam.source || "Unknown source",
    title: scam.title || "Unknown title",
    message: scam.message || "N/A",
    amountInr: scam.amount || 0,
    reactionSeconds: Number(formatSecondsFromMs(reactionMs)),
    decisionSeconds: Number(toNumber(elapsedSeconds).toFixed(3)),
    pressureWindowSeconds: Number(formatSecondsFromMs(state.pressureWindowMs)),
  };
}

function promptAuthoritySubmission(record, onDone) {
  const root = $("#freezeRoot");
  if (!root) {
    if (onDone) onDone();
    return;
  }
  root.innerHTML = `
    <div class="freeze-overlay">
      <div class="freeze-card report-card">
        <h2>Report Scam Transaction</h2>
        <p>Is this the correct transaction to submit to authorities?</p>
        <div class="report-preview">
          <p><strong>Transaction ID:</strong> ${record.id}</p>
          <p><strong>Source:</strong> ${record.source}</p>
          <p><strong>Title:</strong> ${record.title}</p>
          <p><strong>Message:</strong> ${record.message}</p>
          <p><strong>Amount:</strong> INR ${record.amountInr}</p>
          <p><strong>Reaction time:</strong> ${record.reactionSeconds}s</p>
          <p><strong>Decision time:</strong> ${record.decisionSeconds}s</p>
          <p><strong>Pressure window:</strong> ${record.pressureWindowSeconds}s</p>
        </div>
        <div class="actions">
          <button id="submitAuthorityYes" class="primary">Yes, Submit</button>
          <button id="submitAuthorityNo">No, Abort</button>
        </div>
      </div>
    </div>
  `;

  $("#submitAuthorityYes").addEventListener("click", () => {
    state.authorityReports.unshift(record);
    save("authorityReports", state.authorityReports);
    appendEvent(`Authority report submitted for ${record.id}.`, "ALERT");
    showAuthorityStatusPopup({
      title: "SUCCESSFULLLY SUBMITTED",
      isSuccess: true,
      onClose: onDone,
    });
  });

  $("#submitAuthorityNo").addEventListener("click", () => {
    appendEvent(`Authority report aborted for ${record.id}.`, "INFO");
    showAuthorityStatusPopup({
      title: "ABORTED",
      isSuccess: false,
      onClose: onDone,
    });
  });
}

function showAuthorityStatusPopup({ title, isSuccess, onClose }) {
  const root = $("#freezeRoot");
  if (!root) {
    if (onClose) onClose();
    return;
  }
  root.innerHTML = `
    <div class="freeze-overlay">
      <div class="freeze-card payment-success-card">
        <div class="${isSuccess ? "success-checkmark" : "decline-cross"}">${
          isSuccess ? "✓" : "✕"
        }</div>
        <h2>${title}</h2>
        <button id="authorityStatusCloseBtn">${isSuccess ? "Ok" : "Close"}</button>
      </div>
    </div>
  `;
  $("#authorityStatusCloseBtn").addEventListener("click", () => {
    $("#freezeRoot").innerHTML = "";
    if (onClose) onClose();
  });
}

function runDemoMode() {
  appendEvent("Demo mode started: trap visible, auto-click in 3s.", "INFO");
  showNextScam();
  let ticks = 3;
  const timer = setInterval(() => {
    $("#decisionClock").textContent = `Demo auto-click in ${ticks}s`;
    ticks -= 1;
    if (ticks < 0) {
      clearInterval(timer);
      $("#payNowBtn").click();
    }
  }, 1000);
}

function runStoryMode() {
  if (state.storyModeRunning) return;
  state.storyModeRunning = true;
  appendEvent("Story Mode started for judge walkthrough.", "INFO");

  const steps = [
    {
      delay: 0,
      action: () => {
        setActiveFeaturePanel("hvmPanel");
        appendEvent("Step 1: Showing HVM live vulnerability profile.", "INFO");
      },
    },
    {
      delay: 1800,
      action: () => {
        setActiveFeaturePanel("dnaPanel");
        appendEvent("Step 2: Showing Scam DNA classification.", "INFO");
        $("#messageInput").value =
          "URGENT bank notice: account blocked in 10 minutes. Verify KYC now to avoid freeze.";
        classifyPastedMessage();
      },
    },
    {
      delay: 3600,
      action: () => {
        setActiveFeaturePanel("classifierPanel");
        appendEvent("Step 3: Running merged threshold classifier.", "INFO");
        runDataPipeline();
      },
    },
    {
      delay: 6200,
      action: () => {
        setActiveFeaturePanel("eventPanel");
        appendEvent("Step 4: Showing attempt chart + labeled event feed.", "INFO");
      },
    },
    {
      delay: 7600,
      action: () => {
        appendEvent("Step 5: Triggering decision intercept demo.", "FREEZE");
        runDemoMode();
      },
    },
    {
      delay: 9800,
      action: () => {
        state.storyModeRunning = false;
        appendEvent("Story Mode completed.", "INFO");
      },
    },
  ];

  steps.forEach((step) => {
    setTimeout(step.action, step.delay);
  });
}

function classifyPastedMessage() {
  const msg = $("#messageInput").value.trim();
  if (!msg) {
    $("#classificationResult").textContent =
      "Paste a suspicious message first to run Scam DNA classification.";
    appendEvent("Scam DNA classify clicked with empty input.", "INFO");
    return;
  }
  const dna = scoreScamDna(msg);
  renderDna(dna);
  $("#classificationResult").textContent =
    "Classified live: " +
    `Urgency ${dna.urgency.toFixed(2)}, Authority ${dna.authority.toFixed(
      2
    )}, Reward ${dna.reward.toFixed(2)}, Fear ${dna.fear.toFixed(2)}.`;
  appendEvent(
    `Scam DNA analyzed: U=${dna.urgency.toFixed(2)} A=${dna.authority.toFixed(
      2
    )} R=${dna.reward.toFixed(2)} F=${dna.fear.toFixed(2)}.`,
    "METRIC"
  );
}

function scoreScamDna(text) {
  const t = text.toLowerCase();
  const urgency = normalizedHits(t, ["urgent", "immediately", "minutes", "now"]);
  const authority = normalizedHits(t, ["bank", "kyc", "officer", "security", "rbi"]);
  const reward = normalizedHits(t, ["reward", "lottery", "cashback", "won"]);
  const fear = normalizedHits(t, ["blocked", "suspended", "penalty", "freeze", "legal"]);
  return { urgency, authority, reward, fear };
}

function normalizedHits(text, words) {
  const matches = words.reduce(
    (count, w) => count + (text.includes(w) ? 1 : 0),
    0
  );
  return clamp01(matches / words.length);
}

function renderDna(dna) {
  const labels = [
    ["Urgency", dna.urgency],
    ["Authority", dna.authority],
    ["Reward", dna.reward],
    ["Fear", dna.fear],
  ];
  $("#dnaBars").innerHTML = labels
    .map(
      ([k, v]) => `
      <div class="bar-wrap">
        <span>${k}</span>
        <div class="bar"><span style="width:${Math.round(v * 100)}%"></span></div>
        <span>${Math.round(v * 100)}%</span>
      </div>
    `
    )
    .join("");
}

function renderHvm() {
  const reactionPct = Math.round(state.hvm.reactionSpeed * 100);
  const rows = [
    ["Panic-prone level", percent(state.hvm.panicProne)],
    ["Authority trust", percent(state.hvm.authorityTrust)],
    ["Reaction speed", `${reactionPct}%`],
    ["Susceptibility", percent(state.hvm.susceptibility)],
    ["Simulations", state.hvm.simulations || 0],
  ];
  $("#hvmGrid").innerHTML = rows
    .map(
      ([k, v]) => `
      <div class="metric">
        <small>${k}</small>
        <strong>${v}</strong>
      </div>
    `
    )
    .join("");
  renderHvmGraph();
}

function renderHvmGraph() {
  const rows = [
    ["Panic", state.hvm.panicProne],
    ["Authority", state.hvm.authorityTrust],
    ["Reaction", state.hvm.reactionSpeed],
    ["Susceptibility", state.hvm.susceptibility],
  ];
  $("#hvmGraph").innerHTML = rows
    .map(
      ([k, v]) => `
      <div class="graph-bar-row">
        <span>${k}</span>
        <div class="graph-bar"><span style="width:${Math.round(v * 100)}%"></span></div>
        <span>${Math.round(v * 100)}%</span>
      </div>
    `
    )
    .join("");
}

function renderDatasetInsights() {
  const summaryRows = [
    ["Source", DATASET_INSIGHTS.source],
    ["Total transactions", DATASET_INSIGHTS.total.toLocaleString()],
    ["Fraud transactions", DATASET_INSIGHTS.fraud.toLocaleString()],
    ["Fraud rate", `${DATASET_INSIGHTS.fraudRate}%`],
  ];

  $("#datasetSummary").innerHTML = summaryRows
    .map(
      ([k, v]) => `
      <div class="metric">
        <small>${k}</small>
        <strong>${v}</strong>
      </div>
    `
    )
    .join("");

  const breakdownLines = [
    ...DATASET_INSIGHTS.paymentMethod.map(
      (row) =>
        `PaymentMethod=${row.label} -> fraud ${row.fraud}/${row.total} (${row.fraudRate}%)`
    ),
    ...DATASET_INSIGHTS.category.map(
      (row) =>
        `Category=${row.label} -> fraud ${row.fraud}/${row.total} (${row.fraudRate}%)`
    ),
    ...DATASET_INSIGHTS.weekend.map(
      (row) =>
        `isWeekend=${row.label} -> fraud ${row.fraud}/${row.total} (${row.fraudRate}%)`
    ),
    "Data quality flag: all positive fraud labels fall under blank isWeekend values.",
  ];

  $("#datasetBreakdown").innerHTML = breakdownLines
    .map((line) => `<li>${line}</li>`)
    .join("");

  renderPipelineResult();
}

async function runDataPipeline() {
  setPipelineStatus("Running data cleaning and risk scoring...");
  try {
    const paymentCsv = await tryLoadBundledCsv();
    const legitCsv = await tryLoadLegitCsv();
    const paymentResult = processFraudCsv(paymentCsv);
    const legitResult = processLegitCsv(legitCsv);
    state.pipeline = combinePipelineResults(paymentResult, legitResult);
    state.scamSeedsFromDatasets = legitResult.scamSeeds;
    state.legitSeedsFromDatasets = legitResult.legitSeeds || [];
    warmupScams();
    applyBestThresholdFromPipeline();
    renderPipelineResult();
    setPipelineStatus(
      `Pipeline complete. Processed ${state.pipeline.totalRows.toLocaleString()} merged rows.`
    );
    appendEvent("Combined pipeline completed from payment + legit datasets.", "INFO");
  } catch {
    setPipelineStatus(
      "Auto-load failed. Ensure payment_fraud.csv and legit_payment_datasets.csv are present."
    );
  }
}

async function tryLoadBundledCsv() {
  const response = await fetch("./payment_fraud.csv");
  if (!response.ok) throw new Error("CSV not available");
  return response.text();
}

async function onCsvFileSelected(evt) {
  const file = evt.target.files?.[0];
  if (!file) return;
  setPipelineStatus(`Reading ${file.name}...`);
  const csv = await file.text();
  const result = processFraudCsv(csv);
  state.pipeline = result;
  applyBestThresholdFromPipeline();
  renderPipelineResult();
  setPipelineStatus(
    `Pipeline complete from uploaded file. Rows: ${result.totalRows.toLocaleString()}.`
  );
  appendEvent("Dataset pipeline completed from uploaded CSV.", "INFO");
}

async function tryLoadLegitCsv() {
  const response = await fetch("./legit_payment_datasets.csv");
  if (!response.ok) throw new Error("Legit CSV not available");
  return response.text();
}

function processFraudCsv(csvText) {
  const lines = csvText.split(/\r?\n/).filter(Boolean);
  const headers = lines[0].split(",");
  const rows = lines.slice(1).map((line) => parseCsvLine(line, headers));
  const modes = computeModes(rows, ["paymentMethod", "Category", "isWeekend"]);
  const cleaned = rows.map((row) => cleanRow(row, modes));
  const model = buildFraudModel(cleaned);
  const scored = cleaned.map((row, idx) => scoreRowRiskDataDriven(row, idx, model));
  const topRisk = [...scored].sort((a, b) => b.riskScore - a.riskScore).slice(0, 10);
  const missingWeekendFraud = cleaned.filter(
    (r) => r._wasWeekendMissing && r.label === 1
  ).length;
  return {
    source: "payment_fraud.csv",
    totalRows: cleaned.length,
    missingFilled: {
      paymentMethod: cleaned.filter((r) => r._wasPaymentMethodMissing).length,
      category: cleaned.filter((r) => r._wasCategoryMissing).length,
      weekend: cleaned.filter((r) => r._wasWeekendMissing).length,
    },
    leakageFlags: {
      missingWeekendFraud,
      leakageLikely: missingWeekendFraud > 0,
    },
    avgRisk:
      scored.reduce((sum, row) => sum + row.riskScore, 0) / Math.max(1, scored.length),
    fraudHitInTop10: topRisk.filter((row) => row.label === 1).length,
    scored,
    topRisk,
    scamSeeds: [],
  };
}

function buildFraudModel(rows) {
  const byMethod = new Map();
  const byCategory = new Map();
  let fraudCount = 0;
  rows.forEach((r) => {
    if (r.label === 1) fraudCount += 1;
    byMethod.set(r.paymentMethod, (byMethod.get(r.paymentMethod) || { t: 0, f: 0 }));
    byCategory.set(r.category, (byCategory.get(r.category) || { t: 0, f: 0 }));
    const m = byMethod.get(r.paymentMethod);
    const c = byCategory.get(r.category);
    m.t += 1;
    c.t += 1;
    if (r.label === 1) {
      m.f += 1;
      c.f += 1;
    }
  });
  return {
    baseRate: fraudCount / Math.max(1, rows.length),
    byMethod,
    byCategory,
  };
}

function scoreRowRiskDataDriven(row, idx, model) {
  const methodStat = model.byMethod.get(row.paymentMethod) || { t: 1, f: 0 };
  const categoryStat = model.byCategory.get(row.category) || { t: 1, f: 0 };
  const methodRate = (methodStat.f + 1) / (methodStat.t + 2);
  const categoryRate = (categoryStat.f + 1) / (categoryStat.t + 2);
  const accountAgeRisk = 1 - clamp01(row.accountAgeDays / 365);
  const methodAgeRisk = 1 - clamp01(row.paymentMethodAgeDays / 180);
  const nightRisk = row.localTime < 6 || row.localTime > 23 ? 1 : 0.15;
  const missingSignal =
    (row._wasPaymentMethodMissing ? 0.03 : 0) +
    (row._wasCategoryMissing ? 0.03 : 0) +
    (row._wasWeekendMissing ? 0.03 : 0);
  const riskScore = clamp01(
    model.baseRate * 0.1 +
      methodRate * 0.25 +
      categoryRate * 0.2 +
      accountAgeRisk * 0.2 +
      methodAgeRisk * 0.2 +
      nightRisk * 0.05 +
      missingSignal
  );
  return {
    id: idx + 1,
    riskScore,
    label: row.label,
    reasons: [
      methodRate > 0.25 ? "high-risk payment method" : "normal payment method",
      categoryRate > 0.25 ? "high-risk category" : "normal category",
      accountAgeRisk > 0.8 ? "new account" : "aged account",
    ],
    row,
  };
}

function processLegitCsv(csvText) {
  const records = parseCsvRecords(csvText);
  if (!records.length) {
    return {
      source: "legit_payment_datasets.csv",
      totalRows: 0,
      scored: [],
      scamSeeds: [],
      missingFilled: { paymentMethod: 0, category: 0, weekend: 0 },
      leakageFlags: { missingWeekendFraud: 0, leakageLikely: false },
      avgRisk: 0,
      fraudHitInTop10: 0,
      topRisk: [],
    };
  }

  let headers = records[0];
  let start = 1;
  if (headers.length >= 5 && headers[0] === "A" && records[1]) {
    headers = records[1];
    start = 2;
  }
  const idx = {
    text: headers.findIndex((h) => h.toLowerCase() === "text"),
    label: headers.findIndex((h) => h.toLowerCase() === "label"),
    phishingType: headers.findIndex((h) => h.toLowerCase() === "phishing_type"),
    severity: headers.findIndex((h) => h.toLowerCase() === "severity"),
    confidence: headers.findIndex((h) => h.toLowerCase() === "confidence"),
  };

  const scored = [];
  const scamSeeds = [];
  const legitSeeds = [];
  for (let i = start; i < records.length; i += 1) {
    const row = records[i];
    if (!row || !row.length) continue;
    const text = (row[idx.text] || "").trim();
    if (!text) continue;
    const label = Number(row[idx.label]) === 1 ? 1 : 0;
    const severityRaw = (row[idx.severity] || "low").toLowerCase();
    const confidence = clamp01(toNumber(row[idx.confidence] || "0.5"));
    const severityWeight =
      severityRaw === "high" ? 1 : severityRaw === "medium" ? 0.65 : 0.35;
    const dna = scoreScamDna(text);
    const lexicalRisk =
      dna.urgency * 0.3 + dna.authority * 0.2 + dna.reward * 0.2 + dna.fear * 0.3;
    const riskScore = clamp01(lexicalRisk * 0.6 + confidence * 0.25 + severityWeight * 0.15);
    scored.push({
      id: `legit-${i}`,
      label,
      riskScore,
      reasons: [`text-${severityRaw}`, `confidence-${confidence.toFixed(2)}`],
      row: {
        paymentMethod: "text-link",
        category: row[idx.phishingType] || "unknown",
        accountAgeDays: 0,
      },
    });

    if (label === 1 && scamSeeds.length < 8) {
      scamSeeds.push(makeScamSeedFromText(text, row[idx.phishingType], severityRaw));
    }
    if (label === 0 && legitSeeds.length < 8) {
      legitSeeds.push(makeLegitSeedFromText(text, row[idx.phishingType]));
    }
  }

  const topRisk = [...scored].sort((a, b) => b.riskScore - a.riskScore).slice(0, 10);
  return {
    source: "legit_payment_datasets.csv",
    totalRows: scored.length,
    missingFilled: { paymentMethod: 0, category: 0, weekend: 0 },
    leakageFlags: { missingWeekendFraud: 0, leakageLikely: false },
    avgRisk:
      scored.reduce((sum, row) => sum + row.riskScore, 0) / Math.max(1, scored.length),
    fraudHitInTop10: topRisk.filter((row) => row.label === 1).length,
    scored,
    topRisk,
    scamSeeds,
    legitSeeds,
  };
}

function combinePipelineResults(primary, secondary) {
  const scored = [...primary.scored, ...secondary.scored];
  const topRisk = [...scored].sort((a, b) => b.riskScore - a.riskScore).slice(0, 10);
  const avgRisk =
    scored.reduce((sum, row) => sum + row.riskScore, 0) / Math.max(1, scored.length);
  return {
    source: `${primary.source} + ${secondary.source}`,
    totalRows: primary.totalRows + secondary.totalRows,
    missingFilled: primary.missingFilled,
    leakageFlags: primary.leakageFlags,
    avgRisk,
    fraudHitInTop10: topRisk.filter((row) => row.label === 1).length,
    scored,
    topRisk,
    components: {
      primaryRows: primary.totalRows,
      secondaryRows: secondary.totalRows,
      scamSeeds: secondary.scamSeeds.length,
    },
  };
}

function parseCsvRecords(text) {
  const rows = [];
  let row = [];
  let cell = "";
  let inQuotes = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const next = text[i + 1];
    if (ch === '"') {
      if (inQuotes && next === '"') {
        cell += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (ch === "," && !inQuotes) {
      row.push(cell);
      cell = "";
      continue;
    }
    if ((ch === "\n" || ch === "\r") && !inQuotes) {
      if (ch === "\r" && next === "\n") i += 1;
      row.push(cell);
      if (row.some((v) => v !== "")) rows.push(row);
      row = [];
      cell = "";
      continue;
    }
    cell += ch;
  }
  row.push(cell);
  if (row.some((v) => v !== "")) rows.push(row);
  return rows;
}

function makeScamSeedFromText(text, phishingType, severity) {
  const normalized = text.replace(/\s+/g, " ").trim();
  const short = normalized.length > 180 ? `${normalized.slice(0, 177)}...` : normalized;
  const amount =
    severity === "high" ? 9000 : severity === "medium" ? 5000 : 2500;
  return {
    title: `Dataset Scenario: ${phishingType || "social-engineering"}`,
    amount,
    source: "Pattern learned from legit/phishing dataset",
    message: short,
  };
}

function makeLegitSeedFromText(text, category) {
  const normalized = text.replace(/\s+/g, " ").trim();
  const short = normalized.length > 180 ? `${normalized.slice(0, 177)}...` : normalized;
  return {
    title: `Verified Notice: ${category || "account-update"}`,
    amount: 1200 + Math.round(Math.random() * 1800),
    source: "Known Sender (dataset legit sample)",
    message: short,
  };
}

function parseCsvLine(line, headers) {
  const parts = line.split(",");
  const obj = {};
  headers.forEach((h, i) => {
    obj[h] = (parts[i] || "").trim();
  });
  return obj;
}

function computeModes(rows, fields) {
  const modes = {};
  fields.forEach((field) => {
    const counts = new Map();
    rows.forEach((row) => {
      const v = (row[field] || "").trim();
      if (!v) return;
      counts.set(v, (counts.get(v) || 0) + 1);
    });
    let top = "";
    let max = -1;
    counts.forEach((count, value) => {
      if (count > max) {
        max = count;
        top = value;
      }
    });
    modes[field] = top;
  });
  return modes;
}

function cleanRow(row, modes) {
  const accountAgeDays = clampNumber(toNumber(row.accountAgeDays), 0, 2000, 0);
  const paymentMethodAgeDays = clampNumber(
    toNumber(row.paymentMethodAgeDays),
    0,
    2000,
    0
  );
  const localTime = clampNumber(toNumber(row.localTime), 0, 24, 0);
  const numItems = clampNumber(toNumber(row.numItems), 1, 100, 1);
  const wasPaymentMethodMissing = !row.paymentMethod;
  const wasCategoryMissing = !row.Category;
  const wasWeekendMissing = row.isWeekend === "";
  const paymentMethod = row.paymentMethod || modes.paymentMethod || "creditcard";
  const category = row.Category || modes.Category || "shopping";
  const isWeekend = row.isWeekend === "" ? modes.isWeekend || "0" : row.isWeekend;
  const label = Number(row.label) === 1 ? 1 : 0;

  return {
    accountAgeDays,
    paymentMethodAgeDays,
    localTime,
    numItems,
    paymentMethod,
    category,
    isWeekend,
    label,
    _wasPaymentMethodMissing: wasPaymentMethodMissing,
    _wasCategoryMissing: wasCategoryMissing,
    _wasWeekendMissing: wasWeekendMissing,
  };
}

function scoreRowRisk(row, idx) {
  const accountAgeRisk = 1 - clamp01(row.accountAgeDays / 365);
  const methodAgeRisk = 1 - clamp01(row.paymentMethodAgeDays / 180);
  const nightRisk = row.localTime < 6 || row.localTime > 23 ? 1 : 0.2;
  const itemRisk = clamp01((row.numItems - 1) / 4);
  const methodRisk =
    row.paymentMethod === "creditcard"
      ? 0.55
      : row.paymentMethod === "paypal"
      ? 0.5
      : 0.35;
  const categoryRisk =
    row.category === "shopping"
      ? 0.55
      : row.category === "electronics"
      ? 0.5
      : 0.45;
  const missingSignal =
    (row._wasPaymentMethodMissing ? 0.05 : 0) +
    (row._wasCategoryMissing ? 0.05 : 0) +
    (row._wasWeekendMissing ? 0.05 : 0);
  const riskScore = clamp01(
    accountAgeRisk * 0.2 +
      methodAgeRisk * 0.25 +
      nightRisk * 0.15 +
      itemRisk * 0.1 +
      methodRisk * 0.15 +
      categoryRisk * 0.1 +
      missingSignal
  );
  const reasons = [];
  if (accountAgeRisk > 0.8) reasons.push("new account");
  if (methodAgeRisk > 0.8) reasons.push("fresh payment method");
  if (nightRisk > 0.9) reasons.push("odd local time");
  if (row._wasWeekendMissing) reasons.push("missing weekend field");
  if (!reasons.length) reasons.push("baseline mixed risk");
  return {
    id: idx + 1,
    riskScore,
    label: row.label,
    reasons,
    row,
  };
}

function renderPipelineResult() {
  const list = $("#topRiskRows");
  if (!list) return;
  if (!state.pipeline) {
    list.innerHTML =
      "<li>Run pipeline to see cleaned records, leakage checks, and top risk rows.</li>";
    $("#thresholdMetrics").innerHTML = "";
    return;
  }
  const p = state.pipeline;
  const summaryRows = [
    `<li><strong>Source:</strong> ${p.source || "merged dataset"}</li>`,
    `<li><strong>Pipeline rows:</strong> ${p.totalRows.toLocaleString()}</li>`,
    `<li><strong>Missing filled:</strong> paymentMethod=${p.missingFilled.paymentMethod}, category=${p.missingFilled.category}, isWeekend=${p.missingFilled.weekend}</li>`,
    `<li><strong>Leakage check:</strong> missing-isWeekend fraud rows=${p.leakageFlags.missingWeekendFraud}</li>`,
    `<li><strong>Average risk score:</strong> ${(p.avgRisk * 100).toFixed(1)}%</li>`,
    `<li><strong>Top-10 fraud hits:</strong> ${p.fraudHitInTop10}/10</li>`,
  ];
  if (p.components) {
    summaryRows.push(
      `<li><strong>Merged rows:</strong> payment=${p.components.primaryRows}, legit=${p.components.secondaryRows}</li>`
    );
    summaryRows.push(
      `<li><strong>Scam simulation seeds added:</strong> ${p.components.scamSeeds}</li>`
    );
  }

  list.innerHTML =
    summaryRows.join("") +
    p.topRisk
    .map(
      (r) =>
        `<li>#${r.id} risk=${(r.riskScore * 100).toFixed(1)}% label=${r.label} method=${
          r.row.paymentMethod
        } category=${r.row.category} accountAge=${r.row.accountAgeDays}d reasons=${r.reasons.join(
          ", "
        )}</li>`
    )
    .join("");

  renderThresholdMetrics();
}

function setPipelineStatus(msg) {
  $("#pipelineStatus").textContent = msg;
}

function onSimulationSourceChanged(evt) {
  state.simulationSource = evt.target.value;
  warmupScams();
  showNextScam();
  appendEvent(`Simulation source switched to ${state.simulationSource}.`, "INFO");
}

function onPressureWindowChanged(evt) {
  state.pressureWindowMs = normalizePressureWindowMs(evt.target.value, 15000);
  const pressureWindowSeconds = formatSecondsFromMs(state.pressureWindowMs);
  $("#msCounter").textContent = `Reaction timer: 0.000s | Cognitive window (${pressureWindowSeconds}s)`;
  appendEvent(
    `Pressure window set to ${pressureWindowSeconds} seconds.`,
    "INFO"
  );
}

function onThresholdChanged(evt) {
  state.classifierThreshold = clampNumber(
    toNumber(evt.target.value),
    0.2,
    0.95,
    0.65
  );
  $("#thresholdValue").textContent = state.classifierThreshold.toFixed(2);
  renderThresholdMetrics();
  appendEvent(
    `Risk threshold updated to ${state.classifierThreshold.toFixed(2)}; live risk score scaling updated.`,
    "INFO"
  );
}

function renderThresholdMetrics() {
  const root = $("#thresholdMetrics");
  if (!root || !state.pipeline) return;
  const stats = evaluateThreshold(
    state.pipeline.scored || [],
    state.classifierThreshold
  );
  const rows = [
    ["Threshold", state.classifierThreshold.toFixed(2)],
    ["TP", stats.tp],
    ["FP", stats.fp],
    ["TN", stats.tn],
    ["FN", stats.fn],
    ["Precision", `${(stats.precision * 100).toFixed(2)}%`],
    ["Recall", `${(stats.recall * 100).toFixed(2)}%`],
    ["F1 Score", `${(stats.f1 * 100).toFixed(2)}%`],
    ["Accuracy", `${(stats.accuracy * 100).toFixed(2)}%`],
  ];
  root.innerHTML = rows
    .map(
      ([k, v]) => `
      <div class="metric">
        <small>${k}</small>
        <strong>${v}</strong>
      </div>
    `
    )
    .join("");
}

function applyBestThresholdFromPipeline() {
  if (!state.pipeline?.scored?.length) return;
  const tuned = findBestF1Threshold(state.pipeline.scored, 0.2, 0.95, 0.01);
  state.classifierThreshold = tuned.threshold;
  const slider = $("#thresholdSlider");
  if (slider) slider.value = tuned.threshold.toFixed(2);
  $("#thresholdValue").textContent = tuned.threshold.toFixed(2);
}

function findBestF1Threshold(scoredRows, start, end, step) {
  let bestThreshold = start;
  let bestStats = evaluateThreshold(scoredRows, start);
  for (let t = start + step; t <= end + 1e-9; t += step) {
    const threshold = Number(t.toFixed(2));
    const stats = evaluateThreshold(scoredRows, threshold);
    const sameF1 = Math.abs(stats.f1 - bestStats.f1) < 1e-9;
    const better =
      stats.f1 > bestStats.f1 ||
      (sameF1 && stats.precision > bestStats.precision) ||
      (sameF1 &&
        Math.abs(stats.precision - bestStats.precision) < 1e-9 &&
        threshold > bestThreshold);
    if (better) {
      bestThreshold = threshold;
      bestStats = stats;
    }
  }
  return { threshold: bestThreshold, stats: bestStats };
}

function evaluateThreshold(scoredRows, threshold) {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  scoredRows.forEach((row) => {
    const predicted = row.riskScore >= threshold ? 1 : 0;
    if (predicted === 1 && row.label === 1) tp += 1;
    else if (predicted === 1 && row.label === 0) fp += 1;
    else if (predicted === 0 && row.label === 0) tn += 1;
    else fn += 1;
  });
  const precision = tp / Math.max(1, tp + fp);
  const recall = tp / Math.max(1, tp + fn);
  const f1 = (2 * precision * recall) / Math.max(1e-9, precision + recall);
  const accuracy = (tp + tn) / Math.max(1, tp + tn + fp + fn);
  return { tp, fp, tn, fn, precision, recall, f1, accuracy };
}

function adjustRiskByThreshold(rawRisk01) {
  // Normalize risk around the selected decision threshold so score visibly varies with slider.
  const threshold = clamp01(state.classifierThreshold);
  const normalized = clamp01((rawRisk01 - threshold + 0.5));
  return Math.round(normalized * 100);
}

function linkGuardian() {
  const name = $("#guardianName").value.trim();
  const contact = $("#guardianContact").value.trim();
  if (!name || !contact) return;
  state.linkedGuardian = { name, contact };
  appendGuardianAlert(`Guardian linked: ${name} (${contact})`);
}

function maybeAlertGuardian(riskScore) {
  if (!state.linkedGuardian) return;
  const message = `${state.linkedGuardian.name} alert: user entered HIGH pressure state (${riskScore}% risk).`;
  appendGuardianAlert(message);
  appendEvent("Family Protect notified guardian.", "ALERT");
}

function computePressure(avgTapSpeed, hesitation, elapsed) {
  const normalizedTap = clamp01(avgTapSpeed / 3);
  const urgencyFactor = clamp01((5 - elapsed) / 5);
  return clamp01(
    normalizedTap * 0.35 +
      (1 - hesitation) * 0.2 +
      urgencyFactor * 0.2 +
      state.hvm.susceptibility * 0.25
  );
}

function appendEvent(msg, label = "INFO") {
  const li = document.createElement("li");
  const lower = label.toLowerCase();
  li.innerHTML = `<span class="event-label ${lower}">${label}</span>${new Date().toLocaleTimeString()} - ${msg}`;
  $("#eventFeed").prepend(li);
}

function pushAttemptResult(isScam, reactionMs = 0) {
  state.recentAttempts.unshift({
    isScam,
    reactionMs,
    at: Date.now(),
    dna: state.currentScam?.dna || { urgency: 0, authority: 0, reward: 0, fear: 0 },
  });
  if (state.recentAttempts.length > 40) state.recentAttempts.pop();
}

function updateHvmFromRecentAttempts() {
  const list = state.recentAttempts;
  if (!list.length) return;
  const scams = list.filter((a) => a.isScam);
  const avgReactionMs =
    list.reduce((sum, a) => sum + (a.reactionMs || 0), 0) / Math.max(1, list.length);
  const panic = scams.length / Math.max(1, list.length);
  const authorityExposure =
    list.reduce((sum, a) => sum + (a.dna.authority || 0), 0) / Math.max(1, list.length);
  const reactionSpeed = clamp01((7000 - avgReactionMs) / 7000);
  const susceptibility = clamp01(panic * 0.65 + reactionSpeed * 0.2 + authorityExposure * 0.15);
  state.hvm = {
    panicProne: panic,
    authorityTrust: authorityExposure,
    reactionSpeed,
    susceptibility,
    simulations: (state.hvm.simulations || 0) + 1,
  };
  save("hvm", state.hvm);
}

function renderAttemptChart() {
  const total = state.attempts.safe + state.attempts.scam;
  const safePct = total ? Math.round((state.attempts.safe / total) * 100) : 0;
  const scamPct = total ? 100 - safePct : 0;
  const donut = `conic-gradient(#55d6be 0 ${safePct}%, #ff4d67 ${safePct}% 100%)`;
  $("#attemptChart").innerHTML = `
    <div class="attempt-donut" style="background:${donut}"></div>
    <div class="attempt-legend">
      <p>Total Events: <strong>${total}</strong></p>
      <p>Safe Attempts: <strong>${state.attempts.safe}</strong> (${safePct}%)</p>
      <p>Scam Attempts: <strong>${state.attempts.scam}</strong> (${scamPct}%)</p>
    </div>
  `;
}

function toggleFeatureMenu() {
  document.body.classList.toggle("menu-open");
}

function setActiveFeaturePanel(panelId) {
  document.querySelectorAll(".feature-panel").forEach((panel) => {
    panel.classList.toggle("hidden", !panelId || panel.id !== panelId);
  });
  document.querySelectorAll(".menu-item").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.panel === panelId);
  });
  if (panelId === "familyPanel") {
    const soon = $("#familyComingSoon");
    if (soon) soon.textContent = "COMING SOON";
  }
}

function triggerPaymentFeedback() {
  if (navigator.vibrate) navigator.vibrate([180, 70, 220]);
  playWarningBeep();
}

function playWarningBeep() {
  const AudioCtx = window.AudioContext || window.webkitAudioContext;
  if (!AudioCtx) return;
  const ctx = new AudioCtx();
  const oscillator = ctx.createOscillator();
  const gain = ctx.createGain();
  oscillator.type = "square";
  oscillator.frequency.value = 920;
  gain.gain.setValueAtTime(0.0001, ctx.currentTime);
  gain.gain.exponentialRampToValueAtTime(0.18, ctx.currentTime + 0.02);
  gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.34);
  oscillator.connect(gain);
  gain.connect(ctx.destination);
  oscillator.start();
  oscillator.stop(ctx.currentTime + 0.36);
  oscillator.onended = () => ctx.close().catch(() => {});
}

function appendGuardianAlert(msg) {
  const li = document.createElement("li");
  li.textContent = `${new Date().toLocaleTimeString()} - ${msg}`;
  $("#guardianAlerts").prepend(li);
}

function clamp01(n) {
  return Math.max(0, Math.min(1, n));
}

function toNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function clampNumber(value, min, max, fallback) {
  if (!Number.isFinite(value)) return fallback;
  return Math.max(min, Math.min(max, value));
}

function formatSecondsFromMs(ms) {
  return (Math.max(0, ms) / 1000).toFixed(3);
}

function syncPressureWindowFromUI() {
  const select = $("#pressureWindow");
  if (!select) return;
  state.pressureWindowMs = normalizePressureWindowMs(select.value, state.pressureWindowMs);
}

function normalizePressureWindowMs(value, fallback = 15000) {
  const n = toNumber(value);
  if (n === 15000 || n === 20000) return n;
  if (fallback === 15000 || fallback === 20000) return fallback;
  return 15000;
}

function percent(n) {
  return `${Math.round(n * 100)}%`;
}

function $(selector) {
  return document.querySelector(selector);
}

function save(key, value) {
  localStorage.setItem(key, JSON.stringify(value));
}

function load(key, fallback) {
  try {
    const data = JSON.parse(localStorage.getItem(key));
    return data || fallback;
  } catch {
    return fallback;
  }
}
