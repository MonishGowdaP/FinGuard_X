# FinGuardX — Autonomous Human Firewall
## Complete Project Documentation

---

## 📁 PROJECT FOLDER STRUCTURE

```
finguardx/
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx          # Risk score, HVM traits, activity log
│   │   │   ├── ScamDetector.jsx       # Live NLP analysis screen
│   │   │   ├── Simulation.jsx         # Scam training scenarios
│   │   │   ├── WhyYouLost.jsx         # Forensic failure analysis
│   │   │   └── FamilyShield.jsx       # Family protection dashboard
│   │   ├── components/
│   │   │   ├── DecisionFreeze.jsx     # Full-screen interrupt overlay
│   │   │   ├── RiskMeter.jsx          # Animated risk score gauge
│   │   │   ├── DNABars.jsx            # Scam vector breakdown chart
│   │   │   ├── HVMProfile.jsx         # Vulnerability trait bars
│   │   │   ├── Toast.jsx              # Real-time notification toasts
│   │   │   └── ActivityLog.jsx        # Live event feed
│   │   ├── ai/
│   │   │   ├── HVMEngine.js           # Human Vulnerability Model
│   │   │   ├── NLPScanner.js          # Scam DNA text analyzer
│   │   │   └── RiskAnalyzer.js        # Composite risk scorer
│   │   ├── hooks/
│   │   │   ├── useSocket.js           # WebSocket connection hook
│   │   │   ├── useBehaviorTracker.js  # Tap/timing signal capture
│   │   │   └── useHVMScore.js         # Live HVM computation
│   │   ├── services/
│   │   │   └── api.js                 # Backend API client
│   │   └── App.jsx
│   ├── public/
│   ├── package.json
│   └── tailwind.config.js
│
├── backend/
│   ├── server.js                      # Main entry point
│   ├── routes/
│   │   ├── behavior.js                # /api/analyze-behavior
│   │   ├── scam.js                    # /api/detect-scam
│   │   ├── simulation.js              # /api/run-simulation
│   │   ├── freeze.js                  # /api/trigger-freeze
│   │   └── user.js                    # /api/user-profile
│   ├── models/
│   │   ├── User.js                    # User + HVM schema
│   │   ├── BehaviorLog.js             # Behavioral signals log
│   │   ├── ScamDetection.js           # NLP detection results
│   │   └── Simulation.js              # Simulation outcomes
│   ├── engines/
│   │   ├── HVMEngine.js               # Server-side HVM scoring
│   │   ├── NLPScanner.js              # Scam DNA classifier
│   │   └── RiskAnalyzer.js            # Risk composition
│   ├── sockets/
│   │   └── alertHandler.js            # WebSocket event handlers
│   ├── middleware/
│   │   ├── auth.js                    # JWT auth middleware
│   │   └── rateLimiter.js             # API rate limiting
│   ├── .env
│   └── package.json
│
├── index.jsx                          # Self-contained demo artifact
├── server.js                          # Complete backend
├── README.md                          # This file
└── package.json
```

---

## 🏗️ SYSTEM ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────┐
│                        FINGUARD X SYSTEM                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   USER DEVICE                                                    │
│   ┌───────────────────────────────────────┐                     │
│   │  React Frontend (Next.js)             │                     │
│   │                                        │                     │
│   │  ┌──────────┐  ┌──────────┐           │                     │
│   │  │Dashboard │  │Scam Det. │           │                     │
│   │  └──────────┘  └──────────┘           │                     │
│   │  ┌──────────┐  ┌──────────┐           │                     │
│   │  │Simulate  │  │Family    │           │                     │
│   │  └──────────┘  └──────────┘           │                     │
│   │                                        │                     │
│   │  Behavior Signals                      │                     │
│   │  [Tap Speed] [Time-to-Decision]        │                     │
│   │  [Reading Depth] [Scroll Pattern]      │                     │
│   └────────────┬──────────────────────────┘                     │
│                │ HTTP + WebSocket (Socket.io)                    │
│                ▼                                                  │
│   ┌───────────────────────────────────────┐                     │
│   │  Node.js + Express Backend            │                     │
│   │                                        │                     │
│   │  REST APIs:                            │                     │
│   │  POST /analyze-behavior ──► HVMEngine  │                     │
│   │  POST /detect-scam ──────► NLPScanner  │                     │
│   │  POST /trigger-freeze ───► FreezeCtrl  │                     │
│   │  POST /run-simulation ───► SimEngine   │                     │
│   │  GET  /user-profile ─────► HVM Profile │                     │
│   │                                        │                     │
│   │  WebSocket Events:                     │                     │
│   │  → trigger_freeze                      │                     │
│   │  → scam_detected                       │                     │
│   │  → risk_update                         │                     │
│   └──────────┬────────────────────────────┘                     │
│              │                                                   │
│   ┌──────────┴──────────────────────────────┐                   │
│   │         AI / ML ENGINE LAYER            │                   │
│   │                                          │                   │
│   │  ┌─────────────┐  ┌─────────────────┐  │                   │
│   │  │  HVMEngine  │  │   NLPScanner    │  │                   │
│   │  │             │  │                  │  │                   │
│   │  │ Inputs:     │  │ Scam DNA Match:  │  │                   │
│   │  │ reactionSpd │  │ - Urgency        │  │                   │
│   │  │ trustBias   │  │ - Authority      │  │                   │
│   │  │ verifyHabit │  │ - Fear           │  │                   │
│   │  │ panicScore  │  │ - Reward         │  │                   │
│   │  │             │  │ - Social         │  │                   │
│   │  │ Output:     │  │                  │  │                   │
│   │  │ Score 0-100 │  │ Output:          │  │                   │
│   │  └──────┬──────┘  │ ScamScore 0-100  │  │                   │
│   │         │         └────────┬─────────┘  │                   │
│   │         └────────┬─────────┘            │                   │
│   │                  ▼                       │                   │
│   │         ┌────────────────┐               │                   │
│   │         │  RiskAnalyzer  │               │                   │
│   │         │                │               │                   │
│   │         │ HVM  × 0.35    │               │                   │
│   │         │ NLP  × 0.40    │               │                   │
│   │         │ Behv × 0.25    │               │                   │
│   │         │                │               │                   │
│   │         │ → HIGH/MED/LOW │               │                   │
│   │         └────────────────┘               │                   │
│   └──────────────────────────────────────────┘                   │
│                                                                   │
│   ┌──────────────────────────────────────────┐                   │
│   │            MongoDB Database              │                   │
│   │                                          │                   │
│   │  Collections:                            │                   │
│   │  • users          (HVM profiles)         │                   │
│   │  • behavior_logs  (signal history)       │                   │
│   │  • scam_detections (NLP results)         │                   │
│   │  • simulations    (training outcomes)    │                   │
│   └──────────────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔗 DATA FLOW

```
1. User opens app → HVM profile loaded from DB
2. User interacts → Behavior signals captured (tap speed, timing)
3. Signals sent via WebSocket → RiskAnalyzer runs
4. If MEDIUM risk → Warning badge shown
5. If HIGH risk → DecisionFreeze() triggered:
   → Full screen overlay
   → 5-second countdown
   → Reasons displayed
   → Actions disabled
6. User receives scam SMS → Paste into ScamDetector
7. NLPScanner.analyze() runs:
   → DNA breakdown (urgency/authority/fear/reward/social)
   → Composite risk score calculated
8. Simulation completed → HVM profile updated (learning rate α=0.15)
9. Family member at risk → Alert dispatched via WebSocket
```

---

## ⚙️ API REFERENCE

| Method | Endpoint               | Description                        |
|--------|------------------------|------------------------------------|
| POST   | /api/analyze-behavior  | Log behavior signals, get risk     |
| POST   | /api/detect-scam       | NLP scam analysis on message       |
| POST   | /api/trigger-freeze    | Force a Decision Freeze event      |
| POST   | /api/run-simulation    | Submit simulation result           |
| GET    | /api/user-profile/:id  | Fetch full HVM profile             |
| POST   | /api/user-profile      | Create/update user profile         |
| GET    | /api/family-dashboard/:id | Family members risk overview    |
| GET    | /api/risk-history/:id  | Past 50 behavior log entries       |

---

## ▶️ HOW TO RUN

### Option A — Demo Artifact (Zero Setup)
The `index.jsx` file is a self-contained React artifact.
Open it in **Claude.ai** as an artifact — it runs instantly with no backend needed.

### Option B — Full Stack

#### Backend Setup
```bash
cd backend
npm install express socket.io cors mongoose dotenv
cp .env.example .env
# Edit .env: set MONGO_URI=mongodb://localhost:27017/finguardx
node server.js
# Server running on http://localhost:4000
```

#### Frontend Setup
```bash
cd frontend
npx create-next-app@latest . --typescript --tailwind
npm install socket.io-client
# Copy pages/* and components/* from source
npm run dev
# App running on http://localhost:3000
```

#### Environment Variables (.env)
```
PORT=4000
MONGO_URI=mongodb://localhost:27017/finguardx
JWT_SECRET=finguardx_secret_key_change_in_prod
NODE_ENV=development
```

---

## 🧪 DEMO SCRIPT (For Judges)

### Step 1 — Dashboard
> "This is FinGuardX's Command Center. The HVM score of 62 means this user has elevated scam susceptibility — specifically high Trust Bias and low Verification Habit."

### Step 2 — Trigger a Decision Freeze
> "Watch what happens when the system detects high-risk behavior..."
Click the **THREAT LEVEL: HIGH** pill in the top bar.
> "This is our Decision Freeze — it creates a mandatory 5-second cognitive pause. Users acting under scam pressure can't override it immediately. It's like an airbag for your finances."

### Step 3 — Live Scam Detection
Navigate to **Scam Detection** → Click **"Bank Scam SMS"** sample.
> "Our NLP engine breaks down the Scam DNA — this message scores 87% on urgency and authority vectors. The system would have blocked this in real-time before the user could act."

### Step 4 — Simulation Engine
Navigate to **Simulation** → Select Scenario 3 (EXPERT difficulty).
> "We put users through realistic scam scenarios — phone calls, SMS, UPI requests. Their responses update their Human Vulnerability Model in real-time. Fail a simulation → your risk score goes up. Pass it → it goes down."

### Step 5 — Why You Lost
Navigate to **Why You Lost**.
> "This is the psychological forensics screen. We show users exactly WHERE their brain failed — Authority Bias at 1.2 seconds, Urgency Anchor at 2.1 seconds. This is cognitive warfare, and we teach users to win it."

### Step 6 — Family Shield
Navigate to **Family Shield**.
> "Older adults and less digitally literate family members are the #1 target. We let you monitor their risk scores, send them simulations, and alert them instantly. Your grandpa's risk score is 91 — that's a crisis we can prevent."

---

## 🧠 HVM SCORE FORMULA

```
HVM Score = min(
  (reactionSpeed / 3000) × 40 +    // Speed vulnerability (max 40)
  trustBias × 25 +                  // Trust bias (max 25)
  (1 - verificationHabit) × 20 +   // Verification deficit (max 20)
  panicScore × 15,                  // Panic susceptibility (max 15)
  100
)
```

## 🔬 COMPOSITE RISK FORMULA

```
Composite Risk = (HVM × 0.35) + (NLP × 0.40) + (Behavior Signals × 0.25)

Behavior Signals =
  tapSpeed > 8 taps/sec  → +20 pts
  timeToDecision < 4s    → +25 pts
  readingDepth < 30%     → +15 pts

Risk Level:
  ≥ 70 → HIGH   (Decision Freeze triggered)
  ≥ 45 → MEDIUM (Warning shown)
  < 45 → LOW    (Normal operation)
```

---

## 💡 UNIQUE VALUE PROPOSITION

| Traditional Security | FinGuardX |
|---------------------|-----------|
| Protects systems | Protects HUMANS |
| Detects after breach | Prevents before decision |
| Technical alerts | Psychological intervention |
| One-size-fits-all | Personalized HVM profile |
| Reactive | Predictive + Adaptive |

---

*FinGuardX v2.4.1 · Built for Hackathon Demo · © 2025*
