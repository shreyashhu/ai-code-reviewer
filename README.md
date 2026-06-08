# AI Code Review — v1.4.2

A production-grade security code analyzer built on Next.js. Paste or upload code and get a scored, multi-stage security audit powered by a 31-stage deterministic + AI pipeline.

**Live demo:** [Try it live on Vercel](https://ai-code-reviewer-kappa-navy.vercel.app/)  
**Desktop App:** [Download for Windows (.exe)](../../releases/latest) — Native desktop experience, no browser or Node.js required.

## What it does

It finds real vulnerabilities in code — SQL injection, XSS, SSRF, command injection, path traversal, prototype pollution, open redirects, hardcoded secrets, missing auth, IDOR, race conditions, and more — and gives you:

- A **0–100 security score** computed after all 31 pipeline stages
- **Exploit chains** — step-by-step attacker payloads, not just "this might be a problem"
- **Verified fixes** — proposed patches are attack-tested before being shown
- **CI gate** — `auditPassed: true/false` you can wire into your pipeline
- **Diff view** — side-by-side original vs patched code
- **Enterprise PDF Exports** — multi-page security dossiers for CISOs and compliance teams
- **Hacker Mode** — a full-screen Matrix-style terminal UI that streams live pipeline logs
- **Local Scan History** — tracks your security posture improvements over time

## What's New in v1.4.2

-  **Retro Mode (Terminal UI):** Full-screen Matrix-style CRT terminal interface streaming live pipeline logs and taint propagation.
-  **Enterprise PDF & JSON Exports:** Multi-page, professionally formatted security dossiers for CISOs and compliance teams.
-  **Local Scan History:** Automatically saves your last 15 scans locally to track security posture improvements.
-  **Deterministic Dominance (Resurrection Protocol):** If deterministic regex mathematically proves a vulnerability, AI and heuristic firewalls are blocked from vetoing it. Zero missed criticals.
-  **Strict CI/CD Gating:** Hardcoded failsafe blocks merges if *any* High/Critical vulnerabilities are detected, overriding AI hallucinations.
-  **Taint Path Hallucination Guard:** Constrain LLMs to only report proven, unbroken taint chains, eliminating false positive data flows.
-  **Call Graph Expansion:** Recognizes Express, Flask, Django, and FastAPI route handlers as actual Call Graph nodes.
-  **Aggressive Deduplication & FP Fixes:** Merges duplicate findings and tightens regexes to eliminate false positives.
-  **Bring Your Own Key (BYOK):** Securely paste your OpenRouter API key into the UI settings, decoupling the app from server-side env vars.

---

## Architecture Overview

Unlike basic LLM wrappers that just send code to an API and hope for the best, this engine runs a rigorous **31-stage deterministic + AI pipeline**. It routes code through four tiers based on complexity, always choosing the minimum analysis needed:

| Tier | Name | When | AI calls |
| --- | --- | --- | --- |
| 0 | `deterministic-only` | Large code, no signals | 0 |
| 1 | `single-reviewer` | Small code / low complexity | 1 |
| 2 | `triple-consensus` | Medium complexity | 3 roles in parallel |
| 3 | `adversarial-full` | High severity signals detected | 5 roles + judge |

**Small code always gets AI eyes.** Files ≤ 80 lines are forced to `single-reviewer` minimum regardless of deterministic signal — short code frequently has high-severity issues that regex engines can't find.

### The 31 Stages

```text
Deterministic pass (stages 1–3)
  ├── Security rules engine       — 100+ regex+context rules (Multi-line traps, cross-language)
  ├── Taint analysis              — source→sink tracking with guard suppression
  └── Pipeline engine             — framework detection, call graph, SSA form

AI review (stages 4–5)
  ├── Single reviewer / triple consensus / adversarial-full
  └── Consensus: Analyzer + Critic + Exploit Verifier + Fix Validator + Judge

Post-processing (stages 6–31)
  ├── Root-cause graph            — deduplication, surface collapsing
  ├── Confidence decay            — probabilistic taint suppression
  ├── Family clustering           — group by vuln class
  ├── Weighted scoring            — context-aware, not just per-finding subtraction
  ├── Attack chain synthesis      — chain findings into multi-step exploits
  ├── Constraint-valid chains     — SSRF→RCE, SQLi→auth bypass validation
  ├── Semantic graph              — auth gaps, cross-module chains
  ├── Trust model                 — suppress known-safe patterns
  ├── Hallucination firewall v1   — AST-backed claim verification
  ├── Differential prioritization — high-risk surface weighting
  ├── Symbolic execution          — constraint-aware path analysis
  ├── Bayesian calibration        — evidence-weighted severity
  ├── Hallucination firewall v2   — contradiction + semantic duplicate detection
  ├── Verified remediation        — patch→taint→replay→certify
  ├── Business-impact risk model  — replaces fake criticals with real CVSS
  ├── Security memory             — suppress recurring FPs, escalate persistent
  ├── Runtime verification        — simulated exploit payload replay
  ├── Whole-system graph          — cross-module auth and sink analysis
  ├── Proof obligations           — every finding must prove source+sink+path
  ├── Security knowledge graph    — CVE/CWE enrichment
  ├── Deterministic dominance     — AI proposes, deterministic decides (Resurrection Protocol)
  ├── FP minimizer                — framework guarantees, sanitizer certainty
  ├── CI/CD delta analysis        — security diff vs baseline
  ├── Incremental graph           — changed-node propagation
  ├── Model specialization        — right model for each task
  ├── Memory refinement           — team suppressions, confidence drift
  ├── Policy layer                — OWASP/PCI-DSS/SOC2 compliance packs
  └── Benchmark harness           — precision/recall on every scan
```

*Highly Optimized Edge Execution — Thanks to the deterministic Smart Context engine, the AI only analyzes security-dense code. This allows the tool to process massive, 2,000+ line files directly on Vercel's free tier without hitting serverless timeout limits.*

---

## 🛠️ Quick Start

### Option 1: Web App (Bring Your Own Key) 🌐
1. Open the [Live Vercel Demo](https://ai-code-reviewer-kappa-navy.vercel.app/).
2. Click the **⚙️ Gear Icon** in the top right navbar.
3. Paste your free OpenRouter API key (get one at [openrouter.ai/keys](https://openrouter.ai/keys)).
4. The key is saved securely in your browser's `localStorage`. Start scanning!

### Option 2: Windows Desktop App (Easiest) 🖥️
1. Go to the [Releases Page](../../releases/latest).
2. Download the `AI-Code-Reviewer-Setup-1.4.2.exe` file.
3. Run the installer, open the app, add your API key in the settings, and launch!

### Option 3: Run Locally (For Developers) 💻

**Prerequisites**
* Node.js 18+
* An [OpenRouter](https://openrouter.ai) API key

**1. Clone & Install**
```bash
git clone https://github.com/shreyashhu/ai-code-reviewer.git
cd ai-code-reviewer
npm install
```

**2. Run**
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000), click the **⚙️ Gear Icon** to add your API key, and click **Analyze**.

*(Note: If you prefer using environment variables locally instead of the UI, create a `.env.local` file with `OPENROUTER_API_KEY=sk-or-v1-...`)*

---

## 📊 Score Interpretation

| Score | Meaning |
| --- | --- |
| **95–100** | No issues found after full pipeline. Genuinely clean or very low risk. |
| **80–94** | Minor risks or low-severity findings. Safe for most contexts. |
| **60–79** | Medium-severity issues present. Review before production. |
| **40–59** | High-severity issues found. Fix before shipping. |
| **0–39** | Critical vulnerabilities. **CI/CD Gate will block deployment.** |

### 🔍 Deep Dive: The "100/100" Paradox
If your code scores **100/100** and shows **0 Bugs / 0 Risks** at the top, the analysis isn't over. Scroll down to the bottom of the **Overview** tab to see the hidden depths of the 31-stage pipeline.

A perfect score often means the engine successfully neutralized complex threats, rewarded secure patterns, or safely escalated ambiguous code. Here is how to read the advanced telemetry:
* **Engine Stats:** See exactly how many **Taint sources** and **Call graph nodes** were mapped across your codebase.
* **Confidence Decay Engine:** Check how many findings were actively suppressed to prevent False Positives (e.g., `⊘ 9 suppressed | 📉 24% FP reduction`).
* **Vuln Family Clustering:** See if the engine grouped raw findings into unique families (e.g., `Cross-Site Scripting (XSS) ×19`) to identify systemic architectural patterns.
* **Root-Cause Graph:** Discover how many unique exploit surfaces were analyzed before being marked as safe or earning **Security Rewards** (e.g., `✓ safe-dom`).
* **Multi-role Consensus:** Understand the AI's confidence. If you see `⚠ escalated`, it means the AI agents flagged suspicious patterns (like obfuscated code or complex logic) but deferred to human review rather than hallucinating a bug.
* **Constraint-Valid Attack Chains:** The most critical metric. The engine maps theoretical multi-step exploits (e.g., `🔗 1 fully proven | CVSS 8.2`) to show you what *could* happen if a single guardrail failed, even if the current code is technically safe.

---

## 📂 Project Structure

```text
ai-code-review/
├── app/
│   ├── api/review/route.ts     # Main 31-stage analysis pipeline & BYOK routing
│   ├── page.tsx                # Editor + UI + Hacker Mode + History + BYOK Settings
│   ├── layout.tsx
│   └── manifest.ts             # PWA manifest for mobile/desktop wrapping
├── components/
│   └── analysis/
│       └── AnalysisPanel.tsx   # Results panel (Overview/Bugs/Risks/Suggest/Diff/Visual)
├── lib/
│   ├── export-report.ts        # Enterprise PDF & JSON dossier generation
│   ├── deterministic-dominance.ts # Resurrection Protocol (AI veto override)
│   ├── adaptive-router.ts      # Tier routing + token budget
│   ├── taint-engine.ts         # Source→sink taint analysis
│   ├── security-rules.ts       # 100+ deterministic rules
│   ├── consensus-engine.ts     # Multi-role AI consensus
│   ├── hallucination-firewall.ts
│   ├── weighted-scoring.ts     # Context-aware scoring
│   ├── bayesian-confidence.ts  # Evidence-weighted confidence
│   ├── fp-minimizer.ts         # False positive suppression
│   ├── policy-layer.ts         # Compliance packs + CI gate
│   ├── benchmark-harness.ts    # Precision/recall test vectors
│   └── ...28 more engines
├── public/
│   └── icon-512.png            # App icon for PWA and Desktop
├── electron.js                 # Native Windows wrapper
├── main.js                     # Example code to analyze
├── dist/                       # Compiled .exe installer (ignored by git)
├── .env.local                  # Your local config (optional if using UI)
└── README.md
```

---

## 🤝 Contributing

This started as a solo project, but I am completely open to contributions, ideas, and suggestions! If you spot a bug, want to add a new deterministic regex trap, or have an idea for a new feature, please open an Issue. I read all of them.

If you want to submit code:
1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-improvement`
3. Make your changes
4. Test locally: `npm run dev`
5. Build check: `npm run build`
6. Open a PR

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

*Built by [@AlpraxIsHim](https://t.me/AlpraxIsHim)*