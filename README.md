# Code Lens — v2.0.0

A source-anchored AI code reviewer built on Next.js. Paste or upload text-based code or configuration, then get a scored review where retained findings point back to the submitted source.

**Live demo:** [Try it live on Vercel](https://ai-code-reviewer-kappa-navy.vercel.app/)  
**Desktop App:** [Download for Windows (.exe)](../../releases/latest) — Native desktop experience, no browser or Node.js required.

## What it does

It reviews security, logic, maintainability, and performance issues—including SQL injection, XSS, SSRF, command injection, path traversal, secrets, authorization gaps, IDOR, and race conditions—and gives you:

- A **0–100 score** computed from the final, de-duplicated findings
- **Evidence gate** — model-only claims without enough source support are removed before display
- **Source evidence cards** — retained findings identify the line and show a nearby source excerpt
- **Verified fixes and diff view** — only offered when a candidate patch passes its safeguards
- **CI status and exportable JSON/PDF reports**
- **Any text-based source or configuration** — known languages get specialised analysis; unfamiliar syntax falls back to generic review instead of being rejected
- **Local scan history** to revisit or export prior reviews
- A persistent **dark/light theme** designed around glassy iOS-style surfaces and crisp Nothing-inspired controls

## What's New in v2.0.0

- **Evidence-first findings:** a final quality gate requires a valid source location and supporting code signal for bugs and risks. Findings are labelled *Source verified* or *Source anchored* so confidence is visible rather than implied.
- **Broader input support:** text-based files, source extensions, and configuration formats are accepted. Files over 2 MB and binary uploads receive an actionable error.
- **Dark and light themes:** the selected theme is saved locally and applies to the editor, panels, controls, and results view.
- **Sharper product UI:** Code Lens v2.0 pairs a glassy, native-feeling layout with precise compact controls and improved readability.
- **Honest review language:** clean results never guarantee safety; manual review remains appropriate for production decisions.

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

### Analysis stages

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

Final evidence gate
  ├── Confirms a source location and supporting signal for each retained claim
  ├── Caps confidence according to the available evidence
  └── Suppresses unsupported model-only bugs and risks
```

*Highly Optimized Edge Execution — Thanks to the deterministic Smart Context engine, the AI only analyzes security-dense code. This allows the tool to process massive, 2,000+ line files directly on Vercel's free tier without hitting serverless timeout limits.*

---

## 🛠️ Quick Start

### Option 1: Web App (Bring Your Own Key) 🌐
1. Open the [Live Vercel Demo](https://ai-code-reviewer-kappa-navy.vercel.app/).
2. Click the **⚙️ Gear Icon** in the top right navbar.
3. Paste your free OpenRouter API key (get one at [openrouter.ai/keys](https://openrouter.ai/keys)).
4. The key is kept only for the current browser session. Start scanning!

### Option 2: Windows Desktop App (Easiest) 🖥️
1. Go to the [Releases Page](../../releases/latest).
2. Download the latest `AI-Code-Reviewer-Setup-2.0.0.exe` file.
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
Open [http://localhost:3000](http://localhost:3000), click the **⚙️ Gear Icon** to add your API key, and click **Review code**.

*(Note: If you prefer using environment variables locally instead of the UI, create a `.env.local` file with `OPENROUTER_API_KEY=sk-or-v1-...`)*

---

## 📊 Score Interpretation

| Score | Meaning |
| --- | --- |
| **95–100** | No retained issues. This is not a guarantee that the code is safe. |
| **80–94** | Minor risks or low-severity findings. Review relevant changes before production. |
| **60–79** | Medium-severity issues present. Review before production. |
| **40–59** | High-severity issues found. Fix before shipping. |
| **0–39** | Critical vulnerabilities. **CI/CD Gate will block deployment.** |

### How to read a finding

- **Source verified** means it matched a deterministic result or strong source signal.
- **Source anchored** means the model claim has a valid location and support in the submitted source, but the surrounding context should still be reviewed.
- A **clean score** means no findings met the reporting threshold. It does not prove absence of vulnerabilities.

---

## 📂 Project Structure

```text
ai-code-review/
├── app/
│   ├── api/review/route.ts     # Analysis pipeline, evidence gate, and BYOK routing
│   ├── page.tsx                # Editor, themes, history, and BYOK settings
│   ├── layout.tsx
│   └── manifest.ts             # PWA manifest for mobile/desktop wrapping
├── components/
│   └── analysis/
│       └── AnalysisPanel.tsx   # Results panel (Overview/Bugs/Risks/Suggest/Diff/Visual)
├── lib/
│   ├── export-report.ts        # Enterprise PDF & JSON dossier generation
│   ├── evidence-gate.ts        # Final source-support quality gate
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
