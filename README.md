# AI Code Review — v1.4.1

A production-grade security code analyzer built on Next.js. Paste or upload code and get a scored, multi-stage security audit powered by a 31-stage deterministic + AI pipeline.

**Live demo:** [🚀 Try it live on Vercel](https://ai-code-reviewer-kappa-navy.vercel.app/) or run locally in under 2 minutes (see [Quick Start](#quick-start)).

---

## What it does

It finds real vulnerabilities in code — SQL injection, XSS, SSRF, command injection, path traversal, prototype pollution, open redirects, hardcoded secrets, missing auth, IDOR, race conditions, and more — and gives you:

- A **0–100 security score** computed after all 31 pipeline stages
- **Exploit chains** — step-by-step attacker payloads, not just "this might be a problem"
- **Verified fixes** — proposed patches are attack-tested before being shown
- **CI gate** — `auditPassed: true/false` you can wire into your pipeline
- **Diff view** — side-by-side original vs patched code

---

## Architecture overview

The pipeline runs in four tiers based on code complexity, always choosing the minimum analysis needed:

| Tier | Name | When | AI calls |
|------|------|------|----------|
| 0 | `deterministic-only` | Large code, no signals | 0 |
| 1 | `single-reviewer` | Small code / low complexity | 1 |
| 2 | `triple-consensus` | Medium complexity | 3 roles in parallel |
| 3 | `adversarial-full` | High severity signals detected | 5 roles + judge |

**Small code always gets AI eyes.** Files ≤ 80 lines are forced to `single-reviewer` minimum regardless of deterministic signal — short code frequently has high-severity issues that regex engines can't find.

### The 31 stages

```
Deterministic pass (stages 1–3)
  ├── Security rules engine       — 60+ regex+context rules
  ├── Taint analysis              — source→sink tracking with guard suppression
  └── Pipeline engine             — framework detection, call graph

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
  ├── Deterministic dominance     — AI proposes, deterministic decides
  ├── FP minimizer                — framework guarantees, sanitizer certainty
  ├── CI/CD delta analysis        — security diff vs baseline
  ├── Incremental graph           — changed-node propagation
  ├── Model specialization        — right model for each task
  ├── Memory refinement           — team suppressions, confidence drift
  ├── Policy layer                — OWASP/PCI-DSS/SOC2 compliance packs
  └── Benchmark harness           — precision/recall on every scan
```

---

## Quick start

### Prerequisites

- Node.js 18+
- An [OpenRouter](https://openrouter.ai) API key (free tier works — uses `claude-sonnet-4` or any available AI agent by default)

### 1. Clone

```bash
git clone https://github.com/shreyashhu/ai-code-reviewer
cd ai-code-reviewer
```

### 2. Install dependencies

```bash
npm install
```

### 3. Set environment variables

Create a `.env.local` file in the project root:

```env
# Required
OPENROUTER_API_KEY=sk-or-v1-...

# Optional — see Configuration section below
POLICY_PACK=
TRUST_PROXY=false
```

Get your OpenRouter key at [openrouter.ai/keys](https://openrouter.ai/keys). No credit card required for the free tier.

### 4. Run

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

### 5. Analyze code

Paste any JavaScript, TypeScript, Python, Go, or other code into the editor and click **Analyze**, or press `Ctrl+Enter`.

---

## Configuration

All configuration is via environment variables in `.env.local`.

### Required

| Variable | Description |
|----------|-------------|
| `OPENROUTER_API_KEY` | Your OpenRouter API key. Get one at openrouter.ai/keys |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `POLICY_PACK` | *(none)* | Comma-separated compliance packs to activate. Options: `owasp-top10`, `pci-dss`, `soc2`, `strict`, `test-env` |
| `TRUST_PROXY` | `false` | Set `true` if behind a trusted reverse proxy (Nginx, Caddy, etc.) for correct IP rate limiting |

### Policy packs

Activate via `POLICY_PACK=owasp-top10,strict` in `.env.local`:

| Pack | What it does |
|------|-------------|
| `owasp-top10` | Escalates IDOR (A01), requires fix on SQLi/XSS (A03) |
| `pci-dss` | Blocks hardcoded credentials, escalates weak crypto |
| `soc2` | Blocks auth bypass findings, suppresses low-confidence |
| `strict` | All high-severity findings require fix; verified exploits escalate |
| `test-env` | Suppresses medium findings in dev/test environments |

---

## Deploying

### Vercel (recommended)

```bash
npm install -g vercel
vercel
```

Set `OPENROUTER_API_KEY` in the Vercel dashboard under Project → Settings → Environment Variables.

### Docker

```bash
docker build -t ai-code-review .
docker run -p 3000:3000 -e OPENROUTER_API_KEY=sk-or-v1-... ai-code-review
```

### Self-hosted (PM2)

```bash
npm run build
npm install -g pm2
pm2 start npm --name "ai-code-review" -- start
```

---

## Score interpretation

| Score | Meaning |
|-------|---------|
| 95–100 | No issues found after full pipeline. Genuinely clean or very low risk. |
| 80–94 | Minor risks or low-severity findings. Safe for most contexts. |
| 60–79 | Medium-severity issues present. Review before production. |
| 40–59 | High-severity issues found. Fix before shipping. |
| 0–39 | Critical vulnerabilities. Do not deploy. |

Scores below 95 on a clean file mean the analysis tier was `single-reviewer` or `deterministic-only` — the pipeline is being honest that it didn't run a full adversarial review.

---

## Project structure

```
ai-code-review/
├── app/
│   ├── api/review/route.ts     # Main 31-stage analysis pipeline
│   ├── page.tsx                # Editor + UI
│   └── layout.tsx
├── components/
│   └── analysis/
│       └── AnalysisPanel.tsx   # Results panel (Overview/Bugs/Risks/Suggest/Diff/Visual)
├── lib/
│   ├── adaptive-router.ts      # Tier routing + token budget
│   ├── taint-engine.ts         # Source→sink taint analysis
│   ├── security-rules.ts       # 60+ deterministic rules
│   ├── consensus-engine.ts     # Multi-role AI consensus
│   ├── hallucination-firewall.ts
│   ├── weighted-scoring.ts     # Context-aware scoring
│   ├── bayesian-confidence.ts  # Evidence-weighted confidence
│   ├── deterministic-dominance.ts
│   ├── fp-minimizer.ts         # False positive suppression
│   ├── policy-layer.ts         # Compliance packs + CI gate
│   ├── benchmark-harness.ts    # Precision/recall test vectors
│   └── ...28 more engines
├── main.js                     # Example code to analyze
├── .env.local                  # Your config (not committed)
└── README.md
```

---

## v1.4.1 changes (this release)

Fixes applied on top of v1.4:

- **Small code 100/100 bug fixed** — files ≤ 80 lines now always get AI review; `deterministic-only` tier no longer applies to small code
- **Score computed at stage 8 of 31 (stale) → now recomputed after all 31 stages**
- **Deterministic dominance over-rejection** — logic/auth/IDOR bugs were being killed as "hallucinations" because they have no regex source+sink; fixed
- **Bayesian AI-only penalty scoped** — was penalising all AI-only findings 40%; now only applies to taint-class bugs where det confirmation is expected
- **Token budget floor** — small code was getting 832 tokens (not enough to reason + respond); floor raised to 1200
- **Consensus early-exit on empty baseIssues** — AI roles were skipped when det engines found nothing; fixed so AI always reviews
- **CRITIC_ROLE rebalanced** — was too biased toward rejection, causing false negatives on small code
- **Regex fix in `symbolic-execution.ts`** — unescaped `://` caused SWC build failure
- **`withCache` import missing** — caused `[stream] fatal` crash on adversarial-full tier
- **`runSecurityRules().issues`** — called `.issues` on an array, silently breaking benchmarks
- **CATEGORY_CONFIG crash** — unknown category `'general'` caused Risks tab to throw
- **Version labels** — header showed `v1.3` + `v10` simultaneously; fixed to `v1.4`
- **Old patch notes removed** — only `WHATS_NEW_v1.4.md` remains
- **6 new security rules** — `Function()` eval, `Math.random()` for crypto, prototype pollution via `for..in`, `process.env` leak, loose equality in auth, missing `await` on async auth
- **31 benchmark test vectors** (was 13) — added SSRF, open redirect, IDOR, `node-serialize`, `Function()` eval, missing-await auth, and 8 FP traps

---

## Known limitations

- **Single-file analysis only** — cross-file taint (e.g. a sink in `utils.js` called from `routes.js`) requires uploading both files concatenated. Multi-file support is planned for v1.5.
- **No real sandboxed execution** — exploit replay simulates payloads with pattern matching, not actual execution. Firecracker/gVisor sandbox is a v1.5 target.
- **Rate limited** — 60 requests/minute per IP by default. Configurable in `middleware.ts`.
- **OpenRouter dependency** — requires an internet connection and OpenRouter account. Local model support planned.

---

## Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-improvement`
3. Make your changes
4. Test locally: `npm run dev`
5. Build check: `npm run build`
6. Open a PR

When adding new security rules, add corresponding test vectors to `lib/benchmark-harness.ts` — one true positive and one false positive trap per new rule class.

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

*Built by [@AlpraxIsHim](https://t.me/AlpraxIsHim)*
