# From Lab to Production: The Real Enterprise Architecture

**Purpose of this document:** two separate things, kept clearly apart on
purpose. Section 1 is what a large organization actually has, or is
expected to have, for AI agent supply chain security — grounded in real
frameworks, not aspiration. Section 2 is an honest map of this lab
against that standard: what's already validated, what's a deliberate lab
shortcut, and what's a genuine gap that has to be built before any of
this goes near production. The point isn't to make the lab look bigger
than it is — it's to know exactly what "production-ready" actually
requires before anyone claims it.

---

## 1. What a real enterprise architecture looks like

Organized by domain. Each one names the real standard or framework it's
grounded in, not just a description of "best practice."

### A. Governance & risk (organizational, not technical — but the foundation everything else sits on)

- **An AI governance function** — a named owner (often a model risk
  committee, security architecture board, or AI CoE) that approves new
  agent tools/capabilities before they reach production, the same way
  a change advisory board approves infrastructure changes.
- **Formal risk classification** per agent/tool — what data it can
  touch, what actions it can take, what the blast radius is if it's
  compromised. This drives how much of everything below actually gets
  applied to a given tool.
- **Grounded in:** NIST AI Risk Management Framework (AI RMF), ISO/IEC
  42001 (AI management systems).

### B. Identity & access

- **Centralized identity provider** (Entra ID, Okta, Ping) — no
  application manages its own user directory.
- **Workload identity federation** for every service-to-service call —
  no long-lived static credentials, anywhere. This lab already builds
  toward this (UC2, Entra ID managed identity).
- **Privileged Access Management (PAM)** with just-in-time elevation for
  any human who can approve a tool registration, touch the registry
  directly, or clear a quarantine.
- **Segregation of duties**, enforced technically, not just on paper —
  the person who can approve a tool registration cannot also be the
  identity that publishes it.
- **Grounded in:** NIST SP 800-207 (Zero Trust Architecture).

### C. Software supply chain (CI/CD, build integrity)

- **Branch protection + required code review** on anything that builds
  or publishes a tool.
- **Signed commits and signed build artifacts**, with build provenance
  attestation — not just "we published this," but a cryptographically
  verifiable "this exact commit, on this exact runner, produced this
  exact artifact."
- **Ephemeral, isolated build runners** — a compromised runner doesn't
  persist and doesn't have standing access to anything beyond that one
  build.
- **SBOM (Software Bill of Materials)** generated on every build,
  checked against known-vulnerable dependencies before publish.
- **Secrets never committed** — pulled from a vault at build time with a
  short-lived token, never a long-lived key in a pipeline variable.
- **Grounded in:** SLSA (Supply-chain Levels for Software Artifacts),
  NIST SSDF (Secure Software Development Framework).

### D. Tool / MCP registry governance

- **Formal approval workflow tied to a change record** — a tool doesn't
  go live because someone called an API; it goes live because a
  documented, auditable approval happened.
- **Re-approval required on ANY change**, not just initial registration
  — this is the single most important control this lab's whole UC1
  story is built around, and it's a real, current best practice, not a
  lab invention.
- **Independent verification the registry isn't trusting the CI/CD
  pipeline blindly** — the registry itself (or a gateway in front of
  it) re-validates what it receives, rather than assuming anything that
  reached it via an authenticated pipeline is automatically safe.
- **Grounded in:** OWASP Agentic AI / MCP Top 10 (MCP03 Tool Poisoning,
  MCP04 Supply Chain), which this lab already maps its own detections to.

### E. Network & runtime isolation

- **Segmented networks per environment** (dev/staging/production), not
  a flat network with role-based access as the only boundary.
- **Private endpoints / no public exposure** for anything internal —
  registry, identity provider, secrets store.
- **Sandboxed execution for actual tool calls** — an agent's tool
  invocation runs in an isolated context, not directly against
  production infrastructure with the agent's full permissions.
- **Real-time inline enforcement at a gateway**, not just logging after
  the fact — this lab's own K8s gateway architecture is a genuine
  instance of this pattern, not a simplification of it.

### F. Detection, response & SOC

- **A real SIEM**, centralized, not optional — Splunk, Microsoft
  Sentinel, or equivalent, receiving telemetry from every layer above.
- **24/7 monitoring**, either an internal SOC or an MDR provider — a
  detection that fires at 3am on a Saturday needs someone to see it.
- **SOAR-driven automated response playbooks** for well-understood
  attack patterns, with human sign-off required for anything ambiguous
  — the same self-consistency + evidence-grounding principle this lab's
  own triage layer already applies, at organizational scale.
- **Scheduled, recurring purple-team exercises** against the real
  production detection rules — not a one-time build-and-forget.
  **This is literally what this lab is for.**

### G. Observability & compliance

- **Full-stack observability** (logs, metrics, traces), not just
  security events — a security incident is often visible first as a
  performance anomaly.
- **Audit log retention meeting compliance requirements** — SOC 2,
  ISO 27001, or sector-specific regulation (e.g., OSFI guidance for
  Canadian financial institutions), which typically means retention far
  longer than this lab's local hash-chained log.
- **Regular third-party audits and penetration tests**, independent of
  the internal purple team.

### H. Resilience

- **Multi-region redundancy** for anything the agent supply chain
  depends on to function — a registry outage shouldn't mean every agent
  in the company stops working.
- **Documented, tested incident response plan specifically for an AI
  agent compromise scenario** — not a generic IR plan with "AI" added
  as an afterthought.

---

## 2. Honest map: this lab against that standard

| Domain | What a real enterprise has | Where this lab stands today |
|---|---|---|
| A. Governance & risk | Named approval authority, formal risk classification | **Not built.** This is an organizational function, not something a lab can simulate — needs a real owner at your company |
| B. Identity & access | Federated workload identity, PAM, segregation of duties | **Partially real.** UC2 uses genuine Entra ID/Workload Identity Federation patterns. PAM and segregation of duties are not implemented — `APPROVED_ACTORS` is a hardcoded list, not a real IAM integration |
| C. Software supply chain | Signed commits, SLSA provenance, ephemeral runners, SBOM | **Lab-realistic, not enterprise-grade.** UC4 hits real Azure DevOps/AWS CodeArtifact APIs — genuine build/publish calls. No commit signing, no SLSA attestation, no SBOM generation exist yet |
| D. Tool/MCP registry governance | Re-approval on every change, independent verification | **This is the lab's strongest area.** UC1's rug-pull detection and the K8s gateway's quarantine-on-change are real instances of exactly this control, not simulations of it |
| E. Network & runtime isolation | Segmented networks, private endpoints, sandboxed execution | **Real in the K8s architecture, absent in local mode.** The gateway's NetworkPolicy segmentation is genuine. No sandboxed tool execution exists anywhere yet — this lab's "tool calls" are always simulated, never real code execution, which is correct for lab safety but is not the isolation control production needs |
| F. Detection, response & SOC | Real SIEM, 24/7 monitoring, SOAR, recurring purple-team | **Detection logic is real; the organization around it isn't.** Splunk forwarding, CrowdStrike/Netskope/Zabbix enrichment, and the AI triage layer are genuine integrations. No 24/7 monitoring, no SOAR, and "recurring purple-team" is literally what running this lab on a schedule would become |
| G. Observability & compliance | Full-stack observability, compliance-grade retention, third-party audit | **Minimal.** The hash-chained audit log proves tamper-evidence as a *mechanism* — it does not meet any real compliance retention/audit standard as deployed today |
| H. Resilience | Multi-region, tested IR plan for AI compromise | **Not built.** Everything in this lab is deliberately single-instance and disposable — that's correct for a lab, wrong for production |

### The honest one-line summary

**This lab proves the detection and prevention *logic* works, against
real cloud services, with real telemetry.** That is a genuinely hard
problem and it's solved here. **It does not yet prove the *organizational
and operational* controls around that logic exist** — approval
authority, PAM, SLSA-level build integrity, 24/7 response, compliance
retention. Those aren't code problems this lab can solve for you; they're
organizational decisions your company has to make and then this lab's
logic gets deployed into.

That's the actual path to production: not "harden the scripts more," but
"put these already-validated scripts inside the organizational controls
in Section 1 that don't exist yet."
