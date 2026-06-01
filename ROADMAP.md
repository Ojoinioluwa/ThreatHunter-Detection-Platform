
# ThreatHunter Detection Platform - Development Roadmap

This document outlines the evolutionary milestones, past engineering achievements, and future development phases for the **ThreatHunter Detection Platform** as it scales from a local endpoint analyzer into an enterprise-grade detection ecosystem.

---

## 📈 Phase Lifecycle Overview


```

┌──────────────────────────┐      ┌───────────────────────────┐      ┌───────────────────────────┐
│   PHASE 1: FOUNDATION     │ ───> │   PHASE 2: ENHANCEMENT    │ ───> │    PHASE 3: ENTERPRISE    │
│ (Core Engine & Telemetry) │      │ (Fidelity & Dynamic Ops)  │      │  (Distributed Scaling)   │
└───────────────────────────┘      └───────────────────────────┘      └───────────────────────────┘

```

---

## ✅ Phase 1: Foundation (Core Engine & Telemetry Ingestion)
*Focus: Build a robust, decoupled object-oriented architecture to parse local telemetry streams.*

* **[x] Object-Oriented Core Platform:** Designed and deployed the main `DetectionEngine` using native PowerShell classes for isolated, reliable event stream parsing.
* **[x] Dynamic Engine Initialization:** Implemented dynamic script discovery via automated subfolder recursion, eliminating the need to hardcode new rules into the pipeline.
* **[x] Decoupled Logging & Output Handling:** Separated system diagnostic collection (`Logger.psm1`) from event reporting (`OutputHandler.psm1`) to minimize runtime performance overhead.
* **[x] Structured Config Routing:** Built a centralized configuration schema (`detectionconfig.json`) to map distinct Security and Operational Event IDs to specific analysis layers.

---

## ✅ Phase 2: Enhancement (Detection Fidelity & Dynamic Operations)
*Focus: Expand the detection matrix across the host kill-chain and increase ingestion flexibility.*

* **[x] Core Threat Coverage Matrix:** Written and validated high-fidelity, standalone rules mapping directly to the **MITRE ATT&CK Framework**:
    * *Authentication:* Local brute-forcing, password spraying, explicit credential swapping (`runas`), and LSASS memory handle requests.
    * *Account Management:* Unprivileged administrative group assignments and unauthorized user provisions.
    * *Persistence:* Windows service registry additions, scheduled tasks, and accessibility feature backdoors (`sethc`).
    * *Process Execution:* Native Base64 PowerShell execution parsing, LOLBas ingress cradles (`certutil`/`bitsadmin`), and system masquerading.
* **[x] Dynamic Parameter-Bound Ingestion:** Upgraded `Start-Monitoring.ps1` with a validation-backed command block (`-CollectorFunction`), allowing the analyst to target specific telemetry collectors at boot.
* **[x] Decoupled Severity Mapping:** Separated risk scoring logic into a standalone switch matrix (`SeverityCalculator.ps1`) to ensure dynamic hazard classification before incident compilation.
* **[x] Automated Adversarial Playbook:** Constructed a safe simulation script (`Run-SafeLiveSimulation.ps1`) to stress-test rules under active conditions without altering system integrity.

---

## 🚀 Phase 3: Enterprise (Distributed Scaling & Detection Engineering)
*Focus: Scale the project toward continuous enterprise infrastructure monitoring and telemetry analysis.*

* **[ ] Unified Log Shipper Integration (Winlogbeat/Splunk Forwarders):**
    * Extend ingestion collectors to parse streaming JSON event feeds from external log shippers, removing the constraint of relying strictly on local windows event query utilities (`Get-WinEvent`).
* **[ ] Advanced Stateful Correlation Engine:**
    * Incorporate sliding-time-window tracking to correlate separate atomic events across realms (e.g., Flag an alert *only if* a successful EID 4624 Logon Type 3 occurs within 60 seconds of 5 failed EID 4625 attempts).
* **[ ] Universal Detection Code Translation (Sigma & Yara-L):**
    * Fully flesh out the conversion modules (`ConvertToSigma.ps1`) to automatically cross-compile internal PowerShell detection functions into standardized, platform-agnostic YAML rules for use in Splunk, Elastic, or Microsoft Sentinel.
* **[ ] Headless CI/CD Pipeline & Automated Lab Deployment:**
    * Build a GitHub Actions or GitLab CI framework to run regression tests on all rules automatically using a cloud-hosted Windows runner whenever a new detection script is merged into the master repository.
