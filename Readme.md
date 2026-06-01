# ThreatHunter Detection Platform

> An enterprise-grade, lightweight, native host-based SIEM/EDR orchestration engine and adversarial simulation framework built entirely in PowerShell.

The platform performs real-time Windows telemetry collection, threat detection, event correlation, severity scoring, and structured incident generation directly from local host security logs.

Designed to emulate core SOC detection engineering workflows while remaining modular, extensible, and fully transparent.

---

## Core Capabilities

### Real-Time Ingestion & Orchestration

Direct parsing and aggregation of local host security and operational event channels.

### Deterministic Sandbox Testing (`Get-SyntheticTelemetry`)

Programmatically generates exactly **1,000 sequenced event records**:

* 700 benign background events
* 300 high-fidelity attack simulations

Used to validate:

* Detection rules
* Correlation logic
* Parsing pipelines
* Severity scoring
* Incident generation

### Modular Detection Rule Architecture

* Stateless atomic detections
* Decoupled rule execution
* Organized by detection category
* Easy extensibility

### Stateful Attack Correlation Engine

Dynamic in-memory temporal analysis capable of tracking:

* Multi-stage attack chains
* User activity sequences
* Persistence mechanisms
* Privilege escalation workflows

### MITRE ATT&CK Mapping

Every alert contains:

* ATT&CK Technique ID
* Technique Name
* Detection Metadata

### Dynamic Severity Scoring

Integrated risk evaluation engine assigns:

* Low
* Medium
* High
* Critical

severity ratings based on event context.

### Safe Adversarial Attack Simulation

Generates realistic Windows telemetry without damaging the host system.

### JSON & CSV Export Pipelines

Automatic export of:

* Structured incident records
* Correlation outputs
* Alert evidence
* Investigation artifacts

---

# Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        ARCHITECTURAL ECOSYSTEM                         │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│   [Local Event Logs]      [Simulation Scripts]    [Synthetic Ingest]   │
│    (Security, PS Op)     (Run-SafeLiveSimulation) (Get-SyntheticData)  │
│            │                        │                        │         │
│            ▼                        ▼                        ▼         │
│   ┌──────────────────────────────────────────────────────────┐         │
│   │                 Start-Monitoring.ps1                     │         │
│   │         (Dynamic Core Execution & Mounting)              │         │
│   └─────────────────────────┬────────────────────────────────┘         │
│                             │                                          │
│                             ▼                                          │
│   ┌──────────────────────────────────────────────────────────┐         │
│   │                 DetectionEngine.psm1                     │         │
│   │          (OOP Pipeline Coordination & Logic)             │         │
│   └────────┬────────────────────────────────────────┬────────┘         │
│            │                                        │                  │
│            ▼                                        ▼                  │
│   ┌──────────────────┐                     ┌──────────────────┐        │
│   │  Stateless Rules │                     │    Correlators   │        │
│   │ (Detections/*)   │                     │  (Correlation/*) │        │
│   └────────┬─────────┘                     └────────┬─────────┘        │
│            │                                        │                  │
│            └───────────────────┬────────────────────┘                  │
│                                │                                       │
│                                ▼                                       │
│   ┌──────────────────────────────────────────────────────────┐         │
│   │                SeverityCalculator.ps1                    │         │
│   │         (Dynamic Score & MITRE ATT&CK Mapping)           │         │
│   └─────────────────────────┬────────────────────────────────┘         │
│                             │                                          │
│                             ▼                                          │
│   ┌──────────────────────────────────────────────────────────┐         │
│   │                 OutputHandler / Exports                  │         │
│   │           (Real-Time JSON, CSV Alerts & Logs)            │         │
│   └──────────────────────────────────────────────────────────┘         │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

# Detection Pipeline

```text
Telemetry Sources (Live Event Logs OR Synthetic Generative Stream)
         │
         ▼
    Collectors
         │
         ▼
  Detection Engine
         │
  ┌──────┴──────┐
  ▼             ▼
Rules       Correlators
         │
         ▼
Severity Calculator
         │
         ▼
Incident Export Engine
```

---

# Project Structure

```text
ThreatHunter-Detection-Platform/
│
├── config/
│   └── detectionconfig.json
│
├── incidents/
│
├── scripts/
│   └── Run-SafeLiveSimulation.ps1
│
├── Start-Monitoring.ps1
│
└── src/
    ├── Collectors/
    │   ├── PowerShellCollector.ps1
    │   ├── ProcessCollector.ps1
    │   ├── RegistryCollector.ps1
    │   ├── ScheduledTaskCollector.ps1
    │   ├── SecurityCollector.ps1
    │   └── Get-SyntheticTelemetry.ps1
    │
    ├── Core/
    │   ├── ConfigLoader.psm1
    │   ├── Correlator.psm1
    │   ├── DetectionEngine.psm1
    │   ├── EventCollector.psm1
    │   ├── Logger.psm1
    │   └── OutputHandler.psm1
    │
    ├── Correlation/
    │   ├── New-AttackTimeline.ps1
    │   ├── Track-AccountEscalation.ps1
    │   ├── Track-LogonSequence.ps1
    │   └── Track-PersistenceChain.ps1
    │
    ├── Detections/
    │   ├── Account/
    │   ├── Authentication/
    │   ├── Persistence/
    │   └── Process/
    │
    └── Utilities/
        ├── ConvertToSigma.ps1
        ├── ExportCsv.ps1
        ├── ExportJson.ps1
        ├── ParseEventXML.ps1
        └── SeverityCalculator.ps1
```

---

# Supported Telemetry

| Category           | Event IDs                    |
| ------------------ | ---------------------------- |
| Authentication     | 4624, 4625, 4648, 4656       |
| Account Management | 4720, 4724, 4728, 4732, 4740, 4726, 4739 |
| Persistence        | 4697, 7045, 106, 140, 200, 141    |
| Process Activity   | 4688, 4689, 4104, 1102       |

---

# Detection Coverage

## Authentication Detections

* Brute Force Detection
* Password Spray Detection
* Privileged Logon Detection
* Explicit Credential Usage
* LSASS Handle Access Monitoring

## Persistence Detections

* Scheduled Task Persistence
* Registry Run Key Persistence
* Service Installation Monitoring
* Accessibility Feature Abuse

## Process Detections

* Encoded PowerShell Execution
* LOLBins Abuse
* Office Macro Spawning
* Process Hollowing Indicators
* Hidden PowerShell Flags
* Temp Directory Execution

---

# Stateful Correlation Engine

The platform supports temporal attack tracking by correlating events across multiple log sources.

### Supported Correlators

| Correlator              | Purpose                                             |
| ----------------------- | --------------------------------------------------- |
| Track-LogonSequence     | Failed logons followed by successful authentication |
| Track-AccountEscalation | User creation followed by administrator assignment  |
| Track-PersistenceChain  | Registry persistence combined with scheduled tasks  |
| New-AttackTimeline      | Multi-stage attack reconstruction                   |

---

# Safe Adversarial Simulation

The included simulation framework generates realistic telemetry to validate detections without impacting system integrity.

## Included Simulations

| MITRE ID  | Technique          | Trigger                     |
| --------- | ------------------ | --------------------------- |
| T1027     | Encoded PowerShell | Base64 PowerShell execution |
| T1562.001 | Defense Evasion    | Audit log clearing attempts |
| T1136.001 | Account Creation   | Local account creation      |
| T1053.005 | Scheduled Task     | Persistence task creation   |

---

# Example Incident Output

```json
{
  "RuleName": "Detect-EncodedPowerShell",
  "MitreTechnique": "T1027",
  "Severity": "Medium",
  "TargetUser": "Inioluwa",
  "HostingComputer": "SIEM-LAB-DC01",
  "Evidence": {
    "ProcessName": "powershell.exe",
    "ParentProcess": "cmd.exe"
  }
}
```

---

# Execution & Usage Guide

## Prerequisites

Run PowerShell as Administrator.

```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process
```

---

## Synthetic Telemetry Validation (Recommended)

Validate the entire detection pipeline using deterministic synthetic telemetry.

```powershell
.\Start-Monitoring.ps1 -CollectorFunction Get-SyntheticTelemetry
```

### What Happens

* Dynamic rule discovery and registration
* Injection of 1,000 synthetic events
* Real-time rule execution
* Stateful correlation testing
* JSON and CSV incident generation

### Expected Results

* Successful detection generation
* Correlation chain creation
* Severity scoring
* Incident exports written to:

```text
incidents/
```

---

## Live Security Telemetry

```powershell
.\Start-Monitoring.ps1 -CollectorFunction Get-SecurityTelemetry
```

---

## Process Telemetry

```powershell
.\Start-Monitoring.ps1 -CollectorFunction Get-ProcessTelemetry
```

---

## Scheduled Task Telemetry

```powershell
.\Start-Monitoring.ps1 -CollectorFunction Get-ScheduledTaskTelemetry
```

---

# Recommended Windows Audit Configuration

Enable the following policies:

### Audit Process Creation

```text
Detailed Tracking → Audit Process Creation
```

### Include Command Line Arguments

```text
Administrative Templates
  → System
  → Audit Process Creation
```

### PowerShell Script Block Logging

```text
Windows Components
  → Windows PowerShell
```

### Security Log Auditing

Enable advanced audit logging for authentication, account management, and object access.

---

# MITRE ATT&CK Alignment

| Technique ID | Technique                       |
| ------------ | ------------------------------- |
| T1027        | Obfuscated Files or Information |
| T1053.005    | Scheduled Task                  |
| T1136.001    | Local Account Creation          |
| T1562.001    | Impair Defenses                 |

---

# Engineering Design Goals

* Native Windows telemetry analysis
* Modular detection engineering
* Lightweight execution footprint
* Minimal external dependencies
* Detection engineering experimentation
* SOC analyst training
* Threat hunting simulation
* Educational research platform

---

# Future Enhancements

* Sigma rule ingestion
* Real-time dashboard
* Remote endpoint monitoring
* Elastic integration
* Splunk forwarding
* Multi-host correlation
* Behavioral anomaly scoring
* YARA-L inspired detection abstraction

---

# Disclaimer

This project is intended strictly for:

* Defensive security research
* Detection engineering education
* SOC workflow simulation
* Threat hunting experimentation

**Do not use this platform for unauthorized offensive activity.**
