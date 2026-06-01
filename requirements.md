# ThreatHunter Detection Platform - System Requirements

This document outlines the prerequisite configurations, environment dependencies, and security auditing requirements necessary to execute the **ThreatHunter Detection Platform** core framework and adversarial simulation playbooks successfully.

---

## 💻 Operating System & Shell Platform

The engine relies on native Windows logging APIs and advanced structured pipeline formatting.

* **Operating System:** Windows 10, Windows 11, or Windows Server 2019/2022+ (64-bit architecture required).
* **Execution Environment:** PowerShell 5.1 (Built-in Windows Desktop Edition) or PowerShell 7.x+ Core.
* **Execution Privileges:** **Elevated Administrative Rights (Run as Administrator)**. Accessing local security channels, process memory handles, and protected event logs requires high-integrity execution tokens.

---

## 🛠️ Mandatory Windows Auditing Policies

By default, standard Windows installations do not log detailed process execution strings or script block transcripts. To enable the ingestion collectors to capture threat telemetry, the following Group Policy Objects (GPOs) must be activated locally:

### 1. Detailed Process Creation Auditing (EID 4688)
Captures every binary invocation across the operating system layer.
* **Path:** `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Detailed Tracking`
* **Setting:** Set **Audit Process Creation** to include both **Success** and **Failure** triggers.

### 2. Process Command-Line Subsystem Enrichment
Ensures that full command strings, arguments, execution flags, and directory contexts are populated inside the telemetry payload.
* **Path:** `Computer Configuration -> Administrative Templates -> System -> Audit Process Creation`
* **Setting:** Enable **Include command line in process creation events**.

### 3. PowerShell Script Block Transcription (EID 4104)
Captures explicit multi-stage code segments executed inside memory space, regardless of obfuscation or runtime evasion attempts.
* **Path:** `Computer Configuration -> Administrative Templates -> Windows Components -> Windows PowerShell`
* **Setting:** Enable **Turn on PowerShell Script Block Logging**.

### 4. Local Account & Credential Tracking (EID 4624 / 4625 / 4720)
Monitors lateral access boundaries, malicious account provisioning, and credential spraying campaigns.
* **Path:** `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Logon/Logoff`
* **Setting:** Set **Audit Logon** and **Audit Logoff** to **Success** and **Failure**.
* **Path:** `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Account Management`
* **Setting:** Set **Audit User Account Management** to **Success** and **Failure**.

---

## ⚙️ Runtime Setup & Module Constraints

Before initiating the orchestration pipeline, verify that the environment permissions match the following security baselines:

### Execution Policy Configuration
To allow the bootstrapper engine to parse nested folders and dynamically link custom modules into memory, assign a relaxed process execution parameter:
```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process -Force