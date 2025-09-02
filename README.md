# InsightIDR LEQL Queries for Threat Detection & Incident Response

A collection of practical and high-signal **Log Entry Query Language (LEQL)** queries designed for use in **Rapid7 InsightIDR**. These queries are tailored to support threat hunting, anomaly detection, and incident response across cloud and endpoint environments.

---

## Purpose

This repository aims to serve as a **ready-to-use and easily customizable toolkit** for security analysts and incident responders working with InsightIDR. It includes LEQL queries mapped to common attack behaviors, detection gaps, and investigation workflows.

The focus is on:
- Rapid detection of suspicious activity
- MITRE ATT&CK-based behavior identification
- Streamlined investigations within InsightIDR dashboards and log search

---

## Repository Structure

Each folder represents a core category of detection or response need:

- `Initial_Access/` — Phishing indicators, suspicious user agents, external RDP attempts
- `Lateral_Movement/` — SMB logins, Pass-the-Hash, RDP relay detection
- `Credential_Access/` — Authentication failures, brute force attempts, password spray
- `Persistence/` — Scheduled task abuse, new services, registry key modifications
- `Exfiltration/` — Cloud storage access anomalies, large file transfers
- `Defense_Evasion/` — Log clearing, PowerShell obfuscation, process tampering
- `User_Behavior/` — Impossible travel, MFA bypass, login anomalies
- `Endpoint_Hunting/` — Suspicious command line patterns, rare process execution
- `Cloud_Monitoring/` — Suspicious OAuth app grants, abnormal login sources
- `General_Hunting/` — Environment-agnostic queries for broader visibility
- `Dashboards/` — Grouped LEQLs for direct dashboard integration

---

## How to Use

1. Log in to **InsightIDR** and go to **Log Search** or **Legacy Log Search**.
2. Copy a LEQL query from the relevant `.leql` file or folder.
3. Paste it into the log search bar or **custom alert rules**.
4. Modify key fields like:
   - `asset.ip`
   - `user.name`
   - `destination.port`
   - `log.source`
   - `timestamp` range
5. Use in dashboards, alerts, or investigations as needed.

Most queries are designed to be plug-and-play but can be adapted based on your environment’s log sources and naming conventions.

---

## Query Design Approach

- **Mapped to MITRE ATT&CK tactics & techniques**
- Focused on **behavioral detection** rather than signature-based rules
- Built from real-world incidents, threat reports, and hunting experience
- Clear annotations for filters, tuning, and false-positive reduction

---

## Example Queries (Preview)

```leql
where(attack.tactic = "lateral_movement") AND logon.type = "remote" AND destination.port = 3389
