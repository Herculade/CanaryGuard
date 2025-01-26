# CanaryGuard 
## Integrates with Pi-hole to block offending IPs and reports malicious activities to Abuse IPDB.

**CanaryGuard** is a Python-based security monitoring tool designed to enhance the capabilities of OpenCanary by tracking and mitigating SSH brute force attacks. CanaryGuard also provides detailed logging and metrics to help analyze attack patterns and improve system security.

## Features

- **SSH Brute Force Detection**: Monitors OpenCanary logs for SSH login attempts and detects brute force attacks.
- **Rate Limiting**: Tracks the number of login attempts from each IP within a specified time window.
- **IP Blocking**: Integrates with Pi-hole to block offending IPs for a configurable duration.
- **Abuse IPDB Reporting**: Reports malicious IPs to Abuse IPDB for broader threat intelligence.
- **Detailed Logging**: Logs all activities to `canaryguard.log` with human-readable timestamps.
- **Log Archiving**: Automatically archives logs when they exceed a specified size to maintain performance.
- **Metrics Tracking**: Tracks and stores various metrics, including total login attempts, unique IP addresses, banned IPs count, and more.
- **Repeat Offender Tracking**: Identifies and tracks repeat offenders for enhanced security measures.

## Prerequisites

- **OpenCanary running somewhere with all services but SSH disabled (So nothing else goes into the log that this script can't parse)
- **Access to the OpenCanary Log file
- **python3
