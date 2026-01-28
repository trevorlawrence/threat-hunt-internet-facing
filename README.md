# Threat Hunt Scenario 1: Devices Exposed to the Internet
---
# 1. Preparation/Scenario
## Objective

The objective of this threat hunt is to identify any virtual machines within the shared services cluster (e.g., DNS, Active Directory Domain Services, DHCP) that may have been mistakenly exposed to the public internet and to determine whether those systems were targeted or compromised via brute-force authentication attempts.

## Background

During routine infrastructure maintenance, concerns were raised that one or more shared services virtual machines may have been unintentionally assigned public network exposure. These systems are high-value targets due to their role in authentication, name resolution, and network configuration.

Several systems in the environment do not enforce strict account lockout policies after repeated failed login attempts, increasing the risk of successful credential brute-forcing.

## Hypothesis

If shared services VMs were exposed to the public internet, then:

- External IP addresses may have attempted repeated authentication failures against these systems.
- Some attempts may have resulted in successful authentication.
- Successful compromise could lead to further activity such as privilege escalation or lateral movement.
---
# 2. Data Collection & Analysis

(For the purposes of this scenario, the Internet-facing VM is already known to us: "windows-target-1".)


Collect sufficient telemetry to:
- Identify which VMs were internet-exposed.
- Detect excessive authentication failures.
- Detect successful logons following failure patterns.
- Attribute activity to external source IP addresses.

**Data Sources**

The following Microsoft Sentinel tables will be used:
- *DeviceInfo* – to identify device roles, exposure, and network configuration
- *DeviceLogonEvents* – to analyze authentication attempts and outcomes


Collection:

//Check logon logs for target machine

DeviceLogonEvents

| where DeviceName == "windows-target-1"

| where Timestamp between(datetime(2026-01-01) .. now())

| sort by Timestamp desc

Analysis:

Windows-target-1 had been Internet-facing for several days in early January. Several bad actors were discovered attempting to log in.
Last Internet-facing time: 2026-01-05T23:03:08.2842198Z


Collection:

//Check for IPs with the most failed logons

DeviceLogonEvents

| where DeviceName == "windows-target-1"

| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")

| where ActionType == "LogonFailed"

| where isnotempty(RemoteIP)

| summarize Attempts = count() by ActionType, RemoteIP, DeviceName

| order by Attempts

Analysis:
The IP with the most attempts had 284 attempts. The next four highest were in the 80s.
The four Logontypes of concern are Network, Interactive, RemoteInteractive, and Unlock.
- Network = access through the network, such as accessing a file share or lateral movement. If detected, we should check for unusual IPs or admin accounts.
- Interactive = access physically on-site through mouse/keyboard. Notable after-hours or on servers.
- RemoteInteractive = remote logon (RDP). Check for first-time logons, after-hours access, or external IPs.
- Unlock = access was performed by unlocking a workstation that is already logged in. Rarely used by attackers, mostly unhelpful.

Collection:


//Check for any successful logons for IPs with the top 10 most logon attempts

let RemoteIPsInQuestion = dynamic(["185.11.61.192","77.90.185.62","77.90.185.64","185.11.61.198","194.180.48.29","77.90.185.39","213.55.95.235","103.87.120.58","34.66.171.22","51.178.174.31"]);

DeviceLogonEvents

| where DeviceName == "windows-target-1"

| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")

| where ActionType == "LogonSuccess"

| where RemoteIP has_any(RemoteIPsInQuestion)

Analysis:

There were no successful logons from the top ten IPs with the most attempts.



