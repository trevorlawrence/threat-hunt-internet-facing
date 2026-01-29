# Threat Hunt Scenario 1: Devices Exposed to the Internet
---
# 1. Preparation/Scenario
## Objective

The objective of this threat hunt is to identify any virtual machines within the shared services cluster (e.g., DNS, Active Directory Domain Services, DHCP) that may have been mistakenly exposed to the public internet and to determine whether those systems were targeted or compromised via brute-force authentication attempts.

## Background

During routine infrastructure maintenance, concerns were raised that one or more shared services virtual machines may have been unintentionally assigned public network exposure. These systems are high-value targets due to their role in authentication, name resolution, and network configuration.

Several systems in the environment do not enforce strict account lockout policies after repeated failed login attempts, increasing the risk of successful credential brute-forcing.


<img width="1536" height="1024" alt="75343de8-da40-49c8-a8fb-251e275a5ea5" src="https://github.com/user-attachments/assets/292fe60a-45b8-4262-8863-59c29ded2a16" />



## Hypothesis

If shared services VMs were exposed to the public internet, then:

- External IP addresses may have attempted repeated authentication failures against these systems.
- Some attempts may have resulted in successful authentication.
- Successful compromise could lead to further activity such as privilege escalation or lateral movement.
---
# 2. Data Collection & Analysis

(For the purposes of this scenario, the Internet-facing VM is already known to us: ```windows-target-1```.)


Collect sufficient telemetry to:
- Identify which VMs were internet-exposed.
- Detect excessive authentication failures.
- Detect successful logons following failure patterns.
- Attribute activity to external source IP addresses.

**Data Sources**

The following Microsoft Sentinel tables will be used:
- *DeviceInfo* – to identify device roles, exposure, and network configuration
- *DeviceLogonEvents* – to analyze authentication attempts and outcomes


<ins>Collection:</ins>

```
// Check logon logs for target machine

DeviceLogonEvents

| where DeviceName == "windows-target-1"

| where Timestamp between(datetime(2026-01-01) .. now())

| sort by Timestamp desc
```

<ins>Analysis:</ins>

```windows-target-1``` had been Internet-facing for several days in early January. Several bad actors were discovered attempting to log in.
Last Internet-facing time: ```2026-01-05T23:03:08.2842198Z```


<ins>Collection:</ins>

```
//Check for IPs with the most failed logons

DeviceLogonEvents

| where DeviceName == "windows-target-1"

| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")

| where ActionType == "LogonFailed"

| where isnotempty(RemoteIP)

| summarize Attempts = count() by ActionType, RemoteIP, DeviceName

| order by Attempts
```

<img src="https://github.com/trevorlawrence/threat-hunt-internet-facing/blob/main/query-results/LogonAttempts.png"> 


<ins>Analysis:</ins>

The IP with the most attempts had 284 attempts. The next four highest were in the 80s.
The four Logontypes of concern are Network, Interactive, RemoteInteractive, and Unlock.
- Network = access through the network, such as accessing a file share or lateral movement. If detected, we should check for unusual IPs or admin accounts.
- Interactive = access physically on-site through mouse/keyboard. Notable after-hours or on servers.
- RemoteInteractive = remote logon (RDP). Check for first-time logons, after-hours access, or external IPs.
- Unlock = access was performed by unlocking a workstation that is already logged in. Rarely used by attackers, mostly unhelpful.

<ins>Collection:</ins>

```
//Check for any successful logons for IPs with the top 10 most logon attempts

let RemoteIPsInQuestion = dynamic(["185.11.61.192","77.90.185.62","77.90.185.64","185.11.61.198","194.180.48.29","77.90.185.39","213.55.95.235","103.87.120.58","34.66.171.22","51.178.174.31"]);

DeviceLogonEvents

| where DeviceName == "windows-target-1"

| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")

| where ActionType == "LogonSuccess"

| where RemoteIP has_any(RemoteIPsInQuestion)
```

<img src="https://github.com/trevorlawrence/threat-hunt-internet-facing/blob/main/query-results/LogonSuccess.png"> 

<ins>Analysis:</ins>

There were no successful logons from the top ten IPs with the most attempts.

---

# 3. Findings & Discussion

**Relevant MITRE ATT&CK TTPs**

MITRE ATT&CK is a knowledge base for detecting, recognizing, preventing, and fighting cyber threats. "TTPs" are tactics, techniques, and procedures commonly used by bad actors. The MITRE ATT&CK TTPs relevant for this scenario are:
```
Brute Force (T1110)
Valid Accounts (T1078)
Remote Services (T1021)
```

Brute forcing is the repetitive attempt to guess a username or password for an unknown login account. Based on the hundreds or dozens of attempts that several of our VM's threats made, we can confidently state that brute force methods were applied.

The Valid Accounts TTP would only have applied if the bad actors successfully logged on, as they would have had access to a legitimate account on the VM and could have abused various resources and potentially bypassed access controls.

Remote Services refers to the use of remote protocols to gain access to a system.

**Remediation of Breached Systems**

If a successful intrusion were discovered, the immediate steps would be: 

1) identify the affected systems, accounts, and attacker IP
2) preserve logs and evidence of the breach
3) isolate the VM and remove its public IP
4) restrict the Network Security Group (NSG) rules
5) block the attacker's IP at the firewall level
6) disable compromised accounts, force a password reset, and revoke the active session

Once this initial response is completed, any attacker footholds should be rooted out and removed. Analysts should check for any suspicious scheduled tasks or startup services, new local/admin accounts, backdoors, or installed malware.
The entire system should have a full scan before rejoining the network. Credentials should be rotated, services should be reenabled gradually, and the system should be continuously monitored. The proper procedures should be followed for reporting and escalating.

Organization security posture and policies should be evaluated. Are there any detection gaps? Is the system hardened efficiently? What was the response time? 

All company employees should be re-trained on the importance of password strength and security. All systems are vulnerable, but human error is the most likely cause of breaches. If a password is too weak, too simple, too short, or used too frequently for different accounts, it is likely to be discovered through brute force or credential stuffing. The latter is when an exposed username and password from a data breach is used on a variety of websites or systems to gain access. If a company employee uses their company username and password combination for non-company logins and that information is exposed to the dark web or discovered in a data breach, it is likely to be used on any site with that username registered until one of them is accessed.

Password policies specifically should be reviewed. NIST STIG 800-53 recommends several best practices for this such as password complexity, password length, how passwords are stored and hashed, how passwords are transmitted, and account lockouts after several failed login attempts.

---

# 4. Conclusion

This threat-hunting exercise demonstrated how quickly publicly exposed infrastructure is identified and targeted by automated threat actors. The investigation confirmed that the virtual machine was unintentionally Internet-facing and subsequently subjected to hundreds of brute-force authentication attempts from multiple external IP addresses.

Although no successful logins were detected and no compromise occurred, the activity observed aligns with well-documented attacker behavior mapped to the MITRE ATT&CK framework. This reinforces the reality that exposure alone is sufficient to attract persistent malicious attention, regardless of the organization or system’s perceived value.

The remediation actions taken—removing public access and tightening network security controls—significantly reduced the system’s attack surface and prevented further external targeting. This outcome highlights the effectiveness of timely detection, centralized logging, and structured threat hunting in identifying security gaps before they result in compromise.

From a defensive perspective, this lab emphasizes the importance of:

- Continuous monitoring of authentication activity

- Regular review of network exposure and configuration

- Defense-in-depth strategies beyond password strength alone

- Proactive threat hunting as a validation tool for existing controls

Overall, this exercise illustrates how misconfigurations can introduce serious risk, how attackers routinely exploit such opportunities, and how security teams can leverage telemetry and structured analysis to detect, investigate, and mitigate threats before damage occurs.
