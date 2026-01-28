# Threat Hunt Scenario 1: Devices Exposed to the Internet

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

# 2. Data Collection

Collect sufficient telemetry to:
- Identify which VMs were internet-exposed.
- Detect excessive authentication failures.
- Detect successful logons following failure patterns.
- Attribute activity to external source IP addresses.

**Data Sources**

The following Microsoft Sentinel tables will be used:
- DeviceInfo – to identify device roles, exposure, and network configuration
- DeviceLogonEvents – to analyze authentication attempts and outcomes

**Data Validation Plan**

Before analysis:
- Confirm tables contain recent data.
- Verify logging coverage for all shared services VMs.
- Confirm timestamps align with the suspected exposure window.

# 3. Data Analysis

