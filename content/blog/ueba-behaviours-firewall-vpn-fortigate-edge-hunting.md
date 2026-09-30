---
title: "Your Firewall Admin Logs Just Got a Behaviour Layer"
date: 2026-09-30
author: Chris Scott
summary: Sentinel's UEBA behaviours layer now covers Fortinet FortiGate, with anomaly rules for Check Point, Fortinet and Zscaler. Here is why that matters for edge device hunting and how to query it without trusting it blindly.
tags:
  - kql
  - sentinel
  - ueba
  - threat-hunting
  - detection-engineering
  - edge-devices
published: true
---

Most of the firewall telemetry I have seen in Sentinel workspaces falls into one of two buckets. It is either ingested and never queried, or it is ingested, queried once during an incident, and then forgotten again. CommonSecurityLog is huge, awkward to read, and every vendor fills the fields slightly differently. So the admin activity on the box that sits at the front door gets the least attention of anything in the estate.

That gap is getting harder to defend. Edge devices have been a favourite target all year, and the August 2026 Sentinel update quietly added something aimed straight at it: UEBA behaviours and anomaly rules for firewall, VPN and web proxy logs.

## What actually shipped

The August update to Microsoft Sentinel adds Fortinet FortiGate events from CommonSecurityLog to the UEBA behaviours layer, with more than 40 new behaviours covering administrative activity on the appliance. Microsoft's examples include rapid system reconfigurations, configuration backups, certificate changes and security service disruptions. They are mapped to ATT&CK techniques including Valid Accounts (T1078), Indicator Removal (T1070) and Data from Configuration Repository (T1602.002).

Alongside that, UEBA anomaly detection now supports Check Point, FortiGate and Zscaler events, with ten new anomaly rules. Each compares a user or device against its own history and the wider organisation. They look for anomalous and failed VPN sign-ins, unusual access to high-risk web categories, bursts of security detections on a device, and suspicious administrative changes. UEBA anomalies also now support identity-linked AWS GuardDuty findings. All of it is in preview, so treat it that way.

The behaviours layer itself is the interesting part. It takes raw logs and turns them into plain-language "who did what to whom" records with ATT&CK mappings, held in the SentinelBehaviorInfo and SentinelBehaviorEntities tables (BehaviorInfo and BehaviorEntities in Advanced Hunting). It has to be enabled separately from UEBA, and those tables only exist if you have switched it on.

## Why the threat picture makes this timely

The reporting on FortiGate compromise this year is consistent about what attackers do once they are on the appliance. They make unauthorised configuration changes, create new administrator accounts for persistence, and pull down the configuration file. That file matters because it can hold stored credentials, including service account details used for directory integration, and the hashes can be cracked offline. Coverage of the January to February campaign describes a financially motivated actor compromising more than 600 devices across over 55 countries, and CISA issued an emergency advisory in June 2026. I have not independently verified the numbers, so check the sources below before quoting them.

Notice what that list of attacker actions looks like. Config backup, new admin, disabled security service, changed certificate. That is almost exactly the list of behaviours Microsoft has just built for FortiGate. The defensive content has finally caught up with what the adversary was already doing.

## The hunting angle

There are two ways to use this. The first is to hunt the behaviours directly. Something along these lines is a sensible starting hypothesis:

```kql
BehaviorInfo
| where Timestamp > ago(30d)
| where Description has "FortiGate" or ServiceSource has "Sentinel"
| where ActionType has_any ("config", "backup", "certificate", "admin")
| project Timestamp, ActionType, Description, AttackTechniques
| order by Timestamp desc
```

I have written that from the documented schema rather than against a live FortiGate feed, so check the column names and ActionType values in your own tenant first. The point is the shape of it: hunt the behaviour record, not the raw syslog string.

The second is to keep a raw-log query alongside it, because the behaviours layer only tells you what Microsoft chose to model:

```kql
CommonSecurityLog
| where DeviceVendor == "Fortinet"
| where Activity has_any ("config", "backup", "admin")
| summarize Events = count(), Actors = make_set(SourceUserName) by DeviceName, bin(TimeGenerated, 1d)
| order by Events desc
```

Here is the logic I would build around either one:

- Configuration backups or exports outside a change window, or by an account that has never done one
- New administrator accounts on the appliance, joined to whoever created them
- Security service or logging disruption close to any of the above
- Management interface logins from addresses that are not your admin ranges

## Considerations and maturity

None of this helps if the logs are not there. FortiGate has to be forwarding into CommonSecurityLog with admin and configuration events included, and plenty of firewall log profiles are tuned to traffic logs only. Check that before anything else.

Anomaly rules also need history. A user compared against their own baseline is only useful once there is a baseline, so a freshly connected feed will be quiet or noisy for a while. Preview features change, and a behaviour name you build a rule around today may be renamed. The same goes for volume: the behaviours layer sits in your workspace and costs something, so it is worth deciding which tables earn it.

The other failure mode is treating vendor-modelled behaviours as complete coverage. They are a good first layer. Your own knowledge of who administers those firewalls, and when, is still what separates a real alert from a Tuesday afternoon change ticket.

## Closing Thoughts

I would start small. Confirm the admin logs are landing, enable the behaviours layer on one workspace, and run a 30 day hunt to see what your baseline actually looks like. If nothing has ever backed up a config outside a change window, that is a comforting result and a useful rule waiting to be written. If something has, you have just found out a lot more than any dashboard would have told you.

## References

1. [What's new in Microsoft Sentinel (August 2026: UEBA data sources, anomalies on behaviours) - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/whats-new)
2. [Translate raw security logs to behavioral insights using UEBA behaviors in Microsoft Sentinel - Microsoft Learn](https://learn.microsoft.com/en-ca/Azure/sentinel/entity-behaviors-layer)
3. [Microsoft Sentinel September 2026 Update - Infernux](https://infernux.no/blog/microsoft-sentinel-september-2026/)
4. [Attackers exploit FortiGate devices to access sensitive network information - Security Affairs](https://securityaffairs.com/189241/security/attackers-exploit-fortigate-devices-to-access-sensitive-network-information.html)
5. [FortiBleed: Default Credential Exploitation and Mass Fortinet Compromise - Cloud Security Alliance](https://labs.cloudsecurityalliance.org/research/csa-research-note-fortibleed-default-credentials-20260620-cs/)
6. [FortiGate edge intrusions - SentinelOne](https://www.sentinelone.com/de/blog/fortigate-edge-intrusions/)
7. [KQL Sources: 2026 Update - kqlquery.com](https://kqlquery.com/posts/kql-sources-2026/)
