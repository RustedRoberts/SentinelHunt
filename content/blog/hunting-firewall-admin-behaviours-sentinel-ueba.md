---
title: "Hunting Firewall Admin Behaviour with Sentinel UEBA Behaviours"
date: 2026-10-10
author: Chris Scott
summary: Microsoft added 40+ FortiGate admin behaviours to Sentinel's UEBA layer in August. Edge devices have no EDR, so here is how to hunt them with BehaviorInfo, and where the gaps are.
tags:
  - kql
  - sentinel
  - threat-hunting
  - detection-engineering
  - advanced-hunting
published: true
---

I went looking for new KQL detection content this week and, honestly, the community repos were quiet. Plenty of stars, not much that was both new and tied to a real campaign. What I did find was a line in the August Sentinel release notes that I think deserves more attention than it has had: the UEBA behaviours layer now covers Fortinet FortiGate admin activity, with more than 40 new behaviours.

It is a small entry in a long changelog, but it lands on a problem every hunter knows. Firewalls and VPN appliances sit at the edge, run the most trusted credentials in the estate, and cannot run an EDR agent. If you want to hunt them, your logs are the only sensor you get.

## Why the edge keeps coming up

Arctic Wolf reported a cluster of automated FortiGate activity from 15 January 2026. Attackers logged in through SSO against admin accounts, exported the device configuration through the GUI, created generic secondary admin accounts and enabled VPN access for them. The actions happened within seconds, which points to automation rather than a person at a keyboard. The entry point was the pair of FortiCloud SSO signature bypass flaws, CVE-2025-59718 and CVE-2025-59719, which were being exploited about three days after patches shipped.

SentinelOne's DFIR team then described early 2026 incidents where the config export was the real prize. In one, the configuration held an encrypted LDAP service account credential. The attackers decrypted it, authenticated to Active Directory and enrolled rogue workstations. In another, they added admin accounts, deployed Pulseway and MeshAgent, moved with PsExec and eventually took NTDS.dit from a domain controller. Both investigations were hampered by short log retention, which is the line I would underline for anyone reading this as a manager.

The pattern is the same each time: admin login, config export, new admin account, VPN change. None of those steps is exotic. Each is a normal thing an administrator does, which is exactly why raw log alerting on them gets noisy and gets switched off.

## Hunting with behaviours instead of raw events

This is where the behaviours layer earns its keep. Instead of writing parsing logic for FortiGate's CEF fields, you query normalised behaviour records that already carry MITRE mappings and entity roles. Microsoft says the new FortiGate behaviours cover rapid system reconfigurations, configuration backups, certificate changes and security service disruptions, mapped to techniques including T1078 (Valid Accounts), T1070 (Indicator Removal) and T1602.002 (Data from Configuration Repository: Network Device Configuration Dump).

In the Defender portal the tables are `BehaviorInfo` and `BehaviorEntities`. In a Sentinel workspace they are `SentinelBehaviorInfo` and `SentinelBehaviorEntities`. A starting hunt looks like this:

```kql
// Starting point: network device behaviours from the UEBA layer
// Behaviour titles are not documented as a fixed list, so check what your tenant produces first
BehaviorInfo
| where TimeGenerated > ago(30d)
| where ServiceSource == "Microsoft Sentinel"
| extend AF = parse_json(AdditionalFields)
| where tostring(AF.TableName) == "CommonSecurityLog"
| where AttackTechniques has_any ("T1602", "T1078", "T1070", "T1562")
| summarize Count = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by Title
| order by Count asc
```

Sorting ascending is deliberate. Rare behaviours are where a hunt starts, and the volume ones tell you what normal admin work looks like in your environment. Then join to entities to see who did it:

```kql
BehaviorInfo
| where TimeGenerated > ago(7d)
| where ServiceSource == "Microsoft Sentinel"
| where Title has "config" or Title has "administrator"
| join kind=inner BehaviorEntities on BehaviorId
| project TimeGenerated, Title, Description, EntityType, EntityRole, AccountUpn
```

The August update also adds anomaly insights to behaviour records, in the `Insights` column of `BehaviorInfo`. A `FirstSeen` insight on an admin account logging in from a new ISP, followed by a configuration backup behaviour, is close to the Arctic Wolf pattern. The `GetFirstSeenBehaviors()` function makes that filter readable, and you can correlate it with the backup behaviour by account and a short time window.

## Where this falls short

I want to be straight about the limits. Microsoft's own documentation says behaviours are neutral observations, not alerts, and that coverage is partial and growing. Missing behaviour does not mean missing activity. You also have to enable each data source for behaviours separately from the rest of UEBA, and only supported vendors in `CommonSecurityLog` produce them. A connected FortiGate that sends the wrong log types will give you nothing.

There is also a retention point. If the logs are not in the Analytics tier, behaviours are not generated. Given that both of the SentinelOne investigations were slowed by retention gaps, I would sort that out before writing a single query. The queries above are starting points and I have not tuned them against a live FortiGate feed, so expect to adjust the title filters once you see what your tenant produces.

## Closing Thoughts

The useful shift here is not the 40 behaviours, it is that edge device admin activity is now queryable without a bespoke parser per vendor. If you have FortiGates forwarding to Sentinel, enable the behaviours layer for that source this week and spend an hour looking at what a normal month of admin behaviour looks like. Then work out which of those would worry you at 3am.

If you run Palo Alto, Check Point or Zscaler instead, the same August release added anomaly rules for those too. The habit is the same: baseline first, hunt the rare second, and keep the logs long enough to matter.

## References

1. [What's new in Microsoft Sentinel - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/whats-new)
2. [Translate raw security logs to behavioral insights using UEBA behaviors - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/entity-behaviors-layer)
3. [Investigate anomalies on UEBA behaviors - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/ueba-anomalies-on-behaviors)
4. [Arctic Wolf detects surge in automated Fortinet FortiGate firewall configuration attacks - Security Affairs](https://securityaffairs.com/187194/hacking/arctic-wolf-detects-surge-in-automated-fortinet-fortigate-firewall-configuration-attacks.html)
5. [Attackers exploit FortiGate devices to access sensitive network information - Security Affairs](https://securityaffairs.com/189241/security/attackers-exploit-fortigate-devices-to-access-sensitive-network-information.html)
6. [KQL Sources: 2026 Update - kqlquery.com](https://kqlquery.com/posts/kql-sources-2026/)
