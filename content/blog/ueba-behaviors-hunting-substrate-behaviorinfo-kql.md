---
title: "Behaviours Are Not Alerts: Hunting the UEBA Behaviors Layer with KQL"
date: 2026-09-29
author: Chris Scott
summary: Sentinel's UEBA behaviors layer gained Fortinet, Check Point, Zscaler and GuardDuty coverage this summer. Behaviours are neutral, ATT&CK-tagged summaries rather than detections, which makes BehaviorInfo one of the better hunting surfaces you are probably not using.
tags:
  - kql
  - sentinel
  - ueba
  - threat-hunting
  - advanced-hunting
  - detection-engineering
published: true
---

I keep meeting teams who have switched UEBA on, looked at the anomalies page, shrugged, and never gone back. That is a shame, because the interesting part of the last few months of Sentinel updates isn't the anomalies at all. It is the behaviors layer sitting quietly next to them.

The reason it gets missed is the name. Behaviours sound like alerts, so people look for the incident queue and find nothing there. But Microsoft is explicit that they are not alerts or anomalies. A behaviour is a neutral summary of "who did what to whom", tagged with MITRE ATT&CK and entity roles, whether the activity was risky or perfectly boring. For a hunter, neutral is exactly what you want. Detections tell you what someone else already decided was bad. Behaviours let you decide.

## What changed

The Sentinel what's new page shows a steady run of additions. The behaviors layer went generally available in February 2026. In June, behaviour results from the `BehaviorInfo` table could be linked straight to incidents from advanced hunting. In August, Fortinet FortiGate behaviours arrived (more than 40 of them, covering things like rapid system reconfiguration, configuration backups, certificate changes and security services being disrupted), alongside ten new anomaly rules for Check Point, FortiGate and Zscaler in `CommonSecurityLog`, and identity-linked AWS GuardDuty findings. Anomalies can now also be attached directly to behaviour records, so you get first-seen activity and unusually high volumes without writing the baseline yourself.

There is also a July change worth a mention for the engineers: custom detection rules can now be managed as code through Sentinel Repositories, which matters once a hunt graduates into a rule.

## Hunting the layer

Behaviours come in two flavours. Aggregated behaviours collect volume over a time window, such as a user touching 50 resources in an hour. Sequenced behaviours capture multi-step patterns, such as an access key created, used from a new IP, then followed by privileged API calls. Both land in `BehaviorInfo`, with the people, hosts and IPs involved in `BehaviorEntities`, joined on `BehaviorId`.

In the Defender portal you use those two tables. In a Sentinel workspace they are `SentinelBehaviorInfo` and `SentinelBehaviorEntities`. The Defender versions also contain behaviours from Defender for Cloud Apps, so filter on `ServiceSource` if you only want UEBA.

The simplest hunt is rarity. Behaviours you have seen a handful of times in a month are a far smaller pile than raw logs.

```kql
BehaviorInfo
| where Timestamp > ago(30d)
| where ServiceSource == "Microsoft Sentinel"
| summarize Occurrences = count(), Accounts = dcount(AccountUpn), LastSeen = max(Timestamp)
    by Title, Categories, AttackTechniques
| where Occurrences < 5
| order by LastSeen desc
```

Next, chain them. Microsoft's own example is a key-creation behaviour followed by privilege elevation within an hour. That is Valid Accounts (T1078) territory, and it is the sort of thing that takes three raw tables and a lot of patience without the layer. The Title strings below are my own matching guesses, so check them against what your tenant actually produces before trusting the output.

```kql
let window = 1h;
let entities = BehaviorEntities
    | where EntityType == "User"
    | project BehaviorId, EntityUpn = AccountUpn;
let tagged = BehaviorInfo
    | where Timestamp > ago(7d)
    | where ServiceSource == "Microsoft Sentinel"
    | join kind=inner entities on BehaviorId
    | project EntityUpn, BehaviorTime = Timestamp, Title;
tagged
| where Title has "access key" and Title has "creat"
| project EntityUpn, KeyTime = BehaviorTime, KeyTitle = Title
| join kind=inner (
    tagged
    | where Title has_any ("elevat", "privilege")
    | project EntityUpn, ElevationTime = BehaviorTime, ElevationTitle = Title
  ) on EntityUpn
| where ElevationTime between (KeyTime .. (KeyTime + window))
| project EntityUpn, KeyTime, KeyTitle, ElevationTime, ElevationTitle
```

When something looks odd, drop to the raw evidence. The `AdditionalFields` column holds references to the underlying events in a `SupportingEvidence` field, so the behaviour becomes the index into the logs rather than a replacement for them.

If you prefer a more classic approach for the raw tables, the window-function write-ups from Blu Raven Academy are a good companion. Their `sliding_window_counts` example for password spray avoids the blind spots that fixed bins leave at the boundaries, and the same idea applies to counting behaviours per account.

## Caveats

This is preview-flavoured territory, and the limits matter. Coverage is partial and growing, and it only generates behaviours for supported vendors and log types. Microsoft says plainly not to treat the absence of a behaviour as the absence of activity. Behaviours can only be enabled on one workspace per tenant, each source has to be switched on separately for behaviours even if it is already enabled for anomalies, and the behaviour records are billed as ingestion into `SentinelBehaviorInfo` and `SentinelBehaviorEntities`. They also need the Analytics tier, which sits awkwardly with anyone pushing noisy firewall logs to the data lake to save money.

Behaviours are also generated with the help of generative AI, so titles and descriptions are worth reading rather than blindly string matching. My matching on `Title` above is fragile for that reason. Once a hunt proves itself, anchor the rule on `AttackTechniques` and the entity fields, and promote it using the usual custom detection guidance: return the required columns, keep the `ago()` filter out of the rule and let the schedule set the lookback.

## Closing thoughts

Most of us spend our time building detections and very little time building the surface we hunt on. The behaviors layer is Microsoft doing some of that second job for you, particularly for firewall and cloud audit data that has never had much context.

If you have UEBA enabled, run the rarity query this week and see what falls out. If you don't, at least check whether your `CommonSecurityLog` vendor is on the supported list. I would be interested to hear which behaviour titles turn out to be worth turning into rules.

## References

1. [What's new in Microsoft Sentinel - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/whats-new)
2. [Translate raw security logs to behavioral insights using UEBA behaviors - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/entity-behaviors-layer)
3. [BehaviorInfo table (Preview) - Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorinfo-table)
4. [BehaviorEntities table (Preview) - Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorentities-table)
5. [KQL Threat Hunting in Microsoft Defender: Full Guide - Security Scriptographer](https://www.securityscriptographer.com/2026/07/kql-threat-hunting-in-microsoft.html)
6. [Advanced KQL for Threat Hunting: Window Functions Part 2 - Blu Raven Academy](https://academy.bluraven.io/blog/advanced-kql-for-threat-hunting-window-functions-part-2)
7. [Microsoft Sentinel September 2026 Update - Infernux](https://infernux.no/blog/microsoft-sentinel-september-2026/)
