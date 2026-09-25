---
title: The 30-Day Wall Just Came Down for Sentinel Hunters
date: 2026-09-25
author: Chris Scott
summary: Advanced Hunting can now run KQL straight against Data Lake tier data, with Sentinel and Defender XDR in one query surface. Here's what that actually changes for long-lookback threat hunting - and the KQL habits worth tightening up before you lean on it.
tags:
  - sentinel
  - kql
  - threat-hunting
  - data-lake
  - advanced-hunting
  - detection-engineering
published: false
---

## Introduction

I've lost count of the number of times a hunt idea has died at the same sentence: "that data's already rolled off the hot tier." Someone spots a pattern worth chasing - a service account authenticating from a new device every few weeks, a beacon that only calls out once every three days - and the conversation stops dead because getting at ninety days of history meant restoring it first, waiting, then hoping the restore actually covered the window you needed. Most teams, understandably, didn't bother. They investigated the alerts they had rather than hunted for the ones they didn't.

That excuse got a lot weaker this month. Microsoft's September 2026 Sentinel update lets Advanced Hunting run interactive KQL directly against Data Lake tier data, with Sentinel and Microsoft Defender XDR data sitting in the same query surface. No restore step, no waiting for a rehydration job to finish before you can even see if your hypothesis holds up. It's a small-sounding change in a release note, but it changes what "we don't have the data for that" actually means for a hunting programme.

## Why this matters now

The attacks that make long retention worth having aren't the noisy ones. Ransomware crews and commodity malware tend to move fast and get caught by things that already fire on day one. It's the patient stuff that benefits from a short memory: lateral movement that trickles across a handful of devices over six weeks rather than six hours, command-and-control beacons deliberately throttled to once every few days specifically so they sit under the noise floor of a 30-day retention window, reconnaissance that looks like normal admin activity until you line up enough of it side by side.

Data Lake tier ingestion for Defender Advanced Hunting tables reached general availability not long before this update, so the pieces were already falling into place - cheap, long-retention storage for the raw data, and now a query layer that can actually reach it without a manual restore. Add Fabric integration for notebooks and scheduled jobs on top, and the direction of travel is clear: Microsoft wants long-lookback hunting to be a KQL query away, not a ticket to the platform team.

## The practical hunting angle

What does this actually change about how you write a hunt? Mostly, it means the hypotheses you were previously talking yourself out of become worth writing down. A lateral movement hunt is a good example - something like a user authenticating successfully to an unusual number of distinct devices within a short window, but measured over a much longer lookback than your hot tier would normally give you:

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0
| summarize DeviceCount = dcount(DeviceDetail.deviceId), Devices = make_set(DeviceDetail.deviceId) by UserPrincipalName, bin(TimeGenerated, 2d)
| where DeviceCount >= 5
| order by DeviceCount desc
```

That's a deliberately simple starting point, not a finished detection - the point is that running it against a full month or more of lake data, rather than whatever survived in the hot tier, is what makes the pattern visible in the first place. The same logic applies to slow beaconing (aggregate outbound connection intervals per host over weeks, not days) and to reconnaissance (look for accounts touching an unusually broad set of resources over a long window rather than a short burst).

The other half of this is discipline about what happens after a hunt finds something. A hunt that never gets promoted to a scheduled rule was, in a real sense, wasted effort - you found the pattern once and now you're relying on someone remembering to look again. The useful pipeline is: document what you found, parameterise the thresholds, promote the logic into a scheduled analytics rule, and make sure the incident and automation logic downstream actually understands what that new rule is telling it. It's not glamorous work, but it's the difference between a one-off insight and a durable improvement to your detection coverage.

## Considerations and caveats

None of this is free, and none of it is a substitute for careful KQL. Long retention at the Data Lake tier is cheaper than keeping everything hot, but summary rules - still in preview - exist precisely because querying huge, high-volume tables raw is expensive; pre-aggregating hourly instead of scanning everything every five minutes is reportedly cutting compute by around 90% for teams using it. If you're about to lean harder on long-lookback queries, it's worth understanding summary rules before your Log Analytics bill notices.

There's also a subtler trap that has nothing to do with data tiers and everything to do with how KQL joins behave. By default, KQL's `join` operator runs as `innerunique`, which quietly keeps only one match per key on the left-hand side rather than every match. For a correlation-heavy hunting query - joining sign-in events to device inventory, or process events to network connections - that default can silently drop the exact multi-match cases you were hunting for, and you'll never see an error telling you so. Specifying `join kind=inner` explicitly, and understanding why the default exists, is one of those unglamorous habits that separates a hunt that actually works from one that quietly lies to you. The same goes for case sensitivity - using `=~` and `in~` rather than assuming your log source normalises case for you - and for checking both `FileName` and `OriginalFileName` when you're hunting for renamed binaries.

None of this works without the basics in place either: sensible ingestion delay expectations (know your 90th percentile arrival time, not just your average), entity mapping that's actually correct so a promoted rule can drive automated response, and a team that has the bandwidth to run hunts on a cadence rather than as a one-off exercise when someone's curious.

## Closing Thoughts

The interesting thing about this update isn't the feature itself - it's that it removes a genuinely reasonable objection teams have had for years. "We'd hunt for that, but we don't have the retention" was, for a lot of organisations, simply true. That's less true now. What's left is the harder, more human problem: whether a team builds hunting into its actual workload, whether hunts get written down and promoted rather than run once and forgotten, and whether the KQL behind them is solid enough to trust. The data being reachable was never really the hard part. It just used to be a convenient place to stop.

## References

1. [Microsoft Sentinel September 2026 Update - infernux.no](https://infernux.no/blog/microsoft-sentinel-september-2026/)
2. [Advanced hunting with Microsoft Sentinel data in Microsoft Defender - Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-microsoft-defender)
3. [Hunting at Machine Speed - KQL on the Sentinel Data Lake - socautomators.substack.com](https://socautomators.substack.com/p/hunting-at-machine-speed-kql-on-the)
4. [KQL Jobs, Summary Rules, and Search Jobs - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/datalake/kql-jobs-summary-rules-search-jobs)
5. [[DxBP] Part 1 - Technical Detection Engineering Best Practices - kqlquery.com](https://kqlquery.com/posts/dxbp-part1/)
6. [Data lake tier Ingestion for Microsoft Defender Advanced Hunting Tables is Now Generally Available - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/data-lake-tier-ingestion-for-microsoft-defender-advanced-hunting-tables-is-now-g/4494206)
