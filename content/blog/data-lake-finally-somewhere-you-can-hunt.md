---
title: "The Data Lake Is Finally Somewhere You Can Hunt (Mostly)"
date: 2026-09-27
author: Chris Scott
summary: Sentinel now lets you run KQL against lake-tier data straight from Advanced Hunting, and the small print matters just as much as the headline.
tags:
  - kql
  - sentinel
  - advanced-hunting
  - data-lake
  - threat-hunting
  - detection-engineering
published: true
---

I've lost count of the number of times I've had some version of this conversation. A new threat intel report lands, there's a juicy list of IPs and domains in it, and someone asks "have we seen any of this in the last year?" The honest answer has usually been "we've seen the last 90 days, the rest is in archive, give me a while". Restore jobs, search jobs, waiting around. By the time the data comes back, the question has usually moved on.

That's the problem Microsoft has been chipping away at with the Sentinel data lake, and the September 2026 update is the most meaningful step so far for anyone who hunts for a living. Interactive KQL against the data lake is now available directly in Advanced Hunting in the Defender portal, sitting alongside your Analytics tier and Defender XDR data. For new customers, lake onboarding is also folded into standard Sentinel onboarding, so you set retention per table in Table management rather than running a separate onboarding and billing setup. Truls over at infernux described it as a sneaky drop buried inside another announcement, which feels about right.

For me, this is the most interesting change to KQL hunting in a while. Not because it's flashy, but because it changes which data you can realistically ask questions of. That said, I went through the docs properly, and there's a caveat in the known issues that I think a lot of people will trip over.

## Why this matters now

Cost has been driving Sentinel architecture for years. High-volume sources like firewall, proxy and DNS logs are exactly the data you want when hunting, and exactly the data that gets pushed to cheaper tiers or dropped altogether because Analytics ingestion adds up fast. Charles Garrett made this point well earlier in the year: the lake tier is a fraction of Analytics pricing but doesn't give you real-time detection, so the architecture needs planning rather than just flipping on.

What I've seen in a lot of estates is a split. A short hot window for detection, and a long cold tail that technically exists but rarely gets touched. Hunting has mostly lived in the hot window, which is a problem when dwell times and retrospective TI hunts regularly reach back further than 90 days.

Lake queries are billed on the data you scan rather than what you ingest into Analytics. That flips the economics. The cold tail becomes something you pay to query when you need it, not something you pay to keep hot just in case.

## Hunting in the lake, and turning it into detections

The obvious first use case is the retrospective IOC hunt. Something like this against a lake-only firewall table:

```kql
let iocs = dynamic(["203.0.113.10", "198.51.100.23"]);
CommonSecurityLog
| where TimeGenerated > ago(365d)
| where DestinationIP in (iocs) or SourceIP in (iocs)
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Events = count()
    by SourceIP, DestinationIP, DeviceVendor, DeviceAction
| order by FirstSeen asc
```

The IOCs are inline on purpose. `externaldata()` isn't supported against the lake, so the habit of pulling a CSV feed from GitHub mid-query won't work here. Neither will `adx()`, `arg()`, `ingestion_time()` or `estimate_data_size()`.

The more interesting pattern, and where hunting starts feeding detection engineering, is KQL jobs. A job runs KQL against lake data and promotes the results into the Analytics tier, either once or on a schedule. So you can build a long-horizon baseline cheaply in the lake, then detect against the small, summarised output in Analytics. A daily job summarising successful sign-ins might look like this:

```kql
SigninLogs
| where ResultType == "0"
| summarize SignIns = count(), FirstSeen = min(TimeGenerated)
    by UserPrincipalName, Country = tostring(LocationDetails.countryOrRegion),
       AppDisplayName, Day = bin(TimeGenerated, 1d)
```

Your analytics rule then compares today's activity against months of baseline, rather than the 14 days a scheduled rule can usually afford to look back over. If you think in terms of rule maturity, this is the jump from an atomic rule ("sign-in from a new country") to a contextual one ("sign-in from a country this user hasn't touched in six months"). The lake is what makes the six months affordable.

## The small print

Here's the one that caught my eye. In the Advanced Hunting known issues, Microsoft states that when an Analytics table has extended retention in the lake tier, Advanced Hunting interactive queries can only reach data within the Analytics retention period. Their own example is `SigninLogs` with 90 days in Analytics and two years total: Advanced Hunting sees 90 days. Anything older needs a search job, or the separate Data lake exploration KQL page. Lake-only tables are queryable from Advanced Hunting. Mirrored tables with a longer lake tail aren't, at least not fully.

So before anyone tells leadership "we can hunt two years back now", check how each table is actually configured. The answer is different per table.

A few other limits are worth knowing before you build a hunting programme on this. Lake queries are capped at 500,000 rows or 64 MB of results and time out after a few minutes (the docs quote four minutes in one place and eight in another). Async queries run for up to an hour, with results cached for 24 hours. Rate limits are per tenant, not per user: 30 queries a minute and 10 concurrent, and anything over that is rejected rather than queued. Get a few hunters working a live incident at once and that ceiling is closer than it sounds. There's also around 15 minutes of latency before new data is queryable, so this is for looking back, not for triaging what's happening right now. Microsoft says as much: lake queries are less performant than Analytics and are meant for historical exploration or lake-only tables.

The one I'd flag loudest for detection engineers is that out-of-the-box and custom functions aren't supported in lake KQL queries. If I'm reading that correctly, anything built on saved functions, ASIM parsers included, won't run as-is against the lake. If your hunting library leans on parsers, you'll need to query the underlying tables directly. Legacy tables like `AzureDiagnostics` aren't supported either.

Then there's cost. Paying per GB scanned is great until someone runs `union *` across twelve months. Microsoft has added hard cost limits for lake queries, jobs and notebooks. Set them before you hand this to a team, not after the first invoice.

## Closing Thoughts

I think this is a real shift in how hunting can work in Sentinel, but it rewards teams that are deliberate about it. Map out which tables are lake-only, which are mirrored, and what the Analytics retention window is on each, because that decides what Advanced Hunting can see. Rewrite the handful of hunts you run most often for the lake: no functions, no `externaldata()`, tight time filters. Then pick one detection that suffers from a short lookback and try the jobs pattern on it.

The hot/cold split was always a cost compromise that hunters quietly paid for. It's nice to see it start to go away, even if it comes with a few footnotes.

## References

1. [What's new in Microsoft Sentinel (September 2026) - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/whats-new)
2. [Advanced hunting with Microsoft Sentinel data in Microsoft Defender (Known issues) - Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-microsoft-defender)
3. [Run KQL queries against the Microsoft Sentinel data lake - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/datalake/kql-queries)
4. [Microsoft Sentinel September 2026 Update - infernux.no](https://infernux.no/blog/microsoft-sentinel-september-2026/)
5. [You're Overpaying for Hunting Data - Adversary Lab (Charles Garrett)](https://adversarylab.substack.com/p/youre-overpaying-for-hunting-data)
6. [Plan costs and understand Microsoft Sentinel pricing and billing - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/billing)
7. [Enforce Cost Limits on KQL Queries and Notebooks in the Microsoft Sentinel Data Lake - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/enforce-cost-limits-on-kql-queries-and-notebooks-in-the-microsoft-sentinel-data-/4511329)
