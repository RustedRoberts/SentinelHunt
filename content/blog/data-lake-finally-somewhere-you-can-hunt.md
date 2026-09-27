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

A new threat intel report lands and there's a juicy list of IPs and domains in it, and someone asks "have we seen any of this in the last year?" The honest answer has usually been "we've seen the last 90 days, but we don't have access to data past this point". That's the problem Microsoft has been chipping away at with the Sentinel data lake, and a September 2026 update solves this issue; hopefully once and for all.

Interactive KQL against the data lake is now available directly in Advanced Hunting in the Defender portal, sitting alongside your Analytics tier and Defender XDR data. For new customers, lake onboarding is also folded into standard Sentinel onboarding, so you set retention per table in Table management rather than running a separate onboarding and billing setup.

For me, this is the most interesting change to KQL hunting in a while. Not because it's flashy, but because it changes which data you can realistically ask questions of. That said, I went through the docs properly, and there's a caveat in the known issues that I think a lot of people will trip over.

## Why this matters now

Cost has been driving Sentinel architecture for years, and high-volume sources like firewalls, proxies, and DNS logs, are exactly the data you want when hunting, and correspondingly the data that gets pushed to cheaper tiers - or dropped altogether - because Analytics ingestion costs add up fast.

What I've seen in a lot of estates is a split: A short hot window for detection, and a long cold tail that technically exists but rarely gets touched. Hunting has mostly lived in the hot window, which is a problem when dwell times and retrospective TI hunts regularly reach back further than 90 days.

Lake queries are billed on the data you scan rather than what you ingest into Analytics. The cold data then becomes something you pay to query when you need it, and not something you pay to keep hot just in case. The potential issue is queries that are far too broad, but the topics of effectively scoped queries and threat hunts are 2 distinct discussions for another post.

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

`externaldata()` isn't supported against the lake and you need to add in the IoCs as a variable, so the method of pulling a CSV feed from GitHub mid-query won't work here. Neither will `adx()`, `arg()`, `ingestion_time()` or `estimate_data_size()`.

The more interesting feature, and where hunting starts feeding detection engineering, is KQL jobs. A job runs KQL against lake data and promotes the results into the Analytics tier, either once or on a schedule. So you can build a long-horizon baseline cheaply in the lake, then detect against the small, summarised output in Analytics. A daily job summarising successful sign-ins might look like this:

```kql
SigninLogs
| where ResultType == "0"
| summarize SignIns = count(), FirstSeen = min(TimeGenerated)
    by UserPrincipalName, Country = tostring(LocationDetails.countryOrRegion),
       AppDisplayName, Day = bin(TimeGenerated, 1d)
```

Your analytics rule then compares today's activity against months of baseline, rather than the 14 days a scheduled rule can usually afford to look back over. If you think in terms of rule maturity, this is the jump from an atomic rule ("sign-in from a new country") to a contextual one ("sign-in from a country this user hasn't touched in six months"), or an anomaly-based one ("sign-ins failing 1-2 times a week for 6 months from distributed IPs using the same ASN" ). The datalake now makes the six months accessible to the analytics query.

## The small print

Here's something that caught my eye too. If a table has both an Analytics retention period and a longer total retention in the lake, Advanced Hunting only searches the Analytics part. Microsoft's own example is SigninLogs with 90 days in Analytics and two years in total. Ask Advanced Hunting for a year of sign-ins and you'll get 90 days back. Say a TI report tells you an IP was spraying your tenant in March. You search from Advanced Hunting, get nothing, and conclude you were never hit, when the March sign-ins are sitting in the lake the whole time and your queries didn't touch it.

### An example to illustrate this better

Your SigninLogs table is configured with:

- Analytics retention: 90 days. This is the fast tier that detections and Advanced Hunting normally use.
- Total retention: 2 years. Anything older than 90 days now lives only in the lake tier.

Today is 27 September 2026, so the Analytics tier holds roughly 29 June to today. Everything from October 2024 to 28 June 2026 is only in the lake.

### Hitting the issue

A TI report lands saying 203.0.113.10 was used for password spraying in March 2026. You open Advanced Hunting and run:

```kql
SigninLogs
| where TimeGenerated > ago(365d)
| where IPAddress == "203.0.113.10"
```

You asked for a year, but Advanced Hunting only reaches back to the Analytics window, so it searches from 29 June onwards. The March sign-ins are sitting in the lake, but this query never touches them. You get zero results and report "not seen in the last year" which is a false negative. You do not get informed that the query didn't honour the 365 day lookback either, so it quietly fails.

For anything older than the Analytics window, you need the Data lake exploration KQL page or a search job. Tables stored only in the lake don't have this problem, because Advanced Hunting queries them directly.

### Getting the right answer

Run the same query from `Data lake exploration` **>>** `KQL queries` in the Defender portal, which queries the lake tier directly, or run it as a search job. Either one returns the March hits.

### The contrast

If `CommonSecurityLog` is set to lake-only (no Analytics tier at all) with a year of retention, the same 365-day query in Advanced Hunting works fine. The issue only arises for those tables that have *both* an Analytics window *and* a longer lake tail.

So before anyone tells leadership "we can hunt two years back now", check how each table is actually configured. The answer is different per table. The datalake gives you the **capacity**, but it's on your team to create the **capability** when you start to pump data into the datalake.

A few other limits are worth knowing before you build a hunting programme on this:

- Lake queries are capped at 500,000 rows or 64 MB of results and time out after a few minutes (the docs quote four minutes in one place and eight in another).
- Async queries run for up to an hour, with results cached for 24 hours.
- Rate limits are per tenant, not per user: 30 queries a minute and 10 concurrent, and anything over that is rejected rather than queued (get a few hunters working a live incident at once and that ceiling is a limitation worth being aware of).

There's also around 15 minutes of latency before new data is queryable, so this is for looking back, not for triaging what's happening right now. Microsoft says as much: *lake queries are less performant than Analytics and are meant for historical exploration or lake-only tables.*

The one I'd want all detection engineers reading this to know about is that out-of-the-box and custom functions aren't supported in lake KQL queries. If I'm reading that correctly, anything built on saved functions, **ASIM parsers included**, won't run as-is against the lake. If your hunting library leans on parsers, you'll need to query the underlying tables directly. Legacy tables like `AzureDiagnostics` aren't supported either, so you really need to get hands-on here and figure out what changes need to be made with your process and automation before diving in and using it during live incidents.

Then there's cost. Paying per GB scanned is great until someone runs `union *` across twelve months or malforms a regex that still executes a much, much broader search than intended. Microsoft has added hard cost limits for lake queries, jobs and notebooks, so set them before you hand this off to other teams to use in anger.

## Closing Thoughts

I think this is a real shift in how hunting can work in Sentinel, but it rewards teams that get the architecture right early and eliminates potential problems later down the line.

- Map out which tables are lake-only, which are mirrored, and what the Analytics retention window is on each, because that decides what Advanced Hunting can see.
- Rewrite the handful of hunts you run most often for the lake: no functions, no `externaldata()`, or tight time filters - then pick one detection that suffers from a short lookback and try the jobs pattern on it.

The hot/cold split was always a cost compromise that hunters quietly were limited under. It's nice to see it start to go away, even if it comes with a few footnotes.

## References

1. [What's new in Microsoft Sentinel (September 2026) - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/whats-new)
2. [Advanced hunting with Microsoft Sentinel data in Microsoft Defender (Known issues) - Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-microsoft-defender)
3. [Run KQL queries against the Microsoft Sentinel data lake - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/datalake/kql-queries)
4. [Microsoft Sentinel September 2026 Update - infernux.no](https://infernux.no/blog/microsoft-sentinel-september-2026/)
5. [You're Overpaying for Hunting Data - Adversary Lab (Charles Garrett)](https://adversarylab.substack.com/p/youre-overpaying-for-hunting-data)
6. [Plan costs and understand Microsoft Sentinel pricing and billing - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/billing)
7. [Enforce Cost Limits on KQL Queries and Notebooks in the Microsoft Sentinel Data Lake - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/enforce-cost-limits-on-kql-queries-and-notebooks-in-the-microsoft-sentinel-data-/4511329)
