---
title: "Custom Detection Rules as Code: The Bit of Sentinel Repositories I Was Waiting For"
date: 2026-10-07
author: Chris Scott
summary: Custom detection rules can now live in Git and deploy through Sentinel Repositories using Bicep. Here is what that changes for threat detection and hunting, and what your pipeline now owns.
tags:
  - kql
  - sentinel
  - detection-engineering
  - advanced-hunting
  - ci-cd
published: true
---

For the last couple of years I have had an awkward split in how I manage detection content. Analytics rules went into Git and flowed out through Sentinel Repositories. Anything that needed to run in Defender XDR as a custom detection got built by hand in the portal, usually after a hunt had proved itself, and usually with nobody reviewing the final version. Two places, two sets of habits, and the portal one always drifted.

In July that split got a lot smaller. Custom detection rules are now supported in Sentinel Repositories as a preview, managed with the Microsoft Security Bicep extension. I have been through the documentation and the community write-ups since, and I think it is the most useful change to detection content this year, mostly because it is not flashy. It just removes an excuse.

So this post covers what actually shipped, how a hunting query becomes a rule in this model, and the things your pipeline now owns that the portal used to quietly handle for you.

## What changed and why it matters

Sentinel Repositories already deployed analytics rules, automation rules, hunting queries, parsers, playbooks and workbooks from a connected GitHub or Azure DevOps repo. Custom detection rules are the new content type, and they behave differently to the rest. They use their own Bicep extension and resource provider, declared in a `bicepconfig.json` at the repo root, and each rule is a `Microsoft.Security/detectionRules` resource [1][2][8].

The reason I care is where custom detections sit. They run against advanced hunting tables, so they can use Defender XDR data and Sentinel data in the same query, and since January they support near real-time configuration on Sentinel data [3]. That makes them the natural home for the detections that stitch endpoint, identity and SIEM telemetry together. Until now, those were exactly the rules most likely to be hand-built and never peer reviewed.

There is a cost to entry. You need a Microsoft 365 E5 licence or equivalent that includes Defender XDR, and your Sentinel workspaces must be onboarded to the Defender portal [2]. If you are still in the Azure portal experience, note that Microsoft has announced its retirement for March 2027, so that conversation is coming anyway [4].

## From hunt to rule

The workflow I like is the boring one. You hunt, you find something worth keeping, and you promote the query into a Bicep file rather than into a portal form. The documented required pieces are an `id`, a `displayName`, a `status`, the `queryCondition` with your `queryText`, a `schedule`, and a `detectionAction` holding the alert template: title, description, severity, tactics, techniques and entity mappings [2].

Take Kerberoasting (T1558.003) as the sort of hunt that earns a rule. Recent practitioner writing makes the point that bulk ticket request counting is no longer enough, because careful actors request a handful of tickets and blend in, so the encryption type on Event ID 4769 matters [5]. A starting hypothesis, not a tuned rule, looks like this:

```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17" // RC4
| where ServiceName !endswith "$" and ServiceName != "krbtgt"
| summarize Tickets = count(), Services = dcount(ServiceName)
    by Account, IpAddress, bin(TimeGenerated, 1h)
| where Services >= 2
```

Wrapped in Bicep, that query sits inside `queryText`, with `T1558` mapped under the Credential Access tactic and the account and IP columns mapped as entities. The pull request that adds it is where someone asks the useful questions. Which service accounts legitimately still use RC4? What happens when the estate moves to AES? Who owns the exclusions? Those questions used to get asked in a Teams chat after the alert fired.

If you want a second source of ideas, Microsoft's August UEBA update added more than 40 behaviours for Fortinet FortiGate administrative activity, plus ten new anomaly rules covering Check Point, FortiGate and Zscaler [4]. Those are Microsoft-built detections, but they make a good hunting baseline to compare your own rules against.

## What your pipeline now owns

This is the part I would not skip. A rule managed in the portal gets quiet help from Microsoft. When the advanced hunting schema changes, portal-managed rules receive automatic table and column migrations. Rules in your repo do not. Your repository becomes the source of truth, and that includes stale queries after a schema change [6].

A few other sharp edges from the documentation and community discussion. Rules are identified by their `id`, so changing it creates a new rule instead of updating the old one, which means duplicates if you are careless. Filtering on `Timestamp` or `TimeGenerated` inside the query is discouraged, because the service pre-filters on lookback. And during the preview, custom frequency for Sentinel-only data and custom details are not supported [2][6]. Repository sync also overwrites portal changes, so anyone tweaking a rule live will lose their work on the next commit.

None of that is a reason to wait. It is a reason to add a schema-check step to your pipeline, run your queries against a test tenant before merge, and make it clear to the team that the portal is now read-only for these rules.

## Closing Thoughts

The community has been shipping detections as code for years, and the KQL commons keeps growing, with new repositories such as KQLAdvancedHunting and Azure-SecOps joining the established lists [7]. What was missing was a supported path for the Defender-side rules to join them. Now there is one, in preview, with caveats you can plan around.

If you run detection content for more than one environment, my suggestion is to move a single custom detection through the pipeline this month. Pick one you already trust. You will learn more about your own review and schema-drift habits from that one rule than from any amount of reading.

## References

1. [Custom detection rules support in Microsoft Sentinel Repositories (Preview) - What's new in Microsoft Sentinel, Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/whats-new)
2. [Manage custom content with repository connections - Microsoft Learn](https://learn.microsoft.com/azure/sentinel/ci-cd-custom-content)
3. [What's new in Microsoft Defender XDR - Microsoft Learn](https://learn.microsoft.com/defender-xdr/whats-new)
4. [What's new in Microsoft Sentinel (UEBA, August 2026 and Azure portal retirement) - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/whats-new)
5. [Stop Kerberoasting: Our Advanced Threat-Hunting Blueprint - 7A Security](https://7asecurity.com/blog/tag/event-id-4769/)
6. [Custom detection rules as code in Sentinel Repositories: what your pipeline owns - Microsoft Tech Community](https://techcommunity.microsoft.com/discussions/microsoft-security/custom-detection-rules-as-code-in-sentinel-repositories-what-your-pipeline-owns-/4536196)
7. [KQL Sources: 2026 Update - kqlquery.com](https://kqlquery.com/posts/kql-sources-2026/)
8. [Microsoft Sentinel Adds Detections-As-Code, Table Insights, and New Data Connectors - Petri](https://petri.com/microsoft-sentinel-detections-as-code-table-insights/)
