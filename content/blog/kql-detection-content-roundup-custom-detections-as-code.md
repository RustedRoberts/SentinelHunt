---
title: "New KQL Detection Content: Custom Detections as Code, and a Flood of Query Libraries"
date: 2026-10-06
author: Chris Scott
summary: Custom detection rules can now be managed as code through Sentinel Repositories, UEBA behaviours are feeding hunts, and community query libraries keep multiplying. Here is what is new, and how to decide what deserves a place in your estate.
tags:
  - kql
  - sentinel
  - detection-engineering
  - threat-hunting
  - advanced-hunting
  - ci-cd
published: true
---

Every few weeks I do a sweep for new KQL detection content, and every few weeks the pile gets bigger. This time the interesting part wasn't a single clever query. It was that the way we ship detections is changing, while the number of places you can copy a query from keeps going up.

So this is a short roundup of what I found in the last couple of months, with a focus on threat detection and hunting rather than platform plumbing, and a view on how to filter it.

## What is actually new

The headline for detection engineers is from July. Microsoft added support for custom detection rules in Sentinel Repositories (preview). You can manage Defender XDR custom detections as code in a GitHub or Azure DevOps repository using the Microsoft Security BICEP extension, then sync them through the Repositories feature or deploy them directly with the BICEP CLI. Until now, most teams I speak to had CI/CD for Sentinel analytics rules and a pile of hand-edited custom detections living in the Defender portal. That gap is closing.

On the behaviour side, UEBA keeps expanding. The behaviours layer went generally available in February, and by August the anomaly detection coverage had grown to include Check Point, Fortinet FortiGate and Zscaler events from `CommonSecurityLog`, with ten new anomaly rules comparing each user and device against its own history and the wider organisation. AWS GuardDuty findings tied to identities are also covered, mapped to techniques such as Valid Accounts (T1078) and Brute Force (T1110). In June, behaviour results from the `BehaviorInfo` table became linkable to incidents straight from advanced hunting.

And in September, interactive KQL against the Sentinel data lake arrived in Advanced Hunting, so you can hunt the lake alongside Analytics tier and Defender XDR data without switching context. I covered the caveats of that in an earlier post, so I won't repeat them here.

## The community side: volume is not quality

The community has been busy too. Benjamin Zulliger's KQLAdvancedHunting repository has passed 490 commits and is organised by both data domain and ATT&CK tactic. GoXDR, shared in July, offers 117 queries covering BEC and AiTM, NTLM and LDAP hunting, OAuth governance and Copilot security, each tagged with severity and platform. A July write-up promises 50 rules mapped to ATT&CK, with false positive notes for each. The kqlquery.com sources list is a good map of where the rest of the commons lives.

All of that is genuinely useful. But look at one of the published examples, a password spray detection (Brute Force: Password Spraying, T1110.003) that looks for one IP failing against more than 20 distinct accounts in an hour with few failures per account. As a teaching example it's fine. As a production rule it will fire on every NAT gateway and every shared egress point in your estate, and it ignores the `ResultType` values that tell you a password was right but conditional access said no. That second point is where the real signal is.

A version I would be happier to deploy looks more like this:

```kql
let lookback = 1h;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType in ("50126", "50053", "50057")
| summarize FailedAccounts = dcount(UserPrincipalName),
            Failures = count(),
            Apps = make_set(AppDisplayName, 5)
    by IPAddress, bin(TimeGenerated, lookback)
| where FailedAccounts > 20 and Failures < FailedAccounts * 3
| join kind=leftanti (
    _GetWatchlist('KnownEgressIPs') | project IPAddress = tostring(SearchKey)
  ) on IPAddress
```

The watchlist is the point. It is not clever KQL, it is context, and no public library can ship it for you because it is specific to your estate.

## From hunt to detection, via a baseline

My favourite recent piece of content is less about threats and more about method. The "new actions" solution on kqlquery.com uses a summary rule to compare actions seen this week against a 180 day history, and reports anything never seen before. The core logic is only a few lines:

```kql
let TimeFrame = 180d;
let Schedule = 7d;
let KnownActions = materialize (Actions_CL
| where TimeGenerated between (startofday(ago(TimeFrame)) .. endofday(ago(Schedule)))
| distinct Action);
Actions_CL
| where TimeGenerated > endofday(ago(Schedule))
| where isnotempty(Action) and Action !in (KnownActions)
| summarize TotalEntries = sum(TotalEvents) by Action, TableName
```

That is a hunt that has been turned into a repeatable detection. It tells you about new logging coverage and new attacker behaviour in the same breath, and it scales because the heavy baseline work happens once.

## Considerations before you adopt any of it

A few cautions. Preview features are preview features, and detections as code is only valuable if your team already has a review and testing habit. Putting a bad query into Git just gets it to production faster. Second, treat every community query as a draft. Read the tables it uses, check that you ingest them, and test it against your own data before it can raise an incident. Third, plan for ownership. A library of 117 queries is 117 things someone needs to tune, and unowned rules rot quickly. Finally, some of the roundup content is vendor or blog marketing in nicely formatted clothing, and the claims about coverage should be treated as such.

## Closing thoughts

The useful skill in 2026 is not finding queries. It is deciding which ones earn a place in your estate, and being able to prove why. If I were setting priorities, I would pick one source from the commons, adopt three queries from it with proper context and exclusions, and run them through a pull request with a real reviewer. Then repeat.

The shift to detections as code makes that discipline easier to enforce, because the review step is built into how content ships. I'd rather have thirty rules I can explain than three hundred I downloaded.

## References

1. [What's new in Microsoft Sentinel - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/whats-new)
2. [KQL Sources: 2026 Update - kqlquery.com](https://kqlquery.com/posts/kql-sources-2026/)
3. [Monitor New Actions in Sentinel & Defender XDR (V2) - kqlquery.com](https://kqlquery.com/posts/monitor-new-actions-sentinel-defender-xdr/)
4. [Sentinel - Defender XDR KQL Queries Library - Microsoft Tech Community](https://techcommunity.microsoft.com/discussions/microsoftsentinel/sentinel---defender-xdr-kql-queries-library/4538669)
5. [benscha/KQLAdvancedHunting - GitHub](https://github.com/benscha/KQLAdvancedHunting)
6. [KQL Detection Queries for Microsoft Sentinel: 50 Rules Mapped to MITRE ATT&CK - Decryption Digest](https://www.decryptiondigest.com/blog/kql-detection-query-library-microsoft-sentinel-mitre-attack)
7. [Microsoft Sentinel September 2026 - infernux.no](https://infernux.no/blog/microsoft-sentinel-september-2026/)
