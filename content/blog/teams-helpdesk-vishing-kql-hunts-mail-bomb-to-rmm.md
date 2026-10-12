---
title: "The Helpdesk Is Calling: KQL Hunts for Teams Vishing and the Mail Bomb Chain"
date: 2026-10-12
author: Chris Scott
summary: In the last six weeks, Microsoft and the community have both shipped hunting content for Teams-based social engineering. Here is what landed, how the pieces fit together, and where the gaps are.
tags:
  - kql
  - advanced-hunting
  - threat-hunting
  - detection-engineering
  - social-engineering
  - teams
published: true
---

I went looking for new KQL content this week expecting a mixed bag of the usual suspects: another LOLBin hunt, another Entra sign-in query. What I actually found was a pattern. Across the official Sentinel repository and a handful of community repos, the newest content is quietly converging on one problem: someone external gets into a user's Teams and pretends to be IT.

That is worth a closer look, because the way these queries are built says a lot about where detection engineering for social engineering is heading. It also shows the gaps you will need to fill yourself.

## The attack chain behind the queries

The scenario is now familiar. A user's inbox is flooded with hundreds of emails in a short window, usually newsletter sign-ups or similar noise. Then a Teams message or call arrives from an external account offering to help. The display name says something like "IT Support" or "Helpdesk". The helpful stranger asks the user to open Quick Assist or install a remote tool, and the attacker has a foothold. The relevant ATT&CK techniques are Phishing (T1566), Spearphishing via Service (T1566.003), User Execution (T1204) and Remote Access Tools (T1219).

None of the individual steps is especially alarming on its own. Mail volume spikes happen. External Teams contact is legitimate in plenty of organisations. Remote support tools are used every day. It is the sequence that gives it away, which is why the content I found this week is more interesting than a single-event rule.

## What landed

On 7 September a batch of Teams protection hunting queries was merged into the Azure-Sentinel repository, mirrored under both the Defender XDR solution and the Microsoft 365 Defender hunting folders. One flags callers whose display name or address looks like IT support, helpdesk, security or account maintenance, and calls out throwaway `.onmicrosoft.com` tenants separately. A neat design choice is that it derives your organisation's domains from inbound mail recipients rather than hard-coding a tenant ID. Another charts all calls against impersonation-style calls by hour of day, so an hour with few calls but a high impersonation share stands out. There are also queries on reported calls and top reporters, and the existing Suspicious Teams Display Name hunt was updated with a broader pattern and throwaway-tenant detection.

On the community side, Benjamin Zulliger published a query that stitches the whole chain together. It looks for mail bursts of at least 100 messages from at least 20 distinct senders in a 15-minute bin, then an external Teams message to the same recipient within two hours of the flood, then a remote support tool or a suspicious script interpreter launch on that user's device within four hours. Matches get a confidence rating, and every threshold sits in a parameter block at the top, which makes tuning straightforward. Sergio Albea took a different approach with a Teams calls by TLD hunt on `CallActivityEvents`, which pulls the TLD from the caller's UPN and maps it to a country, giving you context on unexpected geography. As he notes himself, a foreign TLD is context rather than a verdict.

## The practical bit

If you want to build on this rather than just import it, I would think about it in three layers. First, the cheap identity signal: external senders or callers with helpdesk-style display names, especially from tenants that look newly created. Second, the volume signal: mail bursts per recipient. Third, the endpoint signal, which is where you get confirmation. The endpoint layer is the one I would start with, because it is the hardest for an attacker to avoid. A minimal sketch (mine, not from the repos above, so test it before you trust it):

```kql
let RmmTools = dynamic(["quickassist.exe", "anydesk.exe", "teamviewer.exe", "screenconnect.windowsclient.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (RmmTools)
| where InitiatingProcessFileName in~ ("explorer.exe", "teams.exe", "ms-teams.exe")
| summarize FirstSeen = min(Timestamp), Launches = count() by DeviceName, AccountName, FileName
```

On its own that is noisy. Join it to the Teams and email layers using the recipient's identity and a time window, as Zulliger's query does, and it becomes something you can actually triage.

## Caveats and maturity

Every one of these hunts depends on telemetry you may not have switched on. The Teams queries need the Defender for Office 365 collaboration tables populated, and the call-based ones need `CallActivityEvents`. Check that before you assume a quiet result means a quiet environment.

Then there is the false positive problem. Approved external helpdesks, managed service providers and your own IT team using Quick Assist will all light these up. The allowlist is the real work, and it needs an owner. I would also be wary of treating display-name matching as a control. It catches the lazy attacker and misses anyone who picks a plausible human name.

Finally, check the repository licence and the commit history before copying anything into production. Some of this content is days old and unreviewed. The Sentinel repo itself saw a fix to entity mappings in a hunting query as recently as 16 September, a reminder that even official content needs a read-through.

## Closing Thoughts

What I like about this wave of content is that it treats social engineering as a sequence to be detected rather than a training problem to be admitted defeat on. User awareness still matters, but a hunt that joins mail, collaboration and endpoint data does not depend on the user spotting the trick.

My suggestion is to pick one of these, run it against 30 days of your data, and see what your external Teams traffic really looks like. Most teams I speak to have never looked. The first run is usually more educational than any alert it produces.

## References

1. [Hunting Queries commit history - Azure-Sentinel (GitHub)](https://github.com/Azure/Azure-Sentinel/commits/master/Hunting%20Queries)
2. [Teams protection hunting queries, pull request 15069 - Azure-Sentinel (GitHub)](https://github.com/Azure/Azure-Sentinel/pull/15069)
3. [Mail Bombing Followed by External Teams Contact and Remote Access Execution - Benjamin Zulliger (GitHub)](https://github.com/benscha/KQLAdvancedHunting/blob/main/Initial%20Access/Mail%20Bombing%20Followed%20by%20External%20Teams%20Contact%20and%20Remote%20Access%20Execution.md)
4. [Threat Hunting Microsoft Teams Calls by TLD - Sergio Albea (GitHub)](https://github.com/Sergio-Albea-Git/Threat-Hunting-KQL-Queries/blob/main/Microsoft_DefenderXDR/CallActivityEvents/Threat%20Hunting%20Microsoft%20Teams%20Calls%20by%20TLD.md)
5. [KQL Search - recent community queries](https://www.kqlsearch.com/)
6. [Detecting Teams Chat Phishing Attacks (Black Basta) - NVISO](https://blog.nviso.eu/2025/01/16/detecting-teams-chat-phishing-attacks-black-basta/)
