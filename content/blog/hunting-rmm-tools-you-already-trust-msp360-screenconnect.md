---
title: "Hunting the Remote Tools You Already Trust: MSP360, ScreenConnect and Zimbra"
date: 2026-10-02
author: Chris Scott
summary: Microsoft's last two threat intelligence posts of September both shipped KQL, and both prove the same point. Hunting the tool is a losing game, hunting the parent and child relationship is not.
tags:
  - kql
  - threat-hunting
  - detection-engineering
  - advanced-hunting
  - rmm-abuse
published: true
---

The most useful thing I did with Microsoft's latest threat intelligence posts wasn't reading them. It was pasting their KQL straight into advanced hunting and seeing what came back in my own tenant. Two posts landed in the last days of September, one on phishing that abuses remote monitoring and management (RMM) tools, one on a Zimbra mail server flaw, and both came with hunting queries attached. That is exactly the sort of new content worth tracking, so I went through them properly.

What struck me is that neither set of queries cares much about the malware. They care about who started what. That is the whole lesson, and it is why I think these are worth adapting rather than just running once.

## The problem with legitimate tools

The RMM campaign Microsoft describes was observed in July 2026 and written up on 29 September. Phishing emails delivered genuine MSP360 RMM installers with filenames dressed up as meeting invitations, PDF readers and software updates. Once the user accepted the UAC prompt, the installer set up Windows services and registry persistence, then used PowerShell to silently pull down ConnectWise ScreenConnect as an MSI. ScreenConnect's RunFile feature then pushed credential theft and collection tools onto the host. [1]

Two commercial, signed, perfectly legitimate remote access products, stacked on top of each other so that losing one doesn't lose the foothold. Nothing in that chain is a malware signature. This isn't a one-off either. Sophos has tracked Qilin affiliates going after ScreenConnect users directly, using fake ScreenConnect login pages to harvest credentials and session cookies. [3] If your detection logic is "alert on ScreenConnect", you will either drown in your own IT team's activity or switch the rule off.

The Zimbra story is the same shape in a different place. CVE-2026-73570 is an unauthenticated command injection in Zimbra's SNMP notification path, hit with a crafted email when the optional zimbra-snmp package is installed. Patched in 10.1.20 on 20 July, publicly disclosed on 13 August, and added to the CISA Known Exploited Vulnerabilities catalogue on 21 August. [2][4] The attackers dropped JSP webshells, built systemd persistence and tried to ship mail archives out with AzCopy. Again, mostly legitimate binaries doing illegitimate things.

## The detection angle: parentage over names

Look at how Microsoft built the RMM hunts. They don't ask "is MSP360 installed". They ask whether PowerShell was launched by `RMM.Agent.exe`, and whether that PowerShell then ran `msiexec.exe` against an `.msi` in a Temp folder. [1]

```kql
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where (InitiatingProcessVersionInfoCompanyName == "MSP360" and ProcessCommandLine == "\"powershell.exe\"")
    or (InitiatingProcessCommandLine == "\"powershell.exe\""
        and ProcessCommandLine has_all ("msiexec.exe", "\\Temp\\", ".msi")
        and InitiatingProcessParentFileName == "RMM.Agent.exe")
```

The next hunt in that post is the one I like most. It builds a list of every URL that PowerShell-under-RMM.Agent reached, then looks for ScreenConnect client processes talking to those same URLs. That is correlation by shared infrastructure, not by indicator, so it still works when the attacker rotates domains. A third query catches the payload stage: ScreenConnect's RunFile command executing something out of a Documents or Temp path.

The Zimbra queries follow the same philosophy. The confirmed injection hunt looks for a shell started by Perl where the parent command line contains `.swatchdog_script` and the child mentions `snmptrap`. A second looks for JSP files written under the jetty webapps or mailboxd paths by `sh`, `bash`, `curl`, `wget` or `java`. A third catches memory-backed execution (`memfd:`) with that same swatchdog context. [2]

```kql
DeviceFileEvents
| where FileName endswith ".jsp" or FileName endswith "_jsp.java"
| where FolderPath contains "/jetty_base/webapps/" or FolderPath contains "/mailboxd/"
| where InitiatingProcessFileName in~ ("sh", "bash", "curl", "wget", "java")
```

If you want to turn any of these into something that runs on a schedule, the useful questions are the same each time. What is the legitimate parent of this process in my estate? What should it never spawn? Where should it never write? Answer those and you have a detection that survives the attacker swapping tooling.

## Considerations and caveats

None of this travels as-is. The MSP360 queries lean on specific names, `RMM.Agent.exe` and one pinned SHA256, so they are excellent for finding this campaign and weak for finding the next one. Treat them as a template: keep the parent-child structure, widen the product list to whichever RMM tools you have approved (and, more importantly, the ones you haven't).

That last point is the real maturity gate. You cannot spot an unsanctioned RMM install if you don't know what sanctioned looks like. A watchlist of approved remote access tools, their expected install paths and the hosts they belong on is worth more than any single query here. Without it, every hit is a conversation with IT instead of a verdict.

The Zimbra hunts have a different dependency. They only fire if you actually have Defender for Endpoint on Linux on your mail servers, or equivalent process telemetry flowing into the workspace. Microsoft's own mitigation advice includes enabling it, which tells you how many estates don't have it. [2] Also worth saying plainly: I have taken these queries from the published posts and have not validated them against a live tenant, so test before you schedule anything.

One more thing from the platform side. September's Sentinel updates mean advanced hunting can now run interactive KQL against data lake tables as well as Defender XDR data, so a 30-day lookback in these queries is no longer the ceiling for retrospective hunts on anything you have tiered down. [5]

## Closing thoughts

Vendors publishing hunting KQL alongside their threat write-ups is quietly becoming the fastest route to usable detection content. The catch is that a query written for one campaign ages the day the campaign changes infrastructure. The structure underneath, the parent that should never spawn that child, is what you keep.

So next time one of these lands, don't just run it. Ask which half is the indicator and which half is the behaviour, keep the behaviour, and write down what normal looks like for the tool in question. Then the next RMM abuse campaign is a tweak, not a project.

## References

1. [Phishing campaigns abuse RMM tools for persistent access - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/)
2. [Unauthenticated command injection on internet-facing mail servers: tracking CVE-2026-73570 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/30/unauthenticated-command-injection-on-internet-facing-mail-servers-tracking-cve-2026-73570/)
3. [Sophos MDR tracks ongoing campaign by Qilin affiliates targeting ScreenConnect - Sophos](https://www.sophos.com/en-gb/blog/sophos-mdr-tracks-ongoing-campaign-by-qilin-affiliates-targeting-screenconnect)
4. [CVE-2026-73570 Exploited Against Zimbra Servers - GridinSoft](https://blog.gridinsoft.com/cve-2026-73570-zimbra-rce/)
5. [Microsoft Sentinel September 2026 Update - Infernux](https://infernux.no/blog/microsoft-sentinel-september-2026/)
6. [KQL Sources: 2026 Update - KQLQuery](https://kqlquery.com/posts/kql-sources-2026/)
