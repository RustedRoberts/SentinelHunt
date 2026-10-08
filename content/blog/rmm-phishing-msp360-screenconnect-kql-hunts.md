---
title: "The Installer Was Signed. The Intent Wasn't: Hunting Dual-RMM Phishing"
date: 2026-10-08
author: Chris Scott
summary: Microsoft's latest phishing research delivers a legitimately signed MSP360 agent, which then quietly installs ScreenConnect as a second way in. There is no malware to detect, so the hunt has to be about authorisation and behaviour, and the published KQL is a good place to start.
tags:
  - kql
  - advanced-hunting
  - threat-hunting
  - detection-engineering
  - phishing
published: true
---

Every so often a piece of research lands that makes me ask a slightly uncomfortable question about my own detection estate: how much of it only works because the attacker brought something obviously bad?

Microsoft Defender Experts published exactly that sort of write-up on 29 September. Phishing emails, themed as meeting invites, Zoom and Google Meet installers, Adobe Reader pages and parcel notices, deliver a digitally signed MSP360 remote management installer. No exploit, no custom implant, and nothing in the file that a reputation check would object to. The victim runs it, accepts the UAC prompt, and the attacker has a foothold through software that a managed service provider might legitimately deploy.

What makes it worth your time is the second stage. The MSP360 agent launches PowerShell, which silently installs ConnectWise ScreenConnect as a second remote access channel. Pull out one and the other is still there. Microsoft also saw a variant using the Faronics Deploy Agent in place of MSP360 to do the same job.

## Why legitimate tooling is the hard case

Remote Access Software (T1219) is not a new technique, and defenders have been warned about RMM abuse for years. What stands out here is how little there is to alert on. The installer is signed. The payloads sit on Amazon S3, Cloudflare R2, Dropbox, GitLab and Supabase, which most organisations allow without a second thought. The follow-on tools, delivered through ScreenConnect's RunFile function, are named to resemble Windows, Defender or Phone Link components, a clear case of Masquerading (T1036).

Microsoft did not observe exploitation of ScreenConnect itself, and it has not attributed the activity to a named actor. That matters for how you read it. Nobody broke anything. Someone was persuaded to install a tool, and every step after that used software working exactly as designed.

So the question stops being whether a file is malicious and becomes whether this particular remote access channel was something the organisation agreed to. Signatures cannot answer that. Only your own knowledge of your estate can.

## Hunting the chain

Microsoft's post includes four advanced hunting queries, and what I like about them is that they follow the chain rather than a single indicator. They are worth lifting straight into your own tenant.

The first looks for the MSP360 agent by SHA256 in `DeviceFileEvents`. Useful, but the weakest of the four, because a hash is a point in time. Treat it as a scoping query, not a detection.

The second is more interesting. It looks in `DeviceProcessEvents` for PowerShell spawned by the MSP360 agent, or for `msiexec.exe` pointing at an `.msi` in a temp folder with `RMM.Agent.exe` as the grandparent. That is the pivot from first RMM to second, and it is the behaviour an attacker cannot easily dress up, because the agent has to run something to install the next tool.

The third and fourth tie it together. The network query takes every URL that the MSP360-spawned PowerShell reached and then checks whether ScreenConnect processes talked to the same places. The process query catches ScreenConnect's RunFile pushing content into `\Documents\` and `\Temp\` paths. Between them you get the install, the second channel and the payload delivery.

Here is the core of the third query, which I find the most transferable idea of the set:

```kql
let StagingUrls = DeviceNetworkEvents
| where Timestamp >= ago(30d)
| where InitiatingProcessCommandLine == "\"powershell.exe\""
| where InitiatingProcessParentFileName == "RMM.Agent.exe"
| where isnotempty(RemoteUrl)
| distinct RemoteUrl;
DeviceNetworkEvents
| where Timestamp >= ago(30d)
| where InitiatingProcessFileName has_any ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe", "ScreenConnect.Client.exe")
| where RemoteUrl in (StagingUrls)
```

It correlates two tools against shared infrastructure, which is far harder to evade than any single filename. The caveat is that it is written around this specific campaign. Swap MSP360 for Faronics and the parent process changes, so the query as written goes quiet.

## Turning the hunt into a detection

This is where I would push beyond the published queries. The campaign-specific versions will age, but the underlying signal does not: two different RMM tools appearing on one endpoint within a short window, neither of which is on your approved list.

A rough shape for that looks like the following. I have not run this against production data, so treat it as a starting point and test it against your own device groups.

```kql
let ApprovedRmm = dynamic(["ScreenConnect.ClientService.exe"]); // replace with your own approved agents
let RmmAgents = dynamic([
    "ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe",
    "RMM.Agent.exe", "FaronicsDeployAgent.exe", "AnyDesk.exe", "RustDesk.exe",
    "NinjaRMMAgent.exe", "Atera.exe", "MeshAgent.exe", "SimpleHelp.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName in~ (RmmAgents)
| where FileName !in~ (ApprovedRmm)
| summarize FirstSeen = min(Timestamp), Tools = make_set(FileName)
    by DeviceId, DeviceName
| where array_length(Tools) >= 2
```

Filtering on filenames is the weak point here, and I would be the first to say so, given what the Microsoft write-up says about renamed payloads. Where you can, anchor on the signer in `InitiatingProcessVersionInfoCompanyName` or on the installed service instead. The principle is the point: maintain a list of what is allowed, and alert on the rest.

## Caveats and maturity

Honest limits first. An approved-tool list is only as good as whoever maintains it. If your service desk uses three RMM products, two of them unofficially, the list is wrong on day one and the detection will either flood or stay silent. Do the inventory before writing the rule.

The Microsoft queries also assume Defender for Endpoint telemetry on the device. An unmanaged laptop or a BYOD machine will not show you any of this, which is a gap worth being clear-eyed about.

And a hunt that finds a second RMM tool is not the end. Remediation has to remove every channel, otherwise you have cleaned up the one you found and left the one you did not. Sources covering the campaign also point out that some operators remove rival RMM agents, so a sudden disappearance of a tool you do deploy deserves the same attention as a new one appearing.

## Closing Thoughts

I keep coming back to how ordinary this campaign looks until you ask who authorised it. That is a hunting question rather than a detection one, and it needs a human who knows what normal looks like for the organisation.

If you take one thing from this, make it the inventory. Find out which remote access tools are really running across your devices today, decide which are meant to be, and put the difference in front of someone on a schedule. Then use Microsoft's chain queries to check the last 30 days, because the campaign has been running since July.

## References

1. [Phishing abuses RMM tools for persistent access - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/)
2. [Unmasking EvilTokens: Getting to the root of device code phishing - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)
3. [Attackers abuse MSP360 to deploy ScreenConnect - The Hacker News](https://thehackernews.com/2026/09/attackers-abuse-msp360-to-deploy.html)
4. [MSP360 Phishing Turns One Fake Invitation Into Two Remote-Access Channels - Gridinsoft](https://blog.gridinsoft.com/msp360-phishing-screenconnect-two-access-channels/)
5. [RMM detection - Zscaler](https://www.zscaler.com/blogs/cybersecurity-best-practices/rmm-detection)
6. [ScreenConnect abuse - TrendAI Security Blog](https://www.trendaisecurity.com/en/resources-insights/trendai-security-blog/screenconnect-abuse)
