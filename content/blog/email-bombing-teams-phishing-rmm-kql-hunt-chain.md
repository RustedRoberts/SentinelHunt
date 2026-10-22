---
title: "Email Bombing, a Teams Chat and an RMM Tool: Hunting the Chain, Not the Link"
date: 2026-10-05
author: Chris Scott
summary: Every link in the email bombing to Teams vishing to RMM chain looks harmless on its own. Three recent pieces of community detection content show why you should be hunting the sequence, and how to build it in KQL.
tags:
  - kql
  - sentinel
  - defender-xdr
  - threat-hunting
  - detection-engineering
  - rmm
published: true
---

I went through this week's crop of new community detection content looking for the odd one out, and found it in a place I didn't expect. Splunk's content team shipped eleven rules, Sublime added seventeen email rules, and SigmaHQ added a single PowerShell discovery rule. Sitting in the middle of all that were a few unglamorous KQL and LOLRMM updates about remote management tools. No zero-day, no clever rootkit. Just Teleport Connect getting RMM coverage and a community hunt that stitches together email bombing, Teams phishing and RMM execution.

That second one is the one I keep thinking about, because it is the only item in the batch that hunts a sequence rather than a single event. And the sequence is the whole point.

## Why this chain keeps working

The pattern is well documented by now. The attacker floods a user's mailbox with benign spam, newsletter sign-ups mostly, until the user is desperate for help. Then someone posing as IT support contacts them over Teams, offers to fix the problem, and talks them into starting a remote session, either with something native like Quick Assist or a third-party RMM tool. Sophos documented this across more than 15 incidents between November 2024 and mid-January 2025, attributed to two distinct clusters, one linked to the 3AM ransomware group. NVISO published a Black Basta focused write-up of the same Teams chat approach.

What makes it hard is that nothing in it is malicious on its face. Newsletters are not malware. A one-to-one Teams chat from an external tenant is not an exploit. A signed ScreenConnect binary is not a threat. Each step passes through a control that was designed to let it through. Scale matters too: figures cited by Netlas from Huntress put RMM abuse up 277 percent year on year, with RMM involved in 24 percent of incidents in 2026 reporting. Red Canary lists NetSupport Manager, ScreenConnect, Itarian, PDQ Connect, SimpleHelp and Chrome Remote Desktop among the tools it sees abused most.

## The hunting angle: correlate, then subtract

NVISO's approach is the one I'd copy. They correlate two weak signals inside a three hour window: more than 100 inbound emails to one recipient, then a one-to-one Teams chat created close to that burst. Either signal alone is noisy. Together they are rare. Their version uses EmailEvents and the OfficeActivity "ChatCreated" operation.

Here is the first half in Defender XDR flavour. It finds recipients who received a burst of inbound mail.

```kql
// Stage 1: email bombing - recipients hit with 100+ inbound emails in 3 hours
let BombWindow = 3h;
let BombThreshold = 100;
EmailEvents
| where Timestamp > ago(1d)
| where EmailDirection == "Inbound"
| summarize Emails = count(), Senders = dcount(SenderFromAddress),
    BurstStart = min(Timestamp), BurstEnd = max(Timestamp)
    by RecipientEmailAddress, Window = bin(Timestamp, BombWindow)
| where Emails > BombThreshold
```

The second half is the one the new LOLRMM content helps with. The detection logic described around LOLRMM is a difference query: take the catalogue of known RMM indicators, subtract the few tools your organisation actually sanctions, and alert on what is left. The catalogue gives you executable names, domains and install paths. Your sanctioned list is the part only you can write.

```kql
// Stage 2: unsanctioned RMM execution by a user who was just bombed
let SanctionedRmm = dynamic(["ScreenConnect.ClientService.exe"]); // your approved tools
let KnownRmm = dynamic(["AnyDesk.exe","ScreenConnect.WindowsClient.exe","Atera.exe",
    "SRService.exe","client32.exe","SimpleService.exe","QuickAssist.exe"]); // seed from LOLRMM
let Bombed = EmailEvents
    | where Timestamp > ago(1d) and EmailDirection == "Inbound"
    | summarize Emails = count() by RecipientEmailAddress, Window = bin(Timestamp, 3h)
    | where Emails > 100
    | distinct RecipientEmailAddress, Window;
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ (KnownRmm) and FileName !in~ (SanctionedRmm)
| extend Window = bin(Timestamp, 3h)
| join kind=inner (Bombed) on $left.AccountUpn == $right.RecipientEmailAddress, Window
| project Timestamp, DeviceName, AccountUpn, FileName, ProcessCommandLine, Emails
```

Treat both as starting points. The join on a fixed time bin will miss a burst that straddles a bin boundary, and you will want to widen it to adjacent windows before relying on it. The process list is deliberately short. Renamed binaries are a known evasion, which is why Red Canary also points at unusual install paths and renamed executables, and why signing certificate and DNS indicators from LOLRMM are worth adding as a second path.

## Caveats and maturity

This only works if the data is there. Teams chat metadata needs the right audit and connector configuration, and the fields differ between OfficeActivity in Sentinel and the Defender XDR tables, so check what your tenant actually exposes. You also need a real sanctioned-tool list. If your helpdesk uses three RMM products and nobody has written them down, the subtraction produces noise and the hunt dies in triage. That is a process problem, not a KQL problem.

There is also a limit to what a query can see. Quick Assist is native to Windows and is trivially hard to tell apart from a legitimate help desk session without context such as who initiated it and whether the helpdesk ticket exists. Netlas makes the same point: deployment origin, process ancestry, tool frequency and timing matter more than the tool itself.

## Closing thoughts

If you take one thing from the week, I'd make it this: stop adding more single-event RMM alerts and start asking which two weak signals, together, are rare in your environment. Email volume plus external Teams chat plus unsanctioned remote tool is one answer. There will be others in your own data. I have not run these queries against a production tenant for this post, so test them against your own baselines before promoting them to analytics rules, and tell me what the false positive rate looks like.

## References

1. [Detecting Teams Chat Phishing Attacks (Black Basta) - NVISO](https://blog.nviso.eu/2025/01/16/detecting-teams-chat-phishing-attacks-black-basta/)
2. [A familiar playbook with a twist: 3AM ransomware actors dropped virtual machine with vishing and Quick Assist - Sophos](https://www.sophos.com/en-gb/blog/a-familiar-playbook-with-a-twist-3am-ransomware-actors-dropped-virtual-machine-with-vishing-and-quick-assist)
3. [Detections Digest #20260824 - RuleCheck.io](https://detections-digest.rulecheck.io/p/detections-digest-20260824)
4. [RMM Abuse - Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/trends/rmm-abuse/)
5. [Weaponized RMM: Hunting the Adversary Abuse of Remote Monitoring Tools - Netlas](https://netlas.io/blog/weaponized_rmm/)
6. [benscha/KQLAdvancedHunting - GitHub](https://github.com/benscha/KQLAdvancedHunting)
