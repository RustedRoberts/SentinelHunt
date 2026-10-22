---
title: "Mail Bombing, Fake Helpdesks and Quick Assist: Hunting the Whole Chain in KQL"
date: 2026-10-09
author: Chris Scott
summary: The mail bomb, Teams helpdesk chat and remote access session playbook is still working in 2026, and the freshest community KQL treats it as one chain rather than three separate alerts.
tags:
  - kql
  - threat-hunting
  - detection-engineering
  - sentinel
  - advanced-hunting
  - social-engineering
published: true
---

I went looking for new KQL this week expecting a pile of one-off IOC queries. What I found instead was a pattern. Across the community feeds, the Azure-Sentinel repository and a couple of vendor write-ups, the most interesting new content isn't about a single technique. It's about a sequence: flood someone's inbox, message them on Teams pretending to be IT, get them to hand over a remote session. Three events that look harmless on their own, and a lot more worrying when you read them in order.

The detection engineering community has clearly noticed. In the space of a few weeks there were queries for mail bombing followed by external Teams contact and RMM execution, a Teams helpdesk impersonation hunt landing in the official Microsoft 365 Defender hunting folder, and a set of Teams call and sender-risk queries from Microsoft Defender for Office 365 contributors. This post pulls those together and looks at what a chain-based hunt needs to work.

## The playbook that refuses to die

The mechanics are well documented now. The attacker subscribes a target's work address to a pile of newsletters, so hundreds or thousands of legitimate but unwanted emails land in minutes. One write-up summarised by UC Today describes more than 3,000 messages in 45 minutes. The victim is overwhelmed, and that is the point. Then a Teams message or call arrives from an external tenant, often with a display name like "Help Desk", offering to sort it out. The default Teams configuration permits external users to start chats unless an admin has restricted it.

CyberProof's H1 2026 analysis shows how this plays out. In one case the attacker joined a call for around 23 minutes, dropped TeamViewer and went hands-on-keyboard through cmd.exe. In a healthcare case the attacker messaged five employees at once, got a user to start Quick Assist, and then ran a PowerShell script that performed Kerberoasting. Public reporting links the technique to former Black Basta affiliates, and the Cloud Security Alliance note traces the wider approach back to the TeamsPhisher tooling of 2023. Same play, three years on, and it still works.

That longevity tells you something. This isn't an exploit you can patch. It's a gap between two configurations and one very patient human being.

## The detection angle: join the dots

Each stage of the chain does generate telemetry, but none of it is high fidelity alone. A burst of inbound mail is Tuesday for a lot of people. An external one-to-one Teams chat is legitimate for anyone who works with suppliers. Quick Assist launching is routine on a helpdesk floor. The signal is in the sequence and the timing.

NVISO published the reference approach in early 2025: find recipients who received a large volume of flagged email, then join to Teams chat creation events within three hours. It's a good query and the logic still holds, but it has a gap worth fixing. The threshold is applied per hour before the three-hour window is built, so 60 emails an hour for three hours (180 in total) slips under a 100-per-hour bar. Apply the threshold after you sum the window instead.

```kql
// Stage 1 and 2: mail burst followed by an external one-to-one Teams chat
// Needs Teams ChatCreated auditing enabled. Validate column names in your tenant.
let bombWindow = 3h;
let bombThreshold = 100;
let bombed = EmailEvents
    | where Timestamp > ago(1d)
    | where EmailDirection == "Inbound"
    | summarize Emails = count(),
                WindowStart = min(Timestamp),
                WindowEnd = max(Timestamp),
                Senders = dcount(SenderFromAddress)
        by RecipientEmailAddress, Window = bin(Timestamp, bombWindow)
    | where Emails > bombThreshold
    | extend Recipient = tolower(RecipientEmailAddress);
OfficeActivity
| where TimeGenerated > ago(1d)
| where RecordType == "MicrosoftTeams" and Operation == "ChatCreated"
| where CommunicationType == "OneOnOne"
| mv-expand Member = Members
| extend Recipient = tolower(tostring(Member.UPN))
| join kind=inner bombed on Recipient
| where TimeGenerated between (WindowStart .. (WindowEnd + 3h))
| project TimeGenerated, Recipient, UserId, Emails, Senders, WindowStart, WindowEnd
```

I've dropped the "flagged mail only" filter that NVISO used, because newsletter floods are often perfectly clean as far as mail filtering is concerned. That makes it noisier, so expect to tune the threshold, and consider excluding recipients with a legitimate high-volume mailbox.

Stage three is where you get the most value for the least effort. Whoever ends up on the receiving end of a helpdesk call, the next thing you want to see is a remote access tool starting on their device. Quick Assist is a Microsoft-signed binary, which is exactly why it gets abused: it won't trip reputation checks.

```kql
// Stage 3: remote access tooling starting on a device shortly after the chat
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("quickassist.exe", "teamviewer.exe", "anydesk.exe", "supremo.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

Then correlate on the account. If the same user shows up in the chat query and the process query inside an hour or two, you have a high-confidence incident rather than three low-confidence signals. CyberProof also describes a `TeamsImpersonationDetected` event in `CloudAppEvents` that can be matched against helpdesk-style keywords and `.onmicrosoft.com` senders. That's a useful additional feed if you have it, although the keyword list will need tuning.

## Caveats, because there are plenty

Be honest about what the telemetry gives you. For voice calls, the victim sees no warning and the logs are thin, so a chat-based hunt only sees the chat side of an attack. If the attacker skips the chat and rings straight away, you're relying on call activity data and the endpoint stage.

Auditing has to be switched on before you can hunt on it. If `ChatCreated` isn't flowing into your workspace, the query above returns nothing and looks perfectly healthy. Check that first. Your mail-bomb baseline matters too, because executives and shared mailboxes receive large volumes all day. And the RMM list is only as good as your knowledge of what your own helpdesk uses, so a watchlist of approved tools and approved operators beats a hardcoded list every time.

Finally, none of this replaces the boring fix. Restricting external Teams access to approved domains removes the front door for most of these attacks, and blocking Quick Assist where the business doesn't need it closes the back one. Detection is the safety net here, not the plan.

## Closing Thoughts

What I like about this wave of content is the shift in thinking. We've spent years writing detections for single events and then wondering why the alert queue is full of noise. The chain-based queries going into the community feeds this autumn are doing the opposite: accepting that every stage is ambiguous and letting the correlation do the work.

If you take one thing from this, build a version of the chain query for your own tenant and run it as a hunt before you promote it to a rule. You'll learn more about your mail baseline and your Teams external access in an afternoon than you will from another IOC feed. Then go and check who is actually allowed to message your staff from outside.

## References

1. [Detecting Teams Chat Phishing Attacks (Black Basta) - NVISO](https://blog.nviso.eu/2025/01/16/detecting-teams-chat-phishing-attacks-black-basta/)
2. [Microsoft Teams Vishing and Cross-Tenant Attack Chronicles: H1 2026 Analysis - CyberProof](https://www.cyberproof.com/blog/microsoft-teams-vishing-and-cross-tenant-attack-chronicles-h1-2026-analysis/)
3. [Email Bombing Followed by Teams IT Impersonation Attacks Continue - BlueVoyant](https://www.bluevoyant.com/blog/email-bombing-followed-by-teams-it-impersonation-attacks-continue)
4. [CSA Research Note: Teams Phishing, A0Backdoor and Quick Assist Abuse - Cloud Security Alliance](https://labs.cloudsecurityalliance.org/research/csa-research-note-teams-phishing-a0backdoor-quick-assist-abu/)
5. [Microsoft Teams Abused in Helpdesk Impersonation Attacks - IANS Research](https://www.iansresearch.com/resources/all-blogs/post/security-blog/2026/04/27/microsoft-teams-abused-in-helpdesk-impersonation-attacks)
6. [KQL Search - recent community queries](https://www.kqlsearch.com/)
7. [Azure-Sentinel Hunting Queries commit history - Microsoft](https://github.com/Azure/Azure-Sentinel/commits/master/Hunting%20Queries)
8. [How Ransomware Gangs Exploit Microsoft Teams - UC Today](https://uctoday.com/cyber-security-alert-how-ransomware-gangs-exploit-microsoft-teams)
