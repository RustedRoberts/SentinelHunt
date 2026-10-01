---
title: "Hunting the Fake Help Desk in Teams, Now With Message Content"
date: 2026-10-01
author: Chris Scott
summary: Attackers are ringing staff on Teams pretending to be IT, and Microsoft is about to give hunters the message text to prove it. Here is how to hunt the pattern in KQL with the tables you already have, and what the new MessageContents table changes.
tags:
  - kql
  - defender-xdr
  - threat-hunting
  - microsoft-teams
  - vishing
published: true
---

I have lost count of the number of times someone has told me their phishing defences are solid because email is locked down. Fair enough, email has had twenty years of attention. But the call that lands in a Teams chat from "IT Help Desk" never goes near your mail gateway, and that is exactly why it is working.

Two things happened recently that made me want to write this up. Researchers have been publishing detailed accounts of Teams-based help desk vishing throughout 2026, and Microsoft has started rolling out a new Defender XDR advanced hunting table, `MessageContents`, which for the first time gives SOC analysts the actual text of Teams messages. One is the problem, the other is a new tool for the problem. Neither is much use unless you already know what you are hunting for.

## What the attackers are doing

The pattern reported by Palo Alto Networks Unit 42 and summarised by several vendors is refreshingly low-tech. Between January and April 2026, attackers registered lookalike tenants on the `.onmicrosoft.com` domain with names along the lines of "ITProtectionDepartment", then used display names such as "IT Help Desk" to open chats with employees. Reporting describes 26 attacker identities approaching more than 150 employees across more than 10 organisations. A voice call follows straight away, and the attacker stays on the line for around 20 minutes, which is a long time to keep someone talking and a long time to build trust.

The goal is to get the victim to launch a remote access tool. CyberProof's H1 2026 write-up describes Windows Quick Assist and TeamViewer being used, followed by PowerShell for credential harvesting. In one healthcare case the script performed Kerberoasting (T1558.003) by querying Active Directory for service principal names, pulling Kerberos tickets and sending the results out to a file sharing site. Initial access here is Phishing via Service (T1566.003) with Remote Access Software (T1219) doing the heavy lifting afterwards.

None of that needs malware at the start. It is a person, a chat window and a tool Microsoft ships with Windows.

## The detection angle

The hunt has three stages, and they are worth thinking about separately because each has a different false positive profile.

First, the lure. External senders from `.onmicrosoft.com` tenants whose names or addresses look like IT support. The `MessageEvents` table surfaces metadata for all messages from external conversations, so this does not rely on the new table at all.

```kql
// Stage 1: external Teams senders styled as IT support
// Replace the tenant domain below with your own
MessageEvents
| where Timestamp > ago(30d)
| where SenderEmailAddress endswith ".onmicrosoft.com"
| where SenderEmailAddress !endswith "yourtenant.onmicrosoft.com"
| where SenderDisplayName matches regex @"(?i)(help\s?desk|service\s?desk|it\s?(support|protection|assistance|department))"
    or SenderEmailAddress matches regex @"(?i)(help|desk|support)"
| mv-expand r = RecipientDetails
| project Timestamp, SenderDisplayName, SenderEmailAddress,
    Target = tolower(tostring(r.RecipientSmtpAddress)), TeamsMessageId
```

Second, the consequence. If a recipient of one of those chats launches a remote access tool shortly afterwards, you have something worth waking someone up for. Quick Assist is the interesting one because it is legitimate and frequently allowed. That makes the correlation with the lure the thing that carries the detection, not the process name on its own.

```kql
// Stage 2: remote access tool launched within two hours of an external "IT" chat
let Lures = MessageEvents
    | where Timestamp > ago(30d)
    | where SenderEmailAddress endswith ".onmicrosoft.com"
    | where SenderEmailAddress !endswith "yourtenant.onmicrosoft.com"
    | where SenderDisplayName matches regex @"(?i)(help\s?desk|service\s?desk|it\s?(support|protection|assistance|department))"
        or SenderEmailAddress matches regex @"(?i)(help|desk|support)"
    | mv-expand r = RecipientDetails
    | project ChatTime = Timestamp, SenderEmailAddress,
        Target = tolower(tostring(r.RecipientSmtpAddress));
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("quickassist.exe", "teamviewer.exe", "anydesk.exe")
| extend Target = tolower(AccountUpn)
| join kind=inner Lures on Target
| where Timestamp between (ChatTime .. (ChatTime + 2h))
| project Timestamp, ChatTime, DeviceName, Target, FileName, SenderEmailAddress
```

Third, the follow-on behaviour: PowerShell querying for SPNs, Kerberos service ticket requests from a workstation that has never made them, uploads to file sharing sites. Those are separate hunts in their own right and I would treat the first two stages as the trigger that tells you which device to point them at.

## What MessageContents changes

Until now, a hunt like this told you who messaged whom and when. You could see the lure existed but not what it said. The new `MessageContents` table, rolling out from late September to mid-October 2026, adds `MessageSnippet` alongside `SenderEmailAddress`, `ThreadId` and `TeamsMessageId`. Microsoft's documentation says it covers supported messages including those with URLs and federated messages, which is exactly the external chat scenario above.

That opens up hunting on the words themselves: "remote session", "Quick Assist", "verify your account", the scripted phrases that campaigns tend to reuse. You can join it to `MessageEvents` on `TeamsMessageId` to enrich the lure hunt with what was actually said, which will cut triage time considerably.

## Considerations and caveats

Please read the access section of the documentation before you get excited. The table contains message content, so it needs advanced hunting access plus the Preview role, and Microsoft's own guidance is to review who in your organisation really needs it. That is a privacy conversation with HR and legal before it is a technical one. Also note that custom detection rules and streaming are not available for `MessageContents`, so for now this is a hunting and investigation tool, not something you can schedule.

The regexes above are deliberately simple, and attackers choose their own display names. Expect to tune. A name-based hunt will miss anything that does not look like IT, which is why the stage 2 correlation matters more. I have not run these against a live tenant for this post, so treat them as starting points and check the columns against your own schema.

And the best control is not a query. Restricting external access in the Teams admin centre to an allowlist of federated tenants removes the entry route altogether, and most organisations I speak to have never looked at that setting.

## Closing thoughts

It is tempting to see a new table and go looking for clever things to do with it. I would start smaller. Work out whether anyone in your organisation can currently receive a chat from a stranger pretending to be IT, find out how many have in the last 30 days, and then decide whether message content is something you actually need.

If you are already hunting Teams abuse, I would genuinely like to hear what your lure patterns look like.

## References

1. [MessageContents table in Microsoft Defender XDR - Microsoft Learn](https://learn.microsoft.com/defender-xdr/advanced-hunting-messagecontents-table)
2. [MC1474106 - New MessageContents table in Advanced Hunting for Microsoft Teams messages - CloudScout](https://app.cloudscout.one/evergreen-item/mc1474106/)
3. [Microsoft Teams Vishing and Cross-Tenant Attack Chronicles: H1 2026 Analysis - CyberProof](https://www.cyberproof.com/blog/microsoft-teams-vishing-and-cross-tenant-attack-chronicles-h1-2026-analysis/)
4. [Security Operations Guide for Teams protection in Microsoft Defender for Office 365 - Microsoft Learn](https://learn.microsoft.com/defender-office-365/mdo-support-teams-sec-ops-guide)
5. [MessageEvents table - Microsoft Learn](https://learn.microsoft.com/defender-xdr/advanced-hunting-messageevents-table)
6. [Microsoft Teams Vishing: How Fake IT Help Desk Calls Get Into Your Network - Arsen](https://arsen.co/en/blog/help-desk-vishing-microsoft-teams)
