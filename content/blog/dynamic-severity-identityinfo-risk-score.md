---
title: "Enriching Detection Content Using KQL and IdentityInfo Risk"
date: 2026-08-11
author: Chris Scott
summary: Static alert severity burns out a SOC when a routine mailbox rule change and a genuinely risky one trip the same rule and get treated identically. A repeatable method for joining triggering events against IdentityInfo's RiskLevel to score severity dynamically.
tags:
  - kql
  - advanced-hunting
  - detection-engineering
  - identity
  - entra-id
published: true
---

Two entities can trip the exact same rule on the same afternoon and get treated identically, because that's how most detection content works. One rule, one severity, applied the same way regardless of who set it off.

The severity rating itself is often left static or reassessed during the 1st touch human triage phase, but even then, that is not changed if the SLA isn't catching you up. This can mean you lose some valuable insight into what is triggering those high alerts (a rant for another time).

When I develop my detection content, each of my detections attempts to use dynamic severity, saving the analyst the effort to always have to step in and change it to better suit the alert and to keep the noise away from the SOC.

I have, over time, developed quick and easy ways to implement this. Here is one such way.

This borrows from the Defender for Identity log source `IdentityInfo` where, amongst many things, it provides us with a Risk Level for identities in our tenant.

> It's worth being clear about where that risk assessment actually comes from: the engine underneath it is Entra ID Protection, not Defender for Identity. Defender for Identity is one of the signal sources that feeds into it, and it's also one of the services that populates `IdentityInfo`.

## The Alert That Keeps on Firing

Take a simple example, where a user account has created or edited a mailbox rule. In itself it's just an event - not something you want to alert on and waste human triage time with (rule logic reduced for this example) but I know some of you out there will be.

```kql
CloudAppEvents
| where Timestamp > ago(1h)
| where Application == "Microsoft Exchange Online"
| where ActionType has_any ("New-InboxRule", "Set-InboxRule")
| project Timestamp, AccountDisplayName, IPAddress, ActionType
```

![user1 mailbox](/SentinelHunt/blog/user1mailbox.png)

What do we see? We see the User1 mailbox account creating and editing mailbox rules 6 times in the morning of 13th of July and more recently on the 4th August.

In isolation this is no use at all. We get nothing useful from this for risk assessment beyond the timestamp, and it's a fairly poor rule that will no doubt burn out a SOC if this is the calibre of detection content being pushed. Every mailbox rule needs to be checked to ensure it's not BAU mailbox admin work. This is where the burn-out starts.

Let's fix this using a repeatable method you can easily add to existing rules.

## Pull Out Your Entity Key Field

First, we introduce our key field. This alert is pulling out a user entity making the rule change, so let's key on this field to begin:

```kql
CloudAppEvents
| where Timestamp > ago(1h)
| where Application == "Microsoft Exchange Online"
| where ActionType has_any ("New-InboxRule", "Set-InboxRule")
   //====Enrich Key Field====//
   | extend UserKey = tolower(AccountObjectId)
   //====Enrich Key Field====//
| project Timestamp, UserKey, AccountDisplayName, IPAddress, ActionType
```

This approach is easy to repeat. Look at the "event" you trigger on and ask yourself: what are the entities being alerted against here?

## Map Out Your Risk Events

Next we take this key and join it on our enrichment source. As mentioned earlier, we are using `RiskLevel` from our `IdentityInfo` table, provided to us by the Defender for Identity license.

The below query will map out any user entity with a risk rating:

```kql
let LatestIdentityRisk = IdentityInfo
| extend UserKey = tolower(AccountObjectId)
| where isnotempty(RiskLevel) and RiskLevel != "None"
| summarize arg_max(TimeGenerated, RiskLevel) by UserKey
```

This gives us what we need - the risk level of accounts in our tenant.

![Risk level screenshot](/SentinelHunt/blog/accountrisklevels.png)

## ...And Join

Now we have our triggering event, and our enrichment source for dynamic severity assessment. Let's join the two together:

```kql
let SuspiciousInboxRules = CloudAppEvents
| where Timestamp > ago(1h)
| where Application == "Microsoft Exchange Online"
| where ActionType has_any ("New-InboxRule", "Set-InboxRule")
//====Enrich Key Field====//
| extend UserKey = tolower(AccountObjectId)
//====Enrich Key Field====//
| project Timestamp, UserKey, AccountDisplayName, IPAddress, ActionType;
let LatestIdentityRisk = IdentityInfo
| extend UserKey = tolower(AccountObjectId)
| where isnotempty(RiskLevel) and RiskLevel != "None"
| summarize arg_max(TimeGenerated, RiskLevel, RiskLevelDetails) by UserKey;
SuspiciousInboxRules
| join kind=leftouter (LatestIdentityRisk) on UserKey
```

Left-outer join ensures we pull through anything from the left table (the triggering event) even if there's nothing on the right table (the user risk), so we still log that informational event.

## Dynamic Severity - The Quick and Simple Method

Then let us add in our dynamic severity logic based on the user risk level at the time of the mailbox rule creation. You can just add the below to the bottom of the query:

```kql
| extend DynamicSeverity = case(
    RiskLevel == "High", "High",
    RiskLevel == "Medium", "Medium",
    RiskLevel == "Low", "Low",
    "Informational" // no Entra ID risk for this account
)
```

You can also add in your own logic to boot:

1. Is the initiating IP geolocated outside your usual office locations?
2. Is the mailbox rule applying to ALL emails?
3. Does the rule forward emails to an external domain?

To top it off, let's add in a line that shows why the severity is set to what is shown in the alert (optional, but it does speed along the L1 analysis):

```kql
| extend EventTrigger = iif(DynamicSeverity == "Informational", ActionType, strcat(ActionType, " + ", RiskLevel, " risk score."))
```

After all that, we have the full detection:

```kql
let SuspiciousInboxRules = CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Microsoft Exchange Online"
| where ActionType has_any ("New-InboxRule", "Set-InboxRule")
//====Enrich Key Field====//
| extend UserKey = tolower(AccountObjectId)
//====Enrich Key Field====//
| project Timestamp, UserKey, AccountDisplayName, IPAddress, ActionType;
let LatestIdentityRisk = IdentityInfo
| where TimeGenerated >= ago (30d)
| extend UserKey = tolower(AccountObjectId)
| where isnotempty(RiskLevel) and RiskLevel != "None"
| summarize arg_max(TimeGenerated, RiskLevel, RiskLevelDetails) by UserKey;
SuspiciousInboxRules
| join kind=leftouter (LatestIdentityRisk) on UserKey
| extend DynamicSeverity = case(
    RiskLevel == "High", "High",
    RiskLevel == "Medium", "Medium",
    RiskLevel == "Low", "Low",
    "Informational" // no current Entra ID risk assessment on file for this account
  )
| extend EventTrigger = iif(DynamicSeverity == "Informational", ActionType, strcat(ActionType, " + ", RiskLevel, " risk score."))
| project Timestamp, AccountDisplayName, ActionType, IPAddress, RiskLevel, RiskLevelDetails, DynamicSeverity, EventTrigger
```

And the results are in, with some randomised data for illustration.

![Risk level screenshot](/SentinelHunt/blog/results.png)

From this we can assign the dynamic severity to the alert using the `AlertSeverityOverride` function in our analytics rule, so any new mailbox rule in isolation of other risks is purely an informational alert and never hits the SOC. If a user is compromised and their risk score during their sign-in is elevated as a result, we get the alert in the SOC as needed, minus the burn-out risk.

## Closing Thoughts

The approach I have shown here was my first pass at dynamic severity for detection content, and I've since refined this quite a bit. I want to show where I started, as I believe each person will develop their own signature method as they hit the issues I did and find ways around them.

Other enrichment sources exist that will allow you to apply other risk weighting to your scoring, but don't lose sight of what you are trying to alert on and end up alerting on a risk even where the actual triggering event is lost in the noise.

Keep it simple to start, see how your changes impact your detection metrics, and improve iteratively with the metrics to validate that the right changes are being made.

## References

1. [IdentityInfo table in the advanced hunting schema - Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table)
2. [CloudAppEvents table in the advanced hunting schema - Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table)
3. [Risky user report, Microsoft Entra ID Protection - Microsoft Learn](https://learn.microsoft.com/en-us/entra/id-protection/concept-risky-user-report)
4. [Microsoft Entra Risk Detections: April 2026 ID Protection Update Explained - IT trip](https://en.ittrip.xyz/microsoft-365/entra-risk-detections)
5. [Sophos 2026 Active Adversary Report: Identity attacks dominate as threat groups proliferate - Sophos](https://www.sophos.com/en-us/press/press-releases/sophos-active-adversary-report-2026-identity-attacks-dominate-as-threat-groups-proliferate)
6. [You Can't Manage What You Can't Score: Why Identity Security Needs Real Risk Measurement - Permiso](https://permiso.io/blog/why-identity-security-needs-risk-scoring)
7. [Smart SIEM visibility and risk prioritisation are reshaping SOC response - nhimg.org](https://nhimg.org/articles/smart-siem-visibility-and-risk-prioritization-are-reshaping-soc-response/)
8. [MC1052160: Changes to the IdentityInfo table in Advanced Hunting - Microsoft 365 Message Center Archive](https://mc.merill.net/message/MC1052160)
