---
title: "Too Many Commands! Finding Domain Account Enumeration"
date: 2026-08-08
author: Chris Scott
summary: Command-based detection for domain account enumeration is trivially evaded - aliasing, runtime string building, or switching tools entirely all defeat it. IdentityQueryEvents lets you watch the protocol instead, where the freedom to evade runs out.
tags:
  - kql
  - advanced-hunting
  - detection-engineering
  - active-directory
  - identity
published: true
---

I spent an afternoon recently doing something I would recommend to any detection engineer: trying to break my own rules.

The concept is fairly simple. Take one of your detections looking for particular behaviour, such as account enumeration, and see how many different ways you can achieve the answer "Account X is Domain Admin." I lost count somewhere around a dozen, and I had not even left PowerShell.

That session confirmed something I had believed for a while but never properly pressure-tested. Detection content that keys on a specific tool or command is brittle and easy to evade, not because the people writing it are careless, but because the thing being watched has almost unlimited freedom to change how it looks while doing identical work underneath.

Domain account enumeration earns the spotlight because it sits at the very start of nearly every Active Directory attack. Before anyone sprays a password, roasts a service account, or plots a route to Domain Admin, they answer one question first: who is in this domain, and which of them matter?

## Many methods, many detections?

Start with the obvious version. A defender writes a rule to catch Account Discovery: Domain Account (T1087.002) by looking for `Get-ADUser` in command line or script block logs. Reasonable first move, and it will catch the lazy and the unaware, which is worth something.

Now watch how little effort it takes to walk around it. You can alias the cmdlet to a name of your choosing. You can build the name as a string at runtime and call it indirectly, so the text `Get-ADUser` never appears in one piece anywhere. You can split the name with a backtick mid-word and the parser will happily reassemble it. Each of these defeats a rule that matches the literal command, and none of them changes what the command does.

Then you can leave the cmdlet behind entirely. The `[adsisearcher]` type accelerator gives you a directory search with no module import and no recognisable command name, using an interface that has shipped with Windows for decades. WMIC offers two more routes: its dedicated LDAP namespace runs a real directory query, while its simpler user account class pulls domain accounts through a different mechanism again. Older still, `net user /domain` and `net group` do the job without any of the above, and that is before we reach `dsquery` or the offensive tooling that automates the lot.

None of this is secret. Public enumeration references now catalogue these techniques grouped not by tool but by the protocol each one reaches the directory through.

## Where every path leads - the nexus to monitor

This is where the Defender XDR `IdentityQueryEvents` table becomes interesting, and why I think it deserves more attention than it gets in most hunting and detection programmes.

The table records directory queries as seen at the domain controller itself, through Defender for Identity. By the time any of those techniques reaches the DC, the obfuscation, the aliasing, and the runtime string building have all been translated down into an ordinary protocol request. It does not care how you typed the query - it standardises the log data and exposes the activity underneath.

The columns worth knowing:

- `ActionType` - tells you whether the request arrived over LDAP, DNS, or as a SAM-R query, and is the field you pivot on
- `Query` and `QueryTarget` - hold what was actually asked for
- `AccountUpn`, `AccountObjectId`, and `AccountSid` - identify who asked
- `DeviceName` and `Application` - tell you where it came from

A starting query looks like this:

```kql
IdentityQueryEvents
| where Timestamp > ago(30d)
| where (QueryType == "EnumerateUsers" and (Query contains "admin" or QueryTarget contains "admin"))
    or ActionType in ("SAMR query", "SamrQuerySuccess")
| project TenantId, Timestamp, AccountUpn, AccountObjectId, AccountSid, DeviceName, Application, ActionType, QueryType, QueryTarget, Query, ReportId
```

Run it without the narrowing conditions first to see what your own environment actually populates, then tighten it.

Most of the useful detail in this table does not live in the flat columns at all. It sits in the nested `AdditionalFields`. Parse that out and you get the source device, the domain controller that observed the query, the result count, and, on a group query, the target group as a SID rather than only a name.

Microsoft even folds its own ATT&CK classification in there, so a SAM-R query for the membership of a privileged group arrives already tagged as Permission Groups Discovery (T1069) and Account Discovery (T1087). The mapping you would otherwise write by hand is handed to you.

```kql
IdentityQueryEvents
| where Timestamp > ago(30d)
| where ActionType == "SAMR query" and QueryType == "QueryGroup"
| extend AF = todynamic(AdditionalFields)
| extend TargetGroup  = tostring(AF["TARGET_OBJECT.GROUP"]),
         GroupSid     = tostring(AF["TARGET_OBJECT.GROUP_SID"]),
         SourceDevice = tostring(AF["FROM.DEVICE"]),
         ObservedByDC = tostring(AF["TO.DEVICE"])
| extend Rid = tolong(extract(@"-(\d+)$", 1, GroupSid))
| project TenantId, Timestamp, SourceDevice, ObservedByDC, TargetGroup, GroupSid, Rid, ReportId
```

Take the last segment of the group SID, match it against the set of well-known privileged RIDs, and you have a detection that is rename-proof and portable across every environment you run it in, with no hard-coded names at all.

```kql
IdentityQueryEvents
| where Timestamp > ago(30d)
| where ActionType == "SAMR query"
| extend AF = todynamic(AdditionalFields)
| extend TargetName   = coalesce(tostring(AF["TARGET_OBJECT.GROUP"]), tostring(AF["TARGET_OBJECT.USER"])),
         TargetSid    = coalesce(tostring(AF["TARGET_OBJECT.GROUP_SID"]), tostring(AF["TARGET_OBJECT.USER_SID"])),
         SourceDevice = tostring(AF["FROM.DEVICE"]),
         ObservedByDC = tostring(AF["TO.DEVICE"])
| extend TargetRid = tolong(extract(@"-(\d+)$", 1, TargetSid))
| where TargetRid in (500, 501, 502, 512, 513, 514, 515, 516, 517, 518, 519, 520)   // 502 = krbtgt, 512 = Domain Admins
| extend AttackTechniques = split(AdditionalFields.AttackTechniques, ",")
| project TenantId, Timestamp, ActionType, QueryType, SourceDevice, ObservedByDC, TargetName, TargetSid, TargetRid, AccountObjectId, AccountSid, ReportId, AttackTechniques
| sort by Timestamp desc
```

Domain Admins is RID 512 in every domain, in every tenant, and you cannot renumber it. Rename the group - which is supported and occasionally done as weak hardening - and a name-based rule goes blind while the RID sits there unchanged. Watch the RID, not the name.

The full list of well-known RIDs is documented on [Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers).

## What this does not solve on its own

I would be doing exactly what I am criticising if I sold this off as a silver bullet detection. It is a better foundation, but it still comes with its own issues, considerations, and dependencies.

### Configuration dependency

The Active Directory PowerShell module - the most innocent-looking tool in the whole set - does not speak raw LDAP. It reaches the directory over Active Directory Web Services, and those queries only appear in the table once event 1644 auditing is enabled on your domain controllers.

### Maturity

As written, that query is still a fixed-condition rule. Any identity or application making a query is part of the whole dataset returned when you run this - there is no identifying what should be sending these queries versus what should never appear in the logs at all.

The natural next step is bringing in identity context, so you can tell a Tier 0 account or a known helpdesk tool apart from a random workstation. The signal shifts from an event to a behaviour.

The RID trick has the same limit worth naming, too. Well-known groups carry well-known RIDs that travel between tenants for nothing, but a custom privileged group - some bespoke local-admins group - gets whatever RID its own domain handed out, and that number means nothing anywhere else. Catching enumeration of those needs a per-tenant watchlist of the SIDs or names that matter to you, which is the identity-context problem again wearing a different hat.

### Scope

This table watches on-premises directory traffic. An attacker enumerating identities purely in the cloud, through the Graph API against Entra ID, may never touch a domain controller at all and would not surface here. That is a different telemetry surface with its own logs. Treat `IdentityQueryEvents` as the nexus for the on-premises AD protocol surface - hard to avoid - rather than a single catch-all for every form of identity enumeration.

## Closing Thoughts

Any time you find yourself writing the fifth rule to catch the fifth way of doing the same thing, it is worth stepping back to ask what all five have in common further down the stack, and whether you can watch that instead.

Attackers have enormous freedom at the command layer and very little at the protocol layer, because the protocol is where the work actually happens. Detection built at that chokepoint forces them to leave the protocol entirely rather than simply retype the request, and that is a far harder thing to ask of them.

None of this makes command-string detection worthless. It is cheap, it is fast, and it will catch known tooling by signature. Keep it. Just don't consider it "job done" and assume the MITRE technique is covered.

## References

1. [IdentityQueryEvents table, advanced hunting schema - Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityqueryevents-table)
2. [What's new archive, Microsoft Defender for Identity (LDAP query event and event 1644 history) - Microsoft Learn](https://learn.microsoft.com/en-us/defender-for-identity/whats-new-archive)
3. [Account Discovery: Domain Account (T1087.002) - MITRE ATT&CK](https://attack.mitre.org/techniques/T1087/002/)
4. [Permission Groups Discovery: Domain Groups (T1069.002) - MITRE ATT&CK](https://attack.mitre.org/techniques/T1069/002/)
5. [Active Directory User Enumeration: A Comprehensive Guide - Hacking Articles](https://www.hackingarticles.in/active-directory-user-enumeration-a-comprehensive-guide/)
6. [WMIC commands - The Red Team Vade Mecum](https://kwcsec.gitbook.io/the-red-team-handbook/techniques/enumeration/recon-commands/wmic-commands)
7. [Convert SID to User/Group Name and User to SID - Windows OS Hub](https://woshub.com/convert-sid-to-username-and-vice-versa/)
