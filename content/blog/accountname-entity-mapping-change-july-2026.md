---
title: Your AccountName Filters Quietly Changed Meaning on July 1 - Here's What Else Moved in KQL Detection Content This Month
date: 2026-07-08
author: Chris Scott
summary: Microsoft finished rolling out a change to how the Account entity is populated on analytics rule alerts, and the cutover date was July 1, 2026. If anything in your environment does exact-match filtering on AccountName, it may have started failing silently a week ago. Plus two other things worth knowing about right now - detection-as-code landing for custom detection rules, and a mass vulnerability disclosure that turned into 54 open KQL rules overnight.
tags:
  - kql
  - detection-engineering
  - analytics-rules
  - sentinel
  - threat-hunting
published: true
---

## Introduction

Most changes to detection content announce themselves. A rule stops firing, a workbook breaks, someone opens a ticket. The change that shipped across Microsoft Sentinel this month is the opposite kind - it does not break anything visibly. Queries keep running. Automation rules keep executing. Dashboards keep rendering. The only symptom is that some of them quietly stop matching the thing they were built to match.

That is the **Account Name entity mapping change**, and the compliance deadline for it was July 1, 2026 - a week before this post. If you have not already gone looking for it, it is worth ten minutes of your afternoon, because "nothing looks broken" and "nothing is broken" are not the same claim when the failure mode is a filter that silently stops matching.

This post covers three things happening in KQL detection content right now: the AccountName change and what to do about it, detection-as-code arriving natively for custom detection rules, and a genuinely unusual mass-disclosure event that produced 54 community-authored KQL rules in the space of about two weeks.

## The Change: Account Name Is Now Always the UPN Prefix

Here is the mechanic. When an analytics rule maps a full User Principal Name (`jdoe@contoso.com`) into the Account entity's Name field, Microsoft Sentinel used to be inconsistent about what ended up in `AccountName` downstream - sometimes the full UPN, sometimes just the prefix. As of the July 1, 2026 cutover, that inconsistency is gone: `AccountName` is now **always** the UPN prefix (`jdoe`), full stop. Two new fields, `UserPrincipalName` and `UPNSuffix`, were added to the account entity to carry the rest of what used to live in `AccountName`.

Microsoft's own framing of the before/after is worth quoting directly, because it is the clearest statement of what actually changes:

- **Before:** Analytics rule fires on `jdoe@contoso.com` → downstream automation rule sees `AccountName` = `jdoe` **or** `jdoe@contoso.com`, inconsistently.
- **After:** Analytics rule fires on `jdoe@contoso.com` → `AccountName` = `jdoe`, always. `UPNSuffix` = `contoso.com`, separately.

If every consumer of that field already treated `AccountName` as "probably just the prefix, sometimes not," this change is a welcome cleanup. If anything - an automation rule condition, a Logic App, a workbook query, a hunting query built on top of `SecurityAlert` entities - relied on the "sometimes full UPN" branch with an exact-equality check, that branch just stopped matching. No error, no incident, no log entry. The condition silently evaluates false where it used to evaluate true.

A related, earlier notice (first published October 2025, updated through the April 2026 "what's new" release) establishes the resolution order Sentinel now applies when picking an identifier for an account entity, and gives the fix directly in KQL:

1. **UPN prefix** - the part before `@` in a UPN
2. **Name** - used if UPN prefix is unavailable
3. **Display Name** - fallback if both are missing

Microsoft's guidance for any KQL that consumes this precedence is to stop doing strict equality against a single field and instead use `coalesce()`:

```kql
coalesce(Account.UPNprefix, Account.Name, Account.DisplayName)
```

## What This Actually Breaks

Three places to check, roughly in order of how often they bite people:

**Automation rules and Logic Apps playbooks.** Anything with a condition like `AccountName Equals jdoe@contoso.com` needs to move to a `Contains` or `Starts with` check against the prefix, plus a separate check against the new `UPNSuffix` field if the domain matters. Microsoft's recommended replacement pattern:

```text
AccountName  Contains  jdoe        (or Starts with)
UPNSuffix    Equals    contoso.com (or Starts with / Contains)
```

**Hunting queries and workbooks that parse entities off `SecurityAlert`.** If you have anything shaped like this:

```kql
SecurityAlert
| mv-expand Entity = parse_json(Entities)
| where Entity.Type == "account"
| extend AccountName = tostring(Entity.Name)
| where AccountName == "jdoe@contoso.com"
```

that `where` clause now compares against a bare prefix on one side and a full UPN on the other, and will not match post-cutover. Rewrite it to build the comparison value the same way Sentinel now does:

```kql
SecurityAlert
| mv-expand Entity = parse_json(Entities)
| where Entity.Type == "account"
| extend
    AccountName = tostring(Entity.Name),
    UPNSuffix   = tostring(Entity.UPNSuffix),
    DisplayName = tostring(Entity.DisplayName)
| extend ResolvedIdentity = coalesce(AccountName, DisplayName)
| where ResolvedIdentity == "jdoe" and UPNSuffix == "contoso.com"
```

**Any detection promoted from a hunting query into a scheduled analytics rule with entity mapping.** This is the one that is easy to miss, because the KQL itself never touched `AccountName` - the entity mapping configuration on the rule did the work of populating it. If a rule maps an Account entity and something downstream consumes that entity by name, it is in scope even though nothing in the query text mentions `AccountName` at all.

None of this requires urgent panic - the change has been telegraphed since October 2025, and most environments will find the actual blast radius is a handful of automation rules rather than dozens. But "telegraphed since October" and "actually gone and checked every consumer" are two different states, and the gap between them is exactly where a detection quietly stops doing its job.

## Also Worth Knowing: Detection-as-Code for Custom Detection Rules

Buried in July 2026's release notes is a feature that matters more than its one-line description suggests: **custom detection rules now support Microsoft Sentinel Repositories (Preview)**. You can manage custom detection rules as code in GitHub or Azure DevOps using the Microsoft Security BICEP extension, sync them into Sentinel through Repositories, or deploy them directly with the BICEP CLI.

This closes a gap that has existed since Sentinel Repositories went GA in March 2026 - analytics rules, hunting queries, and workbooks could already be managed as code, but custom detection rules (the Defender XDR-native rule type, distinct from Sentinel scheduled analytics rules) were still a portal-only, click-through experience. If you have been maintaining a hunt library the way this site does - versioned files, pull requests, a documented rationale per query - this is Microsoft moving the platform's own workflow closer to that model rather than the other way around. Worth watching if your team runs both rule types and has wanted one CI/CD story instead of two.

## Also Worth Knowing: 54 Community KQL Rules, Zero Vendor Coordination

On June 23, 2026, an anonymous researcher operating under the handle "bikini" released proof-of-concept material for 15+ distinct vulnerabilities across 109+ files, without prior vendor notification - a research dump that became known as the "exploitarium" disclosure. Within roughly two weeks, a separate GitHub repository (`Exploitarium-Detections`) had assembled **54 KQL detection rules** for Microsoft Sentinel and Defender XDR covering the disclosed vulnerabilities across 23 affected products, including libssh2, Splunk, 7-Zip, RustDesk, AnyDesk, curl, Docker, and Firefox.

The headline vulnerability is `CVE-2026-55200`, a pre-authentication remote code execution flaw in libssh2 (CVSS 9.2, triggered by oversized `packet_length` values during SSH key exchange causing heap corruption). It alone has five associated rules covering the pre-auth RCE pattern, malicious cipher-negotiation scaffolding, harness execution, linkage reconnaissance (`ldd` / `readelf` / `strings` against the target binary), and the public-key heap-corruption PoC itself - a reasonable illustration of what "detection coverage" looks like for a single CVE when someone builds it properly: not one rule, but a set covering recon, exploitation, and post-exploitation artifact patterns.

Treat this the way you would treat any KQL sourced from a repository you do not control: useful as a starting point and a reference for what the exploitation pattern looks like, not something to deploy as a scheduled analytics rule without reading every line first. Rules built from PoC analysis in the days after an uncoordinated disclosure are a fast first draft, not a validated detection - false-positive tuning against your own environment is still your job.

## Closing Thoughts

None of these three items is dramatic on its own. A field got more consistent. A preview feature closed a gap in content management. A community responded quickly to an unusual disclosure. But together they are a reasonable snapshot of what "detection content" means right now: it lives partly in your KQL, partly in entity mapping configuration you don't see in the query text, and increasingly partly in how that content gets versioned and shipped in the first place.

The concrete action item this week is the first one. Go find every place `AccountName` gets compared for equality - automation rules, playbooks, entity-parsing hunting queries, workbooks - and check whether the cutover changed what it matches. It has been a quiet week. That is exactly the kind of week worth double-checking.
