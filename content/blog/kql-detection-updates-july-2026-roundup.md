---
title: KQL Detection Roundup - What Changed Across Sentinel, Defender XDR, and the Hunting Community This Month
date: 2026-07-01
author: Chris Scott
summary: An account entity change lands today with a hard deadline for existing automation. Custom detections are quietly merging Sentinel and Defender XDR onto a new schema. And the community keeps shipping CVE-driven KQL faster than most SOCs can review it.
tags:
  - kql
  - advanced-hunting
  - sentinel
  - defender-xdr
  - threat-hunting
  - roundup
published: true
---

## Introduction

This is the first in what's intended to be a recurring check-in on the KQL
detection landscape - official platform changes from Microsoft, plus what's
moving in the wider threat hunting community. Two threads dominate this
cycle: a breaking change to how account entities resolve in Sentinel that
takes effect **today**, and the ongoing migration of detection logic from
Sentinel's classic Log Analytics schema onto the Unified schema that powers
custom detections in the Defender portal.

## The account entity deadline is today, not "coming soon"

Microsoft has been running a phased change to how the `Account` entity
resolves in Sentinel incidents and alerts, and the compliance deadline is
**July 1, 2026**. If you have automation rules, playbooks, or hunting queries
that compare `AccountName` against a full UPN (`user@contoso.com`), they may
already be silently failing.

The short version: `AccountName` used to be inconsistent - sometimes the UPN
prefix (`user`), sometimes the full UPN (`user@contoso.com`), depending on
how the analytics rule mapped it. As of today, it consistently resolves to
the UPN prefix only, and Sentinel adds dedicated `UserPrincipalName` and
`UPNSuffix` fields to the account entity so you can reconstruct the full
value when you need it.

Microsoft's guidance is to stop doing strict equality checks on `AccountName`
and use a precedence-aware pattern instead:

```kql
// ============================================================
// PATTERN: Account entity resolution post-July 2026
// ============================================================
// Purpose: Resolve the most reliable account identifier now that
//          AccountName is consistently the UPN prefix only.
//          Falls back through Name and DisplayName for records
//          where UPN mapping wasn't available.
// ============================================================
coalesce(Account.UPNprefix, Account.Name, Account.DisplayName)
```

If your automation rules or playbooks do `AccountName equals user@contoso.com`,
replace that with a `Contains`/`Starts with` check against the prefix, plus a
separate check against `UPNSuffix` if you need the full identity. Test in a
non-production workspace first - this is exactly the kind of change that
passes CI and then quietly drops incidents from automated triage.

## Custom detections are merging Sentinel and Defender data - on a new schema

The bigger structural shift this cycle is the continued push toward **custom
detections** in the Defender portal as the unified way to write scheduled KQL
across both Sentinel and Defender XDR data. Conceptually these work like
analytics rules - scheduled KQL that returns results and can raise alerts -
but they run against the Defender portal's **Unified table schema**, not the
classic Log Analytics schema that existing Sentinel analytics rules use.

That distinction matters if you're planning to port anything: rules built
against Log Analytics tables and columns don't drop in unchanged. Some column
names differ between the two schemas, and a portion of Log Analytics columns
don't have a direct equivalent in the Unified schema, which means detection
logic - not just table/column names - sometimes needs to be reworked rather
than just renamed. Before migrating a batch of analytics rules to custom
detections, it's worth doing a pass over your rule library to flag which ones
reference Log Analytics-specific columns so you're not surprised by a query
that deploys clean but silently stops matching.

This sits inside a longer timeline worth keeping on the radar: Sentinel in
the Azure portal is being wound down in favor of the Defender portal, with
full Defender-portal-only support already in effect and Azure portal support
ending March 31, 2027.

## What else shipped in June 2026

Straight from Microsoft's official changelog:

- **Link behavior results to incidents in advanced hunting (Preview)** - You
  can now take a result row from the `BehaviorInfo` table (Sentinel UEBA) and
  link it directly to a new or existing incident from within advanced
  hunting. The wizard auto-populates alert metadata and entities from the
  behavior record, which closes a gap where UEBA behaviors were useful for
  context but awkward to formally attach to a case.
- **Reason over Sentinel graphs with the graph tool (Preview)** - The graph
  tool collection in the Sentinel MCP server adds visual, graph-based
  exploration across identities, devices, threats, and signals, aimed at
  assessing coverage and configuration gaps rather than just individual
  incidents.

And from May 2026, still relevant if you haven't reviewed UEBA settings
recently:

- **UEBA now supports `OktaV2_CL`** alongside the legacy `Okta_CL` table,
  extending the existing Anomalous Activity and Anomalous MFA Failures
  detections to the newer Okta connector format - no new anomaly types, just
  wider coverage for anyone who has migrated connectors.
- **Five new GCP Audit Logs anomaly detections** covering unusual login
  behavior, privileged actions, resource deployments, secret/KMS key access,
  and infrastructure usage patterns - worth a look if you have GCP audit logs
  flowing into Sentinel and haven't touched UEBA config since the connector
  went in.

## What the hunting community is shipping

Outside of Microsoft's own roadmap, two things stood out this cycle:

**CVE-to-KQL turnaround is getting faster.** Multiple independent detection
write-ups this month produced ready-to-deploy KQL candidates for actively
exploited vulnerabilities within days of disclosure, including the Check
Point Remote Access VPN/Mobile Access authentication bypass
(CVE-2026-50751, CVSS 9.3, linked with medium confidence to a Qilin
ransomware affiliate), the PAN-OS GlobalProtect authentication bypass
(CVE-2026-0257), and the Ivanti Sentry auth-bypass/RCE pair
(CVE-2026-10520/CVE-2026-10523). If any of these products are in your
environment, treat "we don't have a detection yet" as a gap worth closing
this week rather than next quarter - all three have confirmed in-the-wild
exploitation.

**T1562.008 (cloud logging suppression) is getting more attention as a
hunting target in its own right**, rather than just a footnote inside
ransomware playbooks. The idea - hunt for the *absence* of expected logging
rather than only for malicious activity within it - translates cleanly to
Sentinel:

```kql
// ============================================================
// HUNT: Diagnostic Setting Tampering - Logging Suppression
// ============================================================
// Purpose: Surface changes that disable or narrow diagnostic
//          settings, a common precursor to defense evasion via
//          logging suppression (MITRE T1562.008). Pair with a
//          gap-detection query (expected log source goes silent)
//          for better coverage than tampering events alone.
// ============================================================
AzureActivity
| where OperationNameValue in (
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE",
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE")
| where ActivityStatusValue == "Success"
| extend Actor = coalesce(Caller, tostring(parse_json(Authorization).evidence.principalId))
| project TimeGenerated, OperationNameValue, Actor, ResourceId, ResourceGroup, SubscriptionId
| order by TimeGenerated desc
```

Treat this as a starting point rather than a finished hunt - the real value
is joining it against a "log source went quiet" gap-detection query so you
catch suppression whether it happens via an explicit diagnostic-setting
change or via a stopped/throttled connector.

**Established repos worth bookmarking if you don't already have them**:
[Bert-JanP/Hunting-Queries-Detection-Rules](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules)
and [SlimKQL/Hunting-Queries-Detection-Rules](https://github.com/SlimKQL/Hunting-Queries-Detection-Rules)
both continue to add out-of-the-box advanced hunting and custom detection
queries organized by product and MITRE ATT&CK technique, and
[reprise99/Sentinel-Queries](https://github.com/reprise99/Sentinel-Queries)
has useful vulnerability-management-flavoured queries (known exploited
vulnerabilities, highest-exposed devices) that pair well with Defender
Vulnerability Management data.

One flag rather than a recommendation: a researcher published a large batch
of KQL detections (15 vulnerability targets, ~100+ files) tied to an
anonymous vulnerability disclosure released without vendor notification in
late June. The detection content itself is defensive, but disclosure without
vendor coordination means affected products may still be unpatched while the
exploitation details are public - validate carefully before deploying
anything sourced this way, and don't assume the underlying vulnerabilities
have fixes available yet.

## Takeaways

1. **Today**: audit automation rules and playbooks for strict `AccountName`
   equality checks against full UPNs - they need the `coalesce()` pattern
   above or they'll start missing matches.
2. **This sprint**: if you're planning or mid-way through a Sentinel →
   Defender portal custom detections migration, inventory which analytics
   rules touch Log Analytics-only columns before you port them.
3. **This week**: confirm you have detection coverage for CVE-2026-50751
   (Check Point), CVE-2026-0257 (PAN-OS), and CVE-2026-10520/10523 (Ivanti
   Sentry) if those products are in your environment - all three are
   confirmed under active exploitation.
