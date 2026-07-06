---
title: Behaviors Can Now Link Straight to an Incident - So It's Time to Actually Hunt in BehaviorInfo
date: 2026-07-06
author: Chris Scott
summary: Microsoft shipped a preview in June 2026 that turns a single BehaviorInfo record into an incident with entities pre-populated. That is a good enough reason to stop treating the behaviors layer as a UEBA side feature and start building hunting queries against it.
tags:
  - advanced-hunting
  - ueba
  - kql
  - behaviorinfo
  - threat-hunting
published: true
---

## Introduction

`BehaviorInfo` has been sitting in the Advanced Hunting schema for a while,
quietly filed under UEBA and mostly ignored outside the workbook it powers.
Most hunters I talk to know it exists the way they know `CloudAppEvents`
exists - present, occasionally referenced in a dashboard, never the table
they reach for first.

Two things changed that this year. In February 2026, the UEBA behaviors
layer went generally available, adding a dedicated **Hunting** tab to the
behaviors workbook. In June 2026, Microsoft shipped a preview that lets you
select a single behavior record and link it directly to a new or existing
incident - the wizard creates the alert, pulls the MITRE ATT&CK mapping,
and pre-populates impacted and related entities straight from
`BehaviorEntities`.

That second change is the one worth paying attention to. A table you can
query is useful. A table where a single row can become a scoped, entity-rich
incident with two clicks is a workflow. If you have not written a hunting
query against `BehaviorInfo` yet, this is the point where that stops being
optional.

## What Actually Shipped

`BehaviorInfo` and `BehaviorEntities` are populated from two sources:
Microsoft Defender for Cloud Apps and Microsoft Sentinel UEBA. Both tables
carry a `ServiceSource` column specifically so you can tell which one
generated a given row - filter to `ServiceSource == "Microsoft Sentinel"`
if you only want UEBA-generated behaviors and not Defender for Cloud Apps
activity mixed into the same result set. Microsoft calls this out explicitly
in their own guidance, which tells you it is a real gotcha, not a footnote.

If you are working from a Sentinel workspace rather than the Defender
portal, the equivalent tables are `SentinelBehaviorInfo` and
`SentinelBehaviorEntities` - same schema, narrower scope, limited to UEBA
behaviors generated from data ingested into that specific workspace. Use the
Defender portal tables for detection rules, incident investigation, and
hunting; use the Sentinel workspace tables for workbooks and ingestion
monitoring.

The behaviors layer aggregates raw, high-volume telemetry - AWS CloudTrail,
GCP audit logs, CommonSecurityLog sources like CyberArk Vault and Palo Alto
firewall logs - into normalised behavior records mapped to MITRE ATT&CK
tactics and techniques. A behavior like "Suspicious mass secret access via
AWS IAM by a given user" can represent twenty raw CloudTrail events collapsed
into one row with `AttackTechniques` already populated. That is the pitch:
hunt on TTPs and titles instead of re-deriving them from raw logs every
time.

The June 2026 addition is the **link a behavior result to an incident**
workflow. Query `BehaviorInfo`, select one `BehaviorId`, select **Link to
incident**, and the wizard auto-populates alert title, category,
description, and MITRE mapping from the behavior record, then pulls
impacted assets and related evidence from `BehaviorEntities`. You still
control severity and recommended actions, and everything is editable before
you commit. It is currently scoped to one behavior at a time and only fully
supports UEBA entity types - non-UEBA behaviors may need manual entity
mapping.

## Why This Matters for Hunters, Not Just Analysts

The incident-linking workflow is built for triage, but it changes the
calculus for hunting too. A hunting query that used to end in "write this up
and open a ticket manually" now ends in "select the row, link to incident,
done." That lowers the bar for promoting a hunt finding to something an
incident responder actually works, which means it is worth spending the
time to write good `BehaviorInfo` queries rather than treating the table as
something you only touch inside the prebuilt workbook.

The `Categories` field carries the MITRE tactic-level classification, and
`AttackTechniques` carries technique IDs. Both are queryable directly,
which means a hunt across the behaviors layer looks less like a SIEM query
and more like a search problem: which techniques have you seen, how often,
against which accounts, and how does that compare to what is already sitting
in open incidents.

## Hunting Queries

**Rare and infrequent behaviors by tactic.** Behaviors that map to
higher-risk tactics but occur rarely for a given title are worth surfacing
even without a specific alert - a single occurrence of a credential-access
or persistence behavior is a different risk profile than the same title
appearing hundreds of times a day as background noise.

```kql
BehaviorInfo
| where ServiceSource == "Microsoft Sentinel"
| where Categories has_any (dynamic(["CredentialAccess", "Persistence", "PrivilegeEscalation"]))
| summarize
    Occurrences = count(),
    Accounts    = make_set(AccountUpn),
    FirstSeen   = min(StartTime),
    LastSeen    = max(EndTime)
    by Title, Categories
| where Occurrences <= 3
| order by LastSeen desc
```

**Full entity correlation for a time window.** `BehaviorInfo` on its own
tells you what happened; `BehaviorEntities` tells you who and what was
involved. Both tables share `BehaviorId` as the join key, and pre-projecting
each side avoids the column collisions you get if you join the tables raw -
both carry overlapping columns like `ServiceSource`, `DetectionSource`, and
`Categories`.

```kql
BehaviorInfo
| where ServiceSource == "Microsoft Sentinel"
| where StartTime >= ago(7d)
| project BehaviorId, Title, AttackTechniques, Categories, AccountUpn, StartTime, EndTime
| join kind=inner (
    BehaviorEntities
    | where ServiceSource == "Microsoft Sentinel"
    | project BehaviorId, EntityType, EntityRole, FileName, FolderPath
) on BehaviorId
| extend EntityLabel = iif(isempty(FileName), EntityType, strcat(EntityType, ": ", FileName))
| summarize
    ImpactedEntities = make_set_if(EntityLabel, EntityRole == "Impacted"),
    RelatedEntities  = make_set_if(EntityLabel, EntityRole != "Impacted")
    by BehaviorId, Title, AttackTechniques, Categories, AccountUpn, StartTime, EndTime
| order by StartTime desc
```

**Promotion candidates: high-risk behaviors on dormant accounts.** The most
useful pattern I keep coming back to across this whole schema - AIAgentsInfo
included - is cross-referencing a finding against recent legitimate sign-in
activity. A credential-access or exfiltration behavior tied to an account
that has not interactively signed in for over a month is exactly the kind
of row you want pre-scoped and ready for the link-to-incident wizard, not
sitting in a query result waiting for someone to notice it.

```kql
BehaviorInfo
| where ServiceSource == "Microsoft Sentinel"
| where Categories has_any (dynamic(["CredentialAccess", "Persistence", "PrivilegeEscalation", "Exfiltration"]))
| where isnotempty(AccountUpn)
| join kind=leftouter (
    EntraIdSignInEvents
    | where Timestamp >= ago(30d)
    | summarize LastInteractiveSignIn = max(Timestamp) by AccountUpn
) on AccountUpn
| where isnull(LastInteractiveSignIn) or LastInteractiveSignIn < ago(45d)
| project BehaviorId, Title, Categories, AttackTechniques, AccountUpn, StartTime, EndTime, LastInteractiveSignIn
| order by StartTime desc
```

## What to Check Before You Rely on This

Both tables are still marked Preview and are not available in GCC. Coverage
depends entirely on what is onboarded - the UEBA behaviors layer's public
preview data sources are limited to AWS CloudTrail, CommonSecurityLog
(CyberArk Vault, Palo Alto Threats), and GCP audit logs, alongside whatever
Defender for Cloud Apps contributes. An empty result set from these queries
tells you nothing about your actual environment if the relevant connectors
were never onboarded.

Linking a behavior to an incident requires the same permissions as managing
custom detections, plus access to both `BehaviorInfo` and `BehaviorEntities`.
And the entity auto-population in the link-to-incident wizard is built
around UEBA entity types specifically - behaviors sourced from Defender for
Cloud Apps may need entities mapped by hand, which is worth knowing before
you promise a team this is a one-click workflow for every row in the table.

## Closing Thoughts

The behaviors layer was designed to spare analysts from manually stitching
together raw CloudTrail and firewall events during an investigation. That is
a fine use case, but it undersells what the table is actually good for. A
schema that arrives pre-tagged with MITRE tactics and techniques, keyed
consistently by `BehaviorId`, joinable to entity data and now linkable
directly to an incident, is a hunting surface first and a UEBA convenience
feature second.

The queries above are a starting point, not a finished detection strategy.
Run the rare-behavior hunt against your own tenant, see what tactics show up
and how often, and decide which titles are worth watching on a schedule
rather than ad hoc. The tooling to act on what you find just got
meaningfully faster - it is worth having queries ready before you need them.
