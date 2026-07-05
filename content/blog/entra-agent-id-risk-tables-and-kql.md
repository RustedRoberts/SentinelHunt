---
title: Your Agents Just Got Entra Identities, Risk Scores, and Sign-In Logs - Here's the KQL
date: 2026-07-05
author: Chris Scott
summary: Microsoft Entra Agent ID turns every AI agent into a first-class identity with its own sign-ins, audit events, and risk detections. Two new Log Analytics tables and an agentic sign-in column mean you can hunt this today.
tags:
  - entra-agent-id
  - ai-agents
  - kql
  - advanced-hunting
  - identity-protection
published: true
---

## Introduction

Back in June, the story was `AIAgentsInfo` - a single Advanced Hunting table
that told you what agents existed in your tenant and where they reached out
to. Useful, but it was inventory. It couldn't tell you whether an agent's
behaviour that morning was normal, whether its credentials had just been used
somewhere unexpected, or who to call when one lit up red.

That gap has closed faster than most SOCs have noticed. Microsoft Entra Agent
ID now treats every agent as a genuine identity object - not a proxy, not a
service principal wearing a costume, but its own principal type with sign-in
logs, audit trail entries, and a dedicated risk detection engine feeding two
new Log Analytics tables. If you're running Microsoft Sentinel or the
Defender portal, this data is queryable in KQL right now, and most of it
plugs directly into hunting patterns you already run against users and
service principals.

This post is the identity half of the picture the June post left open.

## Three Identity Objects, Not One

Microsoft Entra Agent ID splits an agent into three distinct principal types,
each mapped onto an existing Entra construct so the platform's plumbing
(sign-in logs, audit logs, Conditional Access, risk detection) already knows
what to do with it:

- **Agent identity blueprint** - the template. Appears in the audit log as
  *application* events, the same way an app registration would.
- **Agent identity** - a running instance created from a blueprint. Appears
  as *service principal* events. One blueprint can back many instances, the
  same relationship an app registration has with its service principals.
- **Agent's user account** - an optional account paired 1:1 with an agent
  identity, for the (still common) case where a downstream system insists on
  a user object rather than an app identity.

Every audit and sign-in event tags which of these it involves via an
`agentType` property, with values `agenticApp` (blueprint), `agenticAppInstance`
(identity instance), `agentIDuser` (user account), and
`agentIdentityBlueprintPrincipal` (the blueprint's own service principal).
`notAgentic` means exactly what it says - a normal app, user, or service
principal with no agent involvement.

The detail worth sitting with: a blueprint compromise outranks an instance
compromise. Compromise the blueprint and every agent identity spawned from it
inherits the problem. Compromise one instance and the blast radius stops at
that instance. Your triage priority should follow that logic, and as you'll
see below, the new risk tables give you the column to enforce it.

## Where This Lands in KQL

Three things changed that matter for hunting:

**1. `AADServicePrincipalSignInLogs` gained an `Agent` column** - "Details of
agentic sign-in," per the schema reference. Agent sign-in traffic that used
to be indistinguishable from any other service principal sign-in now carries
its own marker in a table most Sentinel deployments already ingest.

**2. Two new risk tables: `AADRiskyAgents` and `AADAgentRiskEvents`.** These
sit alongside the workload identity risk tables (`AADRiskyServicePrincipals`,
`AADServicePrincipalRiskEvents`) that hunters already query, exported the same
way - via Microsoft Entra diagnostic settings to your Log Analytics workspace.
`AADAgentRiskEvents` carries a `RiskEventType` column with eight documented
values: `adminConfirmedAgentCompromised`, `earlyLifeMaliciousActivity`,
`entraDirectoryReconnaissance`, `failedAccessAttempt`,
`threatIntelligenceAccount`, `signInSpike`, `suspiciousCredentialUsage`, and
`unfamiliarResourceAccess`. Both tables carry an `IdentityType` column -
`AgentIdentity`, `AgentUser`, or `AgentIdentityBlueprintPrincipal` - which is
exactly the field you filter on to catch blueprint-level risk before
instance-level risk.

**3. The Sentinel data lake's Agent Identities Asset Connector** adds
identity context for agents the same way `EntraUsers` and
`EntraServicePrincipals` already do for humans and apps - owner, sponsor, and
blueprint lineage, refreshed as a daily snapshot rather than an event stream.

None of the risk detections in `AADAgentRiskEvents` are real-time yet - the
`DetectionTimingType` column will tell you that plainly if you ask it. That's
not a caveat to bury in a footnote; it changes how you use this data. Treat it
as a triage and hunting source, not a blocking control, until Microsoft ships
real-time enforcement to match.

## Queries You Can Run Today

Start with what's already flagged. This surfaces every open risk detection
across both new tables, joined so you get the event-level detail
(`RiskEventType`, `RiskEvidence`) alongside the current state of the agent
itself, and flags offline detections separately since those need a human to
close the loop rather than a Conditional Access policy.

```kql
// ============================================================
// HUNT: Open Agent Risk Detections - State + Evidence
// ============================================================
// Purpose: Surface every agent currently flagged at-risk, joined
//          with the specific detection(s) that triggered it.
//          DetectionTimingType is broken out explicitly - offline
//          detections have no enforcement point behind them yet,
//          so they need to be worked as hunting leads, not treated
//          as already-actioned alerts.
//
// Tables:  AADRiskyAgents, AADAgentRiskEvents
// ============================================================

let OpenRiskyAgents =
    AADRiskyAgents
    | where RiskState == "atRisk"
    | summarize arg_max(TimeGenerated, *) by Id;
AADAgentRiskEvents
| where DetectedDateTime >= ago(30d)
| join kind=inner OpenRiskyAgents on $left.AgentId == $right.Id
| extend NeedsManualReview = DetectionTimingType == "offline"
| project
    DetectedDateTime,
    AgentDisplayName,
    AgentId,
    IdentityType,
    RiskEventType,
    RiskEvidence,
    DetectionTimingType,
    NeedsManualReview,
    RiskLevel,
    RiskState
| order by NeedsManualReview desc, RiskLevel desc, DetectedDateTime desc
```

Next, isolate blueprint-level risk specifically. This is the query worth
promoting to a scheduled analytics rule ahead of the others - a risky
blueprint means every agent it has ever spawned is suspect, not just the one
that tripped the detection.

```kql
// ============================================================
// HUNT: Blueprint-Level Agent Risk - Highest Blast Radius
// ============================================================
// Purpose: Isolate risk detections tied to the blueprint principal
//          itself rather than a single agent instance. A flagged
//          blueprint means every instance spawned from it needs
//          re-review, not just the instance that triggered the
//          detection.
//
// Tables:  AADAgentRiskEvents
// ============================================================

AADAgentRiskEvents
| where IdentityType == "AgentIdentityBlueprintPrincipal"
| where DetectedDateTime >= ago(90d)
| summarize
    DetectionCount   = count(),
    RiskEventTypes   = make_set(RiskEventType),
    FirstDetected    = min(DetectedDateTime),
    LastDetected     = max(DetectedDateTime),
    HighestRiskLevel = max(RiskLevel)
    by AgentId, AgentDisplayName
| order by DetectionCount desc, LastDetected desc
```

Then look at the sign-in side. `suspiciousCredentialUsage` and
`failedAccessAttempt` are both detections you can partially reconstruct
yourself, ahead of Identity Protection scoring them, by watching the `Agent`
column directly:

```kql
// ============================================================
// HUNT: Agentic Sign-Ins with Repeated Failures
// ============================================================
// Purpose: Surface agent sign-in traffic (Agent column populated)
//          with a failure rate high enough to suggest credential
//          replay or an attacker probing what a stolen agent token
//          can reach - the same pattern failedAccessAttempt scores,
//          available here ahead of the offline detection landing.
//
// Tables:  AADServicePrincipalSignInLogs
// ============================================================

AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(7d)
| where isnotempty(Agent)
| summarize
    TotalSignIns  = count(),
    FailedSignIns = countif(ResultType != "0" and ResultType != ""),
    DistinctIPs   = dcount(IPAddress),
    DistinctResources = dcount(ResourceIdentity),
    LastSeen      = max(TimeGenerated)
    by ServicePrincipalId, ServicePrincipalName
| where FailedSignIns > 5 or DistinctIPs > 3
| order by FailedSignIns desc, DistinctIPs desc
```

Finally, close the loop on ownership. A risk score without a name attached to
it just sits in a queue. Joining the risk tables against the data lake's
agent asset tables gets you there in one query if you're running it from the
Sentinel data lake's KQL surface, where both Log Analytics and asset tables
are queryable together:

```kql
// ============================================================
// HUNT: Risky Agents Enriched with Owner Context
// ============================================================
// Purpose: Attach human accountability to every open agent risk
//          detection. Run from the Sentinel data lake KQL surface
//          against the System tables workspace, where both
//          Log Analytics tables and asset tables are queryable
//          side by side.
//
// Tables:  AADRiskyAgents, EntraAgentIdentities, EntraAgentUsers
// ============================================================

let RiskyAgentIds =
    AADRiskyAgents
    | where RiskState == "atRisk"
    | summarize arg_max(TimeGenerated, RiskLevel, RiskDetail, IdentityType) by Id;
EntraAgentIdentities
| join kind=inner RiskyAgentIds on $left.id == $right.Id
| join kind=leftouter (
    EntraAgentUsers
    | summarize by displayName, userPrincipalName, agentIdentitySPID, accountEnabled
) on $left.id == $right.agentIdentitySPID
| project
    AgentDisplayName = displayName,
    RiskLevel,
    RiskDetail,
    IdentityType,
    CreatedDateTime = createdDateTime,
    OwnerDisplayName = displayName1,
    OwnerUpn = userPrincipalName,
    OwnerAccountEnabled = accountEnabled
| order by RiskLevel desc
```

## What's Still Missing

None of this replaces the AI-agent-specific telemetry from June -
`AIAgentsInfo` and the identity data described here are complementary, not
overlapping. `AIAgentsInfo` tells you what an agent is configured to reach.
The Agent ID tables tell you whether its identity is behaving normally. A
mature hunting program will eventually join both, but that's a bigger query
than either data source can support cleanly on its own today, given they sit
in different ingestion paths with different retention defaults.

Licensing is also not uniform yet. ID Protection for agents needs a
Microsoft Entra ID P2 license during preview, moving to a Microsoft Agent 365
license requirement as it matures. The asset connector tables are Sentinel
data lake features, which means data lake onboarding is a prerequisite before
any of the enrichment queries above will return results. And every risk
detection currently listed as offline means detection, not enforcement -
pair the blueprint-level query above with a Conditional Access policy that
blocks on high agent risk, or the finding sits in a queue with nothing
downstream acting on it.

## Closing Thoughts

The pattern here is the same one that showed up with `AIAgentsInfo`: Microsoft
ships the schema first, coverage catches up over months, and the SOCs that
get value early are the ones hunting against what exists rather than waiting
for full parity with human-identity tooling. Agent identities, sign-ins, and
risk detections are queryable in KQL today, sitting next to tables most teams
already ingest. The blueprint-versus-instance distinction is the one detail
worth building into every query from day one - it's the difference between
finding one bad agent and finding the twenty it could have spawned.
