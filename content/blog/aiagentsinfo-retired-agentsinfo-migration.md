---
title: The Table I Wrote About Last Month Is Already Gone - Migrating AIAgentsInfo Hunts to AgentsInfo
date: 2026-07-12
author: Chris Scott
summary: AIAgentsInfo, the table behind last month's agent-hunting post, was retired on 1 July 2026. Its replacement, AgentsInfo, is a bigger table with a different shape. Here's the column mapping and what it means for the hunts built on the old schema.
tags:
  - ai-agents
  - advanced-hunting
  - kql
  - agent-365
  - schema-migration
published: true
---

## Introduction

Last month's post on this blog walked through hunting AI agent misconfiguration
using the `AIAgentsInfo` table - regex-extracted URLs from `RawAgentInfo`,
JSON-parsed knowledge sources, MCP servers pulled out of `AgentToolsDetails`.
As of 1 July 2026, that table is gone. Queries built against it - including
the ones in that post - now return nothing.

This isn't a case of Microsoft quietly breaking things. The deprecation was
flagged in the [advanced hunting schema change log](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-changes)
back in early June, with a hard cutoff date attached. But it's a useful
reminder for anyone building hunts on preview tables: schema in the
`AIAgentsInfo` / `AgentsInfo` generation is moving fast, and content written
against it has a shelf life measured in weeks, not the months or years you'd
expect from `DeviceProcessEvents` or `SigninLogs`. If you copied last month's
queries into a saved hunting query or a workbook, they need attention now.

## What actually changed

`AIAgentsInfo` was built for Copilot Studio specifically, and its schema
showed it - fields like `KnowledgeDetails`, `AgentActionTriggers`, and
`AgentToolsDetails` all carried Copilot Studio's internal JSON shapes, which
is why the original hunt needed regex extraction and `mv-expand` gymnastics
to pull anything structured out of them.

`AgentsInfo` is a wider table covering agent inventory across platforms -
Copilot Studio, Microsoft Foundry, Microsoft 365 Copilot, third-party agents,
and endpoint-discovered agents alike. The result is a schema with more
first-class columns and less need to parse blobs of raw JSON to get at basic
facts about an agent.

The column mapping, for anyone migrating saved queries:

| `AIAgentsInfo` (retired) | `AgentsInfo` (current) | Notes |
| --- | --- | --- |
| `AIAgentId` | `AgentId` | Direct rename |
| `AIAgentName` | `AgentName` | Direct rename |
| `AgentStatus` (`Published`) | `PublishedStatus` (`Draft`/`Published`) + `LifecycleStatus` (`Active`/`Blocked`/`Uninstalled`/`Deleted`) | Split into two fields - "is it published" and "is it currently active" are now separate questions |
| `OwnerAccountUpns` | `Owners` | Direct rename |
| `CreatorAccountUpn` | *(no direct equivalent)* | Creator identity isn't a first-class column in the new schema; may be recoverable from `RawAgentInfo` per tenant, needs verification |
| `AgentCreationTime` | `CreatedDateTime` | Direct rename |
| `LastPublishedTime` | `LastPublishedDateTime` | Direct rename; new `LastUpdatedDateTime` also added, tracking metadata edits separately from publish events |
| `KnowledgeDetails` (regex/JSON parse required) | `DeclaredDataSources` | Now a dedicated dynamic column instead of nested inside a Copilot Studio-specific blob |
| `AgentToolsDetails` (regex/JSON parse required) | `DeclaredTools` + `McpServers` | MCP connections are now their own column rather than mixed in with generic tool definitions |
| `RawAgentInfo` / `AgentActionTriggers` (regex-extracted URLs) | `Endpoints` | Runtime endpoints are now structured, including (per Microsoft's description) an external-connectivity flag, rather than requiring URL extraction from free text |
| `ConnectedAgentsSchemaNames` / `ChildAgentsSchemaNames` | `ConnectedAgents` | Collapsed into a single field; the parent/child distinction from the old schema doesn't have a clean equivalent yet |

New columns with no `AIAgentsInfo` predecessor worth knowing about:
`Permissions` and `ToolsAuthenticationType` (structured identity/auth/consent
data - previously invisible), `Instructions` (the agent's system prompt,
queryable directly), `Guardrails`, `Memory`, `Triggers`, `Skills`, and
`ObservabilityId` (for correlating against Agent 365 usage telemetry). If
you're doing agent governance hunting, `Permissions` in particular is worth
exploring before you rebuild anything else - it's the kind of over-permissioning
signal the old table couldn't give you at all.

## Rewriting the inventory hunt

The core question from last month's post - which published, active agents
reach outside the tenant, and does anyone own them - is actually easier to
answer now, because `DeclaredDataSources`, `McpServers`, and `Endpoints` are
dedicated columns instead of values buried inside Copilot Studio-shaped JSON.

One caveat up front: Microsoft's reference documents the columns but not the
full inner shape of each dynamic field. The extraction below is a starting
point, not a finished query - treat it the way this repo treats any
Experimental-maturity hunt: validate the inner JSON paths against what your
own tenant actually returns before trusting the output.

```kql
// ============================================================
// HUNT: Agent Inventory - Active Agents with External Reach
// ============================================================
// Purpose: Migrated from the AIAgentsInfo-based hunt published
//          last month. Surfaces published, active agents with
//          declared data sources, MCP connections, or external
//          endpoints, alongside ownership.
//
// Table:   AgentsInfo (AIAgentsInfo retired 2026-07-01)
// Status:  Experimental - inner JSON shape of the dynamic
//          columns below needs validation against live data
//          before this is relied on for triage.
// ============================================================

AgentsInfo
| where PublishedStatus == "Published" and LifecycleStatus == "Active"
| extend
    DataSourceCount = array_length(todynamic(DeclaredDataSources)),
    McpServerCount   = array_length(todynamic(McpServers)),
    EndpointCount    = array_length(todynamic(Endpoints)),
    ConnectedAgentCount = array_length(todynamic(ConnectedAgents))
| extend
    HasNoOwner = isempty(Owners) or Owners == "[]" or Owners == "[]"
| extend ExternalReachScore = toint(
    (DataSourceCount * 1) + (McpServerCount * 2) + (EndpointCount * 1)
  )
| project
    Timestamp,
    AgentId,
    AgentName,
    Platform,
    LifecycleStatus,
    PublishedStatus,
    Owners,
    HasNoOwner,
    CreatedDateTime,
    LastPublishedDateTime,
    DataSourceCount,
    McpServerCount,
    EndpointCount,
    ConnectedAgentCount,
    ExternalReachScore,
    DeclaredDataSources,
    McpServers,
    Endpoints,
    ConnectedAgents
| order by ExternalReachScore desc, HasNoOwner desc
```

This drops the regex extraction and Microsoft-domain allowlist filtering
entirely - not because false positives disappeared, but because without
confirmed inner-JSON field names for `DeclaredDataSources` and `Endpoints`,
building a domain allowlist against them would be guessing. Once you've
inspected a few rows of real output and confirmed which nested property
holds the URL or hostname, add that filtering back in the same way the
original hunt did.

## The ownerless-agent hunt still works, mostly unchanged

The join against `EntraIdSignInEvents` to catch agents owned by departed
users only needed the column rename:

```kql
AgentsInfo
| where LifecycleStatus != "Deleted"
| mv-expand Owner = todynamic(Owners)
| extend OwnerUpn = tostring(Owner)
| join kind=leftouter (
    EntraIdSignInEvents
    | where Timestamp >= ago(30d)
    | summarize LastSignIn = max(Timestamp) by AccountUpn
) on $left.OwnerUpn == $right.AccountUpn
| where isnull(LastSignIn) or LastSignIn < ago(90d)
| project AgentId, AgentName, OwnerUpn, LastSignIn, CreatedDateTime, LifecycleStatus
```

The one behavioural change worth flagging: `Owners` is `dynamic` rather than
the flat string `OwnerAccountUpns` was, so an agent with multiple owners
now correctly produces one row per owner via `mv-expand` instead of being
silently collapsed into a single string the old query would have needed
extra handling to split.

## What this means beyond this one table

The lesson isn't really about agents. It's that any hunt built on a table
still carrying "Beta," "Preview," or a first-year existence in the advanced
hunting schema needs a review cadence attached to it - not just a promotion
checklist for the detection logic, but a recheck of whether the underlying
table still exists in the shape you built against. Microsoft does publish
the [naming changes log](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-changes)
with advance notice, and it's worth a monthly glance if you maintain any
hunts against identity, agent, or newer endpoint tables - the boolean
`1`/`0` to `True`/`False` change that shipped in February 2026 is the same
category of quiet breakage, just less dramatic than a whole table
disappearing.

For this library specifically: the AI agent hunt from last month is being
reworked against `AgentsInfo` and will be re-published here once the
dynamic-column extraction has been validated against real tenant data rather
than inferred from documentation alone.
