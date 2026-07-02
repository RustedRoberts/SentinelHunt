---
title: AIAgentsInfo Is Retiring - What Changes in Your Advanced Hunting Queries
date: 2026-07-02
author: Chris Scott
summary: The AIAgentsInfo table we covered here in June is being replaced by AgentsInfo as part of the Microsoft Agent 365 transition. The cutover window closes 1 July 2026. Here's what changed and what to check first.
tags:
  - advanced-hunting
  - kql
  - agent-365
  - schema-change
published: true
---

## Introduction

Three weeks ago we wrote about `AIAgentsInfo`, the table that first gave Advanced
Hunting visibility into AI agents registered across Copilot Studio and Azure AI Foundry.
That table is now on its way out.

Microsoft's June 2026 advanced hunting schema update confirmed that `AIAgentsInfo` is
transitioning to a new `AgentsInfo` table, and the legacy table remains queryable only
until **1 July 2026**. If you built anything on the queries in our earlier post -
saved hunts, custom detection rules, workbooks, automation - it is worth checking today
whether that content silently stopped returning data.

Custom detection rules saved inside the Defender portal are migrated automatically, so
those are not at risk. Anything run through the API, scheduled outside Microsoft
Defender, or pasted into a runbook or scheduled analytics rule as raw KQL is not
automatically rewritten and needs manual attention.

## Why the Table Changed

`AIAgentsInfo` was built for one platform: Copilot Studio. Its schema reflected that -
fields like `EnvironmentId`, `AgentTopicsDetails`, and `AgentToolsDetails` all carried
Power Platform-specific shapes. As Microsoft broadened AI agent governance into Microsoft
Agent 365, that single-platform schema became a limitation rather than a feature.

`AgentsInfo` is the replacement: a unified schema covering Copilot Studio, Microsoft
Foundry, Microsoft 365 Copilot, third-party agents, and endpoint-discovered agents in one
table. It expands coverage of agent identity, authentication, permissions, lifecycle, and
configuration, and adds a catch-all `RawAgentInfo` column so new provider-specific detail
doesn't require another schema break down the line.

The tradeoff is that this is a genuine schema change, not a rename. Column names,
structure, and semantics are different enough that a straight find-and-replace of the
table name will not work.

## What Changed, Column by Column

The columns that carried the most weight in our original hunting queries map roughly as
follows. Treat this as a starting point for your own migration, not a guarantee - several
of the new columns are `dynamic` fields whose internal JSON shape has not been fully
documented with worked examples yet, which we flag explicitly below.

| `AIAgentsInfo` (retiring) | `AgentsInfo` (current) | Notes |
| --- | --- | --- |
| `AIAgentId` | `AgentId` | Direct replacement |
| `AIAgentName` | `AgentName` | Direct replacement |
| `AgentStatus` | `LifecycleStatus` / `PublishedStatus` | Split into two fields - lifecycle (`Active`, `Blocked`, `Uninstalled`, `Deleted`) and publication (`Draft`, `Published`) are now tracked separately |
| `CreatorAccountUpn` / `OwnerAccountUpns` | `Owners` | Consolidated into a single `dynamic` field |
| `AgentCreationTime` | `CreatedDateTime` | Direct replacement |
| `LastPublishedTime` | `LastPublishedDateTime` | Direct replacement |
| `KnowledgeDetails` | `DeclaredDataSources` | Renamed and restructured - no longer nested under a Power Platform-style `spec.knowledgeSources` path |
| `AgentToolsDetails` | `DeclaredTools` | Renamed and restructured |
| — (no equivalent) | `McpServers` | New: MCP server connections are now a first-class column rather than something you had to mine out of `AgentToolsDetails` |
| — (no equivalent) | `Endpoints` | New: runtime endpoints, including transport type and an external-connectivity flag |
| `RawAgentInfo` | `RawAgentInfo` | Retained, still your fallback for anything not yet surfaced as a typed column |

The `AgentsInfo` table also stores multiple snapshots per agent over time rather than one
row per current state, so every query needs `arg_max(Timestamp, *) by AgentId` to collapse
to the latest snapshot before you do anything else with it - this is a genuine behavioural
difference, not just a naming one, and it is easy to miss if you port a query without
re-reading the table reference.

## A Safe Starting Query

This is the direct, documented replacement for the inventory query we opened with in the
original post - list every Agent 365-registered agent, collapsed to its current state:

```kql
// ============================================================
// MIGRATION: AIAgentsInfo -> AgentsInfo baseline inventory
// ============================================================
// Purpose: Direct replacement for a simple "list all active
//          agents" query. Confirms the AgentsInfo table is
//          populated for your tenant before porting anything
//          more complex.
//
// Tables:  AgentsInfo
// ============================================================

AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId   // collapse snapshots to latest state per agent
| where LifecycleStatus != "Deleted"
| project
    AgentId,
    AgentName,
    Platform,
    PublishedStatus,
    LifecycleStatus,
    CreatedDateTime,
    LastPublishedDateTime,
    Owners,
    SharedWith
| order by LastPublishedDateTime desc
```

## Porting the External-Sources Hunt

Our original post's most-used query mapped external knowledge sources, HTTP action
URLs, and MCP server connections per agent. The external-connectivity story is still
there in `AgentsInfo` - it now lives across `DeclaredDataSources`, `DeclaredTools`,
`McpServers`, and `Endpoints` - but we have not yet seen a documented worked example of
the internal JSON shape for those columns from Microsoft, and we don't want to publish a
query built on guessed field paths.

Until that reference lands, the honest starting point is to surface the raw structure for
manual review rather than assume a path that may not match what your tenant actually
returns:

```kql
// ============================================================
// MIGRATION: AgentsInfo - external connectivity, raw surface
// ============================================================
// Purpose: Transitional query pending a documented schema for
//          DeclaredDataSources / DeclaredTools / McpServers /
//          Endpoints. Surfaces the raw dynamic values so you
//          can inspect the shape your tenant actually returns
//          and refine the projection once confirmed.
//
// Tables:  AgentsInfo
// ============================================================

AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus == "Active" and PublishedStatus == "Published"
| where isnotempty(McpServers) or isnotempty(Endpoints) or isnotempty(DeclaredDataSources)
| project
    AgentId,
    AgentName,
    Platform,
    Owners,
    DeclaredDataSources,
    DeclaredTools,
    McpServers,
    Endpoints
| order by AgentName asc
```

Run this against your own tenant, inspect a handful of rows in the results pane to
confirm the nested shape, and rebuild the `mv-expand` / `parse_json` logic from our
original post against the confirmed structure. We'll follow up with a fully worked
replacement once Microsoft publishes sample output for these columns.

## What To Do Before 1 July

1. **Search your saved content for `AIAgentsInfo`** - custom detection rules inside the
   Defender portal migrate automatically, but anything run via API, stored in a
   repository, or embedded in a playbook does not.
2. **Re-point automation and reporting**, not just interactive hunts. Scripts and
   integrations calling the Advanced Hunting API directly are the most likely thing to
   silently break, since there is no UI warning for those.
3. **Re-validate false-positive tuning.** The consolidated `Owners` field and the split
   `LifecycleStatus` / `PublishedStatus` columns change the shape of any filtering logic
   you had tuned against `AgentStatus` or the old owner fields.
4. **Check licensing.** `AgentsInfo` is powered by Microsoft Agent 365. If your access to
   the Copilot Studio agent inventory was previously coming through a Defender for Cloud
   Apps preview opt-in rather than an Agent 365 license, confirm that entitlement carries
   forward - the preview access path documented alongside the original table is
   specifically scoped "until July 1, 2026."

## Closing Thoughts

None of this is a reason to have skipped the original inventory work - if anything, it's
confirmation that AI agent governance in Advanced Hunting is still actively taking shape,
and early movers are the ones who will notice this kind of change before it costs them
visibility. The schema is evolving quickly enough that anything built on it needs a
recheck cadence, not a one-time setup.

If you have not looked at `AgentsInfo` yet, today is a reasonable day to start - the old
table's clock has effectively run out.
