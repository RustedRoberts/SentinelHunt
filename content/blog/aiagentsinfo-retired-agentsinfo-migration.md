---
title: "AIAgentsInfo Is Gone: Migrating the AI Agent Hunt to AgentsInfo"
date: 2026-07-14
author: Chris Scott
summary: The table our last post's hunt queries were built on was retired on 1 July 2026. Here's what replaced it, why the new AgentsInfo schema is a bigger deal than a rename, and why detection-as-code pipelines won't get this migration for free.
tags:
  - ai-agents
  - advanced-hunting
  - kql
  - agent-365
  - schema-migration
  - detection-engineering
published: false
---

## Introduction

Four weeks ago I wrote about `AIAgentsInfo` - the table that gave SOCs their
first queryable view into AI agents running across Microsoft 365. The post
included a set of hunts for orphaned agents, unowned agents, and agents
reaching out to external knowledge sources and MCP servers.

Those queries stopped working on 1 July 2026. `AIAgentsInfo` is retired.

This isn't a footnote. Microsoft has replaced it with a new `AgentsInfo`
table as part of the Microsoft Agent 365 transition, and the schema change is
substantial enough that a straight find-and-replace on the table name will
not get any of the old hunts running again. Column names changed, column
*types* changed in ways that matter for KQL syntax, and the new table folds
in agent platforms `AIAgentsInfo` never covered at all.

If you copied the queries from the last post into a saved hunting query, a
workbook, or - worse - a custom detection rule managed outside the Defender
portal, this is worth twenty minutes of your afternoon.

## What Actually Changed

The retirement was announced in June 2026 and took effect on 1 July 2026,
[per Microsoft's naming-changes reference](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-changes#june-2026).
The stated reason is not cosmetic: `AIAgentsInfo` was built specifically for
Copilot Studio agents, and most of its columns reflected that. `AgentsInfo`
is a unified schema covering Copilot Studio, Microsoft Foundry, Microsoft 365
Copilot, third-party agents, and agents discovered locally on endpoints
through Defender for Endpoint - platforms that previously had no common
inventory table at all.

The column mapping, based on the [published AgentsInfo reference](https://learn.microsoft.com/defender-xdr/advanced-hunting-agentsinfo-table)
and the retired [AIAgentsInfo reference](https://learn.microsoft.com/defender-xdr/advanced-hunting-aiagentsinfo-table):

| AIAgentsInfo (retired) | AgentsInfo (current) | Notes |
|---|---|---|
| `AIAgentId` (guid) | `AgentId` (string) | Type changed - joins on this column need casting reviewed |
| `AIAgentName` | `AgentName` | Direct rename |
| `AgentCreationTime` | `CreatedDateTime` | Direct rename |
| `LastPublishedTime` | `LastPublishedDateTime` | Direct rename |
| `LastModifiedTime` | `LastUpdatedDateTime` | Direct rename |
| `OwnerAccountUpns` (string) | `Owners` (dynamic) | No longer a flat string - needs `mv-expand` or `parse_json` |
| `AgentStatus` (Created/Published/Deleted) | `PublishedStatus` (Draft/Published) + `LifecycleStatus` (Active/Blocked/Uninstalled/Deleted) | One field split into two with different semantics |
| `KnowledgeDetails` | `DeclaredDataSources` (dynamic) | Structured instead of embedded JSON-in-string |
| `AgentActionTriggers` | `Triggers`, `Capabilities` (dynamic) | Split across two columns |
| `RawAgentInfo` (string) | `RawAgentInfo` (dynamic) | Same name, different type - `parse_json()` calls on it will now fail |
| *(no equivalent)* | `McpServers` (dynamic) | New first-class column - server URLs and credential config, no regex required |
| *(no equivalent)* | `Permissions`, `Guardrails`, `Endpoints`, `Instructions`, `Model`, `ConnectedAgents`, `Memory` | Entirely new surface area |

That last row is the one worth sitting with. `AgentsInfo` doesn't just carry
forward what `AIAgentsInfo` had - it adds columns for the agent's system
prompt (`Instructions`), the model backing it (`Model`), its granted
permissions (`Permissions`), attached guardrails, and a first-class
`McpServers` column. The external-source hunt from the last post spent most
of its logic regex-extracting URLs out of `RawAgentInfo` and
`AgentActionTriggers` because there was no structured field for it. That
entire arm of the query is now unnecessary - `McpServers` and `Endpoints`
carry that data directly.

## Why Detection-as-Code Doesn't Get This for Free

Microsoft's migration guidance includes one line worth flagging on its own:

> Naming changes are automatically applied to queries that are saved in
> Microsoft Defender, including queries used by custom detection rules...
> However, you will need to update queries that are run using the API or
> saved elsewhere outside Microsoft Defender.

Every hunt in this library is saved elsewhere outside Microsoft Defender -
it's YAML in a git repository. That's not a criticism of the approach,
it's the entire point of running a hunt library this way, but it means the
automatic migration Microsoft describes does not apply to a single query in
this repo, or to any team running detection-as-code against custom Sentinel
detection rules synced through Repositories.

This lines up with a governance gap that's been called out separately as
Sentinel has expanded its own detection-as-code surface. Custom detection
rules can now be managed in Sentinel Repositories as Bicep-defined
`Microsoft.Security/detectionRules` resources, syncing from GitHub or Azure
DevOps on every commit - joining analytics rules, parsers, and workbooks as
pipeline-managed content. The tradeoff called out for that feature is the
same one biting `AIAgentsInfo` users right now: portal-managed rules ride
along with Microsoft's schema migrations automatically; repository-managed
rules do not, and there is currently no tooling that diffs your source
control against upcoming schema deprecations. If your PR review process
doesn't already check for tables and columns on Microsoft's deprecation
list, this is a good week to add that check.

## Migrating the External Exposure Hunt

Here is the external-source and MCP-sprawl hunt from the last post, rebuilt
against `AgentsInfo`. The `McpServers` and `Endpoints` columns replace the
three-way regex extraction the old version needed, which cuts the query by
more than half:

```kql
// ============================================================
// HUNT: AI Agent External Exposure - AgentsInfo (Agent 365)
// ============================================================
// Purpose: Inventory published agents with external connectivity -
//          MCP server connections and externally-reachable endpoints -
//          alongside ownership and permission state. Rebuilt against
//          AgentsInfo after the 1 July 2026 AIAgentsInfo retirement.
//
// Tables:  AgentsInfo
//
// Caveat:  Nested field names inside McpServers, Endpoints, and
//          Permissions (dynamic columns) are documented at a
//          descriptive level only as of this writing - confirm exact
//          property names against your tenant's live schema with
//          `AgentsInfo | take 5 | project McpServers, Endpoints`
//          before promoting this beyond a manual hunt.
// ============================================================

AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus !in ("Deleted", "Uninstalled")
| where PublishedStatus == "Published"
| extend
    McpServerCount   = array_length(McpServers),
    EndpointCount    = array_length(Endpoints),
    HasOwner         = array_length(Owners) > 0,
    HasConnectedAgents = array_length(ConnectedAgents) > 0
| where McpServerCount > 0 or EndpointCount > 0
| extend DaysSincePublish = datetime_diff('day', now(), LastPublishedDateTime)
| project
    AgentId,
    AgentName,
    Platform,
    LifecycleStatus,
    PublishedStatus,
    Model,
    CreatedDateTime,
    LastPublishedDateTime,
    DaysSincePublish,
    Owners,
    HasOwner,
    McpServerCount,
    McpServers,
    EndpointCount,
    Endpoints,
    HasConnectedAgents,
    ConnectedAgents,
    DeclaredDataSources,
    Permissions
| order by McpServerCount desc, EndpointCount desc, DaysSincePublish desc
```

And the ownership-drift hunt, which needed the least rework - the join logic
is unchanged, only the column names and the fact that `Owners` is now
`dynamic` rather than a flat string:

```kql
// ============================================================
// HUNT: AI Agent Ownership Drift - AgentsInfo
// ============================================================
// Purpose: Flag agents whose owners have no sign-in activity in the
//          last 90 days - an immediate deprovisioning gap. Owners is
//          dynamic in AgentsInfo, so mv-expand replaces the direct
//          string join used against AIAgentsInfo's OwnerAccountUpns.
//
// Tables:  AgentsInfo, EntraIdSignInEvents
// ============================================================

AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| mv-expand Owner = Owners
| extend OwnerUpn = tostring(Owner)
| where isnotempty(OwnerUpn)
| join kind=leftouter (
    EntraIdSignInEvents
    | where Timestamp >= ago(30d)
    | summarize LastSignIn = max(Timestamp) by AccountUpn
) on $left.OwnerUpn == $right.AccountUpn
| where isnull(LastSignIn) or LastSignIn < ago(90d)
| project AgentId, AgentName, Platform, OwnerUpn, LastSignIn, CreatedDateTime, LifecycleStatus
```

## Also Worth Knowing About

Two more changes landed alongside the table migration that affect detection
coverage for AI agents specifically:

**Real-time protection Block rules need to be redefined.** If your tenant
had legacy Agent 365 real-time protection rules set to Block, those stopped
enforcing on 1 July 2026. They need to be recreated under the new Policies
experience (Settings > Security for AI > Policies & rules > Real-time
protection) - the cutover does not carry the old rule configuration forward.
Blocking silently lapsing is the kind of gap that doesn't show up until
something gets through.

**Copilot Studio alerting moved tables.** Existing threat detection alerts
for Copilot Studio agents that ran through Defender for Cloud Apps are
deprecated. The equivalent detections now run over Agent 365 observability
logs, surfaced in Advanced Hunting through the `BehaviorInfo` table - a
genuinely new hunting surface if you haven't queried it before, and worth a
follow-up post of its own.

Separately, and unrelated to the Agent 365 transition specifically: Sentinel
shipped two new ASIM schemas this cycle - Asset Entities and AI Agent Events
- aimed at normalising exactly this kind of cross-platform agent telemetry
longer-term, alongside expanded ASIM coverage for AWS CloudTrail and
third-party firewall and identity products. If you're building detections
that need to survive the next schema churn, writing against ASIM-normalised
fields rather than raw provider tables is the more durable bet - this
migration is a decent case study in why.

One more thing worth flagging if you're using AI to help draft hunting
queries: a [side-by-side test published last month](https://detect.fyi/testing-ai-threat-hunting-against-real-world-kql-a-side-by-side-test-4cdda76a5772)
compared LLM-generated KQL hunts against a hand-written production query and
found the AI-generated versions missed roughly a third of true positives by
querying only one relevant table where two were needed. A model trained
before 1 July 2026 will confidently hand you a query against `AIAgentsInfo`
with no idea the table is gone. Treat AI-drafted KQL as a first draft that
needs a schema check, not a finished hunt - which is exactly the review step
this migration makes unavoidable anyway.

## What to Do This Week

1. Search saved hunting queries, workbooks, and any custom detection rules
   managed outside the Defender portal for references to `AIAgentsInfo`.
   Portal-saved queries and custom detections migrated automatically;
   anything in a repo, a script, or run via the API did not.
2. If you're managing Sentinel or Defender detection content as code, add a
   check against Microsoft's [schema naming-changes page](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-changes)
   to your PR review process. This will not be the last table this happens
   to.
3. Confirm whether your tenant had Agent 365 real-time protection Block
   rules configured, and redefine them under the new Policies experience if
   so.
4. Verify the exact nested field names inside `McpServers`, `Endpoints`, and
   `Permissions` against your own tenant before promoting the queries above
   past manual hunting - the top-level column migration is well documented,
   the nested JSON shape is not yet.

The underlying threat model from the last post hasn't changed - over-permissioned,
under-reviewed agents with unclear ownership are still the pattern to hunt
for. What changed is the table you hunt them in. Better to find that out from
a blog post than from a hunt that's been silently returning zero rows for two
weeks.
