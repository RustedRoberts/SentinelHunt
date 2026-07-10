---
title: The Table We Told You to Hunt On Is Gone - Migrating AIAgentsInfo Hunts to AgentsInfo (and a New Behavioural Signal)
date: 2026-07-10
author: Chris Scott
summary: Microsoft's July 1 cutoff for AIAgentsInfo has passed. If you built hunts on our last post, they're running against a deprecated table. Here's the AgentsInfo rewrite - and a genuinely new detection surface in BehaviorInfo that's worth more than the migration itself.
tags:
  - ai-agents
  - advanced-hunting
  - kql
  - agent-365
  - schema-migration
published: true
---

## Introduction

Three weeks ago we published hunts against `AIAgentsInfo`, walking through how to
surface AI agents reaching untrusted external sources and MCP servers. If you
built any of those queries into a saved hunt or a custom detection rule, it's
worth checking on them now: Microsoft's cutoff for `AIAgentsInfo` was July 1,
2026, and the table is being retired in favour of a new one, `AgentsInfo`.

This is not a rename. The column names changed, several columns were
restructured from raw JSON blobs into first-class typed fields, the primary
key semantics changed, and the table now stores multiple snapshots per agent
over time rather than one row per agent. A find-and-replace of
`AIAgentsInfo` → `AgentsInfo` on last month's queries will not run - and if
you patch the syntax errors without understanding what changed, it will run
and quietly return the wrong thing.

We rebuilt our own hunts against the new schema below. We're also covering a
second, unrelated change that shipped in the same release wave and matters
more for detection than the migration does: real-time protection events for
AI agents are now landing as queryable telemetry in a table called
`BehaviorInfo`, rather than existing only as alerts you have to react to
after the fact.

## Why the Table Changed

`AIAgentsInfo` was built for Copilot Studio. Its columns - `AgentAppId`,
`AgentTopicsDetails`, `EnvironmentId` - reflected Power Platform concepts and
didn't generalise to Foundry agents, Microsoft 365 Copilot agents, or
third-party and endpoint-discovered agents. As Microsoft Agent 365 became the
single source of truth for agent inventory across all of those platforms, it
needed a schema that wasn't shaped around one product.

`AgentsInfo` is that schema. The practical upshot for hunters: several things
that used to require regex extraction or nested JSON parsing are now typed
columns you can query directly.

## What Changed, Column by Column

The mapping isn't 1:1, and some of it is a genuine improvement rather than
just a rename:

- `AIAgentId` / `AIAgentName` → `AgentId` / `AgentName`. Straightforward
  rename, but `AgentId` is no longer guaranteed unique per row - see below.
- `AgentStatus == "Published"` → split into two independent fields:
  `PublishedStatus` (`Draft` / `Published`) and `LifecycleStatus` (`Active`
  / `Blocked` / `Uninstalled` / `Deleted`). An agent can be `Published` and
  `Blocked` at the same time. Filtering on publish status alone, the way our
  old hunt did, now misses agents an admin has explicitly blocked - which is
  exactly the population worth excluding from an "active risk" view, not
  including in it. Filter on both.
- `OwnerAccountUpns` (string, sometimes a stringified array) → `Owners`
  (proper `dynamic` array). No more `== "[]"` string comparisons to detect
  an empty owner list - use `array_length(Owners) == 0`.
- `KnowledgeDetails` (raw JSON you had to `parse_json` and drill into
  `spec.knowledgeSources.publicSites`) → `DeclaredDataSources` (`dynamic`,
  structured). One less parsing layer.
- `RawAgentInfo` + `AgentActionTriggers` (regex-scraped for URLs because
  there was no structured field for external HTTP endpoints) →
  `Endpoints` (`dynamic`, described as including URL, transport type, and an
  external-connectivity flag). This is the biggest win in the new schema for
  the exact hunt we published last time - what used to be an
  `extract_all(@"https?://...")` against a blob of raw config is now a
  typed field. The old regex arm of our hunt is now unnecessary as
  written; verify the exact property names against your own tenant's data
  before relying on them, since the table is still Preview and Microsoft
  hasn't published a worked sample for this field yet.
- The `AgentToolsDetails` parsing we did last time - filtering
  `Tool["$kind"] == "TaskDialog"` to find MCP connections buried in a
  Power Automate action tree - is replaced entirely by `McpServers`, a
  dedicated `dynamic` column. No more kind-filtering through generic tool
  definitions to find the MCP ones.
- New in this schema and worth hunting on separately: `Permissions`
  (requested vs. granted, with consent state), `ToolsAuthenticationType`,
  `Guardrails`, and `EntraAgentId` - the agent's own Entra ID object, which
  matters for the `BehaviorInfo` correlation further down.

One more change matters more than any single column rename: **the table
stores multiple snapshots per agent over time.** Query it without
deduplicating and you'll get one row per snapshot, not one row per agent.
Microsoft's own sample query handles this with `arg_max(Timestamp, *) by
AgentId` - if you drop that line, every downstream count and `dcount` in a
hunt copied from the old table will be wrong, and it won't fail loudly. It
will just look plausible.

## The Rewritten Hunt

Here's last month's "external sources" hunt rebuilt against `AgentsInfo`.
The core logic is the same - flag agents whose declared data sources,
endpoints, or MCP servers point somewhere outside the Microsoft estate - but
two of the three extraction arms are now direct field reads instead of
parsing exercises, and the mandatory `arg_max` step is new.

```kql
// ============================================================
// HUNT: AI Agent External Sources - Active Agents Only (AgentsInfo)
// ============================================================
// Purpose: AgentsInfo replacement for the AIAgentsInfo external-sources
//          hunt. Two of three extraction arms simplify from
//          parse_json/regex into direct field reads under the new schema.
//          Scoped to agents that are both Published AND Active - an agent
//          can be Published yet Blocked, and a blocked agent belongs in a
//          "who got blocked and why" review, not an active-risk list.
//
// Tables:  AgentsInfo
// ============================================================

let MicrosoftDomains = dynamic([
    "microsoft.com", "azure.com", "windows.net", "dynamics.com",
    "sharepoint.com", "office.com", "microsoftonline.com",
    "powerplatform.com", "copilotstudio.microsoft.com",
    "adaptivecards.io", "aka.ms", "m365.cloud.microsoft",
    "azurefd.net"
]);
let TemplateDomains = dynamic([
    "contoso.com", "contoso.sharepoint.com"
]);
// ---------------------------------------------------------------
// AgentsInfo stores a snapshot per change - collapse to the latest
// row per agent before doing anything else, then scope to agents
// that are both published AND not blocked/uninstalled/deleted.
// ---------------------------------------------------------------
let ActiveAgents =
    AgentsInfo
    | summarize arg_max(Timestamp, *) by AgentId
    | where PublishedStatus == "Published"
    | where LifecycleStatus == "Active";
// ---------------------------------------------------------------
// Arm 1: Declared data sources - was KnowledgeDetails parse_json,
// now a direct dynamic field.
// ---------------------------------------------------------------
let DataSourceHits =
    ActiveAgents
    | mv-expand Source = DeclaredDataSources
    | extend ExtractedUrl = tostring(Source.url)
    | where isnotempty(ExtractedUrl)
    | where not(ExtractedUrl has_any (MicrosoftDomains))
    | where not(ExtractedUrl has_any (TemplateDomains))
    | project
        AgentId, AgentName, Platform, EntraAgentId, Owners,
        CreatedDateTime, LastPublishedDateTime,
        SourceType = "DeclaredDataSource", ExtractedValue = ExtractedUrl;
// ---------------------------------------------------------------
// Arm 2: Runtime endpoints - was regex-extracted from RawAgentInfo
// and AgentActionTriggers, now a direct dynamic field. Property
// names below (url / isExternal) are inferred from the column
// description, not a published sample - validate against your own
// tenant's data before trusting this arm, and widen the extraction
// if the real property names differ.
// ---------------------------------------------------------------
let EndpointHits =
    ActiveAgents
    | mv-expand Endpoint = Endpoints
    | extend
        ExtractedUrl = tostring(Endpoint.url),
        IsExternal   = tobool(Endpoint.isExternal)
    | where isnotempty(ExtractedUrl)
    | where not(ExtractedUrl has_any (MicrosoftDomains))
    | where not(ExtractedUrl has_any (TemplateDomains))
    | project
        AgentId, AgentName, Platform, EntraAgentId, Owners,
        CreatedDateTime, LastPublishedDateTime,
        SourceType = "Endpoint",
        ExtractedValue = strcat(ExtractedUrl, iff(IsExternal, " [external]", ""));
// ---------------------------------------------------------------
// Arm 3: MCP servers - was Tool["$kind"] == "TaskDialog" filtering
// through AgentToolsDetails, now a dedicated dynamic field.
// ---------------------------------------------------------------
let McpHits =
    ActiveAgents
    | mv-expand Mcp = McpServers
    | extend
        McpName = tostring(Mcp.name),
        McpUrl  = tostring(Mcp.url)
    | where isnotempty(McpName) or isnotempty(McpUrl)
    | project
        AgentId, AgentName, Platform, EntraAgentId, Owners,
        CreatedDateTime, LastPublishedDateTime,
        SourceType = "McpServer",
        ExtractedValue = strcat(McpName, " | ", McpUrl);
// ---------------------------------------------------------------
// Union and collapse to one row per agent, same shape as before.
// ---------------------------------------------------------------
union DataSourceHits, EndpointHits, McpHits
| summarize
    AgentName            = take_any(AgentName),
    Platform             = take_any(Platform),
    EntraAgentId         = take_any(EntraAgentId),
    Owners               = take_any(Owners),
    CreatedDateTime      = take_any(CreatedDateTime),
    LastPublishedDateTime = take_any(LastPublishedDateTime),
    SourceTypes          = make_set(SourceType),
    ExternalSources      = make_set(ExtractedValue),
    ExternalSourceCount  = dcount(ExtractedValue)
    by AgentId
| extend
    NoOwner          = array_length(Owners) == 0,
    DaysSincePublish = datetime_diff('day', now(), todatetime(LastPublishedDateTime))
| project
    AgentId, AgentName, Platform, EntraAgentId,
    CreatedDateTime, LastPublishedDateTime, DaysSincePublish,
    Owners, NoOwner, ExternalSourceCount, SourceTypes, ExternalSources
| order by DaysSincePublish desc, AgentName asc
```

The orphaned-owner join and the topology query from the original post carry
over the same way: rename `AIAgentId`/`AIAgentName` to `AgentId`/`AgentName`,
swap `OwnerAccountUpns` for `Owners` and `mv-expand` it before joining against
`EntraIdSignInEvents.AccountUpn` (it's an array now, not a string), and
replace `AgentStatus != "Deleted"` with `LifecycleStatus != "Deleted"`.
`ConnectedAgentsSchemaNames` and `ChildAgentsSchemaNames` both collapse into a
single `ConnectedAgents` field in the new schema, so the topology risk score
needs re-deriving rather than a straight port - budget more validation time
for that one than for the query above.

## The More Interesting Change: BehaviorInfo

The schema migration is maintenance. This next part is new detection
surface, and it's a bigger deal for anyone actually running agents in
production.

Until this release, Agent 365 real-time protection - the feature that
inspects tool invocations before they execute and can block risky ones - only
surfaced its findings as alerts. You'd see a block in the portal, or you
wouldn't. There was no queryable telemetry to build a custom detection rule
against, no way to trend audit-mode findings before deciding whether to flip
a rule to blocking, and no way to correlate a block event with other activity
on the same agent in the same investigation.

That changed with `BehaviorInfo`. Every real-time protection audit and block
decision - along with UEBA and Defender for Cloud Apps behaviors more
broadly - now lands as a row: what happened, which MITRE ATT&CK technique it
maps to, which account or agent was involved, and whether it was audited or
blocked. Block events from Prompt Shields for Foundry and Microsoft 365
Copilot Agent Builder land here too, though Copilot Studio agents aren't
covered by that particular signal yet.

This is worth hunting on for a specific reason: **default real-time
protection audits every agent without blocking anything.** That means
`BehaviorInfo` already contains a record of what your agents would have
triggered had blocking been enabled - a live test of your blocking policy's
blast radius before you turn it on.

```kql
// ============================================================
// HUNT: AI Agent Real-Time Protection - Audit vs. Block Volume
// ============================================================
// Purpose: Trend real-time protection behaviours per agent identity to
//          (a) find agents already generating block events worth
//          investigating now, and (b) size the blast radius of flipping
//          an audit-mode rule to blocking, before you flip it.
//          EntraAgentId -> AccountObjectId join assumes real-time
//          protection attributes the behaviour to the agent's own Entra
//          identity rather than the invoking user - confirm this holds
//          for your tenant's data before trusting the join; both tables
//          are Preview and this mapping isn't documented yet.
//
// Tables:  BehaviorInfo, AgentsInfo
// ============================================================

let lookback = 14d;
let LatestAgents =
    AgentsInfo
    | summarize arg_max(Timestamp, *) by AgentId
    | where isnotempty(EntraAgentId)
    | project AgentId, AgentName, Platform, EntraAgentId, Owners, LifecycleStatus;
BehaviorInfo
| where Timestamp > ago(lookback)
| where isnotempty(AccountObjectId)
| join kind=inner LatestAgents on $left.AccountObjectId == $right.EntraAgentId
| summarize
    TotalBehaviors = count(),
    BlockedCount   = countif(ActionType has "Block"),
    AuditCount     = countif(ActionType has "Audit"),
    Techniques     = make_set(AttackTechniques),
    Titles         = make_set(Title),
    FirstSeen      = min(StartTime),
    LastSeen       = max(EndTime)
    by AgentId, AgentName, Platform, Owners, LifecycleStatus
| extend BlockRate = round(100.0 * BlockedCount / TotalBehaviors, 1)
| where TotalBehaviors > 0
| order by BlockedCount desc, TotalBehaviors desc
```

Rows with `BlockedCount > 0` are already actionable - something tripped a
custom blocking rule and it's worth knowing which agent and why. Rows with a
high `TotalBehaviors` but `BlockedCount == 0` are your audit-mode signal:
agents generating a lot of flagged activity under the default audit rule,
which is exactly the population to review manually before deciding whether a
custom blocking rule for that agent or tool is warranted. Pivot into
`BehaviorEntities` on `BehaviorId` for the specific tool, URL, or OAuth
application involved in any row that looks worth a closer look.

## What to Do This Week

If you have anything - a saved hunt, a custom detection rule, an automation
- still pointed at `AIAgentsInfo`, it's past the point where "we'll get to it"
is a safe answer; the cutoff has already passed and the table's continued
availability from here is not something to depend on. Three concrete steps:

1. Search your saved queries and custom detection rules for `AIAgentsInfo`
   and migrate each one using the column mapping above - don't just
   find-and-replace the table name.
2. Add the `arg_max(Timestamp, *) by AgentId` deduplication step to
   anything querying `AgentsInfo`. Skipping it doesn't error, it just
   silently inflates every count.
3. Run the `BehaviorInfo` query above even if you haven't touched the
   AIAgentsInfo hunts at all. It doesn't require any migration - it's new
   telemetry that didn't exist for AI agents before this release, and it's
   the more useful of the two changes covered here.

## Closing Thoughts

Schema churn in a Preview table is expected and this one came with a real
upgrade attached - typed fields where there used to be regex, and queryable
behavioural telemetry where there used to be alerts you could only react to
after the fact. The cost is that anything built against the old table needs
active maintenance, not a one-time port. Treat every auto-migrated query as
suspect until you've re-validated it against real data, and treat
`BehaviorInfo` as the actual news here - it's the first time AI agent
real-time protection has produced anything you can hunt on proactively rather
than just get alerted about.
