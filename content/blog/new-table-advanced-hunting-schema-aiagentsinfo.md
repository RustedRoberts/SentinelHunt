---
title: There's a New Table in Your Advanced Hunting Schema - and Most SOCs Haven't Noticed
date: 2026-06-13
author: Chris Scott
summary: AI agents are proliferating across enterprise Microsoft 365 environments. The telemetry to detect their misuse arrived quietly in May 2026. Here's what to do with it.
tags:
  - ai-agents
  - advanced-hunting
  - kql
  - agent-365
published: true
---

## Introduction

Ask most SOC teams how many AI agents are running in their environment and you
will get one of two answers: a confident number that is almost certainly
wrong, or a shrug. Until recently, there was no reliable way to find out.
Agents built on Copilot Studio, Azure AI Foundry, or third-party runtimes
connected via Model Context Protocol (MCP) servers were functionally
invisible to Advanced Hunting - they did not appear in `DeviceProcessEvents`,
they did not generate identity logs in the way a user account would, and
there was no dedicated schema to query against.

That changed in May 2026. Microsoft shipped the `AIAgentsInfo` table as part
of the Agent 365 preview, alongside local AI agent discovery in Defender for
Endpoint. For the first time, every AI agent registered in your tenant - its
identity, owner, runtime, connected MCP servers, transport configuration, and
operational status - is queryable in KQL alongside the endpoint, identity, and
cloud telemetry your team already uses.

Most SOCs have not looked yet. That is a problem, because the
misconfigurations are already there.

## Why This Attack Surface Is Familiar - and Different

AI agents are not passive tools. They read files, invoke external APIs,
access SharePoint and Exchange data, and execute actions on behalf of the user
identity they run under. In environments where Copilot Studio or Azure AI
Foundry has been deployed, agents may have access to sensitive internal
knowledge bases, HR systems, or finance data - often with broader permissions
than anyone configured deliberately.

The threat model will feel familiar if you have spent time hunting service
account abuse. Agents, like service accounts, tend to be over-permissioned at
creation and under-reviewed afterwards. Ownership drifts. People leave and
their agents keep running. MCP servers - the mechanism by which agents connect
to external tools and data sources - can be configured over HTTP, exposed to
untrusted endpoints, or left pointing at stale integrations nobody has touched
in months.

The difference is the blast radius is larger. A compromised or manipulated
agent does not just move laterally - it can be prompted to exfiltrate data
through legitimate channels like email or external APIs, leak system
instructions, or misuse internal tools in ways that generate no traditional
security signal. Microsoft's real-time protection documentation lists
persistent jailbreak attempts and suspicious agent execution patterns as
primary detection targets. Neither has an equivalent in the pre-AI hunting
playbook.

## What You Can Hunt Right Now

Most organisations I speak to have started thinking about AI governance from a user behaviour angle - who's prompting what, and what's coming back. Fewer are looking at the agents themselves; what they're configured to reach out to, and whether anyone actually knows.

This query is an attempt to close that gap.

It works across three surfaces inside AIAgentsInfo: knowledge source URLs pulled from structured JSON in KnowledgeDetails, external endpoints extracted via regex from raw agent configuration in RawAgentInfo and AgentActionTriggers, and MCP server connections identified from AgentToolsDetails.

Microsoft-owned domains and known template placeholders are filtered out to keep the results meaningful, and everything is scoped to Published agents so you're looking at what's reachable right now rather than drafts. Results collapse to one row per AIAgentId using make_set(), which preserves the full external source list per agent without the noise of repeated rows. Grouping by ID rather than name is deliberate - if two agents share a display name but have different IDs, they'll appear separately, which is a useful property when you're trying to spot agents that shouldn't exist.

```kql
// ============================================================
// HUNT: AI Agent External Sources - Active Agents Only
// ============================================================
// Purpose: Scope the external source hunt to agents that are
//          actively reachable - Published status only.
//          Reduces noise during triage by excluding draft agents
//          that cannot currently be interacted with.
//          Use this as the starting point when triaging findings
//          for immediate risk rather than full inventory coverage.
//
// Tables:  AIAgentsInfo
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
// Pre-filter to active agents only before any expensive parsing
// ---------------------------------------------------------------
let ActiveAgents =
    AIAgentsInfo
    | where AgentStatus == "Published";
// ---------------------------------------------------------------
// Arm 1: Knowledge source URLs
// ---------------------------------------------------------------
let KnowledgeSources =
    ActiveAgents
    | where isnotempty(KnowledgeDetails)
    | extend KD = parse_json(KnowledgeDetails)
    | mv-expand Site = KD.spec.knowledgeSources.publicSites
    | extend ExtractedUrl = tostring(Site.url)
    | where isnotempty(ExtractedUrl)
    | where not(ExtractedUrl has_any (MicrosoftDomains))
    | where not(ExtractedUrl has_any (TemplateDomains))
    | project
        AIAgentId,
        AIAgentName,
        TenantId,
        CreatorAccountUpn,
        OwnerAccountUpns,
        AgentCreationTime,
        LastPublishedTime,
        SourceType = "KnowledgeSource",
        ExtractedValue = ExtractedUrl;
// ---------------------------------------------------------------
// Arm 2: HttpRequest action URLs
// ---------------------------------------------------------------
let HttpActionUrls =
    ActiveAgents
    | where isnotempty(RawAgentInfo) or isnotempty(AgentActionTriggers)
    | extend CombinedRaw = strcat(tostring(RawAgentInfo), tostring(AgentActionTriggers))
    | extend UrlMatches = extract_all(@"(https?://[^\s'""\\<>]{8,})", CombinedRaw)
    | mv-expand ExtractedUrl = UrlMatches to typeof(string)
    | extend ExtractedUrl = trim_end(@"[)\.,\\rn]+", ExtractedUrl)
    | where isnotempty(ExtractedUrl)
    | where not(ExtractedUrl has_any (MicrosoftDomains))
    | where not(ExtractedUrl has_any (TemplateDomains))
    | where ExtractedUrl !startswith "https://<"
    | where ExtractedUrl !startswith "https://..."
    | distinct
        AIAgentId,
        AIAgentName,
        TenantId,
        CreatorAccountUpn,
        OwnerAccountUpns,
        AgentCreationTime,
        LastPublishedTime,
        SourceType = "HttpRequestAction",
        ExtractedValue = ExtractedUrl;
// ---------------------------------------------------------------
// Arm 3: MCP servers
// ---------------------------------------------------------------
let McpServers =
    ActiveAgents
    | where isnotempty(AgentToolsDetails)
    | extend ToolsJson = parse_json(AgentToolsDetails)
    | mv-expand Tool = ToolsJson
    | where tostring(Tool["$kind"]) == "TaskDialog"
    | extend McpName = tostring(Tool.modelDisplayName)
    | extend ConnRef = tostring(Tool.action.connectionReference)
    | extend OpId = tostring(Tool.action.operationDetails.operationId)
    | where isnotempty(OpId)
    | project
        AIAgentId,
        AIAgentName,
        TenantId,
        CreatorAccountUpn,
        OwnerAccountUpns,
        AgentCreationTime,
        LastPublishedTime,
        SourceType = "McpServer",
        ExtractedValue = strcat(McpName, " | connRef: ", ConnRef, " | opId: ", OpId);
// ---------------------------------------------------------------
// Union and collapse to one row per AIAgentId
// Summarising by AIAgentId rather than AIAgentName intentionally -
// a mimic agent sharing a legitimate agent's name will have a
// different AIAgentId and appear as a separate row
// ---------------------------------------------------------------
union KnowledgeSources, HttpActionUrls, McpServers
| summarize
    AIAgentName         = take_any(AIAgentName),
    TenantId            = take_any(TenantId),
    CreatorAccountUpn   = take_any(CreatorAccountUpn),
    OwnerAccountUpns    = take_any(OwnerAccountUpns),
    AgentCreationTime   = take_any(AgentCreationTime),
    LastPublishedTime   = take_any(LastPublishedTime),
    SourceTypes         = make_set(SourceType),
    ExternalSources     = make_set(ExtractedValue),
    ExternalSourceCount = dcount(ExtractedValue)
    by AIAgentId
| extend
    NoOwner          = isempty(OwnerAccountUpns) or OwnerAccountUpns == "[]",
    DaysSincePublish = datetime_diff('day', now(), todatetime(LastPublishedTime))
| project
    AIAgentId,
    AIAgentName,
    TenantId,
    AgentCreationTime,
    LastPublishedTime,
    DaysSincePublish,
    CreatorAccountUpn,
    OwnerAccountUpns,
    NoOwner,
    ExternalSourceCount,
    SourceTypes,
    ExternalSources
| order by DaysSincePublish desc, AIAgentName asc

```

We can also broaden this further and map out where child agent relationships exist.

This query below does much of what the above does, but expands this out further. The result is a single collapsed row per agent showing not just what external data it reaches, but how far that data could travel if the agent were manipulated through a poisoned source. Sort by score descending to prioritise agents with the broadest potential blast radius.

```kql

// ============================================================
// HUNT: AI Agent External Sources - Topology
// ============================================================
// Purpose: Map agents with external data sources alongside their
//          connected and child agent relationships. An agent that
//          both reaches external sources AND can invoke child agents
//          represents a higher blast radius - external data can
//          propagate through the agent graph.
//
// Tables:  AIAgentsInfo
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
// Arm 1: Knowledge source URLs
// ---------------------------------------------------------------
let KnowledgeSources =
    AIAgentsInfo
    | where isnotempty(KnowledgeDetails)
    | extend KD = parse_json(KnowledgeDetails)
    | mv-expand Site = KD.spec.knowledgeSources.publicSites
    | extend ExtractedUrl = tostring(Site.url)
    | where isnotempty(ExtractedUrl)
    | where not(ExtractedUrl has_any (MicrosoftDomains))
    | where not(ExtractedUrl has_any (TemplateDomains))
    | project
        AIAgentId,
        AIAgentName,
        TenantId,
        CreatorAccountUpn,
        OwnerAccountUpns,
        AgentCreationTime,
        AgentStatus,
        ConnectedAgentsSchemaNames = tostring(ConnectedAgentsSchemaNames),
        ChildAgentsSchemaNames     = tostring(ChildAgentsSchemaNames),
        SourceType = "KnowledgeSource",
        ExtractedValue = ExtractedUrl;
// ---------------------------------------------------------------
// Arm 2: HttpRequest action URLs
// ---------------------------------------------------------------
let HttpActionUrls =
    AIAgentsInfo
    | where isnotempty(RawAgentInfo) or isnotempty(AgentActionTriggers)
    | extend CombinedRaw = strcat(tostring(RawAgentInfo), tostring(AgentActionTriggers))
    | extend UrlMatches = extract_all(@"(https?://[^\s'""\\<>]{8,})", CombinedRaw)
    | mv-expand ExtractedUrl = UrlMatches to typeof(string)
    | extend ExtractedUrl = trim_end(@"[)\.,\\rn]+", ExtractedUrl)
    | where isnotempty(ExtractedUrl)
    | where not(ExtractedUrl has_any (MicrosoftDomains))
    | where not(ExtractedUrl has_any (TemplateDomains))
    | where ExtractedUrl !startswith "https://<"
    | where ExtractedUrl !startswith "https://..."
    | distinct
        AIAgentId,
        AIAgentName,
        TenantId,
        CreatorAccountUpn,
        OwnerAccountUpns,
        AgentCreationTime,
        AgentStatus,
        ConnectedAgentsSchemaNames = tostring(ConnectedAgentsSchemaNames),
        ChildAgentsSchemaNames     = tostring(ChildAgentsSchemaNames),
        SourceType = "HttpRequestAction",
        ExtractedValue = ExtractedUrl;
// ---------------------------------------------------------------
// Arm 3: MCP servers
// ---------------------------------------------------------------
let McpServers =
    AIAgentsInfo
    | where isnotempty(AgentToolsDetails)
    | extend ToolsJson = parse_json(AgentToolsDetails)
    | mv-expand Tool = ToolsJson
    | where tostring(Tool["$kind"]) == "TaskDialog"
    | extend McpName = tostring(Tool.modelDisplayName)
    | extend ConnRef = tostring(Tool.action.connectionReference)
    | extend OpId = tostring(Tool.action.operationDetails.operationId)
    | where isnotempty(OpId)
    | project
        AIAgentId,
        AIAgentName,
        TenantId,
        CreatorAccountUpn,
        OwnerAccountUpns,
        AgentCreationTime,
        AgentStatus,
        ConnectedAgentsSchemaNames = tostring(ConnectedAgentsSchemaNames),
        ChildAgentsSchemaNames     = tostring(ChildAgentsSchemaNames),
        SourceType = "McpServer",
        ExtractedValue = strcat(McpName, " | connRef: ", ConnRef, " | opId: ", OpId);
// ---------------------------------------------------------------
// Union and compute topology risk indicators
// ---------------------------------------------------------------
union KnowledgeSources, HttpActionUrls, McpServers
| extend
    HasConnectedAgents = isnotempty(ConnectedAgentsSchemaNames)
        and ConnectedAgentsSchemaNames != "[]",
    HasChildAgents     = isnotempty(ChildAgentsSchemaNames)
        and ChildAgentsSchemaNames != "[]"
// Summarise per agent so each agent is one row with all its sources
// and its full topology picture visible together
| summarize
    ExternalSources        = make_set(ExtractedValue),
    ExternalSourceCount    = dcount(ExtractedValue),
    SourceTypes            = make_set(SourceType),
    HasConnectedAgents     = max(tobool(HasConnectedAgents)),
    HasChildAgents         = max(tobool(HasChildAgents))
    by AIAgentId, AIAgentName, TenantId, CreatorAccountUpn,
       OwnerAccountUpns, AgentCreationTime, AgentStatus,
       ConnectedAgents = ConnectedAgentsSchemaNames,
       ChildAgents     = ChildAgentsSchemaNames
// Topology risk score - higher = more worth investigating
// External sources + child agents is the highest-risk combination
| extend TopologyRiskScore = toint(
    (ExternalSourceCount * 1)
    + (iif(HasConnectedAgents, 2, 0))
    + (iif(HasChildAgents, 3, 0))   // Child agents weighted higher - direct invocation chain
  )
| extend AgentIsActive = AgentStatus == "Published"
| project
    TopologyRiskScore,
    AIAgentId,
    AIAgentName,
    TenantId,
    AgentCreationTime,
    AgentStatus,
    AgentIsActive,
    CreatorAccountUpn,
    OwnerAccountUpns,
    ExternalSourceCount,
    ExternalSources,
    SourceTypes,
    HasConnectedAgents,
    HasChildAgents,
    ConnectedAgents,
    ChildAgents
| order by TopologyRiskScore desc, AgentCreationTime asc

```

If you are simply looking to base-line what external resources agents are accessing and look for those with an excessive count, or those reaching out to potentially malicious sources, this query will provide you with a basic count of the external resources accessed per agent, those with or without an owner assigned, and those with either an MCP or HTTPRequestAction to reach out and get that external data

```kql

// ============================================================
// HUNT: AI Agent External Sources - Active Agents Only
// ============================================================
// Purpose: Scope the external source hunt to agents that are
//          actively reachable - Published status only.
//          Reduces noise during triage by excluding draft agents
//          that cannot currently be interacted with.
//          Use this as the starting point when triaging findings
//          for immediate risk rather than full inventory coverage.
//
// Tables:  AIAgentsInfo
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
// Pre-filter to active agents only before any expensive parsing
// ---------------------------------------------------------------
let ActiveAgents =
    AIAgentsInfo
    | where AgentStatus == "Published";
// ---------------------------------------------------------------
// Arm 1: Knowledge source URLs
// ---------------------------------------------------------------
let KnowledgeSources =
    ActiveAgents
    | where isnotempty(KnowledgeDetails)
    | extend KD = parse_json(KnowledgeDetails)
    | mv-expand Site = KD.spec.knowledgeSources.publicSites
    | extend ExtractedUrl = tostring(Site.url)
    | where isnotempty(ExtractedUrl)
    | where not(ExtractedUrl has_any (MicrosoftDomains))
    | where not(ExtractedUrl has_any (TemplateDomains))
    | project
        AIAgentId,
        AIAgentName,
        TenantId,
        CreatorAccountUpn,
        OwnerAccountUpns,
        AgentCreationTime,
        LastPublishedTime,
        SourceType = "KnowledgeSource",
        ExtractedValue = ExtractedUrl;
// ---------------------------------------------------------------
// Arm 2: HttpRequest action URLs
// ---------------------------------------------------------------
let HttpActionUrls =
    ActiveAgents
    | where isnotempty(RawAgentInfo) or isnotempty(AgentActionTriggers)
    | extend CombinedRaw = strcat(tostring(RawAgentInfo), tostring(AgentActionTriggers))
    | extend UrlMatches = extract_all(@"(https?://[^\s'""\\<>]{8,})", CombinedRaw)
    | mv-expand ExtractedUrl = UrlMatches to typeof(string)
    | extend ExtractedUrl = trim_end(@"[)\.,\\rn]+", ExtractedUrl)
    | where isnotempty(ExtractedUrl)
    | where not(ExtractedUrl has_any (MicrosoftDomains))
    | where not(ExtractedUrl has_any (TemplateDomains))
    | where ExtractedUrl !startswith "https://<"
    | where ExtractedUrl !startswith "https://..."
    | distinct
        AIAgentId,
        AIAgentName,
        TenantId,
        CreatorAccountUpn,
        OwnerAccountUpns,
        AgentCreationTime,
        LastPublishedTime,
        SourceType = "HttpRequestAction",
        ExtractedValue = ExtractedUrl;
// ---------------------------------------------------------------
// Arm 3: MCP servers
// ---------------------------------------------------------------
let McpServers =
    ActiveAgents
    | where isnotempty(AgentToolsDetails)
    | extend ToolsJson = parse_json(AgentToolsDetails)
    | mv-expand Tool = ToolsJson
    | where tostring(Tool["$kind"]) == "TaskDialog"
    | extend McpName = tostring(Tool.modelDisplayName)
    | extend ConnRef = tostring(Tool.action.connectionReference)
    | extend OpId = tostring(Tool.action.operationDetails.operationId)
    | where isnotempty(OpId)
    | project
        AIAgentId,
        AIAgentName,
        TenantId,
        CreatorAccountUpn,
        OwnerAccountUpns,
        AgentCreationTime,
        LastPublishedTime,
        SourceType = "McpServer",
        ExtractedValue = strcat(McpName, " | connRef: ", ConnRef, " | opId: ", OpId);
// ---------------------------------------------------------------
// Union and collapse to one row per AIAgentId
// Summarising by AIAgentId rather than AIAgentName intentionally -
// a mimic agent sharing a legitimate agent's name will have a
// different AIAgentId and appear as a separate row
// ---------------------------------------------------------------
union KnowledgeSources, HttpActionUrls, McpServers
| summarize
    AIAgentName         = take_any(AIAgentName),
    TenantId            = take_any(TenantId),
    CreatorAccountUpn   = take_any(CreatorAccountUpn),
    OwnerAccountUpns    = take_any(OwnerAccountUpns),
    AgentCreationTime   = take_any(AgentCreationTime),
    LastPublishedTime   = take_any(LastPublishedTime),
    SourceTypes         = make_set(SourceType),
    ExternalSources     = make_set(ExtractedValue),
    ExternalSourceCount = dcount(ExtractedValue)
    by AIAgentId
| extend
    NoOwner          = isempty(OwnerAccountUpns) or OwnerAccountUpns == "[]",
    DaysSincePublish = datetime_diff('day', now(), todatetime(LastPublishedTime))
| project
    AIAgentId,
    AIAgentName,
    TenantId,
    AgentCreationTime,
    LastPublishedTime,
    DaysSincePublish,
    CreatorAccountUpn,
    OwnerAccountUpns,
    NoOwner,
    ExternalSourceCount,
    SourceTypes,
    ExternalSources
| order by DaysSincePublish desc, AIAgentName asc
```

Agents owned by departed users are an immediate deprovisioning gap. Cross-referencing against Entra ID sign-in activity surfaces these quickly:

```kql
AIAgentsInfo
| where AgentStatus != "Deleted"
| join kind=leftouter (
    EntraIdSignInEvents
    | where Timestamp >= ago(30d)
    | summarize LastSignIn = max(Timestamp) by AccountUpn
) on $left.OwnerAccountUpns == $right.AccountUpn
| where isnull(LastSignIn) or LastSignIn < ago(90d)
| project AIAgentId, AIAgentName, OwnerAccountUpns, LastSignIn, AgentCreationTime
```

Beyond posture, the Agent 365 connector streams agent audit logs into
Sentinel's data lake, normalised to ASIM schemas. Once that connector is in
place, you can correlate agent activity against existing endpoint and
identity telemetry. An agent accessing unusual SharePoint sites, invoking
external tools at anomalous hours, or operating without clear human context in
the initiating session is detectable through KQL joins against
`CloudAppEvents` and `IdentityLogonEvents`.

Defender also surfaces blocked actions as incidents - any action that
real-time protection stops generates an alert that lands in Advanced Hunting,
linkable to the responsible agent, user, and tool invocation. These are worth
promoting to custom detection rules early, given the low volume of expected
legitimate blocks.

## What You Need in Place First

There are real prerequisites before any of this works reliably. Agent 365 is
in preview and becomes a paid subscription requirement from 1 July 2026. The
`AIAgentsInfo` table only populates for agents registered in Agent 365 or
Copilot Studio - agents built on other platforms need the Agent 365 SDK
instrumented by the developer before they emit audit logs. Local AI agent
discovery in Defender for Endpoint, also currently in preview, requires MDE
onboarding and only produces telemetry for agents running on managed devices.

Coverage is not automatic. An agent deployed in a web app, running in Azure
Container Apps, or built by a team that has not integrated the SDK will not
appear in your hunting results. Absence of results is not absence of agents -
a gap that is easy to misread as a clean environment.

The posture-based queries above are a sensible first sweep precisely because
they work with whatever is already registered. Behavioural detection -
correlating agent actions against expected baselines - requires sustained log
collection and a clear picture of what normal looks like for your agents. Most
organisations will need time to build that. Starting with inventory, promoting
stable queries to scheduled analytics rules, and layering behavioural logic
incrementally is the right sequencing. Skipping straight to complex
behavioural detections on incomplete telemetry produces noise that discredits
the programme before it gets going.

## Closing Thoughts

The `AIAgentsInfo` table is not a finished detection capability - it is the
beginning of one. The foundations are solid: familiar KQL, ASIM-normalised
schemas, incident correlation, and integration with the hunting workflows your
team already runs. But coverage gaps are real, the maturity requirements are
non-trivial, and most environments will have agents that are not visible yet.

The right response is not to wait for full coverage. Run the inventory
queries now. Understand what you can and cannot see. Start building detection
logic against the telemetry that does exist. The threat model for AI agent
compromise is not abstract - it is the same over-permissioning and lifecycle
drift that security teams have been cleaning up for years, in a context where
the consequences are significantly larger.

Your Advanced Hunting schema just grew. It is worth finding out what is in it.
