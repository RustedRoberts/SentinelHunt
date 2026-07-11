---
title: ASIM Just Got an Agent Event Schema - Here's How to Hunt Across It
date: 2026-07-11
author: Chris Scott
summary: Microsoft added a dedicated ASIM schema for AI agent telemetry in June 2026 - _Im_AgentEvent - alongside a public-preview Agent 365 connector and an Agent Identities asset connector. Here's what changed since the AIAgentsInfo post, and three hunting queries to run against it today.
tags:
  - ai-agents
  - asim
  - kql
  - agent-365
  - advanced-hunting
published: true
---

## Picking up where the last post left off

Back in May, [`AIAgentsInfo`](/blog/new-table-advanced-hunting-schema-aiagentsinfo) gave SOCs their first queryable inventory of AI agents - identity, ownership, connected MCP servers, external sources. It answered "what agents exist and what could they reach." It did not answer "what are they actually doing."

That gap has started closing. In June 2026, Microsoft shipped a dedicated ASIM normalization schema for AI agent telemetry - Agent Event - together with a public-preview **Agent 365 connector** that streams agent observability data from Agent 365, Azure AI Foundry, and Copilot into the Sentinel data lake, normalized and ready to query. A separate **Agent Identities asset connector** brings identity context into the same picture, tracing from owner to identity to blueprint to permissions.

Where `AIAgentsInfo` is posture, this is behaviour. The two are meant to be queried together.

## What `_Im_AgentEvent` actually captures

The Agent Event schema (currently version 0.1.0 - young, expect it to move) represents "events associated with the activities and telemetry of AI agents operating throughout enterprise environments": model invocations, tool usage, token consumption, agent-to-agent communication, and thought-process detail, all normalized into one shape regardless of which platform generated it. As with every ASIM schema, you query it through a unifying parser rather than a raw table - `_Im_AgentEvent` - so a single query can span every agent platform that ships a conforming parser, not just Agent 365.

The fields worth knowing before writing anything against it:

- **SrcAgentId / SrcAgentName / SrcAgentBlueprintId** - the agent that initiated the event.
- **TargetAgentId / TargetAgentName / TargetAgentBlueprintId** - set when one agent invokes another. This is the field that matters most for hunting agent-to-agent chains.
- **PlatformTargetAgentId / PlatformTargetAgentName** - the platform-level target, distinct from a logical target agent.
- **ActorUserId / ActorUsername** - the human or service principal behind the activity, normalized the same way as the User entity across every other ASIM schema.
- **ModelProviderName / ModelName** and **InputTokensUsed / OutputTokensUsed** - what model answered the call and what it cost.
- **ToolId / ToolName / ToolDescription** - the tool invoked, when the event represents tool usage.
- **EventType / EventOriginalType** - normalized vs. source-reported operation. Because agents can perform an open-ended range of actions, `EventType` isn't a closed enumeration the way it is in more mature schemas - expect to lean on `EventOriginalType` for platform-specific nuance for a while yet.
- **EventThoughtProcessDetails / EventThoughtProcessId** - reasoning trace, where the source platform exposes one.
- **EventFinishReasons** - dynamic array of why the event completed, useful for spotting truncated or refused responses at scale.

The parser also supports filtering parameters worth using for performance: `starttime`, `endtime`, `agentid_has_any`, `agentname_has_any`, and `username_has_any`. Pushing these into the parser call rather than filtering after the fact is the difference between a query that scans everything and one that doesn't.

## Three hunts to run

### 1. Token and tool-fan-out outliers

A simple baseline: which agents are burning disproportionate tokens or touching an unusually wide set of tools in a given window. Neither is inherently malicious, but both are cheap signals worth a first look, and either can indicate a compromised or misbehaving agent looping against a tool or model.

```kql
_Im_AgentEvent(starttime=ago(1d), endtime=now())
| where isnotempty(SrcAgentId)
| summarize
    TotalInputTokens  = sum(InputTokensUsed),
    TotalOutputTokens = sum(OutputTokensUsed),
    DistinctTools     = dcount(ToolId),
    ToolsUsed         = make_set(ToolName),
    DistinctModels    = dcount(ModelName),
    EventCount        = count()
    by SrcAgentId, SrcAgentName, bin(TimeGenerated, 1h)
| where DistinctTools >= 5 or TotalOutputTokens > 500000
| order by TotalOutputTokens desc
```

Tune the thresholds against your own agent population before trusting them - a handful of legitimate orchestration agents will always sit at the high end, and the point of a first pass is to find and baseline them, not to alert on them immediately.

### 2. New edges in the agent-to-agent communication graph

The most interesting field in this schema for hunting purposes is `TargetAgentId`. When it's populated, one agent called another. Most agent-to-agent relationships in a mature deployment are stable - the same orchestrator invoking the same handful of sub-agents day after day. A source agent calling a target it has never called before is a new edge in that graph, and new edges are worth a look, the same way a service account authenticating to a host it has never touched before is worth a look.

```kql
let Baseline  = 14d;
let Lookback  = 1d;
let priorEdges =
    _Im_AgentEvent(starttime=ago(Baseline + Lookback), endtime=ago(Lookback))
    | where isnotempty(SrcAgentId) and isnotempty(TargetAgentId)
    | distinct SrcAgentId, TargetAgentId;
_Im_AgentEvent(starttime=ago(Lookback), endtime=now())
| where isnotempty(SrcAgentId) and isnotempty(TargetAgentId)
| distinct SrcAgentId, SrcAgentName, TargetAgentId, TargetAgentName, EventSessionId
| join kind=leftanti priorEdges on SrcAgentId, TargetAgentId
| summarize FirstSeenSessions = make_set(EventSessionId), Count = count()
    by SrcAgentId, SrcAgentName, TargetAgentId, TargetAgentName
| order by Count desc
```

This is a first-seen-edge query, not a verdict - pair it with the blueprint and ownership context from `AIAgentsInfo` (or the new Agent Identities asset connector) before deciding whether a new edge is a legitimate orchestration change or something that needs a closer look.

### 3. Tool execution with no `invoke_agent` root

This one is more of a coverage hunt than a behavioural one, but it's worth knowing about because it exposes a real blind spot. Per Microsoft's Agent 365 observability documentation, a run is only visible to the agent-inventory and posture views (and to `AIAgentsInfo`) if it has a valid `invoke_agent` span at its root. A run consisting only of `chat`, `execute_tool`, or `output_messages` spans - no root - is invisible everywhere except Advanced Hunting's `CloudAppEvents` table, where it still lands with `ActionType` values including `InvokeAgent`, `InferenceCall`, `ExecuteToolBySDK`, `ExecuteToolByGateway`, and `ExecuteToolByMCPServer`, with the per-span attributes carried in `RawEventData`.

In practice that means tool executions can occur that never show up in your agent inventory at all. Hunting for `ExecuteTool*` events with no matching `InvokeAgent` in the same conversation is a way to find them:

```kql
let toolCalls =
    CloudAppEvents
    | where ActionType in ("ExecuteToolBySDK", "ExecuteToolByGateway", "ExecuteToolByMCPServer")
    | extend RawJson = parse_json(RawEventData)
    | extend ConversationId = tostring(RawJson.ConversationId), AgentId = tostring(RawJson.AgentId);
let invokedConversations =
    CloudAppEvents
    | where ActionType == "InvokeAgent"
    | extend ConversationId = tostring(parse_json(RawEventData).ConversationId)
    | distinct ConversationId;
toolCalls
| join kind=leftanti invokedConversations on ConversationId
| project Timestamp, AgentId, ActionType, ConversationId, RawEventData
```

Treat the `Application` scoping and exact `RawEventData` field names as things to confirm against your own tenant's ingested schema before relying on this - the connector is in public preview and the attribute mapping is documented as `gen_ai.*` and `microsoft.a365.*` OpenTelemetry span attributes underneath, which can shift. But the underlying idea - orphaned tool calls with no inventory-visible parent - is a durable hunting pattern regardless of exact field names, and it's the kind of gap that's easy to mistake for "no activity" rather than "no visibility."

## What's still missing

None of this replaces the posture work `AIAgentsInfo` already does - it extends it. Ownership, blueprint identity, and permission context now flow in separately through the Agent Identities asset connector rather than living inside the activity events themselves, so a proper investigation still means joining across at least two, and often three, of these sources: `AIAgentsInfo` for what an agent is authorized to reach, `_Im_AgentEvent` (or `CloudAppEvents`) for what it actually did, and the identity graph for who's accountable for it.

The schema is version 0.1.0 for a reason. `EventType` isn't a closed enumeration yet, coverage depends entirely on which platforms ship conforming parsers, and the Agent 365 connector itself is still public preview. Treat everything above as a starting point for building baselines, not as a promoted detection - the same caution that applied to the AIAgentsInfo queries in May applies here. But the direction is right: agent activity is becoming first-class, normalized, joinable telemetry, and that's worth building hunting muscle against now rather than after the first incident forces the issue.
