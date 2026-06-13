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

The `AIAgentsInfo` table is the starting point. It surfaces agent identity,
last activity, owner, runtime, status, and connected MCP server
configuration. The immediate wins are posture-based - finding the
misconfigured agents before an attacker does.

This query identifies agents whose MCP servers are operating over HTTP rather
than HTTPS, a straightforward configuration risk on any network where an
attacker has any foothold:

```kql
AIAgentsInfo
| where McpServerUrl startswith "http://"
| project AIAgentId, AIAgentName, AIModel, McpServerUrl, AgentOwner, AgentCreationTime
| order by AgentCreationTime asc
```

Agents owned by departed users are an immediate deprovisioning gap.
Cross-referencing against Entra ID sign-in activity surfaces these quickly:

```kql
AIAgentsInfo
| where AgentStatus != "Deleted"
| join kind=leftouter (
    AADSignInLogs
    | where TimeGenerated > ago(30d)
    | summarize LastSignIn = max(TimeGenerated) by UserPrincipalName
) on $left.AgentOwner == $right.UserPrincipalName
| where isnull(LastSignIn) or LastSignIn < ago(90d)
| project AIAgentId, AIAgentName, AgentOwner, LastSignIn, AgentCreationTime
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
