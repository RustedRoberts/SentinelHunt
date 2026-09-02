---
title: "New Hunting Queries for AI Agent Drift, Built on a Table That Only Went Live Three Weeks Earlier"
date: 2026-09-02
author: Chris Scott
summary: Microsoft shipped genuinely useful KQL for hunting AI agent configuration drift in July 2026, but the queries depend on AgentsInfo, a table that only became authoritative on 1 July after replacing AIAgentsInfo outright. Here's the hunting logic, and why detections-as-code teams need to treat schema churn as part of the threat model.
tags:
  - ai-agents
  - advanced-hunting
  - kql
  - agent-365
  - detection-engineering
  - ci-cd
published: false
---

## Introduction

I wrote back in June about `AIAgentsInfo`, the table Microsoft shipped as part of the Agent 365 preview to give SOCs their first real visibility into AI agent inventory. The queries I put together then were mostly posture and topology - what can this agent reach, does it have an owner, how far could a poisoned source travel through it. Useful for a first sweep, but static. They tell you what an agent looks like right now.

In July, Microsoft's own team went further. A set of hunting queries merged into the Azure-Sentinel GitHub repository that hunt configuration *drift* on AI agents - instructions being edited on a published agent, a new MCP server wired in, an owner added, sharing scope quietly expanding from a restricted group to the whole tenant. Exactly the behavioural layer that inventory queries alone can't give you.

Here's the complication. Those drift queries run against `AgentsInfo`, not `AIAgentsInfo`. And `AgentsInfo` only became the authoritative source on 1 July 2026, the same week the older table stopped returning data entirely. Not a rename - a different primary key, a different column set, a different backing data source (Microsoft Agent 365 as the single source of truth). So the newest hunting content in the Sentinel ecosystem right now sits on top of one of the newest schemas, and if you're running detections as code, that combination is worth taking seriously rather than just bookmarking.

## AI agents are now something you hunt, not just something you inventory

Governance controls tell you who can create an agent and what it can touch at creation time. They don't tell you what happened to it since. An agent that was compliant on day one can drift - someone adds a new MCP server that gives it access to a data source it never had, an owner gets added who shouldn't have visibility into how its instructions work, sharing goes from "my team" to "everyone in the tenant" without a change request in sight.

None of that is automatically malicious. But the question that matters, as the author of the drift queries puts it, isn't "what does this agent look like now" - it's "what changed since the last known state." That's a hunting problem, not a policy problem, and it needs the same baseline-and-diff thinking we already apply to identity and endpoint telemetry.

## The hunting logic

The pattern will feel familiar if you've built drift detection for anything else - conditional access policies, firewall rules - applied here to agent configuration. Two non-overlapping windows, a longer baseline and a short recent period, compared against each other:

```kql
let lookback = 14d;
let recent = 2d;
```

From there it's `arg_max(Timestamp, *)` to pull the latest snapshot per agent within each window, an `inner join` to restrict comparison to agents that existed in both periods (so you're diffing drift, not catching new agent creation), and `mv-expand` to flatten dynamic array fields - McpServers, Owners, SharedWith - so each entry can be compared individually. Where a field is an array, `set_difference()` does the work of surfacing what was added or removed between snapshots.

One detail worth calling out: for instruction changes, the query doesn't return both versions of the instruction text in plaintext. It exposes a hash and a length delta instead. Instructions can carry sensitive business logic, and a hash-plus-delta tells an analyst something changed and roughly how much without scattering the full content across alert payloads and incident notes.

The ATT&CK mappings are deliberately restrained. An instruction change maps to Stored Data Manipulation (T1565.001). An owner addition maps to Account Manipulation (T1098), under persistence and privilege escalation. New MCP servers and expanded sharing are left unmapped, because they describe a change in exposure or capability rather than a specific attacker technique. I'd rather see that restraint than a forced mapping - these queries frame an investigation hypothesis, they don't declare every drift event malicious, and treating unmapped behaviour as unmapped keeps the signal-to-noise conversation honest from day one.

## What this costs you if you're not watching the schema

Here's where the timing becomes the actual story. Two weeks before these drift queries landed, Microsoft Sentinel extended its detections-as-code capability to custom detection rules - teams can now manage them through GitHub or Azure DevOps and deploy via a dedicated Bicep extension, alongside analytics rules, parsers, playbooks and workbooks. Good news if you're trying to get detection content out of the portal and into a proper pipeline.

The complication is what happens when a table underneath one of those pipeline-managed rules gets replaced. The portal has a safety net for exactly this - rules managed there that reference a deprecated table like `AIAgentsInfo` get migrated automatically. Repository-managed rules don't get that safety net. If your `AgentsInfo`-based hunting query, or any custom detection built on it, lives in a Bicep file in your repo, an upstream schema change is entirely your problem to catch, not Microsoft's to quietly absorb. Given that `AIAgentsInfo` to `AgentsInfo` wasn't a rename but a genuine breaking change, that's not theoretical. It's the exact scenario that just happened, weeks before the new hunting content shipped on top of the replacement table.

If you're adopting detections as code, or copying the `AgentsInfo` queries into your own repo, add a PR check that flags references to advanced hunting tables Microsoft has flagged for deprecation or replacement, and run it before merge, not after a rule silently returns zero results in production.

## Closing thoughts

None of this is a reason to hold off on the `AgentsInfo` drift queries - they're good hunting logic and worth adapting even if your organisation is still cautious about agent sprawl. It's a reminder that detection engineering for AI agents right now means treating the schema itself as part of the threat model, not just the behaviour you're hunting for. If you're managing detections as code, this is a good moment to add a deprecated-table check to your pipeline before leaning further into agent telemetry - the next `AIAgentsInfo`-to-`AgentsInfo` style migration won't announce itself any louder than this one did.

While you're auditing pipeline dependencies, it's also worth checking whether any analytics rules still assign playbooks the old way, through the classic "Automated response" tab rather than automation rules. Microsoft is retiring that method on 15 March 2026 (new assignments through it were already blocked back in 2023), so if those rules haven't been migrated yet, they belong on the same list.

## References

1. [Hunting AI Agent Configuration Drift with Microsoft Sentinel - Microsoft Community Hub](https://techcommunity.microsoft.com/discussions/microsoftsentinel/hunting-ai-agent-configuration-drift-with-microsoft-sentinel/4538962)
2. [Custom Detection Rules as Code in Sentinel Repositories: What Your Pipeline Owns Now - Microsoft Community Hub](https://techcommunity.microsoft.com/discussions/microsoft-security/custom-detection-rules-as-code-in-sentinel-repositories-what-your-pipeline-owns-/4536196)
3. [AIAgentsInfo table in the advanced hunting schema - Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aiagentsinfo-table)
4. [AgentsInfo table in the advanced hunting schema - Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-agentsinfo-table)
5. [AIAgentsInfo to AgentsInfo: A Technical Migration Guide Before the July 1, 2026 Cutoff - Derk van der Woude, Medium](https://derkvanderwoude.medium.com/aiagentsinfo-agentsinfo-a-technical-migration-guide-before-the-july-1-2026-cutoff-e35052fd616c)
6. [Important Update for Microsoft Sentinel Users: Deprecation of Alert-Triggered Playbooks - Rod Trent, Substack](https://rodtrent.substack.com/p/important-update-for-microsoft-sentinel)
