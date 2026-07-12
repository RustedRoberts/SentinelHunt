---
title: LinkedIn companion post
linkedTo: content/blog/aiagentsinfo-retired-agentsinfo-migration.md
date: 2026-07-12
---

The AI agent hunting queries I published last month stopped working on
1 July.

Not because of a bug. Microsoft retired the table they were built on -
AIAgentsInfo - and replaced it with a new one, AgentsInfo, with a
different (better) shape.

It's a good example of a pattern I keep running into with anything in
the advanced hunting schema less than a year old: preview and beta
tables move fast. If you've saved a hunting query, built a workbook, or
promoted a detection against AIAgentsInfo, AADSignInEventsBeta, or
anything else still finding its footing, it's worth a recurring check
against Microsoft's schema change log - not just a review of your own
detection logic.

The upside this time: AgentsInfo is a genuinely better table.
DeclaredDataSources, McpServers, and Endpoints are now first-class
columns instead of values you had to regex out of Copilot Studio-shaped
JSON blobs. And a new Permissions column exposes agent consent and
authorization data that simply wasn't queryable before.

I've mapped the full column rename (AIAgentId -> AgentId,
OwnerAccountUpns -> Owners, AgentStatus -> PublishedStatus +
LifecycleStatus, and the rest) and rewritten the core inventory hunt
against the new schema in the full post - link in comments.

If you maintain hunts against any table still in preview: when did you
last check whether it's still there?

#KQL #ThreatHunting #MicrosoftSentinel #DetectionEngineering #Agent365
