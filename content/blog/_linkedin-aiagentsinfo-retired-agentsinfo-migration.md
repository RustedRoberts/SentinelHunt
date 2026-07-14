---
title: "LinkedIn companion - AIAgentsInfo retirement"
date: 2026-07-14
author: Chris Scott
summary: Short-form LinkedIn post companion to the AIAgentsInfo -> AgentsInfo blog post. Not published to the site (underscore-prefixed, excluded by blog-plugin.ts).
published: false
---

If you copied hunt queries from my post six weeks ago on the AIAgentsInfo
table, they stopped returning results on July 1st.

Microsoft retired AIAgentsInfo and replaced it with a unified AgentsInfo
table as part of the Agent 365 transition. Not a rename - columns split
(AgentStatus became two separate fields with different meaning), types
changed (Owners went from a string to dynamic, RawAgentInfo did too), and
several new first-class columns showed up: McpServers, Permissions,
Guardrails, Instructions (the agent's system prompt), Model.

The part I'd flag loudest for anyone doing detection-as-code: Microsoft
auto-migrates queries saved in the Defender portal, including custom
detection rules built there. It does NOT touch anything saved outside the
portal - repo-managed hunts, custom detections synced through Sentinel
Repositories, anything hit via the API. If your detection content lives in
git, this migration did not happen for you automatically, and it won't be
the last table this happens to.

I've rewritten the external-exposure and ownership-drift hunts from the
original post against the new schema - the external-source hunt got a lot
shorter, since McpServers and Endpoints are now structured columns instead
of something you regex out of raw JSON.

Full writeup, column mapping table, and both rebuilt queries on the blog.

#MicrosoftSentinel #KQL #ThreatHunting #DetectionEngineering #DefenderXDR #Agent365
