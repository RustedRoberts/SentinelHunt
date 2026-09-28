---
title: "Your Detections-as-Code Pipeline Doesn't Know When Microsoft Renames a Table"
date: 2026-09-28
author: Chris Scott
summary: Custom detection rules can now live in Git and deploy on every commit - but the safety net that protects portal-saved queries doesn't follow them there.
tags:
  - kql
  - detection-engineering
  - sentinel
  - advanced-hunting
  - ci-cd
published: true
---

I've spent a fair bit of time this year arguing that detection content belongs in source control. Version history, pull requests, a reviewer who isn't just you at half eleven on a Friday - all the usual reasons. So when Microsoft Sentinel Repositories picked up support for custom detection rules as code in July, my first reaction was relief. Custom detections became the unified way to build detection logic across Defender XDR and Sentinel back in late 2025, and until now they'd been the one content type you still had to author by hand in the portal. That gap is closed.

My second reaction, a few days later, was less comfortable. The feature works by declaring a `Microsoft.Security/detectionRules` resource through a dedicated Bicep extension, syncing it to your workspace on every commit. That's a solid, familiar pattern - the same one Sentinel already uses for analytics rules, playbooks and parsers. What's different is what happens when Microsoft changes the schema underneath you. A query saved in the portal gets migrated automatically. A query sitting in your Git repo does not. Nobody tells you. It just keeps running against a table or column that no longer means what it used to, or no longer exists at all.

That's not a hypothetical. It already happened once, in miniature, with a table most Sentinel and Defender XDR customers were only just starting to use.

## The Precedent: A Table That Moved Without Warning

Back in May, Microsoft shipped `AIAgentsInfo` as part of the Agent 365 preview - the first reliable way to query registered AI agents, their owners, runtimes and connected MCP servers through Advanced Hunting. I wrote about it at the time, because it filled a real visibility gap for anyone trying to keep tabs on Copilot Studio and Azure AI Foundry deployments. What I didn't cover, because it hadn't happened yet, is what came next: at general availability, Microsoft folded `AIAgentsInfo` into a unified `AgentsInfo` table with a modified column set.

If you'd saved a hunting query or built an analytics rule against `AIAgentsInfo` through the portal, Microsoft migrated it for you. If that same query lived in a Bicep file in your repository, deployed through CI/CD, it kept referencing the old table name until someone noticed the rule had gone quiet. There's no error, no failed deployment, no red flag in your pipeline. The query is syntactically valid. It simply stops finding anything, because the table it's pointed at has been renamed out from under it.

That's the pattern worth sitting with as custom detections join the as-code family: portal-managed content gets Microsoft's safety net, and repository-managed content doesn't. The more detection logic you move into Git, deliberately, the more of that safety net you give up.

## What This Actually Means for Your Pipeline

None of this is an argument against detections-as-code. It's an argument for treating your pipeline as the thing now responsible for schema lifecycle, rather than assuming Microsoft still has it covered. In practice that means building a few checks most teams haven't had to think about before.

A pull request touching a custom detection rule should be validated against:

- References to advanced hunting tables that are deprecated or mid-migration, checked against a maintained list rather than assumed current
- The result columns the detection engine actually requires - `Timestamp` or `TimeGenerated`, a device identifier, and `ReportId` for anything outside the core Defender tables
- Complete entity mappings, since incomplete mappings quietly break incident grouping rather than failing outright
- No filtering on `Timestamp` or `TimeGenerated` inside the query body - the service prefilters on ingestion time already, so doing it again just burns CPU for nothing

That last point isn't theoretical either. Testing comparing string-matching operators on identical datasets found `in~()` running at roughly 31ms versus 78ms for `has` and 171ms for `contains`. That's invisible in a functional test where the rule either fires or it doesn't, and entirely visible once you're running hundreds of custom detections against high-volume tables at scale.

There's a second, quieter risk worth building a check for: rule ID stability. Custom detection rules are addressed by ID. Change it, deliberately or by accident during a refactor, and you don't update the existing rule - you create a duplicate. Now you've got two rules, one of which nobody's watching.

## Considerations Before You Commit to This

The honest caveat is that this is still preview functionality, and two gaps are worth knowing about before you build a team's workflow around it. Custom frequency isn't yet supported for Sentinel-only data sources, and custom details - the extra structured fields you can attach to a detection for downstream automation - aren't supported through the Bicep path yet either. If either of those matters to your use case, you're not there yet.

There's also a workflow cost that's easy to underestimate. Analysts are used to testing a query in Advanced Hunting and promoting it to a rule with a few clicks. Moving to Bicep splits that workflow: you still prototype in the portal, but now you have to translate a working query into a resource definition, get it through review, and trust the pipeline to deploy it correctly. That's a genuine shift in how detection engineers and SOC analysts hand work to each other, and it's worth deciding, before you migrate a single rule, who owns that translation step and who's accountable for noticing when a rule's coverage has silently changed. Teams I've spoken to who've already made this move are pairing it with a named schema-drift owner and routine threat hunting coverage specifically to catch rules that have gone quiet without anyone flagging it.

## Closing Thoughts

The shift towards detections-as-code is the right direction of travel, and I'd still rather have my custom detections in Git with a review process than scattered across a portal with no change history at all. But "as code" means the code is now yours to maintain in every sense, including the parts Microsoft used to quietly handle for you. Before you migrate your custom detection rules into a repository, go and check which of your existing portal-saved queries reference tables that have already been renamed once this year. If you find any, you've just found your first pipeline check.

## References

1. [Custom Detection Rules as Code in Sentinel Repositories: What Your Pipeline Owns Now - Microsoft Community Hub](https://techcommunity.microsoft.com/discussions/microsoft-security/custom-detection-rules-as-code-in-sentinel-repositories-what-your-pipeline-owns-/4536196)
2. [Manage custom content with repository connections - Microsoft Sentinel - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/ci-cd-custom-content)
3. [Your Sentinel CI/CD Detections Are Now Defender XDR Detections - Precursor Security](https://www.precursorsecurity.com/blog/sentinel-detections-as-code-defender-xdr)
4. [Source Control for Microsoft Defender Custom Detection Rules - SOC Anywhere Blog](https://socanywhere.com/blog/source-control-for-microsoft-defender-custom-detection-rules.html)
5. [Sentinel-As-Code: Defender Custom Detections - noodlemctwoodle (GitHub)](https://github.com/noodlemctwoodle/Sentinel-As-Code/blob/main/Docs/Content/Defender-Custom-Detections.md)
