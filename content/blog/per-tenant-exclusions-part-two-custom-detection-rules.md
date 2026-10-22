---
title: "Per-Tenant Exclusions, Part Two: Taking the Pipeline Pattern to Custom Detection Rules"
date: 2026-10-07
author: Chris Scott
summary: A follow-up to the four exclusion patterns. Custom detection rules can now be deployed as code through Sentinel Repositories, which changes where the exception block lives and what your pipeline now owns.
tags:
  - kql
  - sentinel
  - multi-tenant
  - detection-engineering
  - ci-cd
published: true
---

When I wrote up [four patterns for per-tenant exclusions](/SentinelHunt/#/blog/per-tenant-exclusions-multi-tenant-sentinel-four-patterns) back in June, the two pipeline patterns both had a quiet assumption baked in. The rule being deployed was a Sentinel analytics rule, because that was the thing Sentinel Repositories could push. Custom detections, the Defender XDR rules that run against advanced hunting tables, stayed a portal job. Whatever noise tuning you had worked out in Git stopped at the edge of that world.

In July that edge moved. Custom detection rules are now supported in Sentinel Repositories as a preview, managed through the Microsoft Security Bicep extension [1][2][5]. I went back to the file-association hijack example from the original post to see what happens when you try to carry the same patterns across. Some of it transfers neatly. Some of it needs rethinking, and one of the new constraints is genuinely useful.

## What is actually new

The example rule in the original post was built on `DeviceRegistryEvents`, an advanced hunting table. That is exactly the sort of rule that fits a custom detection better than an analytics rule, and since January custom detections have also supported near real-time configuration on Sentinel data [3]. So the content most worth tuning per tenant is the content that previously had no supported pipeline.

The new content type uses its own extension and resource provider. You declare the extension in a `bicepconfig.json` at the repo root, and each rule becomes a `Microsoft.Security/detectionRules` resource with an `id`, a `displayName`, a `status`, a `queryCondition` holding the `queryText`, a `schedule`, and a `detectionAction` carrying the alert template with severity, tactics, techniques and entity mappings [2]. You need a Microsoft 365 E5 licence or equivalent, and your workspaces must be onboarded to the Defender portal [2].

## Where the exception block goes

In Patterns 3 and 4 the trick was marker comments in the base query, with a script splicing a tenant-specific KQL fragment between them at deployment time. With Bicep you do not need the splicing script for this, because the language can compose strings itself. One approach, which I have reasoned through but not run end to end against this extension, is to keep the base query and each tenant's exceptions as plain `.kql` files and let a small per-tenant Bicep file join them:

```bicep
extension MicrosoftSecurity

var baseQuery = loadTextContent('../../queries/file-assoc-hijack.kql')
var exceptions = loadTextContent('./file-assoc-hijack.exceptions.kql')

resource fileAssocHijack 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'contoso-file-assoc-hijack'
  displayName: 'File association hijack from UNC path'
  status: 'enabled'
  queryCondition: {
    queryText: '${baseQuery}\n${exceptions}'
  }
  schedule: {
    frequency: 'PT1H'
  }
  // detectionAction omitted for brevity
}
```

The exception file still starts with `| where ...`, and the same weakness from Pattern 3 applies, because nothing enforces that convention. What you gain is that the composition is visible in the template rather than hidden in a script, and a reviewer can see the final shape in one place. Treat it as a starting point and test it in a non-production tenant first.

## The constraints that change the design

This is where the continuation gets interesting, because three documented details push back on the earlier patterns.

First, rules are identified by their `id`, and changing it creates a new rule instead of updating the old one [4]. In a per-tenant world, that makes the ID convention a design decision. A name like `contoso-file-assoc-hijack` is stable and readable, but renaming a customer or restructuring a repo now leaves duplicate rules firing in production.

Second, the docs advise against filtering on `Timestamp` or `TimeGenerated` inside the query, because the service pre-filters on lookback [4]. If your base queries were written as hunts with their own time windows, strip them out before promoting.

Third, and the one I find most useful, repo-managed rules do not get the automatic table and column migrations that portal rules receive when the advanced hunting schema changes [4]. The Patterns 3 and 4 caveat was that the repo is the source of truth for everything except the exception block. For custom detections, it is the source of truth for schema drift as well. A tenant-specific exception file that references a renamed column will fail in that tenant first, which is an argument for a validation step in the pipeline. In the original post I said a KQL validation or dry-run step would help. Here it stops being a nice-to-have.

During the preview, custom frequency for Sentinel-only data and custom details are not supported [2], so check your base rules do not rely on either before you convert them.

## Closing Thoughts

None of this replaces the earlier patterns. Watchlists still suit values that change weekly and are edited by people who do not write KQL, and functions still suit logic you reuse across many rules. If anything, the Bicep route sharpens the original advice: pick a mix, and decide early where each kind of exclusion lives.

If you already run Pattern 3, I would move one custom-detection-worthy rule across this month and see which of those three constraints bites you first. Mine was the ID convention, and I would rather find that out on one rule than on forty.

## References

1. [What's new in Microsoft Sentinel (custom detection rules in Repositories, July 2026) - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/whats-new)
2. [Manage custom content with repository connections - Microsoft Learn](https://learn.microsoft.com/azure/sentinel/ci-cd-custom-content)
3. [What's new in Microsoft Defender XDR - Microsoft Learn](https://learn.microsoft.com/defender-xdr/whats-new)
4. [Custom detection rules as code in Sentinel Repositories: what your pipeline owns - Microsoft Tech Community](https://techcommunity.microsoft.com/discussions/microsoft-security/custom-detection-rules-as-code-in-sentinel-repositories-what-your-pipeline-owns-/4536196)
5. [Microsoft Sentinel Adds Detections-As-Code, Table Insights, and New Data Connectors - Petri](https://petri.com/microsoft-sentinel-detections-as-code-table-insights/)
6. [Per-Tenant Exclusions in a Multi-Tenant Sentinel Estate - SentinelHunt](/SentinelHunt/#/blog/per-tenant-exclusions-multi-tenant-sentinel-four-patterns)
