---
title: "Per-Tenant Exclusions in a Multi-Tenant Sentinel Estate: Four Patterns for Handling Customer-Specific Noise"
date: 2026-06-09
author: Chris Scott
summary: Generic rule logic, bespoke noise per customer. Four patterns for handling per-tenant exclusions in Sentinel - saved functions, watchlists, and two flavours of CI/CD-injected exception blocks - and how to pick between them.
tags:
  - sentinel
  - kql
  - multi-tenant
  - detection-engineering
  - ci-cd
published: true
---

If you run detection content across more than one Sentinel workspace, you may have an exclusions problem. It might not feel like one yet.... maybe you are early enough in the rollout that the noise hasn't started, but eventually you hit the same wall: the rule logic you want to ship is generic and going from 1 repo base to multiple customers, but the *noise* is bespoke per customer.

## The Scenario

One tenant's IT team distributes software from `\\srv-util01\software installs\`. Another uses an SCCM share. A third pushes everything via Intune. The rule that fires on "file association registry write from a UNC path" is correct in all three environments, but only useful in one of them, and only after you have taught it what each environment's normal actually looks like.

The wrong way to solve this is to embed tenant-specific exclusions in the rule body. The right way involves picking from four patterns - saved functions, watchlists, and two flavours of CI/CD-injected exceptions - and knowing when each one fits. This post walks through all four and ends with a comparison of when to reach for each.

## The problem, restated

That concrete example here makes for an easy start:

Take this hunt query, which looks for file-association hijack - registry writes to a `\shell\open\command` key that hand an attacker code execution every time a user opens a file of a given type:

```kql
DeviceRegistryEvents
| where ActionType == @"RegistryValueSet"
| where RegistryKey contains @"\SOFTWARE\Classes\"
| where RegistryKey endswith @"\shell\open\command"
| where InitiatingProcessAccountName != @"system"
```

The technique is real and the query is sound. All good so far!

The trouble starts the moment you run it across a multi-tenant estate. In one tenant you see hundreds of hits a day from a Lenovo System Update rollout. In another, a wave of TeamViewer Host installs from an internal software share. In a third, a Visual Studio update spraying VSIX registrations across developer workstations.

None of these are malicious, but they all need tuning out in different ways, and you cannot do that with a one-to-many rule deployment without introducing blind spots or excluding on string content that is exposing customer data.

The naive response is to keep adding `| where not (...)` clauses to the query until the noise stops. Within a few months you have a 200-line monster query, 80% of which is exclusions, and nobody on the team can tell you which lines protect against which false positives or which customer they were added for.

Worse, the exclusions for Customer A are running against Customer B's data - which is at best wasted compute and at worst a data-segregation concern in a multi-tenant setup.

Four patterns solve this properly. They are not mutually exclusive - most mature setups use a mix - but they have different strengths and weaknesses.

## Pattern 1: Saved functions

A saved function is a named, parameterised piece of KQL stored inside a Log Analytics workspace. Once saved, you can call it from any query in that workspace as if it were a built-in operator. If you have used the ASIM parsers, you have been calling saved functions without necessarily realising it - `_ASim_ProcessEvent` is a function, not a table.

For per-tenant exclusions, the pattern is to define a function whose body contains the allowlist logic and call it from your hunt or analytics rule. The hunt content itself stays tenant-agnostic - only the function's body changes per workspace.

In each tenant's workspace, save a function with the alias `IsTrustedSoftwareSource` and parameters `folderPath:string, valueData:string`. The body for a customer with two internal software shares:

```kql
let trustedUncPaths = dynamic([
    @"\\srv-util01\software installs\",
    @"\\srv-util02\data\"
]);
let isTrustedSource =
    folderPath has_any (trustedUncPaths)
    or folderPath startswith @"c:\program files\"
    or folderPath startswith @"c:\program files (x86)\";
let isTrustedTarget =
    valueData matches regex @'^"?[A-Z]:\\Program Files( \(x86\))?\\';
isTrustedSource and isTrustedTarget
```

Then the hunt query becomes:

```kql
DeviceRegistryEvents
| where ActionType == @"RegistryValueSet"
| where RegistryKey contains @"\SOFTWARE\Classes\"
| where RegistryKey endswith @"\shell\open\command"
| where InitiatingProcessAccountName != @"system"
| where not (IsTrustedSoftwareSource(InitiatingProcessFolderPath, RegistryValueData))
```

The hunt now contains zero tenant-specific data. Every tenant's workspace gets the same hunt, but each one calls its own version of `IsTrustedSoftwareSource`. If a tenant adds a new software share, you update one function in one workspace and every hunt that uses it picks up the change at next execution.

**The strengths:**

- The query stays readable.
- Exclusion logic is testable independently of the rules that use it.
- Updates take effect immediately - no deployment pipeline involved.
- Functions can encapsulate complex logic (regex matching, conditional branches, multi-parameter checks) in a way that watchlists simply cannot.

**The weaknesses** - and if you have tried this at a larger scale you will have run into these:

- You cannot share a function natively across workspaces, so in a multi-tenant Lighthouse setup you have to define it separately in each one.
- Cross-workspace function calls via `workspace("xxx").FunctionName` exist but are fiddly and do not always play nicely with analytics rule contexts.
- Because the function lives inside the workspace, version control happens elsewhere - there is no native git-style history on a saved function unless you have built it via infrastructure-as-code.

Use functions when the exclusion logic is complex enough to deserve its own home, when it is reused across many rules, or when it needs to take parameters and return a computed result rather than just match a list.

## Pattern 2: Watchlists

A watchlist is a Sentinel-native feature: a small reference table you can upload as a CSV, edit through the portal, and join against from KQL via the `_GetWatchlist` function. They are designed for exactly this kind of "list of known-good things" use case - and very handy for a detection engineer working inside a SOC with only one tenant to worry about.

Continuing the same example, create a watchlist called `TrustedSoftwarePaths` with a single column `SearchKey`, then query against it:

```kql
let trusted = toscalar(
    _GetWatchlist("TrustedSoftwarePaths")
    | summarize make_list(SearchKey)
);
DeviceRegistryEvents
| where ActionType == @"RegistryValueSet"
| where RegistryKey contains @"\SOFTWARE\Classes\"
| where RegistryKey endswith @"\shell\open\command"
| where InitiatingProcessAccountName != @"system"
| where not (InitiatingProcessFolderPath has_any (trusted))
```

**The strengths** are mostly around the human UX:

- Watchlists have a CSV editor in the portal, so non-engineers can maintain them without writing KQL.
- They are well-suited to long, flat lists that change frequently - IP allowlists, known service accounts, approved software installer hashes.
- They support multi-column lookups, so you can attach metadata to each entry (owner, justification, expiry date) and surface that in your rule output.

**The weaknesses** make it ill-suited to multi-tenant environments - and in some setups it simply will not work:

- Watchlists are size-limited - Microsoft caps them at 10MB or 30,000 rows depending on which limit you hit first, and lookups against large watchlists can be slow.
- They are tenant-scoped just like functions, so multi-tenant deployments still need a synchronisation story.
- They are optimised for "is this thing in the list" matching. If your exclusion logic involves regex, conditional branches, or relationships between fields, you are back in function territory - and any multi-field matching starts to surface the original problem of ungainly, massive KQL queries.

Use watchlists when the allowlist is a list of values (not logic), when it changes often enough that non-engineers need to maintain it, or when you want each entry to carry metadata that downstream rules can reference.

## Patterns 3 and 4: CI/CD-injected exception blocks

The third and fourth patterns are both doing the same thing at heart - splicing a customer-specific KQL fragment into a base rule at deployment time. They sit outside the product itself, which means you are building this yourself in your deployment pipeline, and you won't find much on either of them in Microsoft's documentation.

That said, they differ enough in how you actually implement them that it is worth treating them as two genuine alternatives rather than variations of the same approach - and which one you go for comes down to a few distinct engineering choices, or simply what you have to work with when you land in a role and get stuck in.

### Pattern 3: Marker-fenced exception blocks

This approach uses KQL line comments as machine-readable bookends:

```text
/// Start of exception

/// End of exception
```

These are inert at query time - KQL ignores them as comments - but a deployment script can search for them. The script has two pieces of logic: one that strips every region between the markers (looping until no more blocks remain, so prior exceptions are cleared before a new one is inserted), and one that appends the markers wrapping the fragment from the customer's exception file, verbatim.

In short - the markers are invisible to KQL but visible to your pipeline. The script finds them, wipes whatever was there before, and drops the new customer-specific exception in. Clean slate for every deployment, so you are not creating exclusion zombies.

That is the whole mechanism. No parsing, no AST, no template substitution, no `| where not(...)` wrapping - the customer-specific KQL is dropped in byte-for-byte between the markers. The markers exist for exactly one reason: to keep things clean on repeat runs. Re-running the workflow with a new exception replaces the prior block rather than stacking exceptions on top of each other.

The rest of the deployment is orchestration: reading the base rule JSON from the repo, loading the customer's workspace details from a customer-config file, pulling service principal credentials from a secret store, locating the existing rule by display name, and PUT-ing the modified rule body back into the analytics query for that specific customer.

A worked example: the exception file for one customer contains:

```kql
| where not (InitiatingProcessFolderPath has_any (
    @"\\srv-util01\software installs\",
    @"\\srv-util02\data\"
))
| where not (
    InitiatingProcessFileName in~ ("teamviewer_host_setup.exe", "teamviewer_host_setup_x64.exe")
    and InitiatingProcessVersionInfoCompanyName =~ "TeamViewer"
)
```

After deployment, the rule running in that customer's workspace is the base query followed by the (above example) markers added as a suffix to the rule logic. A different customer's workspace gets a different exception block, or none at all. Same source rule, tenant-tailored result - each customer has their own exception file.

**The strengths** are relatively simple but powerful:

- Everything lives in git - version control, PR review, blame history, and rollback for free.
- The exception is data, but the rule deployment is code, so changes go through the same review process as anything else.
- Because the exception is appended literally rather than templated, the full expressiveness of KQL is available - joins, lets, regex, anything you can write in a base rule, you can write in an exception.

**The weaknesses** - and this is still not a silver bullet:

- The fragment is concatenated raw onto whatever the previous query ended with, so if the base query does not terminate cleanly and the exception fragment does not start cleanly, you get invalid KQL.
- There is no syntactic check before PUT, so a malformed exception only surfaces when Azure rejects the deployment - or worse, accepts it and the rule fails at evaluation time.
- Convention has to carry the load. Exception files always begin with `| where ...`, but nothing in the pipeline enforces it. The repo is also treated as the source of truth for everything except the exception block, so any manual edits made in the Sentinel portal to a deployed rule are silently overwritten on the next deployment.
- May result in many, many files being created and maintained (but as this is generally deployment-as-code here, you generally can ignore them).

### Pattern 4: Tuning overlay with workflow dialog

A different take on the same fundamental idea, with several engineering choices going the other way. The most visible difference is how the exception gets into the file in the first place.

Instead of relying on engineers raising pull requests, this approach ships a GitHub Actions workflow with a manual dispatch dialog. An engineer - or in principle, an analyst with the right permissions - navigates to **Actions → Apply Tuning and Deploy → Run workflow** and fills in three fields: the customer (a dropdown), the detection ID, and the KQL lines to add. This is something you build using GitHub Actions, so you won't natively see it sitting there when you go looking.

The workflow then:

- Locates the tuning file for the selected customer and detection under `Tuning/<Customer>/<detection-id>.kql`, creating it if it does not exist
- Appends the new lines if the file already exists
- Commits the updated file back to `main` under `github-actions[bot]` so the change is preserved in version control
- Merges the tuning into the detection query in memory
- Deploys the merged rule using OIDC authentication

The splice mechanism is similar in spirit to the marker-fenced approach - comment lines to denote where exception logic begins - but uses a single separator line rather than paired markers:

```text
//==========TUNING BELOW==========/
```

The base query sits above the separator. The customer-specific tuning sits below it. On re-deployment, the deploy script replaces everything below the separator rather than duplicating it - achieving the same clean result on repeat runs as the marker pair.

The differences from Pattern 3 reflect different bets about how exceptions should reach the pipeline and how the surrounding infrastructure should be shaped.

**Trigger model.** Pattern 3 assumes a git-native workflow: edit the exception file, raise a PR, get review, merge, deploy. Pattern 4 exposes a form-based dialog in the GitHub Actions UI. Same end state - a commit to the exception file and a deployment - but the friction is different. The dialog makes the operation accessible to someone who has never opened a YAML file. The PR approach gives more rigorous review by default. Neither is universally better; it depends on whether your team's culture sits closer to engineering or operations.

**Authentication model.** Pattern 3 typically authenticates via service principal credentials pulled from a secret store at runtime. Pattern 4 uses OIDC federated credentials issued by GitHub and trusted by Azure, with each customer mapped to a named GitHub Environment that holds that customer's Azure tenant, client, and subscription IDs. No long-lived credentials live in the repository or in GitHub secrets. The workflow references its environment by name, so credentials are scoped correctly without conditional logic in the workflow steps themselves.

**Append behaviour.** Pattern 3 replaces the entire exception block on each apply. Pattern 4 appends new lines to the existing tuning file. Both keep things clean at the rule-deployment level. The replace approach means the file at any point in time equals the current set of exceptions. The append approach builds up a chronological history of every suppression added - you can see in `git log` exactly when each line was added - but the file grows over time and may need periodic compaction.

**Job isolation.** Pattern 4's workflow has one job per customer with an explicit `if:` condition. GitHub evaluates these at queue time and skips any job that does not match the selected customer. The guarantee this provides is that selecting Customer A in the dropdown cannot result in any action against Customer B's workspace or credentials, even if the workflow logic is later modified incorrectly. That is a sharper form of isolation than relying on a single job that branches on the customer parameter internally.

**The strengths of Pattern 4** overlap with Pattern 3, plus a few specific to the dialog-driven model:

- git-backed, version-controlled, full KQL expressiveness, tenant-scoped.
- The three-minute round-trip from "this is firing repeatedly on legitimate behaviour" to "exception merged and deployed" is easily accessible to non-engineers.
- OIDC removes a class of credential-leak concerns entirely. The per-customer environment model gives defence-in-depth on cross-tenant accidents.

**The weaknesses** overlap too, plus some specific to this design:

- The same "no syntactic check before PUT" problem applies - a malformed KQL line typed into the dialog produces a broken rule, and you find out at deployment time.
- The dialog-driven flow bypasses PR review by design, which is the point, but means a junior analyst can deploy a broken exception without anyone noticing until the next on-call rotation. Some kind of automated KQL validation step in the workflow, or a dry-run toggle that runs the merge but skips the PUT, would help here.
- The append-only file model accumulates zombie exceptions over time - suppressions added for a one-off rollout that never came back never get removed, and they all live inside each tenant individually.

## Picking between them

A useful mental model:

If the exclusion is **a list of values** that changes weekly, edited by humans who do not write KQL, with metadata attached - that is a watchlist.

If the exclusion is **a piece of logic** that is reused across many rules and benefits from parameterisation - that is a function.

If the exclusion is **per-customer-per-rule, version-controlled, reviewed via PR, and your team is git-native** - that is Pattern 3.

If the exclusion is **per-customer-per-rule, needs to be accessible to people who do not write PRs, and you want OIDC credential isolation** - that is Pattern 4.

In practice most mature setups use a mix. Watchlists handle the things that change too often to put through PR review and do not need the full expressiveness of KQL. Functions sit underneath, encapsulating logic that is genuinely reused across many rules. And one of the two pipeline patterns handles the long tail of per-customer-per-rule tuning that is too specific for functions and too logic-heavy for watchlists.

The pattern you start with is less important than recognising early that you need one. Embedding tenant-specific exclusions inside the rule body is the trap - and it is a very easy one to fall into when you are just trying to stop the noise. Once you have made that choice and shipped it, every rule update becomes an exercise in not breaking the customisations you have layered on top, and the cognitive overhead compounds with every new tenant.

Pick a pattern - or more honestly, pick a mix - and commit to it before the noise forces your hand.
