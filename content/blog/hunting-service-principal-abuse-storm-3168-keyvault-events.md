---
title: "Hunting Service Principal Abuse in Azure: Storm-3168 and the New Key Vault Table"
date: 2026-10-13
author: Chris Scott
summary: A compromised service principal deleted over a hundred storage accounts in about seven minutes, and a newly documented Key Vault table gives you somewhere to hunt for the step before that.
tags:
  - kql
  - threat-hunting
  - detection-engineering
  - advanced-hunting
  - entra-id
published: true
---

Most of the cloud hunting I see is aimed at people. Impossible travel, risky sign-ins, MFA fatigue. Service principals get a lot less attention, and I think that is a gap, because nobody is sat behind a service principal to notice something odd. It just runs, with whatever RBAC role someone gave it three years ago.

Two pieces of content landed in the last few weeks that made this concrete for me. Microsoft published its write-up of Storm-3168 on 25 September, and Bert-Jan Pals documented the CloudKeyVaultEvents table in Advanced Hunting on 13 October. Read together, they describe both ends of the same problem: what a compromised service principal does, and where you can see it.

## What Storm-3168 actually did

The activity is a nice example of how little an attacker needs. Microsoft could not confirm how the service principal was first compromised, but its client ID, secret and tenant ID had been posted in plaintext in a public GitHub issue. The secret was later removed, but it stayed in the edit history. Microsoft could not confirm that this secret was the one used, which is worth saying plainly, but the lesson stands either way: a secret that has been public is a secret that is burned.

From there the pattern was patient discovery followed by very fast destruction. One principal spent around 15.5 hours enumerating VMs, subscriptions, resource groups and resources (Cloud Service Discovery, T1526). A second one, using the same infrastructure and user agent, did the same across two subscriptions and then looked at App Service configuration stores, possibly hunting for more credentials. About 16 hours after that came a roughly seven minute destructive run: over 100 storage account deletion attempts, most of which succeeded (Data Destruction, T1485), plus deletion of a Key Vault, a Function App and an App Service plan, and attempts to remove Site Recovery and Azure Backup protection (Inhibit System Recovery, T1490). About 30 minutes later the actor pulled access keys for more than 30 storage accounts.

Two details matter for detection. Five tokens were issued to the destructive principal, some overlapping inside the same 70 seconds, which points to scripting rather than someone clicking around the portal. And everything was done using existing RBAC roles, Storage Account Contributor, Contributor and SQL DB Contributor. No exploit, no malware. Valid Accounts: Cloud Accounts (T1078.004) doing exactly what its permissions allowed. Microsoft observed no ransom note and no confirmed data exfiltration, so treat the extortion angle as an assessment rather than a fact.

## Where to hunt

The Azure control plane is the first place to look, and that means the `AzureActivity` table. The idea is not to alert on a single delete, because deletes are normal. It is to alert on one identity doing a lot of them, quickly, across many resources.

```kql
// Burst of successful deletions by a single caller
AzureActivity
| where TimeGenerated > ago(1h)
| where CategoryValue =~ "Administrative"
| where OperationNameValue endswith "/delete"
| where ActivityStatusValue in~ ("Success", "Succeeded")
| summarize Deletes = count(),
            Resources = dcount(_ResourceId),
            Types = make_set(tostring(split(OperationNameValue, "/")[1]), 10),
            IPs = make_set(CallerIpAddress, 5)
    by Caller, bin(TimeGenerated, 10m)
| where Resources >= 10
| order by Deletes desc
```

The `Caller` column holds the object ID for a service principal, so you will want to join it to your own inventory of application identities. The threshold of ten is a starting point, not a recommendation. Run it over 30 days first and see what your normal infrastructure pipelines look like, because Terraform destroying a test environment will trip it.

The credential collection step is just as useful and usually much quieter. A principal listing keys on one or two storage accounts is routine. One listing keys on thirty is not.

```kql
// Storage key retrieval across many accounts
AzureActivity
| where TimeGenerated > ago(1d)
| where OperationNameValue =~ "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION"
| where ActivityStatusValue in~ ("Success", "Succeeded")
| summarize Accounts = dcount(_ResourceId),
            First = min(TimeGenerated),
            Last = max(TimeGenerated)
    by Caller, CallerIpAddress
| where Accounts >= 5
```

## The Key Vault gap

This is where the new table comes in. Bert-Jan's post documents `CloudKeyVaultEvents`, which his testing suggests is fed by the Defender for Key Vault plan. Disabling the plan stopped data arriving. He puts the cost at $0.25 per vault per month, which is hard to argue with, though check that against your own pricing.

The useful part for hunting is the identity and correlation columns: `AccountType`, `AccountObjectId`, `ActivityName`, `IPAddress` and an `AdditionalFields` property that can carry the `UniqueTokenIdentifier`. That token identifier is what lets you join Key Vault activity back to a sign-in in `EntraIdSignInEvents` or `EntraIdSpnSignInEvents`, which is the missing link in most investigations. I would start with a simple enumeration-versus-read view per identity, in the spirit of his examples.

```kql
// Key Vault enumeration and reads per identity (validate ActivityName values with getschema first)
CloudKeyVaultEvents
| where Timestamp > ago(1d)
| summarize Lists = countif(ActivityName has "List"),
            Reads = countif(ActivityName has "Get"),
            Vaults = dcount(AzureResourceId),
            IPs = make_set(IPAddress, 5)
    by AccountObjectId, AccountType
| where Vaults >= 3 or Lists + Reads >= 50
```

## Caveats

Please treat the queries above as starting points that I have not run against a live tenant for this post. Table and column names in this area vary, and Bert-Jan himself notes that some columns referenced in his write-up do not appear in the schema table, so run `getschema` in your own environment before you trust anything. The `ActivityName` matching in particular is a placeholder until you have seen your real values.

The bigger dependency is logging. `AzureActivity` needs the subscription activity log connector, and the Key Vault table needs the Defender plan switched on. If a vault is not sending data, you will not see an attack on it, which is why his coverage check, comparing vaults sending data against your total, is worth running before any hunting.

## Closing thoughts

The thing that sticks with me from Storm-3168 is the 16 hour gap between discovery and destruction. That is a window, and discovery behaviour from an identity that has never done discovery before is a far better signal than the deletes themselves. If you have only got time for one thing, baseline what your service principals normally do and alert when one steps outside it.

The other action is much less glamorous. Check your repositories and issue trackers for pasted credentials, and treat anything that has ever been public as compromised, whether or not it was later removed.

## References

1. [Storm-3168: Agentic-driven cloud attacks using compromised service principals - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)
2. [CloudKeyVaultEvents: Azure Key Vault Logs, Schema and KQL Hunting - KQL Query (Bert-Jan Pals)](https://kqlquery.com/posts/cloudkeyvaultevents/)
3. [Unmasking EvilTokens: Getting to the root of device code phishing - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)
4. [KQL Sources: 2026 Update - KQL Query](https://kqlquery.com/posts/kql-sources-2026/)
5. [Microsoft Defender XDR custom detection rules guide - Security Scriptographer](https://www.securityscriptographer.com/2026/07/kql-threat-hunting-in-microsoft.html)
