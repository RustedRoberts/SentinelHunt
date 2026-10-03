---
title: "The Credential That Isn't a Secret: Hunting Federated Identity Persistence in Entra"
date: 2026-10-03
author: Chris Scott
summary: Federated identity credentials give attackers durable access to an app registration without a secret or certificate to rotate, and they log in a place most persistence detections never look. Two KQL hunts, one new KQL community roundup, and a Teams table worth planning for.
tags:
  - kql
  - sentinel
  - entra-id
  - threat-hunting
  - detection-engineering
  - identity
published: true
---

I read the KQL community roundups every few weeks, mostly to see what practitioners are actually building rather than what vendors say we should be building. The latest Kusto Insights update (29 September) had the usual mix: an NTLM lateral movement anomaly query, an invisible Unicode hunt for email, and two Entra queries that kept pulling me back, one on unusual credentials being added to OAuth apps and one on federated credentials being added to app registrations.

Those last two are the same worry from different angles. Most of us have a persistence detection for "someone added a secret or certificate to a service principal". Far fewer of us have one for "someone told the app to trust an identity provider they control". If that is you, there is a gap, and it is a quiet one.

This post walks through why that gap exists, the two hunts I would run this week, and what else landed in the last few days that is worth knowing about.

## A credential with nothing to rotate

Workload identity federation lets an Entra app trust tokens issued by an external OpenID Connect provider, so a GitHub Actions pipeline or a Kubernetes cluster can get an Entra token without anyone storing a client secret. That is a good thing. It removes secrets from pipelines, which is exactly what we have been asking for. The trust is expressed as a federated identity credential (FIC) attached to the app, made up of an issuer, a subject and an audience.

The problem is what that looks like from an attacker's side. If they hold enough permission on an app registration, they can add a FIC that trusts an issuer they control, mint tokens that satisfy the subject claim, and sign in as the service principal whenever they like. There is no secret to expire, no certificate to renew, and nothing for a rotation policy to catch. A July write-up on the trackr blog makes the point well: the write that creates the persistence is the thing to detect, because it happens once, early, before any token is exchanged.

Elastic's detection for this tradecraft covers the other end of the chain. Their rule alerts the first time a service principal authenticates using a federated credential, and they describe the attack as bring-your-own-OIDC-provider. Which is neat, but it only fires after the attacker has already used the access. I would rather know when the trust was created.

## The detection and hunting angle

The catch, and the reason naive detections miss this, is that adding a FIC to an app registration is not logged as "Add service principal credentials". It appears in the Entra audit log as `Update application`, and the useful part is buried in `modifiedProperties` under a property called `FederatedIdentityCredentials`. If your persistence rule keys on the credential-add operation names, it will never see it. Technique-wise this maps to Account Manipulation: Additional Cloud Credentials (T1098.001) and Valid Accounts: Cloud Accounts (T1078.004).

Here is the hunt for app registrations, adapted from the trackr write-up:

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Update application"
| mv-expand tr = TargetResources
| mv-expand mp = tr.modifiedProperties
| where tostring(mp.displayName) == "FederatedIdentityCredentials"
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),
         ActorSpId = tostring(InitiatedBy.app.servicePrincipalId),
         SrcIp = tostring(InitiatedBy.user.ipAddress),
         AppName = tostring(tr.displayName)
| project TimeGenerated, Actor, ActorSpId, SrcIp, AppName, OldValue = mp.oldValue, NewValue = mp.newValue
```

The second half is easy to forget. User-assigned managed identities can also carry FICs, and those writes do not show up in the Entra audit log at all. They sit in Azure Activity:

```kql
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue =~ "MICROSOFT.MANAGEDIDENTITY/USERASSIGNEDIDENTITIES/FEDERATEDIDENTITYCREDENTIALS/WRITE"
| where ActivityStatusValue in~ ("Succeeded", "Success")
| project TimeGenerated, Caller, CallerIpAddress, _ResourceId, Properties
```

Two objects, two tables. If you only cover one, you have half a detection and a false sense of coverage.

The tuning is where the real work is. Build an allowlist of issuers you expect, such as `https://token.actions.githubusercontent.com` if you use GitHub Actions, and alert on anything outside it. Then look at who made the change. A FIC added by a deployment pipeline's service principal is a very different story from one added by a human account from an unfamiliar IP address. Finally, parse the subject claim in `NewValue` and ask whether it matches a repository or cluster you actually own.

## Caveats and maturity

A few honest limitations. First, `AuditLogs` needs to be flowing into Sentinel, and plenty of tenants still have partial diagnostic settings. Check before you trust a quiet result. Second, the `NewValue` payload is a JSON string, so extracting issuer and subject for allowlisting takes a little extra parsing, and I would build that into a saved function rather than copy-pasting it into each rule.

Third, this is an atomic detection. It tells you a FIC was added, not whether that was bad. In an organisation that is adopting workload identity federation at pace, which is most of them, a flat alert on every addition will be noisy fast. The maturity step is to enrich with who the actor is, whether the app is one the actor normally touches, and whether the issuer is known. Bert-Jan Pals added an unusual-addition-of-credentials-to-OAuth-apps hunt to his repository on 16 September, and the "unusual" in the name is the right instinct: baseline first, then alert on deviation.

## Also worth knowing this week

Microsoft is rolling out a `MessageContents` table in Advanced Hunting for Teams message snippets and metadata (message centre item MC1474106), from late September to mid-October. Access needs both Advanced Hunting permissions and message preview permissions, so it is worth working out now who in your SOC will hold that second one. External-chat phishing and help desk impersonation have been a hunting blind spot for a long time, and this gives us message context to pivot on.

## Closing thoughts

Every time we move secrets out of the way, attackers move to whatever replaced them. Federation is the right design, and it also changes what persistence looks like. Check that your cloud identity detections cover the FIC write on both app registrations and managed identities, then spend your effort on the allowlist and actor context rather than on more alerts.

If you only do one thing after reading this, run the first query over 30 days. Either you will find nothing and have a baseline, or you will find a trust relationship nobody can explain. Both are useful.

## References

1. [A Federated Identity Credential Adds No Secret. Your Service Principal Persistence Alert Never Fires - trackr](https://www.trackr.live/?p=1229)
2. [Entra ID Federated Identity Credential Issuer Modified - CraftedSignal](https://feed.craftedsignal.io/briefs/2026-03-entra-id-federated-issuer-modified/)
3. [Entra ID Service Principal Federated Credential Authentication by Unusual Client - Elastic](https://www.elastic.co/guide/en/security/8.19/entra-id-service-principal-federated-credential-authentication-by-unusual-client.html)
4. [Kusto Insights - Summer Update](https://kustoinsights.substack.com/p/kusto-insights-summer-update)
5. [Hunting-Queries-Detection-Rules commit history - Bert-JanP](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/commits/main)
6. [MC1474106: New MessageContents table in Advanced Hunting for Microsoft Teams messages - Microsoft Message Center](https://mc.merill.net/message/MC1474106)
7. [Configure an app to trust an external identity provider - Microsoft Learn](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust)
8. [NTLM Network Logon Anomalies (Lateral Movement) - KQLSearch](https://kqlsearch.com/query/NTLM%20Network%20Logon%20Anomalies%20(Lateral%20Movement)&cmpfkhqju00009xmbn7iwt2mj)
