---
title: The Attacks Hiding In Your Retention Window
date: 2026-07-24
author: Chris Scott
summary: Sentinel's data lake retention and KQL graph semantics are exposing slow lateral movement that used to hide inside a 30-day window - while a live AiTM phishing kit shows why fast-moving threats need a completely different kind of query.
tags:
  - kql
  - threat-hunting
  - detection-engineering
  - lateral-movement
  - sentinel-data-lake
published: false
---

I've lost count of the number of hunting queries I've written that start with
`TimeGenerated > ago(30d)`. It's not usually a considered decision, it's just
what the workspace retains, so it's what you hunt against. The trouble is
that attackers know this too. If you're moving through a network one or two
new devices a day, staying under a 30-day retention window isn't hard, it's
the default outcome of being patient. That's not a hypothetical. A write-up
published in June 2026 on hunting against Microsoft's Sentinel data lake laid
out hunts running 90 days deep for infostealer token replay across
geographies, and 180 days for nation-state DNS tunnelling, both patterns that
simply don't exist if you're only looking at a month.

At the same time, some of the most useful detection content published this
year has been about the opposite problem: catching things that move fast. A
phishing-as-a-service kit called Sneaky2FA has been doing the rounds, and Eye
Security published a KQL query in April that catches it not by IoC list but
by session behaviour. Put those two threads together and you get a genuinely
useful lesson for anyone doing detection engineering with KQL right now: the
query class you reach for has to match the tempo of the thing you're
hunting, and most of us are still defaulting to one setting.

## Slow attackers, short memories

Lateral movement, MITRE's Lateral Movement (TA0008), is the textbook case
for this mismatch. A domain compromise rarely goes straight from initial
access to Domain Admin. It goes through a chain of "this account has local
admin on that box, which has a cached session for an account that's admin
somewhere else" repeated a handful of times, often over weeks. Traditional
KQL queries are bad at this. You can join `DeviceLogonEvents` to itself a
couple of times, but multi-hop, variable-length path-finding is exactly the
kind of problem relational thinking struggles with, which is why teams have
historically reached for a bolt-on tool like BloodHound to do it properly.

That's changed more than most Sentinel users seem to have noticed. KQL graph
semantics, the `make-graph` and `graph-match` operators, went generally
available back in May 2024, and Fabian Bader's write-up on using them for
lateral movement mapping is still one of the clearest demonstrations of what
they're for. You model identities and devices as nodes, pulled from
`IdentityInfo` (Microsoft Defender for Identity) and `DeviceInfo` (Microsoft
Defender for Endpoint), and connect them with edges like `AdminTo`,
`HasSession` and `HadSession`. Then you pattern-match.

## Building and reading the graph

Conceptually, it looks something like this:

```kql
IdentityInfo
| where AccountUPN != ""
| project NodeId = AccountUPN, NodeType = "Identity"
| union (
    DeviceInfo
    | project NodeId = DeviceName, NodeType = "Device"
)
| make-graph NodeId --> NodeId with_node_id=NodeId

// separately, build edges from AdminTo / HasSession / HadSession
// and use graph-match to find paths like:
// (compromisedUser)-[AdminTo*3..9]->(domainAdmin)
```

The real value is in the `graph-match` step, where you can ask for any path
between three and nine hops long connecting a specific compromised identity
to a Domain Admin account, and get back the actual chain, not just a "yes,
connected" answer. If your workspace doesn't have data lake retention or
you're not ready for graph semantics yet, Rod Trent's September 2025 piece on
simulating graph-like traversals with recursive unions and dynamic arrays is
a decent stopgap, though it's noticeably more work for the same result.

Now put that next to Sneaky2FA. This is an AiTM kit that proxies a victim's
session through an attacker-controlled relay to lift both credentials and
session tokens, which is how it survives MFA. Eye Security's detection
doesn't try to keep a list of known bad user agent strings, which would be a
losing game against a kit that rotates through five or six of them. Instead
it groups `SigninLogs` by `CorrelationId` (the session identifier), looks for
three or more distinct user agents inside that single session, and uses a
Jaccard similarity check between agent pairs to flag genuinely dissimilar
ones rather than minor version drift. Roughly:

```kql
SigninLogs
| where isempty(tostring(DeviceDetail.deviceId))
| where ResultType == 0
| summarize UserAgents = make_set(UserAgent) by CorrelationId, UserPrincipalName
| where array_length(UserAgents) >= 3
// then compare UA pairs and flag Jaccard similarity below ~0.8
```

That's a fast-turnaround detection: the anomaly exists inside a single
session, so it doesn't need weeks of retention, it needs a query that runs
often and catches the pattern within minutes of it occurring.

## Where each approach falls over

None of this works for free. Graph-based lateral movement hunting is only as
good as your MDE and MDI coverage, if either data source has gaps, the graph
has gaps, and you'll miss hops rather than get a clean "no path found."
Long-retention hunting against the data lake tier needs that tier actually
provisioned and ingesting the tables you care about, and promoting a hunt
that works into a scheduled analytics rule means re-validating thresholds
and re-checking that your automation rules and Logic Apps playbooks still
behave correctly under the unified incident model, that's not a copy-paste
job.

And if your instinct after reading about Sneaky2FA is "let's make this an
NRT rule so it fires in near-real-time," it's worth knowing what you'd be
signing up for. FalconForce's research from February this year, and the
community-run Kusto Insights updates, catalogue the constraints in detail:
NRT rules can only query a single table, no joins or unions at all, which
rules out most cross-table correlation. The advertised one-minute cadence is
really closer to two minutes once ingestion delay is accounted for. And the
syntax is unforgiving, a single `//` comment in the query body breaks NRT
eligibility entirely, and regex patterns need double-escaping that scheduled
rules don't require. A `SentinelScope_CF` requirement added in April 2026
can also cause alerts to go unseen by analysts if it's missed during setup.
None of that makes NRT rules a bad choice, but it does mean they're the
wrong tool for the multi-hop, cross-table graph queries above.

## Closing Thoughts

If there's one thing worth taking from this year's crop of KQL content,
it's that "threat hunting query" isn't one category of thing. A
session-level AiTM detection, a multi-hop lateral movement graph, and a
sub-two-minute NRT rule are solving different problems with different
constraints, and reaching for the wrong one doesn't just underperform, it
can leave a genuine gap. My suggestion, if you haven't already, is to pick
one hunt you're fairly sure is only working because your retention happens
to be short enough to miss the pattern, and go and prove yourself right or
wrong against the longer window. You might not like what you find.

## References

1. [Hunting at Machine Speed - KQL on the Sentinel Data Lake](https://socautomators.substack.com/p/hunting-at-machine-speed-kql-on-the), socautomators.substack.com, 8 June 2026
2. [Find lateral movement paths using KQL Graph semantics](https://cloudbrothers.info/en/find-lateral-movement-paths-kql-graph-semantics/), Fabian Bader, cloudbrothers.info, 8 July 2024
3. [Simulating Graph-Like Traversals and Recursive Patterns in KQL](https://rodtrent.substack.com/p/simulating-graph-like-traversals), Rod Trent, rodtrent.substack.com, 15 September 2025
4. [Sneaky 2FA: Use This KQL Query to Stay Ahead of the Emerging Threat](https://www.eye.security/blog/sneaky2fa-use-this-kql-query-to-stay-ahead-of-the-emerging-threat), Eye Security, 10 April 2026
5. [FalconFriday - Need for Speed: going underground with near-real-time (NRT) rules - 0xFF26](https://falconforce.nl/falconfriday-need-for-speed-going-underground-with-near-real-time-nrt-rules-0xff26/), FalconForce, 6 February 2026
6. [Kusto Insights - May Update](https://kustoinsights.substack.com/p/kusto-insights-may-update-94e), kustoinsights.substack.com, May 2026
