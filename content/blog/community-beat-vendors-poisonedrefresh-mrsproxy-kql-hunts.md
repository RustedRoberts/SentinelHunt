---
title: "The Community Beat the Vendors to These Detections. Again."
date: 2026-09-20
author: Chris Scott
summary: Two fresh 2026 exploit chains - a fileless F5 BIG-IP rootkit and a pre-auth NTLM relay against Exchange's MRSProxy - had usable community KQL hunts before the vendor content hubs caught up. What that says about detection engineering speed and the state of the KQL commons.
tags:
  - kql
  - sentinel
  - threat-hunting
  - detection-engineering
  - vulnerability-research
published: true
---

I keep a rough mental stopwatch running whenever a big vulnerability drops: how long until there's a decent detection query for it, and where does that query come from first. In August and September this year I ran that stopwatch twice, once for a Linux rootkit hiding inside F5 BIG-IP's memory, and once for a pre-auth exploit chain against Exchange's MRSProxy service. Both times, a solo researcher's GitHub repo had usable KQL before I'd finished reading the vendor writeups.

That's not a dig at Microsoft or F5. It's just a reminder of something practitioners already feel in their bones but don't say out loud enough: the KQL commons, the scattered mess of personal repos, blog posts and Slack shares, is doing a huge amount of the actual detection engineering legwork in this industry. If your team only pulls content from the official content hub, you're reading yesterday's news by the time it lands.

So this post is about those two cases specifically, what the detections actually look like, and what it tells us about how mature a hunting practice needs to be to keep up.

## What actually happened

PoisonedRefresh, the name ESET gave it, is a fileless rootkit found on compromised F5 BIG-IP Access Policy Manager appliances. It's tied to CVE-2025-53521, a flaw F5 originally under-rated and later reclassified as unauthenticated remote code execution once new information came in, CVSS 9.8. The clever bit, and the annoying bit for defenders, is that it doesn't touch disk. It hooks `mmap()` calls inside Apache's `libphp` module and injects a PHP web shell straight into the in-memory view of a handful of specific scripts, `apm_css.php3` among them. The files on disk stay clean. Antivirus and integrity checks looking at the filesystem find nothing, because there's nothing there to find.

CVE-2026-62911 is a different beast but the same underlying lesson. It chains three known primitives against Exchange Server into a single pre-auth path: a PetitPotam-style coercion request over the `lsarpc` named pipe forces the Exchange machine account to authenticate outbound to an attacker-controlled SMB listener, which then relays that NTLM authentication straight into `/EWS/MrsProxy.svc` because MRSProxy doesn't enforce Extended Protection for Authentication. First demonstrated at Pwn2Own Berlin 2026, and as of the reporting I read, still sitting unpatched on roughly 22,000 internet-facing servers.

Two very different products, two very different techniques, but both are the kind of thing a signature-based rule was never going to catch, because there's no dropped file and no obviously malicious binary. You're hunting behaviour, not artefacts.

## The detection angle: behavioural hunting over IOC matching

Within days of public disclosure, a researcher running the `MaikCyberSec/Threat-Hunting-` repo on GitHub had KQL hunting queries published for both. Not polished, vendor-reviewed analytics rules with entity mapping and severity tuning, but working starting points that a SOC could adapt that same day. That's the gap I want to talk about.

For PoisonedRefresh, the useful signals aren't file hashes, there aren't any reliable ones, they're process and memory behaviour: Apache worker processes reading `/proc/self/maps`, memory region permissions flipping from writable-and-executable back to executable-only around `libphp`, the creation of `/run/bigtlog.pipe`, and Apache-related processes spawning `/bin/bash`. If you're forwarding Linux audit logs or Sysmon for Linux telemetry into your workspace, a hunt roughly along these lines gets you started:

```kql
Syslog
| where ProcessName has "httpd" or ProcessName has "apache2"
| where SyslogMessage has_any ("/proc/self/maps", "bigtlog.pipe", "/bin/bash")
| project TimeGenerated, Computer, ProcessName, SyslogMessage
| order by TimeGenerated desc
```

That's deliberately rough, it's a starting hypothesis, not a tuned rule, but it points a hunter at the right haystack instead of leaving them to guess.

For CVE-2026-62911, the practical detection surface is the correlation between an outbound coercion attempt and unusual authentication into MRSProxy. If you've got IIS logs and NTLM authentication events landing in Sentinel, the hunt is about looking for machine-account NTLM authentication reaching `MrsProxy.svc` from sources or at volumes that don't match your normal mailbox replication traffic:

```kql
W3CIISLog
| where csUriStem has "MrsProxy.svc"
| where csUsername has "$" // machine account pattern
| summarize RequestCount = count(), Sources = make_set(cIP) by bin(TimeGenerated, 1h), csUsername
| where RequestCount > 5
```

Again, a hypothesis to refine against your own baseline, not a drop-in rule. But it's the difference between having somewhere to start on day one and waiting for a Microsoft Sentinel analytics template that, by the nature of the review process, is going to land later.

## Considerations, caveats and what maturity actually requires

None of this works if a team doesn't already have the plumbing in place. Both hunts assume you're actually collecting the right telemetry, Linux audit or Sysmon for Linux on your F5 estate, IIS and authentication logs from Exchange, and that you've got enough of a baseline to know what "normal" MRSProxy traffic volume even looks like for your environment. A behavioural hunt against a baseline you don't have is just noise with extra steps.

There's also a quality problem worth naming honestly. The KQL community had its own reckoning with this in 2026, the curator behind the annual "KQL Sources" roundup on kqlquery.com specifically called out that they'd pulled AI-generated repos out of their list this year because too much of it was low-quality slop dressed up as detection content. That's a useful gut check for anyone leaning on community content, including me writing this: read the query, understand the logic, test it against your own data before you trust it in a hunt, let alone promote it to a scheduled analytics rule.

And a rough GitHub hunt is not the end state. It's the seed. Turning it into something you'd actually run on a schedule means entity mapping, tuning thresholds against your environment's baseline, deciding what MITRE ATT&CK technique it maps to, and building in the exceptions every SOC ends up needing once a rule goes from one workspace to twenty.

## Closing Thoughts

The lesson I keep coming back to isn't "trust random GitHub repos blindly," it's that the fastest usable detection content right now comes from practitioners publishing rough, honest, testable hunts in public, and the slowest comes from waiting for a fully polished vendor rule to appear in a content hub. If your hunting practice is mature enough to take a rough hypothesis, validate it against your own telemetry, and turn it into a tuned rule within a day or two, you're in a genuinely good position. If it isn't, these two cases are as good a reason as any to start closing that gap now, before the next fileless rootkit or pre-auth chain shows up.

---

## References

1. PoisonedRefresh: A Fileless Linux Rootkit That Injects PHP Web Shells Into F5 BIG-IP APM Server Memory, Security Affairs, September 2026 - https://securityaffairs.com/198746/malware/poisonedrefresh-a-fileless-linux-rootkit-that-injects-php-web-shells-into-f5-big-ip-apm-server-memory.html
2. F5 BIG-IP APM Malware Injects a PHP Web Shell Into Memory, Evading Disk Scans, The Hacker News, September 2026 - https://thehackernews.com/2026/09/f5-big-ip-apm-malware-injects-php-web.html
3. CVE-2026-62911 Enables Pre-Auth RCE on Exchange Server, SOC Prime - https://socprime.com/active-threats/cve-2026-62911-enables-pre-auth-rce-on-exchange-server/
4. Over 21,000 Microsoft Exchange Servers Remain Exposed to Active CVE-2026-62911 Exploitation, Cyber Security News - https://cybersecuritynews.com/exchange-servers-remain-exposed-2026-62911/
5. MaikCyberSec/Threat-Hunting- repository, GitHub - https://github.com/MaikCyberSec/Threat-Hunting-
6. KQL Sources: 2026 Update, kqlquery.com - https://kqlquery.com/posts/kql-sources-2026/
7. Detection and automation, reimagined, Microsoft Sentinel Blog, Microsoft Tech Community - https://techcommunity.microsoft.com/blog/microsoftsentinelblog/detection-and-automation-reimagined/4527933
8. Azure-Sentinel Hunting Queries, GitHub - https://github.com/Azure/Azure-Sentinel/blob/master/Hunting%20Queries/readme.md
