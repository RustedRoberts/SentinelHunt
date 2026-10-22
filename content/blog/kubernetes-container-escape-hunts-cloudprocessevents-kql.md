---
title: "Hunting Container Escapes and Token Theft in Kubernetes with CloudProcessEvents"
date: 2026-10-04
author: Chris Scott
summary: A week of new community KQL landed for Kubernetes and container threats. Two of the queries show how far a single table and a bit of process logic will get you, and where they stop.
tags:
  - kql
  - threat-hunting
  - detection-engineering
  - advanced-hunting
  - kubernetes
published: true
---

I do a weekly skim of what's new in the public detection repos, and most weeks it's the usual mix of phishing rules, Sigma tweaks and another batch of remote management tool signatures. This week one thing stood out. Benjamin Zulliger's KQLAdvancedHunting repo picked up 13 new queries in a single week, and almost all of them were about Kubernetes and containers. Reverse shells, crypto-miners, escape primitives, service account token theft, audit log hunts for cluster-admin grants.

Container workloads are a blind spot for plenty of SOCs. The cluster belongs to a platform team, the telemetry lives in a different product, and nobody has written the hunting content because nobody is sure whose job it is. Seeing a practitioner publish a block of ready-to-run KQL for it, in the same query language the rest of the team already uses, is worth a closer look.

## Why containers keep slipping through

The Sentinel and Defender side of the world has been busy lately. Interactive KQL against the Sentinel data lake now runs from Advanced Hunting in the Defender portal, and Sentinel's UEBA has picked up more anomaly rules and data sources. That's all useful, but none of it writes your hunting hypotheses for you. Behavioural content for cloud workloads still tends to come from people building it themselves and sharing it.

The other community drop worth a mention this month is the Exploitarium detections repo, which has 54 KQL rules across 23 products, written after an anonymous researcher released unreported vulnerability research on 23 June 2026. The repo's own notes say the community response was mixed, with some findings independently verified as high risk and others dismissed as low-impact noise. I'd treat it as a source of ideas for process-behaviour logic, not as a set of rules to switch on.

## The detection angle: two queries worth understanding

Both of the queries below read from `CloudProcessEvents`, which holds process activity from containers. That matters because it means one table covers the pod, the namespace, the container image and the command line. You get Kubernetes context without having to stitch anything together.

The first looks for a container process touching the service account token, certificate or namespace files mounted into the pod. This maps to Credentials in Files (T1552.001).

```kql
let Lookback = 1d;
let AllowedNamespaces = dynamic(["kube-system", "gatekeeper-system", "azure-arc", "calico-system", "cilium"]);
CloudProcessEvents
| where Timestamp > ago(Lookback)
| where isnotempty(KubernetesPodName)
| extend Command = tolower(ProcessCommandLine)
| where Command has_any ("/var/run/secrets/kubernetes.io/serviceaccount/token", "serviceaccount/token", "serviceaccount/ca.crt", "serviceaccount/namespace")
| where KubernetesNamespace !in (AllowedNamespaces)
| project Timestamp, KubernetesNamespace, KubernetesPodName, ContainerName, ContainerImageName, AccountName, ParentProcessName, ProcessName, ProcessCommandLine, HostName
```

The logic is simple. A compromised container that wants to talk to the Kubernetes API needs that token, so reading it from a shell, curl or a script is a strong early sign. The allow-list of system namespaces is the tuning knob. Anything legitimate in your estate that reads the token from a command line, think operators, agents and CI runners, will show up until you add it.

The second targets Escape to Host (T1611). It looks for the well-worn breakout moves: `nsenter` targeting PID 1, `chroot` into a host mount, references to `/proc/1/root`, `release_agent` or `core_pattern` tricks, container runtime sockets such as `docker.sock` and `containerd.sock`, and `unshare` with user namespace flags.

```kql
CloudProcessEvents
| where Timestamp > ago(1h)
| where ContainerName != "host" and isnotempty(ContainerId)
| where (ProcessName =~ "nsenter" and ProcessCommandLine has_any ("-t 1", "--target 1", "--target=1"))
     or (ProcessName =~ "chroot" and ProcessCommandLine has_any ("/host", "/proc/1/root", "/rootfs"))
     or ProcessCommandLine has_any ("/proc/1/root", "release_agent", "/proc/sys/kernel/core_pattern", "notify_on_release", "docker.sock", "containerd.sock", "crio.sock")
     or (ProcessName in~ ("ctr", "crictl", "docker", "runc"))
| project Timestamp, KubernetesNamespace, KubernetesPodName, ContainerName, ContainerImageName, AccountName, ParentProcessName, ProcessName, ProcessCommandLine
```

I've trimmed the `mount` and `unshare` branches from the original to keep it readable, so go and read the full version in the repo. The point to take from it is the shape. It isn't hunting for a named exploit. It's hunting for the handful of things a process inside a container has no ordinary reason to do.

## Considerations, caveats and what maturity requires

Neither query is a finished analytics rule. Both come with caveats the author doesn't claim to have solved. The token query documents no known false positives, which in my experience means nobody has run it across enough clusters yet. The escape query has a very broad last branch that flags any use of `docker`, `crictl` or `runc` inside a container, and that will be noisy anywhere build tooling runs in pods.

There's also the prerequisite problem. These hunts assume the Defender for Cloud container telemetry that feeds `CloudProcessEvents` is enabled to the clusters you care about, that the data is reaching Advanced Hunting, and that someone knows which namespaces are meant to behave oddly. If you can't answer that last one, you aren't ready to promote either query to a scheduled rule. Run them as hunts first, learn what normal looks like, and then decide what earns an alert.

The last failure mode is ownership. The best KQL in the world does nothing if the platform team never hears about the hit. Agree before you switch anything on who gets the alert and what they're expected to do with it.

## Closing Thoughts

What I like about this batch isn't the individual queries. It's that someone has mapped a whole area, from the process layer through to Kubernetes audit events, and put it somewhere a hunter can pick it up on a Monday morning. If your team has never run a single container hunt, start with the token query in a test cluster, see what it finds and use the results to start the conversation with whoever owns the platform.

If you're lucky enough to have good coverage already, the more interesting question is how quickly you can take community content like this, test it against your own telemetry and turn it into something tuned. That's the skill that separates teams who read about new detections from teams who actually run them.

## References

1. [Detections Digest #20260928 - RuleCheck](https://detections-digest.rulecheck.io/p/detections-digest-20260928)
2. [benscha/KQLAdvancedHunting - GitHub](https://github.com/benscha/KQLAdvancedHunting)
3. [Kubernetes Pod Accessing Service Account Tokens - GitHub](https://github.com/benscha/KQLAdvancedHunting/blob/main/ThreatHunting/Kubernetes%20Pod%20Accessing%20Service%20Account%20Tokens.md)
4. [Kubernetes Container Escape - GitHub](https://github.com/benscha/KQLAdvancedHunting/blob/main/ThreatHunting/Kubernetes%20Container%20Escape.md)
5. [Exploitarium-Detections - GitHub](https://github.com/Ethan-Andrews/Exploitarium-Detections)
6. [What's new in Microsoft Sentinel - Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/whats-new)
7. [Sentinel - Defender XDR KQL Queries Library - Microsoft Tech Community](https://techcommunity.microsoft.com/discussions/microsoftsentinel/sentinel---defender-xdr-kql-queries-library/4538669)
8. [KQL Sources: 2026 Update - kqlquery.com](https://kqlquery.com/posts/kql-sources-2026/)
