---
title: "Your Sign-In Telemetry Just Changed Names - and There's a New AiTM Detection to Go With It"
date: 2026-06-14
author: Chris Scott
summary: AADSignInEventsBeta is gone, replaced by EntraIdSignInEvents. Here's what changed, what it breaks, and a new hunt that uses the new table to catch AiTM session cookie replay - the technique behind Tycoon 2FA and Sneaky 2FA.
tags:
  - kql
  - advanced-hunting
  - entra-id
  - aitm
  - threat-hunting
published: true
---

## A quiet rename with a not-so-quiet deadline

On 9 December 2025, Microsoft replaced the preview `AADSignInEventsBeta` table
in the Defender XDR advanced hunting schema with `EntraIdSignInEvents`. The
companion service-principal table, `AADSpnSignInEventsBeta`, was replaced by
`EntraIdSpnSignInEvents` on the same timeline. The column schema is unchanged
- this is a rename to remove "Beta" branding and align with the rest of the
Entra ID product naming, not a functional rewrite.

That sounds like a non-event, and Microsoft's own guidance says custom
detections built on the old tables "will be updated automatically and won't
require any changes." But two things make this worth a five-minute check of
your own content:

- **Any saved hunting query, workbook, notebook, or external tooling that
  references `AADSignInEventsBeta` or `AADSpnSignInEventsBeta` by name will
  not be silently rewritten.** Custom detection rules get the automatic
  update; ad-hoc hunting queries, saved searches, and anything outside the
  detection-rule mechanism do not. If you have a folder of go-to hunting
  queries for Entra sign-ins, grep it for the old table names.
- **A second, unrelated schema change lands around the same period**: from 25
  February 2026, several boolean columns across the advanced hunting schema
  move from numeric `1`/`0` to textual `True`/`False`. On
  `EntraIdSignInEvents` specifically, `IsConfidentialClient` and
  `IsGuestUser` are typed `boolean` and are in scope for that change;
  `IsManaged`, `IsCompliant`, and `IsExternalUser` are typed `int` and are
  not. If a query anywhere does `| where IsGuestUser == 1`, it is worth
  testing against `True` as well before the transition completes.

Neither of these is dramatic on its own. Together, they're a reminder that
"Beta" tables in the advanced hunting schema have a habit of becoming
permanent fixtures right up until the day they're renamed out from under you
- and that's as good a prompt as any to actually look at what
`EntraIdSignInEvents` can do that the old `SigninLogs`-based hunts in this
library don't already cover.

## What's actually new in the table

`EntraIdSignInEvents` carries the full interactive and non-interactive
sign-in picture: account identity, device (`EntraIdDeviceId`, `OSPlatform`,
`DeviceTrustType`, `IsManaged`, `IsCompliant`), network (`IPAddress`,
`Country`, `State`, `City`, `Latitude`, `Longitude`,
`NetworkLocationDetails`), client (`UserAgent`, `Browser`, `ClientAppUsed`),
risk (`RiskLevelAggregated`, `RiskState`, `RiskDetails`), conditional access
outcome, and - the column that matters most for what follows - `SessionId`.

`SessionId` is easy to overlook. It isn't the per-request `CorrelationId`
(every sign-in attempt gets a unique one of those); it's the identifier
carried by the session token itself. Two sign-in events sharing a
`SessionId` mean the same token was presented twice. For a normal user, that
happens constantly and harmlessly - token refreshes, silent SSO, repeated app
access, all from the same device. For a stolen session cookie, it means
something else entirely.

## The detection this enables: AiTM session cookie replay

Adversary-in-the-Middle phishing kits - Tycoon 2FA, Sneaky 2FA, and the wider
family of Evilginx-derived reverse-proxy kits - have made "phish-resistant
unless you're phish-resistant MFA" the default reality for most tenants.
These kits sit transparently between the victim and Entra ID, relay the
entire authentication flow including the MFA challenge, and capture the
resulting session token once the victim completes sign-in. The operator then
loads that token into their own browser and is instantly inside Microsoft
365 - no password, no second MFA prompt, because as far as Entra ID is
concerned it's the same session.

That replay is exactly what `SessionId` exposes. The victim's genuine sign-in
and the operator's replayed sign-in share a `SessionId` but diverge on
everything else: `EntraIdDeviceId`, `Browser`, `OSPlatform`, `IPAddress`, and
often `Country`. A user does not authenticate from their managed laptop in
the UK and then, twenty minutes later, present the exact same session token
from an unmanaged device on a VPS in another country. Public write-ups from
Sekoia and eye.security on Sneaky 2FA describe variations of this same
signal - inconsistent device/browser fingerprints and rotating user agents
within what should be one continuous session.

We've added **[HL-016: AiTM Session Cookie Replay - Cross-Device Sign-In
Fingerprint Drift](/hunts/HL-016)** to the library, built directly on
`EntraIdSignInEvents`. It groups successful sign-ins by `SessionId` and
`AccountUpn`, and flags any session where the device/browser/OS fingerprint
changes AND the IP address or country changes, within a 12-hour window. The
deliberate requirement for *both* a fingerprint change and a network change
is what keeps this from firing on routine VPN or mobile-network switches -
either alone is normal; both together, on the same session token, is not.

```kql
EntraIdSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode == 0
| extend FingerprintKey = strcat(tostring(EntraIdDeviceId), "|", tostring(OSPlatform), "|", tostring(Browser))
| summarize DistinctFingerprints = dcount(FingerprintKey),
            DistinctIPs = dcount(IPAddress),
            DistinctCountries = dcount(Country),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
        by SessionId, AccountUpn
| where DistinctFingerprints > 1 and (DistinctIPs > 1 or DistinctCountries > 1)
```

The full hunt adds severity grading, the supporting evidence sets (every
IP/country/device/browser seen for the session), and a triage path that ends
in the only remediation that actually works against a stolen session cookie:
revoking the session and its refresh tokens, not just resetting the
password.

## Where this fits with what's already in the library

`HL-016` is deliberately complementary to **HL-010 (Dynamic Multi-Factor
Sign-In Risk Score)**, not a replacement for it. HL-010 runs against
`SigninLogs` in Log Analytics and asks "is this sign-in unusual for this
user, relative to their history?" HL-016 runs against
`EntraIdSignInEvents` in Defender XDR advanced hunting and asks "is this
session internally consistent?" - no baseline required. A session flagged by
both is about as close to a confirmed AiTM compromise as KQL alone can get
you.

One licensing note worth flagging early: `EntraIdSignInEvents` requires a
Microsoft Entra ID P2 licence. If your tenant is on P1, this hunt won't
return data, and that's worth knowing before you spend time wondering why
it's silent rather than assuming the environment is clean.

## The takeaway

Schema renames are easy to file under "nothing to do here." Usually that's
true. But every one of these table-lifecycle moments is also a reasonable
trigger to ask what the new (or newly-renamed) table can see that your
existing detection content doesn't - and in this case, the answer was a
genuinely useful new hunt, not just a find-and-replace exercise.
