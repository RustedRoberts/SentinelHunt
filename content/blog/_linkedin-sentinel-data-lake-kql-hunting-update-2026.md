<!--
Companion LinkedIn post for content/blog/sentinel-data-lake-kql-hunting-update-2026.md
Leading underscore excludes this file from the blog build (see blog-plugin.ts).
Draft only - review before posting.
-->

For years the honest answer to "can we hunt for slow, patient lateral movement" was no, not really, because the data had already rolled off the hot tier by the time anyone thought to look. Microsoft's September update changes that. Advanced Hunting can now run KQL straight against Data Lake tier data, with Sentinel and Defender XDR sitting in the same query surface, no restore job in between. That means the hunts people talk themselves out of because "we don't have the retention" stop having that excuse. Beacons that call out once every few days specifically to sit under a 30 day noise floor. Recon that looks fine in isolation and only becomes obvious across six weeks of activity. That data is reachable now.

It's not a free win though. Querying huge tables raw over long windows gets expensive, which is exactly why summary rules exist, pre aggregating so you're not scanning everything every five minutes. And retention doesn't fix a query that was already lying to you. KQL's default join is innerunique, which quietly drops matches a plain join kind=inner would catch. That's the sort of thing that turns a hunting query into one that looks like it works while missing exactly the pattern you were after.

The tech just took away the excuse. Whether your team turns that into an actual hunting cadence, with hunts that get promoted into rules rather than run once and forgotten, is the part that's still down to you. Anyone actually running long lookback hunts against the lake tier yet? Keen to hear what's turned up.

<!-- Editorial note: led with the Data Lake/Advanced Hunting merge as it's the most concrete, dated change found in research; the innerunique join pitfall is folded in as the caveat rather than given its own post. -->
