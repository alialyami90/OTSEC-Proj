# B4: the receiver side of HR-11 (the `syslog-unknown` stream)

Status: PR for review by B5 (node wiring), B3 (HR-11 condition) and B6 (the fill test). Evidence is `desk`: unit tests against an in-memory committer, no device and no node.

## What changed

`receive.Config.UnknownStream` (a `store.StreamID`, optional). When set:

- A record from a sender that resolves to no asset is built with that stream and class `syslog-unknown`, and its event's `id.stream` is that stream. `asset-unresolved` and the per-window unknown budget are as before.
- **Datagrams.** A batch that holds both kinds is split into two `AppendBatch` groups, the known sender's records first, each group in arrival order. Each group is then cut into parts at the commit caps as before.
- **Streams.** A connection is one sender's, so it writes to one stream only. An unknown sender's connection writes only to the unknown stream, and a known sender's connection makes no call on it.
- **At the class quota** (`CodeQuotaReached` on an unknown-class part) the part is dropped and counted as `unknown-full`, on a stream as on a datagram listener. The connection is not held and is read on. The store raises `syslog-unknown-full` once per fill (C5 0.4).
- Any other refusal of an unknown part is handled as a known one's: held and retried on a stream, dropped as `store` for a datagram.
- Empty `UnknownStream` keeps the 0.3 behaviour: unknown records in the listener's own stream, with no absolute bound. The node sets the field when it moves `asset-unresolved` records (B5's node PR).
- `New` refuses an `UnknownStream` that is not a valid stream ID or equals `Stream`. It cannot check that the layout declares the stream with class `syslog-unknown`; the store refuses a mismatch at the first commit.

## Limits

- A part refused at the quota is dropped whole, so records in it that would have fitted are dropped too. At most one part's bytes (the commit caps) is lost to this per refusal. The quota is never exceeded.
- `Config.UnknownSpent` now means what unknown senders stored in the window on the unknown stream. The node must count that stream when it sets `UnknownStream` (C5 0.4 proposal, section 4). The first 0.4 start refills the window once, as that section records.
- A listener's known and unknown records are in two streams with separate seq orders. Anything that rebuilds a timeline merges by `received.utc`.
- Not verified on the real binaries or on Windows. B6's fill test (fill the class across a simulated outage while a known device still stores) needs the node wiring first.
