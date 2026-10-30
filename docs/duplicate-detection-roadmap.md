# Roadmap: duplicate-id detection

Current behavior is described in
[the architecture guide](architecture.md#duplicate-id-detection). Detection
catches accidental identity reuse among trusted peers. These are possible
extensions, not implemented features.

## Persistent client identities

Normal clients use ephemeral endpoint ids, including a new id after an
endpoint rebuild. Quick clients keep their session's id across rebuilds so
that the quick server's allowlist remains valid. Neither persists it across
process restarts.

If clients gain persistent identities, revisit automatic duplicate blocking:
copying a key between devices could then block a legitimate client until an
operator clears the record. The design would need clear provenance and
operator recovery, and should consider warning or rejecting the newcomer
before persisting a block. Endpoint identity and the separately authorized
client auth key must remain distinct.

## Earlier duplicate-server detection

Current detection needs a client to observe server nonce A, then B, then A
again. A client that only reaches one instance cannot report the other, so
detection depends on connection churn. Isolated deployments with no client
that can reach both are outside this observation mechanism.

If prompt detection is needed, a shared registration service could track
live leases by endpoint id and report concurrent registrations before client
traffic reveals them. Lease expiry, restarts and temporary network partitions
would need explicit handling; a second registration alone does not establish
that both processes are still alive.

## Client persistence and UI

The observing client currently logs and sends an advisory; it keeps no durable
record. Possible additions are:

- persist duplicate-server observations across client restarts;
- expose them through CLI/FFI status so apps can show an operator warning;
- add acknowledgement and recovery controls if persistent client ids are
  introduced.

Any change must preserve the distinction between an observation and confirmed
concurrent identity reuse.
