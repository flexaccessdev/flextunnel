# Roadmap

Possible extensions, not implemented features. Each topic with a document of
its own is listed in the index; this file holds the items that have no
document of their own.

## Index

- [HTTP proxy](http-proxy-roadmap.md): the remaining HTTP proxy work. HTTP
  proxy support is implemented on the client side; the wire protocol and
  server stay front-end-agnostic.
- [Duplicate-id detection](duplicate-detection-roadmap.md): non-ephemeral
  client ids and their pitfalls, a signaling-server path for prompt
  duplicate-server detection, and client-side acknowledgement and flagging
  of duplicates.
- [Client blocking mode](../README.md#roadmap): refusing targets that no
  destination routes instead of connecting them directly.
- [Under consideration](#under-consideration): items not yet planned.
  - [Dynamic configuration](#dynamic-configuration)

## Under consideration

### Dynamic configuration

#### Today: apply on save

The desktop app applies a saved change at once, as described in
[its README](../crates/flextunnel-desktop/README.md); for the client's routing
table, see [the architecture guide](architecture.md#routing-client). This is a
convenience: it saves people from changing a setting and forgetting to
restart. A change restarts only the part it touches:

- a server change restarts the server, never the client;
- a destination's change reconnects that destination, never the others or
  the server;
- a proxy port change rebinds that port, never the other.

The touched part may blip briefly. For example, a request held for a
destination that a save removes, or a request whose handshake straddles the
save, can fail. A reconfigure does not account for this exactly:

- each routing table gets a fresh hold budget, so for up to
  `TUNNEL_RECOVERY_HOLD` after a save, held requests can exceed
  `MAX_HELD_CONNS`;
- a close cut short by the session's runtime shutting down is not resumed.

Holding requests exists for reconnecting after a dropped link, not for
reconfiguring.

#### Later: configuration for when uptime matters

When a deployment needs changes to land without even a brief blip, the
configuration could graduate to a dynamic source, such as a database-backed
config that clients and servers watch. Changes would then apply as a
continuous stream rather than as saves. That design would need:

- **Exact accounting across reconfigures.** Requests held under an old
  routing table count against the same caps as the new one, and each kept
  destination keeps its share of the hold budget.
- **Closes that always finish.** A close cut short is resumed by the next
  one, even on another runtime, so a removed destination never keeps its
  sockets.
- **Routing at request time.** A request routes by the table current when it
  is read, not when it was accepted.
- **Servers reconfigured in place.** Server settings such as allowlists and
  routed lists change without restarting the server, keeping its clients
  connected.

The branch `desktop-apply-on-save` explored the first three on top of apply on
save. It has a hold ledger shared across routings, resumable closes in
`ClientEndpoint`, and listener routing taken after the handshake. Its iroh
change, a later `Endpoint::close` finishing one that was cut short, is on the
iroh fork's `flextunnel-1.5.0-apply-on-save` branch. That branch is a starting
point, not a design: it grew one review finding at a time, so a real design
should begin from the invariants above.
