//! flextunnel's endpoints: what this program layers onto the shared
//! [`flexaccess_iroh::endpoint`] builder — its two ALPNs, the native
//! quick-client allowlist hook, the client/server identity rules, and the
//! client's rebuildable endpoint handle ([`ClientEndpoint`], the reconnect
//! loop's escalation for a wedged endpoint). Relay configuration, the
//! per-relay startup probe, the bind-and-come-online policy, and the server's
//! in-place home-relay failover come from the shared crate; the server's
//! secret-key file is [`crate::secret`]'s.

use crate::transport::{ALPN, QUICK_ALPN, build_quic_transport_config};
use anyhow::{Context, Result};
use flexaccess_iroh::endpoint::{
    CreatedEndpoint, EndpointOptions, create_endpoint, endpoint_builder,
};
pub use flexaccess_iroh::endpoint::{PendingCloses, tear_down_runtime};
use flexaccess_iroh::relay::online_timeout;
use futures::future::BoxFuture;
use iroh::{
    Endpoint, EndpointId, SecretKey,
    endpoint::{
        AfterHandshakeOutcome, Builder as EndpointBuilder, Connection, EndpointHooks, Side, VarInt,
    },
};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::task::TaskTracker;

pub use flexaccess_iroh::relay::{RELAY_CONNECT_TIMEOUT, RelayConfig};

/// QUIC application close code sent when a quick client on [`QUICK_ALPN`] is
/// rejected by the endpoint-id allowlist (distinct from the in-band
/// auth-failure code `1` and the duplicate-id code `2` used on the keypair
/// client path).
pub const CLOSE_NOT_ALLOWLISTED: u32 = 3;

/// Native allowlist access control: an [`EndpointHooks`] that rejects inbound
/// [`QUICK_ALPN`] connections whose TLS-authenticated endpoint id is not one
/// of the allowed quick clients. Runs the moment the handshake completes, so
/// a rejected peer never reaches the accept loop; the dialer sees the
/// connection close with [`CLOSE_NOT_ALLOWLISTED`] and the reason text.
///
/// The allowlist is the sole and mandatory credential on that ALPN, so an
/// empty set disables quick mode entirely. Inbound [`ALPN`] client
/// connections pass through (gated by their keypair handshake).
#[derive(Debug)]
pub struct AllowlistHook {
    /// Clients allowed to connect over [`QUICK_ALPN`] (normally a single id,
    /// entered on the quick server).
    quick_clients: HashSet<EndpointId>,
}

impl AllowlistHook {
    pub fn new(quick_clients: HashSet<EndpointId>) -> Self {
        Self { quick_clients }
    }
}

impl EndpointHooks for AllowlistHook {
    async fn after_handshake(&self, conn: &Connection) -> AfterHandshakeOutcome {
        if conn.side() != Side::Server || conn.alpn() != QUICK_ALPN {
            return AfterHandshakeOutcome::Accept;
        }
        let remote_id = conn.remote_id();
        if self.quick_clients.contains(&remote_id) {
            return AfterHandshakeOutcome::Accept;
        }
        let reason = if self.quick_clients.is_empty() {
            "quick mode is not enabled on this server"
        } else {
            "client id is not on this server's quick-client allowlist"
        };
        log::warn!("Rejecting quick client {remote_id}: {reason}");
        AfterHandshakeOutcome::Reject {
            error_code: VarInt::from_u32(CLOSE_NOT_ALLOWLISTED),
            reason: reason.as_bytes().to_vec(),
        }
    }
}

/// The shared base builder with flextunnel's QUIC transport tuning. mDNS
/// local-network discovery is on (the shared crate's `mdns` feature; compiled
/// out on iOS by the crate itself).
fn base_builder(relay_config: &RelayConfig, side: Side) -> Result<EndpointBuilder> {
    Ok(endpoint_builder(
        relay_config,
        EndpointOptions {
            transport_config: build_quic_transport_config(side)?,
            publish_address: side == Side::Server,
            relay_only: false,
        },
    ))
}

/// What makes an endpoint a flextunnel server's, whatever base it is built
/// on: its persistent identity, the client [`ALPN`] and the quick-client
/// [`QUICK_ALPN`], and an [`AllowlistHook`] over `quick_clients` gating the
/// latter natively (an empty set = quick mode disabled). Applied here and
/// nowhere else, so the hermetic tests' loopback servers get exactly what a
/// real one does.
pub(crate) fn server_setup(
    base: EndpointBuilder,
    secret: SecretKey,
    quick_clients: HashSet<EndpointId>,
) -> EndpointBuilder {
    base.alpns(vec![ALPN.to_vec(), QUICK_ALPN.to_vec()])
        .hooks(AllowlistHook::new(quick_clients))
        .secret_key(secret)
}

/// Create a server endpoint on the shared base (its identity published on the
/// default relays); `setup` makes that base the server's own — see
/// [`server_setup`].
///
/// A single endpoint serves both relay modes. With the default relays internet
/// discovery is on, so the server publishes its current home relay and clients
/// resolve it by endpoint ID. With custom relays discovery is off, so clients
/// reach the server through relay hints. The endpoint binds with every custom
/// relay and must come online, while each relay is probed beside it and taken
/// out of the relay map if it fails; startup fails only if none answers. The
/// startup probe comes back in [`CreatedEndpoint::relays`] for the home-relay
/// failover (run by [`crate::server::RunningServer::serve`]), which puts the
/// relays it left out back once they are connectable.
///
/// The probe's task and endpoints, and any close the creation stops waiting
/// for, are kept in `closes`, which the server drains at shutdown
/// ([`crate::server::RunningServer::close`]): its runtime ends with it.
pub async fn create_server_endpoint(
    relay_config: &RelayConfig,
    closes: &PendingCloses,
    setup: impl FnOnce(EndpointBuilder) -> EndpointBuilder,
) -> Result<CreatedEndpoint> {
    create_endpoint(
        relay_config,
        setup(base_builder(relay_config, Side::Server)?),
        closes,
    )
    .await
}

/// A client endpoint builder. A client never publishes its address (it only
/// dials out), even with a quick-mode secret bound as its identity.
fn client_builder(
    relay_config: &RelayConfig,
    secret: Option<SecretKey>,
) -> Result<EndpointBuilder> {
    let mut builder = base_builder(relay_config, Side::Client)?;
    if let Some(secret) = secret {
        builder = builder.secret_key(secret);
    }
    Ok(builder)
}

/// Create a client endpoint (ephemeral identity) that can rebuild itself
/// mid-session. The first creation probes every custom relay and must come
/// online (see [`create_endpoint`]); rebuilds are tolerant (see
/// [`rebuild_client_endpoint`]).
///
/// The closes that creation stops waiting for — a relay probe's, or the
/// endpoint's own when it never came online — are kept in `closes`, whether
/// it succeeds or not. A caller whose runtime ends with its request waits for
/// them ([`PendingCloses::finished`]); one whose runtime lasts drops the set.
pub async fn create_client_endpoint(
    relay_config: &RelayConfig,
    closes: &PendingCloses,
) -> Result<ClientEndpoint> {
    create_client(relay_config, None, closes).await
}

/// Create a **quick-mode** client endpoint: same as [`create_client_endpoint`]
/// but bound to the given (session-ephemeral) `secret`, so the endpoint id the
/// user entered on the quick server is the id this endpoint presents in the
/// TLS handshake — that id is the quick client's sole credential. The
/// identity is still never published (the client only dials), so pkarr
/// publishing stays off exactly as for an anonymous client, and a rebuild
/// keeps the same id.
pub async fn create_quick_client_endpoint(
    relay_config: &RelayConfig,
    secret: SecretKey,
    closes: &PendingCloses,
) -> Result<ClientEndpoint> {
    create_client(relay_config, Some(secret), closes).await
}

async fn create_client(
    relay_config: &RelayConfig,
    secret: Option<SecretKey>,
    closes: &PendingCloses,
) -> Result<ClientEndpoint> {
    // A relay that failed the startup probe stays out of this endpoint's relay
    // map for its lifetime: a client only dials, runs no failover, and
    // reaches the server through the relay hints it attaches, so a rebuilt
    // endpoint (below) goes back to the full configured set instead.
    let CreatedEndpoint { endpoint, .. } = create_endpoint(
        relay_config,
        client_builder(relay_config, secret.clone())?,
        closes,
    )
    .await?;
    let factory: EndpointFactory = {
        let relay_config = relay_config.clone();
        Arc::new(move || {
            let relay_config = relay_config.clone();
            let secret = secret.clone();
            Box::pin(async move {
                let builder = client_builder(&relay_config, secret)?;
                rebuild_client_endpoint(&relay_config, builder).await
            })
        })
    };
    Ok(ClientEndpoint::from_parts(endpoint, factory))
}

/// Mid-session replacement of a client endpoint, the recipe behind an
/// [`EndpointFactory`]. Differs from [`create_endpoint`] deliberately:
///
/// - **No per-relay probe.** At creation the probe validates the
///   configuration; during an outage it would only delay the reconnect it is
///   part of.
/// - **The online wait is tolerated failing.** A fresh endpoint is no worse
///   than the wedged one it replaces — a client only dials, so its relay
///   hints and mDNS can still reach the server without a home relay — and the
///   reconnect loop that asked for the rebuild escalates again if the relays
///   stay unreachable.
///
/// The wait is the shared crate's [`online_timeout`] for an endpoint waited on
/// without the startup probe: [`RELAY_CONNECT_TIMEOUT`], plus iroh's QUIC
/// address discovery probe timeout where the endpoint runs it, since it picks
/// no home relay until those probes are done.
async fn rebuild_client_endpoint(
    relay_config: &RelayConfig,
    builder: EndpointBuilder,
) -> Result<Endpoint> {
    let endpoint = builder
        .bind()
        .await
        .context("Failed to create iroh endpoint")?;
    let wait = online_timeout(relay_config, &endpoint);
    if tokio::time::timeout(wait, endpoint.online()).await.is_err() {
        log::warn!(
            "Rebuilt endpoint has no connected home relay after {}s; continuing (relay hints \
             and local discovery may still reach the server)",
            wait.as_secs()
        );
    }
    Ok(endpoint)
}

/// Recipe producing a fresh, fully bound endpoint — how a [`ClientEndpoint`]
/// replaces itself mid-session.
pub type EndpointFactory = Arc<dyn Fn() -> BoxFuture<'static, Result<Endpoint>> + Send + Sync>;

/// Bound wait on the old endpoint's graceful close during a rebuild. The close
/// runs as its own task and is never cancelled (dropping a bound endpoint
/// without `close()` is fatal under panic=abort); the bound only keeps the
/// reconnect loop from stalling behind it, letting a slow close finish in the
/// background.
const REBUILD_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// A client endpoint handle that can be **rebuilt** from scratch mid-session.
///
/// `Endpoint::network_change()` re-binds dead UDP transports, but a wedged
/// endpoint can be broken beyond what a rebind repairs: a relay link lost to a
/// ping timeout that never re-establishes, stale cached paths for the server,
/// dead discovery state. A process restart always recovers because it builds a
/// brand-new endpoint; [`Self::rebuild`] gives the reconnect loop that same
/// remedy in-process — fresh sockets, fresh relay connections, fresh discovery
/// — without dropping anything else the process holds (the bound proxy
/// listeners, port forwards, the status socket).
///
/// The handle is `Clone` and shared: the reconnect loop escalates to
/// [`Self::rebuild`] after repeated failures, while the embedder logs
/// [`Self::id`] and [`Self::close`]s whatever endpoint is current at teardown.
/// Client-only: the server's endpoint is bound once and kept, its home relay
/// moved in place by the shared failover.
#[derive(Clone)]
pub struct ClientEndpoint {
    /// The live endpoint, swapped by [`Self::rebuild`]. Std lock: accessors
    /// clone the handle out synchronously and never hold it across an await.
    current: Arc<std::sync::RwLock<Current>>,
    factory: EndpointFactory,
    /// Serializes [`Self::rebuild`]'s build-and-swap: the handle is shared,
    /// and two callers noticing the same outage must not each build an
    /// endpoint and have the second discard (and close) the first's good one.
    /// [`Self::close`] takes it too, so it waits a rebuild in flight out.
    rebuilding: Arc<tokio::sync::Mutex<()>>,
    /// The closes of the endpoints rebuilds replaced, each a task of its own,
    /// for [`Self::close`] to wait for: one still running when the session's
    /// runtime goes would be dropped with it. A wait given up on loses none
    /// of them: the next one finds them all the same.
    replaced: TaskTracker,
}

/// The installed endpoint plus how many rebuilds produced it, so a rebuild
/// caller can tell whether one already happened while it waited its turn.
struct Current {
    generation: u64,
    endpoint: Endpoint,
    /// Latched by [`ClientEndpoint::close`]: no rebuild installs an endpoint
    /// after it.
    closed: bool,
}

impl ClientEndpoint {
    /// Wrap a bound endpoint with the recipe that rebuilds it.
    pub fn from_parts(endpoint: Endpoint, factory: EndpointFactory) -> Self {
        Self {
            current: Arc::new(std::sync::RwLock::new(Current {
                generation: 0,
                endpoint,
                closed: false,
            })),
            factory,
            rebuilding: Arc::new(tokio::sync::Mutex::new(())),
            replaced: TaskTracker::new(),
        }
    }

    /// A clone of the current endpoint handle. Take it fresh per use: a handle
    /// held across a [`Self::rebuild`] keeps pointing at the old, closed
    /// endpoint.
    pub fn endpoint(&self) -> Endpoint {
        self.current.read().expect("endpoint lock").endpoint.clone()
    }

    /// The current endpoint id. Changes on rebuild for an ephemeral identity;
    /// stable when the factory binds a fixed secret (quick mode).
    pub fn id(&self) -> EndpointId {
        self.endpoint().id()
    }

    fn generation(&self) -> u64 {
        self.current.read().expect("endpoint lock").generation
    }

    /// Swap in a freshly built endpoint and close the old one. On error the
    /// current endpoint stays in place, so the caller can simply retry with it.
    ///
    /// Concurrent calls coalesce: a caller that arrives while another rebuild
    /// is in flight waits for it and, if it installed a fresh endpoint,
    /// returns `Ok` without building another — its trigger was the same dead
    /// endpoint, and [`Self::endpoint`] now yields the replacement. Only if
    /// the in-flight rebuild failed does the waiter build one itself.
    ///
    /// The build-and-swap runs as its own task, so a caller dropped half-way
    /// never drops the fresh endpoint with it (a bound endpoint must be
    /// closed, never just dropped): the task installs it — or, once
    /// [`Self::close`] has run, closes it — and closes the one it replaced.
    pub async fn rebuild(&self) -> Result<()> {
        let seen = self.generation();
        let this = self.clone();
        let swap = tokio::spawn(async move {
            let _serialized = this.rebuilding.lock().await;
            if this.current.read().expect("endpoint lock").closed {
                anyhow::bail!("the endpoint is closed");
            }
            if this.generation() != seen {
                log::info!(
                    "Endpoint already rebuilt by a concurrent caller; endpoint id: {}",
                    this.id()
                );
                return Ok(None);
            }
            // `close` waits for this lock, so it cannot run before the swap.
            let fresh = (this.factory)().await?;
            let old = {
                let mut current = this.current.write().expect("endpoint lock");
                current.generation += 1;
                std::mem::replace(&mut current.endpoint, fresh)
            };
            // Graceful close on its own task: bounded wait below, but the task
            // is never cancelled (see [`REBUILD_CLOSE_TIMEOUT`]). It is
            // tracked for `close`, which waits for this lock and so finds it.
            Ok(Some(this.replaced.spawn(async move { old.close().await })))
        });
        let close = match swap.await {
            Ok(swapped) => swapped?,
            Err(e) => anyhow::bail!("the endpoint rebuild task failed: {e}"),
        };
        let Some(mut close) = close else {
            return Ok(());
        };
        if tokio::time::timeout(REBUILD_CLOSE_TIMEOUT, &mut close)
            .await
            .is_err()
        {
            log::warn!("Old endpoint's close is slow; leaving it to finish in the background");
        }
        log::info!("Endpoint rebuilt; endpoint id: {}", self.id());
        Ok(())
    }

    /// Close the current endpoint gracefully (session teardown). A rebuild in
    /// flight is waited out first, so the endpoint it installs is the one
    /// closed here; none is installed after. The closes of the endpoints that
    /// rebuilds replaced are waited for as well, where still running.
    ///
    /// Run it to its end: it is not made to be dropped part-way and called
    /// again. A second call still waits for the replaced endpoints, but not
    /// for the current one once the first call began closing it, since iroh
    /// returns at once for an endpoint that is already closing. A caller that
    /// cannot wait keeps the one close running, on a task say, and stops
    /// waiting for it.
    pub async fn close(&self) {
        let _serialized = self.rebuilding.lock().await;
        let endpoint = {
            let mut current = self.current.write().expect("endpoint lock");
            current.closed = true;
            current.endpoint.clone()
        };
        // Nothing is replaced from here on, so the wait can end.
        self.replaced.close();
        futures::future::join(endpoint.close(), self.replaced.wait()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{RelayMode, endpoint::presets};

    // Hermetic: loopback-only endpoints, no relays, no discovery.
    fn loopback() -> EndpointBuilder {
        Endpoint::builder(presets::Empty)
            .relay_mode(RelayMode::Disabled)
            .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
    }

    #[tokio::test]
    async fn client_endpoint_swaps_and_closes_the_old_one() {
        let first = loopback().bind().await.unwrap();
        let first_id = first.id();
        let handle = ClientEndpoint::from_parts(
            first.clone(),
            Arc::new(|| Box::pin(async { loopback().bind().await.map_err(Into::into) })),
        );
        assert_eq!(handle.id(), first_id);

        handle.rebuild().await.unwrap();
        assert_ne!(handle.id(), first_id, "an ephemeral rebuild gets a new id");
        assert!(first.is_closed(), "the replaced endpoint is closed");
        handle.close().await;
        assert!(handle.endpoint().is_closed());
    }

    /// A close waits for the close of an endpoint a rebuild replaced, which
    /// runs on a task of its own: here one that is held open and let go only
    /// once the close has had time to return without it. A close given up on
    /// before that leaves it for the next one to wait for.
    #[tokio::test]
    async fn a_close_waits_for_the_close_of_a_replaced_endpoint() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let handle = ClientEndpoint::from_parts(
            loopback().bind().await.unwrap(),
            Arc::new(|| Box::pin(async { loopback().bind().await.map_err(Into::into) })),
        );
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let over = Arc::new(AtomicBool::new(false));
        handle.replaced.spawn({
            let over = over.clone();
            async move {
                // Gives up if the close never lets this test get to release.
                let _ = tokio::time::timeout(Duration::from_secs(30), released).await;
                over.store(true, Ordering::SeqCst);
            }
        });
        let given_up = tokio::time::timeout(Duration::from_millis(100), handle.close()).await;
        assert!(given_up.is_err(), "the close waits while it is held");

        // On this test's single thread the held task cannot run between its
        // release and the join returning, unless the close is waiting for it.
        tokio::join!(handle.close(), async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            release.send(()).unwrap();
        });
        assert!(over.load(Ordering::SeqCst), "the close waited for it");
    }

    #[tokio::test]
    async fn concurrent_rebuilds_coalesce_into_one() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let builds = Arc::new(AtomicUsize::new(0));
        let first = loopback().bind().await.unwrap();
        let handle = ClientEndpoint::from_parts(first.clone(), {
            let builds = builds.clone();
            Arc::new(move || {
                builds.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    // Hold the build long enough for the second caller to
                    // queue behind it.
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    loopback().bind().await.map_err(Into::into)
                })
            })
        });

        let a = handle.clone();
        let b = handle.clone();
        let (ra, rb) = tokio::join!(a.rebuild(), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            b.rebuild().await
        });
        ra.unwrap();
        rb.unwrap();
        assert_eq!(
            builds.load(Ordering::SeqCst),
            1,
            "the second caller joined the first"
        );
        assert!(first.is_closed());
        assert!(
            !handle.endpoint().is_closed(),
            "the one fresh endpoint is live"
        );

        // A rebuild after the coalesced one is a new outage: it builds again.
        handle.rebuild().await.unwrap();
        assert_eq!(builds.load(Ordering::SeqCst), 2);
        handle.close().await;
    }

    /// A caller dropped mid-rebuild (its destination closed, say) leaves the
    /// fresh endpoint installed, and a close waits that rebuild out and
    /// closes it; no rebuild installs one after the close.
    #[tokio::test]
    async fn a_rebuild_whose_caller_is_dropped_still_ends_closed() {
        let first = loopback().bind().await.unwrap();
        // The build says when it has started, then waits to be let go.
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let handle = ClientEndpoint::from_parts(first.clone(), {
            let (started, release) = (started.clone(), release.clone());
            Arc::new(move || {
                let (started, release) = (started.clone(), release.clone());
                Box::pin(async move {
                    started.notify_one();
                    release.notified().await;
                    loopback().bind().await.map_err(Into::into)
                })
            })
        });
        {
            let rebuild = handle.rebuild();
            tokio::pin!(rebuild);
            tokio::select! {
                _ = &mut rebuild => panic!("the build was held"),
                () = started.notified() => {}
            }
            // Dropped here, with the build under way.
        }
        release.notify_one();

        handle.close().await;
        let fresh = handle.endpoint();
        assert_ne!(fresh.id(), first.id(), "the rebuild was installed");
        assert!(fresh.is_closed(), "and closed by the close");
        // The replaced one closes on a task of its own, which the close
        // waited for with the caller dropped.
        assert!(first.is_closed(), "the replaced endpoint is closed");
        assert!(
            handle.rebuild().await.is_err(),
            "nothing is built after a close"
        );
    }
}
