/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 */

//! Operational client — once a device is commissioned, this is how the
//! controller talks to it.
//!
//! ## Architecture
//!
//! The controller-side runtime reuses `crate::Matter<'a>` (the same struct
//! the device-side uses). All it really needs is:
//!
//! 1. A configured fabric whose root cert this controller owns + has the
//!    `Admin` privilege on the target node. This is what [`crate::fabric`]
//!    + [`crate::credentials`] already manage.
//! 2. A working `Transport` — UDP/IPv6 by default. The same one device-side
//!    code uses, just with no responder exchanges waiting on it (we only
//!    initiate, not accept).
//! 3. A `Crypto` impl (rustcrypto, openssl, or mbedtls).
//!
//! Given those, every Interaction Model operation is just:
//!
//! ```text
//!   Exchange::initiate(matter, fabric_idx, peer_node_id, secure=true) ──► Exchange
//!     │  reuses cached CASE session, or returns NoSession if none
//!     ▼
//!   exchange.read_sender() / .write_sender() / .invoke_sender() / .subscribe_sender()
//!     │  ImClient trait — automatically available on any Exchange when the
//!     │  trait is `use`d (see `crate::im::client::ImClient`)
//!     ▼
//!   sender.build_request(closure that writes the TLV) → .tx() → response chunks
//! ```
//!
//! If no CASE session is cached we drive one ourselves:
//!
//! ```text
//!   Exchange::initiate_unsecured(matter, crypto, peer_addr) ──► Exchange
//!     ▼
//!   CaseInitiator::initiate(&mut exchange, crypto, fab_idx, peer_node_id)
//!     │  Sigma1 → Sigma2 → Sigma3 → secure session upgraded
//!     ▼
//!   Next Exchange::initiate(..., secure=true) finds the session and succeeds.
//! ```
//!
//! ## What lives in this file
//!
//! - [`OperationalClient`] — the public handle. Borrows the runtime by
//!   reference; everything else is on-demand.
//! - [`AttributePath`] / [`CommandPath`] — thin newtype wrappers over the
//!   raw rs-matter [`crate::im::attr::AttrPath`] / [`crate::im::types`]
//!   IDs, kept small so consumers like zman aren't forced to learn the
//!   full IM type lattice.
//! - Convenience methods: [`OperationalClient::read_attribute`],
//!   [`OperationalClient::write_attribute`], etc.
//!
//! ## Wire-level references
//!
//! - Matter Core Spec §4.13 (Operational Discovery) — mDNS-SD lookup of
//!   `_matter._tcp` for `<fabric_id>:<node_id>` is upstream rs-matter's
//!   `crate::transport::network::mdns` — the controller benefits from
//!   that infrastructure as a side effect of running on the same Matter
//!   stack as the device side.
//! - Matter Core Spec §4.14 (CASE Session) — `crate::sc::case` does this.
//!   `CaseInitiator::initiate` is the entry point.
//! - Matter Core Spec §8 (Interaction Model) — `crate::im::client::ImClient`
//!   exposes the four IM transactions.

use core::num::NonZeroU8;

use crate::crypto::Crypto;
use crate::error::Error;
use crate::im::client::ImClient;
use crate::im::types::{AttrId, ClusterId, CmdId, EndptId, NodeId};
use crate::transport::exchange::Exchange;
use crate::transport::network::Address;
use crate::Matter;

/// A fully-qualified attribute path: `<node, endpoint, cluster, attribute>`.
///
/// Newtype around the raw IDs so callers don't have to construct
/// [`crate::im::attr::AttrPath`] directly (it's a TLV struct with optional
/// fields, error-prone to build by hand).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributePath {
    pub node: NodeId,
    pub endpoint: EndptId,
    pub cluster: ClusterId,
    pub attribute: AttrId,
}

/// A fully-qualified command path: `<node, endpoint, cluster, command>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandPath {
    pub node: NodeId,
    pub endpoint: EndptId,
    pub cluster: ClusterId,
    pub command: CmdId,
}

/// Information needed to open a CASE session to a node when no secure
/// session is cached. The caller obtains this via mDNS-SD operational
/// discovery (`_matter._tcp.local` for `<compressed_fabric_id>-<node_id>`).
///
/// Once the controller's mDNS plumbing lands as a public API we'll expose
/// a `resolve_node` helper that hides this; for now the consumer provides
/// the resolved address explicitly.
#[derive(Debug, Clone, Copy)]
pub struct OperationalLocator {
    pub node_id: NodeId,
    pub address: Address,
}

/// The operational client. Borrows the runtime + crypto + fabric reference
/// for its lifetime; all CASE session caching is handled by the underlying
/// `Matter::transport`.
///
/// ## Construction
///
/// ```ignore
/// use rs_matter::Matter;
/// use rs_matter::crypto::Crypto;
/// use rs_matter::controller::operational::OperationalClient;
/// use core::num::NonZeroU8;
///
/// # fn doc<'a, C: Crypto>(matter: &'a Matter<'a>, crypto: &'a C) {
/// let client = OperationalClient::new(matter, crypto, NonZeroU8::new(1).unwrap());
/// // client.read_attribute(...).await
/// # }
/// ```
pub struct OperationalClient<'a, C: Crypto + 'a> {
    matter: &'a Matter<'a>,
    crypto: &'a C,
    fabric_idx: NonZeroU8,
}

impl<'a, C: Crypto + 'a> OperationalClient<'a, C> {
    /// Construct an operational client bound to a specific fabric on the
    /// shared Matter runtime.
    pub const fn new(matter: &'a Matter<'a>, crypto: &'a C, fabric_idx: NonZeroU8) -> Self {
        Self {
            matter,
            crypto,
            fabric_idx,
        }
    }

    /// Borrow the underlying Matter runtime (for callers that need to
    /// reach into the IM/transport machinery directly).
    pub fn matter(&self) -> &'a Matter<'a> {
        self.matter
    }

    /// The fabric this controller is operating on.
    pub fn fabric_idx(&self) -> NonZeroU8 {
        self.fabric_idx
    }

    /// Obtain an Exchange bound to a cached CASE session for `node_id`.
    ///
    /// Returns the underlying rs-matter error if no session is cached —
    /// callers that want automatic CASE establishment should first call
    /// [`Self::establish_case`] with an [`OperationalLocator`].
    pub async fn open_exchange(&self, node_id: NodeId) -> Result<Exchange<'a>, Error> {
        Exchange::initiate(self.matter, self.fabric_idx.get(), node_id, true).await
    }

    /// Drive a CASE handshake against `locator`, upgrading the local
    /// session table so subsequent [`Self::open_exchange`] calls hit a
    /// cached session.
    ///
    /// Implementation note: the actual handshake driver
    /// (`crate::sc::case::initiator::CaseInitiator::initiate`) requires a
    /// `&mut Exchange` on an unsecured session. We `initiate_unsecured` to
    /// the locator's address, then hand the exchange to `CaseInitiator`;
    /// on success rs-matter's session manager has the new secure session
    /// cached.
    pub async fn establish_case(&self, locator: OperationalLocator) -> Result<(), Error> {
        let mut exchange =
            Exchange::initiate_unsecured(self.matter, self.crypto, locator.address).await?;
        crate::sc::case::CaseInitiator::initiate(
            &mut exchange,
            self.crypto,
            self.fabric_idx,
            locator.node_id,
        )
        .await
    }

    /// Read one attribute from a commissioned node.
    ///
    /// Returns the raw TLV bytes of the response (caller decodes into
    /// whatever cluster-specific type they expect). Consumers like zman's
    /// `cluster_map` translate these bytes into protocol-agnostic property
    /// values for the DeviceStore.
    ///
    /// Errors if no CASE session is cached *and* no locator was registered
    /// for the node — call [`Self::establish_case`] beforehand (or, once
    /// it lands, `resolve_and_establish_case`).
    ///
    /// The actual TLV body construction inside the read request is left
    /// to the caller via the `build` closure so that `*Sender` builder
    /// patterns from `crate::im` (which have rich type-state) can be
    /// driven without re-encoding their full API here.
    pub async fn read_attribute<F, Fut, T>(
        &self,
        node_id: NodeId,
        build: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(crate::im::client::ReadSender<'a>) -> Fut,
        Fut: core::future::Future<Output = Result<T, Error>>,
    {
        let exchange = self.open_exchange(node_id).await?;
        let sender = exchange.read_sender().await?;
        build(sender).await
    }

    /// Write one attribute on a node.
    ///
    /// Same delegation pattern as [`Self::read_attribute`] — the caller
    /// gets the `WriteSender` and drives its build/tx cycle.
    ///
    /// `timed_timeout_ms` is the optional Timed Request timeout
    /// (spec §8.7). Pass `None` for normal writes; required for clusters
    /// that mandate timed interactions (e.g. DoorLock, WindowCovering).
    pub async fn write_attribute<F, Fut, T>(
        &self,
        node_id: NodeId,
        timed_timeout_ms: Option<u16>,
        build: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(crate::im::client::WriteSender<'a>) -> Fut,
        Fut: core::future::Future<Output = Result<T, Error>>,
    {
        let exchange = self.open_exchange(node_id).await?;
        let sender = exchange.write_sender(timed_timeout_ms).await?;
        build(sender).await
    }

    /// Invoke a command on a node.
    ///
    /// `timed_timeout_ms` is the optional Timed Request timeout from spec
    /// §8.7 (used by clusters that require timed interactions for safety —
    /// e.g. DoorLock, WindowCovering). Pass `None` for normal invocations.
    pub async fn invoke_command<F, Fut, T>(
        &self,
        node_id: NodeId,
        timed_timeout_ms: Option<u16>,
        build: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(crate::im::client::InvokeSender<'a>) -> Fut,
        Fut: core::future::Future<Output = Result<T, Error>>,
    {
        let exchange = self.open_exchange(node_id).await?;
        let sender = exchange.invoke_sender(timed_timeout_ms).await?;
        build(sender).await
    }

    /// Subscribe to attribute changes. The returned `SubscribeSender` is
    /// driven by the caller through the priming chunk + established state
    /// per `crate::im::client`'s documented pattern.
    pub async fn subscribe_attribute<F, Fut, T>(
        &self,
        node_id: NodeId,
        build: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(crate::im::client::SubscribeSender<'a>) -> Fut,
        Fut: core::future::Future<Output = Result<T, Error>>,
    {
        let exchange = self.open_exchange(node_id).await?;
        let sender = exchange.subscribe_sender().await?;
        build(sender).await
    }
}
