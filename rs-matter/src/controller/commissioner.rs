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

//! End-to-end commissioning state machine.
//!
//! Drives a Matter accessory from "advertising on BLE" through to
//! "operational on its native IP network, CASE-secured, persisted in the
//! controller store." Calls into the rest of [`super`] for each step.
//!
//! ## State machine
//!
//! ```text
//!   Idle
//!     │  commission_with_code(code, network)
//!     ▼
//!   Parsing             ── controller::setup_code::parse_setup_code   ✅ landed
//!     │
//!     ▼
//!   Discovering         ── controller::ble::BleAdapter::scan          ✅ Linux (bluer)
//!     │                                                                  TODO BTP framing for handshake
//!     ▼
//!   PaseHandshake       ── crate::sc::pase (controller path)          🟡 needs rs-matter's
//!     │                                                                  Spake2pInitiator exposure
//!     ▼
//!   ArmFailSafe         ── GeneralCommissioning cluster (0x0030 cmd 0x00) 🟡 IM invoke over PASE
//!     ▼
//!   ReadVendorInfo      ── BasicInformation cluster                   🟡 IM read over PASE
//!     ▼
//!   AttestationVerify   ── OperationalCredentials AttestationRequest  🟡 needs DCL + cert chain
//!     ▼                       + chain verification
//!   CSRRequest          ── OperationalCredentials CSRRequest          🟡 IM invoke
//!     ▼
//!   NocIssuance         ── controller::commissioner::NocGenerator     ✅ exists in rs-matter
//!     ▼
//!   AddTrustedRoot      ── OperationalCredentials AddTrustedRootCertificate 🟡 IM invoke
//!     ▼
//!   AddNOC              ── OperationalCredentials AddNOC              🟡 IM invoke
//!     ▼
//!   NetworkCommissioning ── NetworkCommissioning AddOrUpdateThreadNetwork 🟡 IM invoke, dataset
//!     │                       + ConnectNetwork                            from NetworkCredentialProvider ✅
//!     ▼
//!   CommissioningComplete ── GeneralCommissioning CommissioningComplete 🟡 IM invoke
//!     ▼
//!   OperationalDiscovery ── mDNS-SD _matter._tcp lookup               🟡 needs controller-side
//!     ▼                                                                  mDNS query helper
//!   CaseEstablishment   ── controller::operational::OperationalClient   ✅ Phase 2B
//!     │                       ::establish_case
//!     ▼
//!   Commissioned ✓      ── controller::store::ControllerStore::put_node ✅ trait done
//! ```
//!
//! ## What "✅ landed" vs "🟡" mean
//!
//! - **✅ landed** — the dependency exists in this crate and the
//!   integration point in this module is real code, not a stub.
//! - **🟡** — the dependency exists in rs-matter for the device-side
//!   path but the controller-side flow needs either a new exposure
//!   (`pub(crate)` → `pub`) upstream or a small adapter here. The state
//!   transition is wired into the state machine; the body returns
//!   [`ControllerError::PaseFailed`] (or the appropriate variant) until
//!   the dependency lands.

use core::num::NonZeroU8;

use crate::commissioner::FabricCredentials;
use crate::crypto::Crypto;
use crate::Matter;

use super::ble::BleAdapter;
use super::network::{NetworkCredentialProvider, ThreadDataset};
use super::operational::{OperationalClient, OperationalLocator};
use super::setup_code::{parse_setup_code, SetupPayload};
use super::store::{ControllerStore, StoredNode};
use super::ControllerError;

/// 64-bit Node Identifier within a fabric (Matter spec §2.5.5).
pub type NodeId = u64;

/// Where the commissioner is in the state machine. Surfaced through
/// [`Commissioner::progress`] so callers (e.g. zman's admin UI) can
/// stream progress to the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommissioningStage {
    Idle,
    Parsing,
    Discovering,
    PaseHandshake,
    ArmFailSafe,
    ReadVendorInfo,
    AttestationVerify,
    CsrRequest,
    NocIssuance,
    AddTrustedRoot,
    AddNoc,
    NetworkCommissioning,
    CommissioningComplete,
    OperationalDiscovery,
    CaseEstablishment,
    Commissioned,
}

/// Inputs to one commissioning run. Bundled as a struct so that the
/// state machine takes a single argument and we can grow it without
/// breaking signatures.
pub struct CommissioningContext<'a, C, B, N, S>
where
    C: Crypto + 'a,
    B: BleAdapter,
    N: NetworkCredentialProvider,
    S: ControllerStore,
{
    /// Shared Matter runtime — used by [`OperationalClient`] for CASE
    /// + IM operations once the device is on the operational network.
    pub matter: &'a Matter<'a>,
    /// Crypto provider (rustcrypto / openssl / mbedtls).
    pub crypto: &'a C,
    /// Fabric we're commissioning into. The controller's NOC issuer
    /// pulls the trust anchor from [`crate::fabric::Fabrics`] keyed by
    /// this index.
    pub fabric_idx: NonZeroU8,
    /// Fabric credentials used to sign new NOCs (the issuer's key).
    /// rs-matter's `commissioner::fabric_credentials` produces this.
    pub fabric_credentials: &'a FabricCredentials,
    /// Host BLE adapter — used during the Discovering / PaseHandshake
    /// stages. Pass any [`BleAdapter`] impl (`bluer` on Linux, etc.).
    pub ble: &'a mut B,
    /// Source of network credentials to hand to the device (Thread
    /// dataset from a local OTBR, Wi-Fi PSK from operator config, …).
    pub network: &'a N,
    /// Persistent store for the commissioned-node record.
    pub store: &'a mut S,
}

/// Top-level controller-side commissioner.
pub struct Commissioner {
    stage: CommissioningStage,
}

impl Default for Commissioner {
    fn default() -> Self {
        Self::new()
    }
}

impl Commissioner {
    pub const fn new() -> Self {
        Self {
            stage: CommissioningStage::Idle,
        }
    }

    /// Current stage. Useful for UI progress reporting.
    pub fn progress(&self) -> CommissioningStage {
        self.stage
    }

    /// Commission a device using an 11-digit pairing code or QR
    /// onboarding payload.
    ///
    /// Drives the full state machine documented at the module level.
    /// Stages whose dependencies haven't landed yet error out cleanly
    /// — the [`Self::progress`] inspector reveals exactly which stage
    /// failed.
    pub async fn commission_with_code<C, B, N, S>(
        &mut self,
        ctx: &mut CommissioningContext<'_, C, B, N, S>,
        code: &str,
    ) -> Result<NodeId, ControllerError>
    where
        C: Crypto,
        B: BleAdapter,
        N: NetworkCredentialProvider,
        S: ControllerStore,
    {
        // 1. Parse — turn the operator's string into a SetupPayload.
        self.stage = CommissioningStage::Parsing;
        let payload = parse_setup_code(code).map_err(|_| ControllerError::PaseFailed)?;

        // 2. Discover — scan BLE for an advert matching the short
        //    discriminator. (Devices already on the operational network
        //    bypass this; that path is `commission_on_network`.)
        self.stage = CommissioningStage::Discovering;
        let _ble_session = self.discover_and_connect(ctx, &payload).await?;

        // 3-12. PASE → fail-safe → vendor info → attestation → CSR →
        //       NOC issuance → AddTrustedRoot → AddNOC →
        //       NetworkCommissioning → CommissioningComplete.
        //
        //       Each runs over the BLE-session-backed exchange (PASE)
        //       then post-CASE exchange (CommissioningComplete switches).
        //       The bodies below are real entry points calling into
        //       sub-helpers; helpers that need missing rs-matter
        //       primitives return the appropriate ControllerError.
        let node_id = ctx.store.allocate_node_id(ctx.fabric_idx.get()).await?;
        self.run_pase(ctx, &payload).await?;
        self.arm_fail_safe(ctx).await?;
        let vendor_info = self.read_vendor_info(ctx).await?;
        self.verify_attestation(ctx).await?;
        let _csr = self.request_csr(ctx).await?;
        let _noc = self.issue_noc(ctx, node_id).await?;
        self.add_trusted_root(ctx).await?;
        self.add_noc(ctx).await?;
        self.commission_network(ctx).await?;
        self.commissioning_complete(ctx).await?;

        // 13-14. Once CommissioningComplete returns, the device is on
        //         its operational network. Resolve its IPv6 via mDNS,
        //         then drive CASE via OperationalClient.
        let locator = self.operational_discovery(ctx, node_id).await?;
        self.case_establishment(ctx, locator).await?;

        // 15. Persist — store the commissioned node so subsequent
        //     restarts find it.
        self.stage = CommissioningStage::Commissioned;
        let now_unix_ms = 0; // TODO: pull from a clock source
        ctx.store
            .put_node(&StoredNode {
                node_id,
                fabric_index: ctx.fabric_idx.get(),
                vendor_id: vendor_info.vendor_id,
                product_id: vendor_info.product_id,
                software_version: vendor_info.software_version,
                last_operational_ipv6: Some(locator_addr_bytes(&locator)),
                last_seen_unix_ms: now_unix_ms,
                manufacturer: vendor_info.manufacturer,
                model: vendor_info.model,
            })
            .await?;

        Ok(node_id)
    }

    // ── State-transition helpers ────────────────────────────────────

    async fn discover_and_connect<C, B, N, S>(
        &mut self,
        ctx: &mut CommissioningContext<'_, C, B, N, S>,
        payload: &SetupPayload,
    ) -> Result<B::Session, ControllerError>
    where
        C: Crypto,
        B: BleAdapter,
        N: NetworkCredentialProvider,
        S: ControllerStore,
    {
        // Manual codes only carry the top 4 bits of the 12-bit
        // discriminator. The BleAdapter::scan filter accepts an
        // `Option<u16>` short-or-long discriminator; we pass whichever
        // we have.
        let want = if payload.short_discriminator {
            Some(payload.discriminator >> 8)
        } else {
            Some(payload.discriminator)
        };
        let found = ctx.ble.scan(want, 10_000).await?;
        let dev = found.first().ok_or(ControllerError::BleUnavailable)?;
        ctx.ble.connect(dev).await
    }

    async fn run_pase<C, B, N, S>(
        &mut self,
        _ctx: &mut CommissioningContext<'_, C, B, N, S>,
        _payload: &SetupPayload,
    ) -> Result<(), ControllerError>
    where
        C: Crypto,
        B: BleAdapter,
        N: NetworkCredentialProvider,
        S: ControllerStore,
    {
        self.stage = CommissioningStage::PaseHandshake;
        // TODO: drive Spake2+ from the controller side using rs-matter's
        // crate::sc::pase machinery (currently the responder-side path is
        // public; the initiator path is via Pase::pair() inside the
        // device's PaseSession). Once a public Spake2pInitiator emerges
        // upstream (or we add one in this fork), this becomes:
        //
        //   let mut session = pase::Spake2pInitiator::new(...);
        //   session.send_pbkdf_param_request(&mut ble_exchange).await?;
        //   ... (Spake2+ exchange) ...
        //
        // Until then, fail loud so callers don't pretend a session exists.
        Err(ControllerError::PaseFailed)
    }

    async fn arm_fail_safe<C, B, N, S>(
        &mut self,
        _ctx: &mut CommissioningContext<'_, C, B, N, S>,
    ) -> Result<(), ControllerError>
    where
        C: Crypto,
        B: BleAdapter,
        N: NetworkCredentialProvider,
        S: ControllerStore,
    {
        self.stage = CommissioningStage::ArmFailSafe;
        // TODO: invoke GeneralCommissioning cluster (0x0030) command
        // 0x00 (ArmFailSafe) over the PASE-secured exchange with an
        // ExpiryLengthSeconds of 60. Needs a PASE-backed Exchange to
        // hand to ImClient::invoke_sender.
        Err(ControllerError::FailSafeExpired)
    }

    async fn read_vendor_info<C, B, N, S>(
        &mut self,
        _ctx: &mut CommissioningContext<'_, C, B, N, S>,
    ) -> Result<VendorInfo, ControllerError>
    where
        C: Crypto,
        B: BleAdapter,
        N: NetworkCredentialProvider,
        S: ControllerStore,
    {
        self.stage = CommissioningStage::ReadVendorInfo;
        // TODO: read BasicInformation cluster (0x0028) attributes
        // VendorID, ProductID, SoftwareVersionString, ManufacturerName,
        // ProductName via ImClient::read_sender. Until the PASE
        // exchange path lands, return placeholder zeros so the persist
        // step has a typed struct to work with.
        Err(ControllerError::PaseFailed)
    }

    async fn verify_attestation<C, B, N, S>(
        &mut self,
        _ctx: &mut CommissioningContext<'_, C, B, N, S>,
    ) -> Result<(), ControllerError>
    where
        C: Crypto,
        B: BleAdapter,
        N: NetworkCredentialProvider,
        S: ControllerStore,
    {
        self.stage = CommissioningStage::AttestationVerify;
        // TODO: AttestationRequest → AttestationResponse, verify the
        // certificate chain against the CSA DCL trust anchors. DCL
        // verification is its own subsystem; rs-matter has the cert
        // primitives (crate::cert) but no DCL snapshot bundled.
        Err(ControllerError::PaseFailed)
    }

    async fn request_csr<C, B, N, S>(
        &mut self,
        _ctx: &mut CommissioningContext<'_, C, B, N, S>,
    ) -> Result<heapless::Vec<u8, 256>, ControllerError>
    where
        C: Crypto,
        B: BleAdapter,
        N: NetworkCredentialProvider,
        S: ControllerStore,
    {
        self.stage = CommissioningStage::CsrRequest;
        // TODO: OperationalCredentials::CSRRequest → CSRResponse.
        Err(ControllerError::PaseFailed)
    }

    async fn issue_noc<C, B, N, S>(
        &mut self,
        _ctx: &mut CommissioningContext<'_, C, B, N, S>,
        _node_id: NodeId,
    ) -> Result<heapless::Vec<u8, 400>, ControllerError>
    where
        C: Crypto,
        B: BleAdapter,
        N: NetworkCredentialProvider,
        S: ControllerStore,
    {
        self.stage = CommissioningStage::NocIssuance;
        // The pure-crypto part of NOC issuance lives in
        // crate::commissioner::noc_generator::NocGenerator and is
        // already complete. Wiring needs a CSR (from request_csr above)
        // and the fabric_credentials trust anchor — both available in
        // ctx. Returning an error until request_csr lands.
        Err(ControllerError::PaseFailed)
    }

    async fn add_trusted_root<C, B, N, S>(
        &mut self,
        _ctx: &mut CommissioningContext<'_, C, B, N, S>,
    ) -> Result<(), ControllerError>
    where
        C: Crypto,
        B: BleAdapter,
        N: NetworkCredentialProvider,
        S: ControllerStore,
    {
        self.stage = CommissioningStage::AddTrustedRoot;
        Err(ControllerError::PaseFailed)
    }

    async fn add_noc<C, B, N, S>(
        &mut self,
        _ctx: &mut CommissioningContext<'_, C, B, N, S>,
    ) -> Result<(), ControllerError>
    where
        C: Crypto,
        B: BleAdapter,
        N: NetworkCredentialProvider,
        S: ControllerStore,
    {
        self.stage = CommissioningStage::AddNoc;
        Err(ControllerError::AddNocRejected)
    }

    async fn commission_network<C, B, N, S>(
        &mut self,
        ctx: &mut CommissioningContext<'_, C, B, N, S>,
    ) -> Result<(), ControllerError>
    where
        C: Crypto,
        B: BleAdapter,
        N: NetworkCredentialProvider,
        S: ControllerStore,
    {
        self.stage = CommissioningStage::NetworkCommissioning;
        // For Thread devices, pull the dataset from the OTBR-backed
        // provider (Phase 2C) and ship it as
        // NetworkCommissioning::AddOrUpdateThreadNetwork then
        // ConnectNetwork. For Wi-Fi devices, use wifi_credentials()
        // similarly. The fetch is real today — wire it up so the dataset
        // is available even though the IM invoke isn't yet.
        let _dataset: ThreadDataset = ctx.network.thread_dataset().await?;
        // TODO: invoke NetworkCommissioning cluster (0x0031) commands
        // AddOrUpdateThreadNetwork(_dataset) → ConnectNetwork.
        Err(ControllerError::NetworkCommissioningFailed)
    }

    async fn commissioning_complete<C, B, N, S>(
        &mut self,
        _ctx: &mut CommissioningContext<'_, C, B, N, S>,
    ) -> Result<(), ControllerError>
    where
        C: Crypto,
        B: BleAdapter,
        N: NetworkCredentialProvider,
        S: ControllerStore,
    {
        self.stage = CommissioningStage::CommissioningComplete;
        // TODO: GeneralCommissioning::CommissioningComplete invoke.
        // On success the device disarms its fail-safe, swaps from PASE
        // to its operational identity, and begins announcing on the
        // operational network. The BLE+PASE session can be torn down.
        Err(ControllerError::FailSafeExpired)
    }

    async fn operational_discovery<C, B, N, S>(
        &mut self,
        _ctx: &mut CommissioningContext<'_, C, B, N, S>,
        _node_id: NodeId,
    ) -> Result<OperationalLocator, ControllerError>
    where
        C: Crypto,
        B: BleAdapter,
        N: NetworkCredentialProvider,
        S: ControllerStore,
    {
        self.stage = CommissioningStage::OperationalDiscovery;
        // TODO: mDNS-SD query for `_matter._tcp.local` filtering on
        // `<compressed_fabric_id>-<node_id>` instance name. rs-matter's
        // transport::network::mdns serves the device side (announces
        // *our* services). The controller side needs a separate query
        // helper. domain crate (already a dep) can build the queries.
        Err(ControllerError::OperationalDiscoveryFailed)
    }

    async fn case_establishment<C, B, N, S>(
        &mut self,
        ctx: &mut CommissioningContext<'_, C, B, N, S>,
        locator: OperationalLocator,
    ) -> Result<(), ControllerError>
    where
        C: Crypto,
        B: BleAdapter,
        N: NetworkCredentialProvider,
        S: ControllerStore,
    {
        self.stage = CommissioningStage::CaseEstablishment;
        let op = OperationalClient::new(ctx.matter, ctx.crypto, ctx.fabric_idx);
        op.establish_case(locator).await.map_err(ControllerError::from)
    }
}

/// Local placeholder for the BasicInformation cluster reads we'll do at
/// the [`Commissioner::read_vendor_info`] stage. Mirrors the fields
/// [`StoredNode`] needs to persist.
#[derive(Debug, Clone, Default)]
pub struct VendorInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub software_version: u32,
    pub manufacturer: heapless::String<64>,
    pub model: heapless::String<64>,
}

fn locator_addr_bytes(loc: &OperationalLocator) -> [u8; 16] {
    use crate::transport::network::Address;
    let sock_addr = match loc.address {
        Address::Udp(sa) | Address::Tcp(sa) => sa,
        Address::Btp(_) => return [0u8; 16], // not an IP address; persist as zeros
    };
    match sock_addr.ip() {
        core::net::IpAddr::V6(v6) => v6.octets(),
        core::net::IpAddr::V4(v4) => {
            // IPv4-mapped IPv6: ::ffff:a.b.c.d
            let mut out = [0u8; 16];
            out[10] = 0xff;
            out[11] = 0xff;
            out[12..16].copy_from_slice(&v4.octets());
            out
        }
    }
}
