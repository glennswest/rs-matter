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
//! This is the controller-side counterpart to [`crate::pairing`] (which is
//! the device-side). It orchestrates the Matter commissioning sequence from
//! BLE scan all the way through CASE establishment.
//!
//! ## Wire-level references
//!
//! - **Matter Core Spec §5.5** — Commissioning Flow (the canonical sequence).
//! - **Matter Core Spec §5.5.2** — Device Discovery.
//! - **Matter Core Spec §5.5.5** — Establish PASE Session.
//! - **Matter Core Spec §11.10** — General Commissioning Cluster
//!   (`ArmFailSafe`, `SetRegulatoryConfig`, `CommissioningComplete`).
//! - **Matter Core Spec §11.18** — Operational Credentials Cluster
//!   (`CSRRequest`, `AddNOC`, `AddTrustedRootCertificate`).
//! - **Matter Core Spec §11.9** — Network Commissioning Cluster
//!   (`AddOrUpdateThreadNetwork`, `AddOrUpdateWiFiNetwork`, `ConnectNetwork`).
//! - **Matter Core Spec §4.13** — Operational Discovery (post-commissioning
//!   via DNS-SD).
//! - **Matter Core Spec §4.14** — CASE Session.
//!
//! ## API shape consulted
//!
//! From `python-matter-server/matter_server/server/device_controller.py`:
//!
//! - `commission_with_code(code, network_only=False)` — the canonical
//!   "commission a device whose setup code/QR I know" entry point.
//! - `commission_on_network(setup_pin_code, ...)` — when the device is
//!   already on the operational network (e.g. Ethernet) and only needs
//!   PASE+credentials over IP, no BLE.
//! - `open_commissioning_window(node_id, ...)` — re-open commissioning
//!   on an already-commissioned device (so a second admin can pair).
//!
//! We translate these to Rust as [`Commissioner::commission_with_code`] etc.,
//! returning a `NodeId` on success.
//!
//! ## State machine
//!
//! ```text
//!   Idle
//!     │  commission_with_code(code)
//!     ▼
//!   Parsing             — decode 11-digit pairing code or QR payload
//!     │
//!     ▼
//!   Discovering         — BLE scan for matching discriminator
//!     │                   (or skip if commission_on_network)
//!     ▼
//!   PaseHandshake       — Spake2+ over BTP (or UDP if on-network)
//!     │
//!     ▼
//!   ArmFailSafe         — fail-safe timer starts (default 60s)
//!     │
//!     ▼
//!   ReadVendorInfo      — read Basic Information cluster
//!     │
//!     ▼
//!   AttestationVerify   — verify device attestation cert chain
//!     │
//!     ▼
//!   CSRRequest          — ask device to generate operational keypair + CSR
//!     │
//!     ▼
//!   NocIssuance         — sign CSR → NOC (uses fabric_credentials::FabricCredentials)
//!     │
//!     ▼
//!   AddTrustedRoot      — install our Root CA on the device
//!     │
//!     ▼
//!   AddNOC              — install the operational identity
//!     │
//!     ▼
//!   NetworkCommissioning — provision Thread (or Wi-Fi) credentials
//!     │                    via super::network module
//!     ▼
//!   CommissioningComplete — fail-safe disarmed, PASE torn down
//!     │
//!     ▼
//!   OperationalDiscovery — mDNS-SD lookup of `_matter._tcp` for the new
//!     │                    fabric+node id
//!     ▼
//!   CaseEstablishment    — CASE handshake over operational IPv6
//!     │
//!     ▼
//!   Commissioned ✓       — node persisted in [`super::store`], handle
//!                          returned to caller.
//! ```
//!
//! Failures at any state roll back via the still-armed fail-safe and surface
//! as [`ControllerError`].

use super::ControllerError;

/// 64-bit Node Identifier within a fabric (Matter spec §2.5.5).
pub type NodeId = u64;

/// Decoded representation of a Matter setup payload (QR code or 11-digit code).
///
/// Matter spec §5.1 "Onboarding Payload."
#[derive(Debug, Clone, Copy)]
pub struct SetupPayload {
    pub version: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub commissioning_flow: u8,
    pub discovery_capabilities: u8,
    pub discriminator: u16,
    pub passcode: u32,
}

/// Top-level controller-side commissioner.
///
/// Concrete type fields are unset during scaffolding; the API surface is
/// what callers (zman, etc.) should depend on.
pub struct Commissioner;

impl Commissioner {
    /// Commission a device using an 11-digit pairing code or QR string.
    ///
    /// This is the primary entry point. Behaviour mirrors
    /// `python-matter-server`'s `commission_with_code(code)`.
    ///
    /// Walks the full state machine documented at the module level.
    pub async fn commission_with_code(
        &mut self,
        _code: &str,
    ) -> Result<NodeId, ControllerError> {
        // TODO: parse code → SetupPayload → drive state machine
        Err(ControllerError::PaseFailed)
    }

    /// Commission a device already reachable on the operational network
    /// (no BLE step). The device must be in commissioning mode and
    /// reachable by mDNS.
    pub async fn commission_on_network(
        &mut self,
        _passcode: u32,
    ) -> Result<NodeId, ControllerError> {
        Err(ControllerError::PaseFailed)
    }

    /// Open the commissioning window on an already-commissioned node so a
    /// second admin can pair the same accessory.
    pub async fn open_commissioning_window(
        &mut self,
        _node: NodeId,
        _duration_secs: u16,
    ) -> Result<SetupPayload, ControllerError> {
        Err(ControllerError::NodeNotCommissioned)
    }
}
