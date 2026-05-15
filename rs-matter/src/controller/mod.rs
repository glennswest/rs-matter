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

//! Matter Controller (Commissioner + Hub) implementation.
//!
//! The bulk of `rs-matter` historically targets the **device/accessory** role —
//! a thing that *gets* commissioned by some controller (HomeKit Hub,
//! Google Home, an Echo, etc.) and then serves clusters over Matter.
//!
//! This module is the inverse: the **controller/hub** role — the thing that
//! *commissions* Matter accessories into a fabric it owns, then drives them
//! operationally (read/write/subscribe attributes, invoke commands).
//!
//! ## Reference implementations consulted
//!
//! - **python-matter-server** (Home Assistant) — controller API shape, WebSocket
//!   message vocabulary, device-state caching strategy. We mirror its
//!   command surface so that hosts speaking to a "Matter server" can swap
//!   between the Python implementation and this one transparently.
//! - **CHIP SDK (connectedhomeip, C++)** — wire-level protocol semantics
//!   when the Matter Core Specification is ambiguous. Not source-translated;
//!   read as a clarification of the spec.
//! - **Matter Core Specification 1.4** — the source of truth for everything
//!   protocol-level. Section references are inline at each translation point.
//!
//! ## Sub-modules
//!
//! - [`ble`] — BLE GATT discovery + client transport for the initial
//!   commissioning channel (Matter spec §5.4.2.2 "Bluetooth Low Energy
//!   Transport Layer", and §5.4.3.4 "BLE Service Discovery").
//! - [`commissioner`] — End-to-end commissioning state machine: device
//!   discovery → PASE → ArmFailSafe → CSRRequest → AddNOC → SetRegulatoryConfig
//!   → CommissioningComplete → CASE establishment (Matter spec §5.5
//!   "Commissioning Flow").
//! - [`operational`] — Post-commissioning: CASE session management,
//!   Interaction Model client (Read/Write/Subscribe/Invoke), device
//!   reachability heartbeat (Matter spec §4.13 "Operational Discovery" and
//!   §8 "Interaction Model").
//! - [`network`] — Network credential delivery during commissioning:
//!   Thread (via NetworkCommissioning cluster) and Wi-Fi (idem). Thread
//!   datasets are sourced from the local OTBR via D-Bus or `ot-ctl`.
//! - [`store`] — Persistence of commissioned-device state (NodeID per
//!   fabric, IPK, last operational IPv6 address, last-seen, vendor/product
//!   ID, supported endpoints/clusters). Trait abstracts the host storage
//!   so the same controller works against an embedded flash blob, a host
//!   filesystem, or a SQL/native_db backing.
//! - [`error`] — Controller-specific error type wrapping the underlying
//!   [`crate::error::Error`] with state-machine context.
//!
//! ## Status
//!
//! Scaffolding only as of this commit. Each sub-module documents which PMS
//! source file and which Matter spec section its implementation will draw
//! from. See `CONTROLLER.md` at the workspace root for the full
//! algorithm-translation plan and contribution roadmap.

pub mod ble;
pub mod commissioner;
pub mod error;
pub mod network;
pub mod operational;
pub mod store;

pub use error::ControllerError;

/// The Matter Controller — owns one or more fabrics, commissions accessories
/// into them, and drives them operationally.
///
/// A `Controller` is the top-level handle a host application (e.g. zman) holds.
/// It wraps the existing rs-matter [`crate::Matter`] runtime in a way that
/// flips its role from "be a Matter device" to "drive Matter devices,"
/// reusing the same transport/session/IM machinery underneath.
///
/// Construction and lifecycle are deliberately left unspecified at this
/// scaffolding stage — the shape will firm up once the
/// [`commissioner::Commissioner`] state machine is implemented and we know
/// what handles need to be plumbed.
#[non_exhaustive]
pub struct Controller {
    // Field set deliberately empty during scaffolding so consumers don't
    // depend on internals that are going to churn.
}

impl Controller {
    /// Placeholder — real constructor will take a fabric set, a network
    /// commissioning provider, a BLE adapter, and a storage backend.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for Controller {
    fn default() -> Self {
        Self::new()
    }
}
