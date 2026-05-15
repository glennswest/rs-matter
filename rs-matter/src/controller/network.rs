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

//! Network credential delivery during commissioning.
//!
//! Most Matter accessories aren't on the LAN until the controller hands
//! them network credentials over the BLE/PASE channel. This module is the
//! interface for "provide me Thread credentials" and "provide me Wi-Fi
//! credentials" so the [`super::commissioner`] state machine can stay
//! transport-agnostic.
//!
//! ## Wire-level references
//!
//! - **Matter Core Spec §11.9** — Network Commissioning Cluster.
//! - **Thread 1.3 Spec §8** — Operational Dataset TLV encoding (the hex
//!   blob `ot-ctl dataset active -x` emits).
//!
//! ## API shape consulted
//!
//! `python-matter-server` delegates Thread credential fetch to Home
//! Assistant's Thread integration (which talks to OTBR over D-Bus or
//! mdns to discover border routers and over OTBR REST to fetch dataset).
//! We mirror the trait shape — caller provides a [`NetworkCredentialProvider`]
//! and the controller asks it for credentials when a device's Network
//! Commissioning cluster reports needing them.
//!
//! ## Implementations
//!
//! Initial concrete implementation: [`OtbrLocalProvider`] — talks to an
//! `otbr-agent` running on the same host via the `ot-ctl` IPC socket
//! (`/run/openthread-wpan0.sock`) or via D-Bus (`org.openthread.BorderRouter`).
//! That's how `zman` will plug in, since it co-runs with OTBR on the Pi.

use super::ControllerError;

/// A Thread operational dataset (the TLV-encoded blob that joins a Thread
/// network — same format `ot-ctl dataset active -x` produces).
#[derive(Debug, Clone)]
pub struct ThreadDataset {
    pub tlv: heapless::Vec<u8, 256>,
}

/// Wi-Fi credentials for a 2.4 GHz Matter accessory.
#[derive(Debug, Clone)]
pub struct WifiCredentials {
    pub ssid: heapless::String<32>,
    pub psk: heapless::Vec<u8, 64>,
}

/// Interface for "the host can supply network credentials when asked."
///
/// During commissioning, the controller reads the accessory's
/// `NetworkCommissioning::FeatureMap` to learn whether it wants Thread or
/// Wi-Fi, then calls one of these methods.
pub trait NetworkCredentialProvider {
    /// Fetch a Thread Operational Dataset to hand to the accessory.
    ///
    /// May be cached — most homes have exactly one Thread network.
    fn thread_dataset(
        &self,
    ) -> impl core::future::Future<Output = Result<ThreadDataset, ControllerError>>;

    /// Fetch Wi-Fi credentials. May prompt the user, may pull from a
    /// stored Wi-Fi profile.
    fn wifi_credentials(
        &self,
    ) -> impl core::future::Future<Output = Result<WifiCredentials, ControllerError>>;
}

/// Placeholder implementation that talks to a local `otbr-agent`.
///
/// Concrete plumbing TBD — will use either:
/// 1. D-Bus to `org.openthread.BorderRouter.wpan0` (cleanest on systemd hosts), or
/// 2. The unix-domain `ot-ctl` socket (simpler, no D-Bus dep), or
/// 3. The OTBR REST API (network-reachable, but adds an HTTP dep).
pub struct OtbrLocalProvider {
    // TODO: handle to the chosen IPC channel
}

impl NetworkCredentialProvider for OtbrLocalProvider {
    async fn thread_dataset(&self) -> Result<ThreadDataset, ControllerError> {
        Err(ControllerError::NetworkCommissioningFailed)
    }

    async fn wifi_credentials(&self) -> Result<WifiCredentials, ControllerError> {
        Err(ControllerError::NetworkCommissioningFailed)
    }
}
