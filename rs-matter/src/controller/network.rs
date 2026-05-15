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
//! ## Concrete provider
//!
//! [`OtbrLocalProvider`] (feature `zbus`) talks to a co-resident `otbr-agent`
//! over D-Bus (`io.openthread.BorderRouter.wpan0`) and fetches the live
//! `ActiveDatasetTlvs` property. This is the path zman uses, since zman and
//! OTBR co-run on the Pi.

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

/// Provider that talks to a local `otbr-agent` over D-Bus.
///
/// Concrete implementation of [`NetworkCredentialProvider::thread_dataset`].
/// Wi-Fi credentials are not provided by OTBR — callers wanting Wi-Fi need
/// to layer their own provider on top.
///
/// ## Connection
///
/// Connects on construction to the system D-Bus and to the
/// `io.openthread.BorderRouter.<ifname>` service. The interface name
/// (typically `wpan0`) is configurable so multiple OTBR instances can
/// coexist.
///
/// ## Errors
///
/// All D-Bus errors fold into [`ControllerError::NetworkCommissioningFailed`].
/// Callers can inspect logs for the underlying cause via the `tracing` /
/// `log` features.
#[cfg(feature = "zbus")]
pub struct OtbrLocalProvider {
    proxy: crate::utils::zbus_proxies::openthread::border_router::BorderRouterProxy<'static>,
}

#[cfg(feature = "zbus")]
impl OtbrLocalProvider {
    /// Connect to the system D-Bus and bind a proxy for the OTBR service
    /// named `io.openthread.BorderRouter.<ifname>`.
    ///
    /// Default `ifname` is `"wpan0"` — see [`OtbrLocalProvider::for_interface`]
    /// to override.
    pub async fn new() -> Result<Self, ControllerError> {
        Self::for_interface("wpan0").await
    }

    /// Connect to a specific OTBR Thread interface (multi-radio hosts).
    pub async fn for_interface(ifname: &str) -> Result<Self, ControllerError> {
        let conn = zbus::Connection::system()
            .await
            .map_err(|_| ControllerError::NetworkCommissioningFailed)?;
        let service = format!("io.openthread.BorderRouter.{}", ifname);
        let path = format!("/io/openthread/BorderRouter/{}", ifname);
        let proxy =
            crate::utils::zbus_proxies::openthread::border_router::BorderRouterProxy::builder(
                &conn,
            )
            .destination(service)
            .map_err(|_| ControllerError::NetworkCommissioningFailed)?
            .path(path)
            .map_err(|_| ControllerError::NetworkCommissioningFailed)?
            .build()
            .await
            .map_err(|_| ControllerError::NetworkCommissioningFailed)?;
        Ok(Self { proxy })
    }
}

#[cfg(feature = "zbus")]
impl NetworkCredentialProvider for OtbrLocalProvider {
    async fn thread_dataset(&self) -> Result<ThreadDataset, ControllerError> {
        let bytes = self
            .proxy
            .active_dataset_tlvs()
            .await
            .map_err(|_| ControllerError::NetworkCommissioningFailed)?;
        if bytes.is_empty() {
            // OTBR returns an empty array when the network is disabled or
            // detached — no useful dataset to hand to an accessory.
            return Err(ControllerError::NetworkCommissioningFailed);
        }
        let mut tlv = heapless::Vec::<u8, 256>::new();
        tlv.extend_from_slice(&bytes)
            .map_err(|_| ControllerError::NetworkCommissioningFailed)?;
        Ok(ThreadDataset { tlv })
    }

    async fn wifi_credentials(&self) -> Result<WifiCredentials, ControllerError> {
        // OTBR doesn't supply Wi-Fi credentials. A future
        // `WifiCredentialProvider` trait split would clarify this; for now,
        // return an error and let callers stack a Wi-Fi-aware provider on
        // top if their accessories need Wi-Fi.
        Err(ControllerError::NetworkCommissioningFailed)
    }
}
