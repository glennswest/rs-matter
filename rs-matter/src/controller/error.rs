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

//! Controller-specific error type.

use crate::error::Error;

/// Errors produced by the controller-side state machines.
///
/// Wraps the underlying rs-matter [`Error`] and adds context unique to the
/// controller role (commissioning step, BLE state, etc.).
#[derive(Debug)]
#[non_exhaustive]
pub enum ControllerError {
    /// Wrapped error from the rs-matter core.
    Inner(Error),

    /// The requested operation requires BLE but no BLE adapter is configured.
    BleUnavailable,

    /// PASE session establishment failed (wrong passcode, timeout, etc.).
    PaseFailed,

    /// ArmFailSafe failed or fail-safe expired during commissioning.
    FailSafeExpired,

    /// AddNOC was rejected by the accessory.
    AddNocRejected,

    /// CASE session establishment failed after commissioning.
    CaseFailed,

    /// The accessory could not be found via operational discovery (mDNS).
    OperationalDiscoveryFailed,

    /// Network credential delivery (Thread/Wi-Fi) failed.
    NetworkCommissioningFailed,

    /// The fabric this controller manages is not provisioned in storage.
    FabricNotProvisioned,

    /// The targeted node is not commissioned on this fabric.
    NodeNotCommissioned,
}

impl From<Error> for ControllerError {
    fn from(e: Error) -> Self {
        Self::Inner(e)
    }
}

impl core::fmt::Display for ControllerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Inner(e) => write!(f, "matter: {:?}", e),
            Self::BleUnavailable => write!(f, "BLE adapter not configured"),
            Self::PaseFailed => write!(f, "PASE session establishment failed"),
            Self::FailSafeExpired => write!(f, "ArmFailSafe failed or fail-safe expired"),
            Self::AddNocRejected => write!(f, "AddNOC rejected by accessory"),
            Self::CaseFailed => write!(f, "CASE session establishment failed"),
            Self::OperationalDiscoveryFailed => write!(f, "operational mDNS discovery failed"),
            Self::NetworkCommissioningFailed => write!(f, "network commissioning failed"),
            Self::FabricNotProvisioned => write!(f, "fabric not provisioned in storage"),
            Self::NodeNotCommissioned => write!(f, "node not commissioned on this fabric"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ControllerError {}
