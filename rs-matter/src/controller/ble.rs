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

//! BLE GATT discovery + client transport for the initial commissioning channel.
//!
//! Matter accessories advertise on BLE while waiting to be commissioned. The
//! controller scans for them, connects over GATT, and runs the PASE handshake
//! across the GATT service.
//!
//! ## Wire-level references
//!
//! - **Matter Core Spec §5.4.2.2** — BLE Transport Layer (BTP framing).
//! - **Matter Core Spec §5.4.3.4** — BLE Service Discovery (service UUID
//!   `0xFFF6`, characteristic UUIDs for C1/C2/C3).
//! - **Matter Core Spec §5.4.4** — BTP Session Lifecycle.
//!
//! ## API shape consulted
//!
//! - `python-matter-server/matter_server/server/device_controller.py`
//!   exposes `commission_with_code(code)` and `commission_on_network(...)`.
//!   We mirror this entry-point shape (see [`super::commissioner`]) so the
//!   BLE discovery+connect step is hidden from callers — the controller is
//!   told a setup code + discriminator and handles BLE internally.
//!
//! ## Translation plan
//!
//! 1. Define a host-OS-agnostic [`BleAdapter`] trait (scan, connect, GATT
//!    read/write/subscribe). Implementations on Linux use BlueZ (D-Bus via
//!    `bluer` crate); on macOS use CoreBluetooth (via `btleplug`); on
//!    embedded use the platform's BLE host stack.
//! 2. Implement BTP (Bluetooth Transport Protocol) framing per spec §5.4.4
//!    — segmentation/reassembly, ack/handshake, MTU negotiation.
//! 3. Expose a [`BleSession`] handle that the commissioner uses as a
//!    Matter-frame transport (analogous to a UDP session in operational mode).
//!
//! Nothing in this file is functional yet — types are scaffolding.

use super::ControllerError;

/// Matter Service UUID advertised by commissionable devices (spec §5.4.3.4).
pub const MATTER_SERVICE_UUID: u128 = 0x0000fff6_0000_1000_8000_00805f9b34fb;

/// Result of a BLE scan: a commissionable Matter device advertising on BLE.
#[derive(Debug, Clone)]
pub struct DiscoveredBleDevice {
    /// The 12-bit discriminator from the device's advertisement.
    pub discriminator: u16,
    /// 16-bit Vendor ID from the advertisement (0 if not present).
    pub vendor_id: u16,
    /// 16-bit Product ID from the advertisement (0 if not present).
    pub product_id: u16,
    /// Opaque address — interpretation is platform-dependent (BD_ADDR on
    /// Linux, NSUUID on macOS). Used to call back into [`BleAdapter::connect`].
    pub addr: [u8; 16],
}

/// Host BLE adapter abstraction.
///
/// Each target platform implements this trait once. The commissioner uses
/// it without caring whether it's BlueZ, CoreBluetooth, or an embedded
/// stack underneath.
pub trait BleAdapter {
    type Session: BleSession;

    /// Scan for Matter-commissionable devices. Returns devices that match
    /// the optional `discriminator` (short or long form).
    fn scan(
        &mut self,
        discriminator: Option<u16>,
        timeout_ms: u32,
    ) -> impl core::future::Future<Output = Result<heapless::Vec<DiscoveredBleDevice, 8>, ControllerError>>;

    /// Connect to a discovered device and open a BTP session over GATT.
    fn connect(
        &mut self,
        device: &DiscoveredBleDevice,
    ) -> impl core::future::Future<Output = Result<Self::Session, ControllerError>>;
}

/// An open BTP session over GATT — used as a transport for Matter frames
/// during the commissioning phase, until CASE establishes an operational
/// session over IP.
pub trait BleSession {
    /// Send one Matter frame (will be segmented per BTP §5.4.4 if larger
    /// than the negotiated MTU).
    fn send(
        &mut self,
        frame: &[u8],
    ) -> impl core::future::Future<Output = Result<(), ControllerError>>;

    /// Receive one Matter frame (with reassembly of segmented frames).
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl core::future::Future<Output = Result<&'a [u8], ControllerError>>;

    /// Close the BTP session and disconnect GATT.
    fn close(
        self,
    ) -> impl core::future::Future<Output = Result<(), ControllerError>>;
}
