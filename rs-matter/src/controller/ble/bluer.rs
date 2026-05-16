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

//! Linux BLE central using the [`bluer`] crate (BlueZ D-Bus).
//!
//! Implements [`BleAdapter`] / [`BleSession`] against BlueZ. The accessory
//! peripheral side already lives in `crate::transport::network::btp::gatt::bluer`
//! (it registers a GATT server and advertises). This module is its mirror:
//! a GATT client that scans for advertising Matter accessories and opens
//! a connection to them.
//!
//! ## Wire-level references
//!
//! - Matter Core Spec §5.4.3.4 — advertisement format
//! - Matter Core Spec §5.4.4 — BTP framing (not yet implemented in this
//!   crate's central-side; tracked separately).
//!
//! ## Matter GATT characteristics (spec §5.4.3.6)
//!
//! | UUID                                    | Role |
//! |-----------------------------------------|------|
//! | `18EE2EF5-263D-4559-959F-4F9C429F9D11`  | C1 — Write (commissioner → accessory) |
//! | `18EE2EF5-263D-4559-959F-4F9C429F9D12`  | C2 — Indicate (accessory → commissioner) |
//! | `64630238-8772-45F2-B87D-748A83218F04`  | C3 — Additional Commissioning Related Data |

// The crate-wide `info!`, `debug!`, `warn!` macros come from `crate::fmt`
// (see lib.rs `#![macro_use]`) — no `use log::...` import here, or it
// shadows them and the compiler reports E0659.
use ::bluer::{Adapter, AdapterEvent, Address, AddressType, Device, Session, Uuid};
use heapless::Vec as HVec;
use tokio_stream::StreamExt;

use crate::controller::ble::{BleAdapter, BleSession, DiscoveredBleDevice, MATTER_SERVICE_UUID};
use crate::controller::ControllerError;

/// Matter Service UUID as the canonical 128-bit form (§5.4.3.4).
const MATTER_UUID: Uuid = Uuid::from_u128(MATTER_SERVICE_UUID);

/// C1 characteristic UUID — commissioner-to-accessory write.
const C1_UUID: Uuid = Uuid::from_u128(0x18EE2EF5_263D_4559_959F_4F9C429F9D11);
/// C2 characteristic UUID — accessory-to-commissioner indicate.
const C2_UUID: Uuid = Uuid::from_u128(0x18EE2EF5_263D_4559_959F_4F9C429F9D12);

/// BlueZ-backed [`BleAdapter`] for Linux hosts.
///
/// Construct with [`BluerAdapter::new`]; the underlying [`bluer::Session`]
/// is owned for the adapter's lifetime so multiple discoveries can share
/// it without re-creating the D-Bus connection.
pub struct BluerAdapter {
    #[allow(dead_code)]
    session: Session,
    adapter: Adapter,
}

impl BluerAdapter {
    /// Open the default BlueZ adapter (typically `hci0`).
    pub async fn new() -> Result<Self, ControllerError> {
        let session = Session::new()
            .await
            .map_err(|_| ControllerError::BleUnavailable)?;
        let adapter = session
            .default_adapter()
            .await
            .map_err(|_| ControllerError::BleUnavailable)?;
        adapter
            .set_powered(true)
            .await
            .map_err(|_| ControllerError::BleUnavailable)?;
        info!(
            "BluerAdapter ready (Matter central) on {}",
            adapter.name()
        );
        Ok(Self { session, adapter })
    }
}

impl BleAdapter for BluerAdapter {
    type Session = BluerSession;

    async fn scan(
        &mut self,
        discriminator: Option<u16>,
        timeout_ms: u32,
    ) -> Result<HVec<DiscoveredBleDevice, 8>, ControllerError> {
        // Discovery is implicit while the stream is held; dropping it stops
        // discovery. We listen for DeviceAdded events and filter by the
        // Matter service-data record per §5.4.3.4.
        let mut events_stream = self
            .adapter
            .discover_devices()
            .await
            .map_err(|_| ControllerError::BleUnavailable)?;

        let mut out: HVec<DiscoveredBleDevice, 8> = HVec::new();
        let deadline =
            tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms as u64);

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let next = tokio::time::timeout(remaining, events_stream.next()).await;
            match next {
                Ok(Some(AdapterEvent::DeviceAdded(addr))) => {
                    if let Ok(device) = self.adapter.device(addr) {
                        match parse_matter_adv(&device).await {
                            Ok(Some(d)) => {
                                if discriminator
                                    .map(|want| (d.discriminator & 0x0fff) == (want & 0x0fff))
                                    .unwrap_or(true)
                                {
                                    debug!(
                                        "Matter advert addr={:?} disc={:04x} vid={:04x} pid={:04x}",
                                        addr, d.discriminator, d.vendor_id, d.product_id
                                    );
                                    if out.push(d).is_err() {
                                        break; // capped at 8 — stop on overflow
                                    }
                                }
                            }
                            Ok(None) => {} // not a Matter device
                            Err(e) => warn!("advertisement parse error addr={:?}: {:?}", addr, e),
                        }
                    }
                }
                Ok(Some(_)) | Ok(None) => continue,
                Err(_) => break, // timeout
            }
        }

        // events_stream drops here — discovery stops.
        Ok(out)
    }

    async fn connect(
        &mut self,
        device: &DiscoveredBleDevice,
    ) -> Result<Self::Session, ControllerError> {
        let addr = Address::new(device.addr[0..6].try_into().unwrap());
        let dev = self
            .adapter
            .device(addr)
            .map_err(|_| ControllerError::BleUnavailable)?;
        if !dev.is_connected().await.unwrap_or(false) {
            dev.connect()
                .await
                .map_err(|_| ControllerError::BleUnavailable)?;
        }

        // Find the Matter GATT service and its C1/C2 characteristics.
        let services = dev
            .services()
            .await
            .map_err(|_| ControllerError::BleUnavailable)?;
        let matter_svc = {
            let mut found = None;
            for s in services {
                if s.uuid().await.ok() == Some(MATTER_UUID) {
                    found = Some(s);
                    break;
                }
            }
            found.ok_or(ControllerError::BleUnavailable)?
        };

        let chars = matter_svc
            .characteristics()
            .await
            .map_err(|_| ControllerError::BleUnavailable)?;
        let mut c1 = None;
        let mut c2 = None;
        for c in chars {
            match c.uuid().await.ok() {
                Some(u) if u == C1_UUID => c1 = Some(c),
                Some(u) if u == C2_UUID => c2 = Some(c),
                _ => {}
            }
        }
        let c1 = c1.ok_or(ControllerError::BleUnavailable)?;
        let c2 = c2.ok_or(ControllerError::BleUnavailable)?;

        info!("Matter GATT connected addr={:?} (C1/C2 found)", addr);

        Ok(BluerSession { device: dev, c1, c2 })
    }
}

/// Open GATT session to a single Matter accessory.
///
/// Holds the BlueZ [`Device`] handle plus the C1 (write) and C2 (indicate)
/// characteristics for the Matter GATT service. The BTP framing layer
/// (§5.4.4) is not yet implemented in this crate's central-side; `send` /
/// `recv` will be wired up alongside that work.
pub struct BluerSession {
    device: Device,
    #[allow(dead_code)]
    c1: ::bluer::gatt::remote::Characteristic,
    #[allow(dead_code)]
    c2: ::bluer::gatt::remote::Characteristic,
}

impl BleSession for BluerSession {
    async fn send(&mut self, _frame: &[u8]) -> Result<(), ControllerError> {
        // TODO: feed `_frame` through the BTP TX framer
        // (segmentation per the negotiated MTU, retry/ack per spec §5.4.4),
        // then `self.c1.write(segment).await` for each segment.
        Err(ControllerError::BleUnavailable)
    }

    async fn recv<'a>(&'a mut self, _buf: &'a mut [u8]) -> Result<&'a [u8], ControllerError> {
        // TODO: subscribe to `self.c2.notify()` and feed indications
        // through the BTP RX reassembler. Return the next complete Matter
        // frame in `_buf`.
        Err(ControllerError::BleUnavailable)
    }

    async fn close(self) -> Result<(), ControllerError> {
        let _ = self.device.disconnect().await;
        Ok(())
    }
}

/// Parse the Matter portion of a BLE advertisement per spec §5.4.3.4.
///
/// Service Data for UUID 0xFFF6 is 8 bytes:
///   `op_code(1) | discriminator(2 le) | vendor_id(2 le) | product_id(2 le) | additional(1)`
async fn parse_matter_adv(
    device: &Device,
) -> Result<Option<DiscoveredBleDevice>, ::bluer::Error> {
    let service_data = device.service_data().await?;
    let Some(data) = service_data.and_then(|m| m.get(&MATTER_UUID).cloned()) else {
        return Ok(None);
    };
    if data.len() < 7 {
        return Ok(None);
    }
    let discriminator = u16::from_le_bytes([data[1], data[2]]) & 0x0fff;
    let vendor_id = u16::from_le_bytes([data[3], data[4]]);
    let product_id = u16::from_le_bytes([data[5], data[6]]);

    let bd = device.address();
    let mut addr_pad = [0u8; 16];
    addr_pad[..6].copy_from_slice(&bd.0);
    addr_pad[6] = match device.address_type().await.unwrap_or(AddressType::LePublic) {
        AddressType::LePublic => 0,
        AddressType::LeRandom => 1,
        _ => 0xff,
    };

    Ok(Some(DiscoveredBleDevice {
        discriminator,
        vendor_id,
        product_id,
        addr: addr_pad,
    }))
}
