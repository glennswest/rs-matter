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

//! Persistence for commissioned-device state.
//!
//! After commissioning, the controller needs to remember each accessory
//! across restarts: which fabric it belongs to, its NodeID, its operational
//! identity (NOC / ICAC / IPK references), the vendor/product info from
//! the Basic Information cluster, and its last-known operational network
//! address (for fast reconnect before falling back to mDNS lookup).
//!
//! This module defines the [`ControllerStore`] trait — the host application
//! (zman, an embedded device, etc.) provides the concrete backing.
//!
//! ## Storage shape consulted
//!
//! `python-matter-server/matter_server/server/storage.py` stores:
//!   - `fabric_id` → fabric data
//!   - `node_id` → MatterNodeData (NOC, ipk_epoch_key, last operational ip,
//!     vendor_id, product_id, software_version, basic_info attributes,
//!     endpoint topology cache)
//!   - separate KV for `next_node_id` per fabric (so new commissions get
//!     unique IDs without conflict).
//!
//! In Rust we model the same as serializable structs (Serde) with the
//! caller plugging in their persistence layer. For zman the backing is
//! `native_db` via the existing `zman-db` crate (new `DbMatterFabric` and
//! `DbMatterNode` models).

use super::commissioner::NodeId;
use super::ControllerError;

/// Persisted state for a node commissioned by this controller.
///
/// Cloned on demand into the live [`super::operational::OperationalClient`]
/// cache. Source of truth lives in the [`ControllerStore`] impl.
#[derive(Debug, Clone)]
pub struct StoredNode {
    pub node_id: NodeId,
    pub fabric_index: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub software_version: u32,
    pub last_operational_ipv6: Option<[u8; 16]>,
    pub last_seen_unix_ms: u64,
    pub manufacturer: heapless::String<64>,
    pub model: heapless::String<64>,
}

/// Host-supplied persistence for the controller.
///
/// The trait is async to accommodate disk- or network-backed stores; an
/// in-memory implementation is trivial.
pub trait ControllerStore {
    /// Persist (or replace) a node's stored state.
    fn put_node(
        &mut self,
        node: &StoredNode,
    ) -> impl core::future::Future<Output = Result<(), ControllerError>>;

    /// Load a node's stored state.
    fn get_node(
        &self,
        node_id: NodeId,
    ) -> impl core::future::Future<Output = Result<Option<StoredNode>, ControllerError>>;

    /// Forget a node (after decommission).
    fn remove_node(
        &mut self,
        node_id: NodeId,
    ) -> impl core::future::Future<Output = Result<(), ControllerError>>;

    /// List all nodes on a given fabric.
    fn list_nodes(
        &self,
        fabric_index: u8,
    ) -> impl core::future::Future<Output = Result<heapless::Vec<NodeId, 64>, ControllerError>>;

    /// Reserve the next-free NodeID on a fabric (atomic w.r.t. concurrent
    /// commissions, even if the impl is just a counter under a mutex).
    fn allocate_node_id(
        &mut self,
        fabric_index: u8,
    ) -> impl core::future::Future<Output = Result<NodeId, ControllerError>>;
}
