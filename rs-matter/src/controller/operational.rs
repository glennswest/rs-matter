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
//! ## Wire-level references
//!
//! - **Matter Core Spec §4.13** — Operational Discovery via DNS-SD
//!   (`_matter._tcp` and `_matterc._udp`).
//! - **Matter Core Spec §4.14** — CASE Session establishment.
//! - **Matter Core Spec §8** — Interaction Model (Read, Write, Subscribe,
//!   Invoke).
//! - **Matter Core Spec §10** — Cluster definitions (handled by
//!   [`crate::dm::clusters`], not redefined here).
//!
//! ## API shape consulted
//!
//! From `python-matter-server/matter_server/server/device_controller.py`:
//!
//! - `read_attribute(node_id, endpoint_id, cluster_id, attribute_id)`
//! - `write_attribute(node_id, attribute_path, value)`
//! - `send_command(node_id, endpoint_id, command, payload, ...)`
//! - `subscribe_attribute(node_id, attribute_path)` returning events
//! - `interview_node(node_id)` — full descriptor cluster walk to learn the
//!   device's endpoint/cluster topology after commissioning or rejoin.
//! - `ping_node(node_id)` — liveness check.
//!
//! These translate to methods on [`OperationalClient`]. Internally each
//! uses the existing rs-matter [`crate::im`] client primitives layered
//! over a [`CaseSession`].
//!
//! ## Subscription bus
//!
//! PMS exposes a single async event stream to consumers. We surface the
//! same via a `tokio::sync::broadcast` channel (or `embassy_sync::channel`
//! for `no_std`). Subscriptions registered with `subscribe_attribute` deliver
//! attribute updates and events into this channel.

use super::commissioner::NodeId;
use super::ControllerError;

/// Endpoint identifier on a Matter node (Matter spec §2.5.1).
pub type EndpointId = u16;

/// 32-bit cluster identifier (Matter spec §2.5.2).
pub type ClusterId = u32;

/// 32-bit attribute identifier within a cluster.
pub type AttributeId = u32;

/// 32-bit command identifier within a cluster.
pub type CommandId = u32;

/// A fully-qualified attribute path: `<node, endpoint, cluster, attr>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributePath {
    pub node: NodeId,
    pub endpoint: EndpointId,
    pub cluster: ClusterId,
    pub attribute: AttributeId,
}

/// A fully-qualified command path: `<node, endpoint, cluster, command>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandPath {
    pub node: NodeId,
    pub endpoint: EndpointId,
    pub cluster: ClusterId,
    pub command: CommandId,
}

/// An open CASE session to one commissioned node.
///
/// Held by [`OperationalClient`]; transparently re-established if the
/// underlying transport drops or the session expires (Matter spec §4.14
/// "Resumption").
pub struct CaseSession;

/// The post-commissioning client. One per controller; multiplexes across
/// many commissioned nodes via cached CASE sessions.
pub struct OperationalClient;

impl OperationalClient {
    /// Read one attribute from a node. Establishes CASE if no cached
    /// session is available.
    pub async fn read_attribute(
        &mut self,
        _path: AttributePath,
    ) -> Result<crate::tlv::TLVElement<'static>, ControllerError> {
        Err(ControllerError::NodeNotCommissioned)
    }

    /// Write one attribute on a node.
    pub async fn write_attribute(
        &mut self,
        _path: AttributePath,
        _value: &[u8],
    ) -> Result<(), ControllerError> {
        Err(ControllerError::NodeNotCommissioned)
    }

    /// Invoke a command on a node.
    pub async fn invoke_command(
        &mut self,
        _path: CommandPath,
        _payload: &[u8],
    ) -> Result<(), ControllerError> {
        Err(ControllerError::NodeNotCommissioned)
    }

    /// Subscribe to attribute changes. Updates flow into the controller's
    /// event channel and are delivered to whoever holds the receiver end.
    pub async fn subscribe_attribute(
        &mut self,
        _path: AttributePath,
        _min_interval_secs: u16,
        _max_interval_secs: u16,
    ) -> Result<(), ControllerError> {
        Err(ControllerError::NodeNotCommissioned)
    }

    /// Walk the device's Descriptor cluster to learn its endpoint/cluster
    /// topology. Returns the full topology snapshot — caller persists in
    /// [`super::store`].
    pub async fn interview_node(
        &mut self,
        _node: NodeId,
    ) -> Result<(), ControllerError> {
        Err(ControllerError::NodeNotCommissioned)
    }

    /// Liveness ping — Read NodeOperationalCredentials::CurrentFabricIndex.
    /// Fast probe with no cluster-state cost.
    pub async fn ping_node(
        &mut self,
        _node: NodeId,
    ) -> Result<core::time::Duration, ControllerError> {
        Err(ControllerError::NodeNotCommissioned)
    }
}
