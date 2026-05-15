# Matter Controller for rs-matter

`rs-matter` historically focuses on the **accessory** role — implementing
the device-side of the Matter spec so embedded hardware can be commissioned
by some external controller (HomeKit, Google Home, etc.).

This document describes a parallel effort to add the **controller** role:
the side that *commissions* Matter accessories into a fabric it owns and
drives them operationally. Without a Rust-native controller, hosts wanting
to integrate Matter today have to wrap the C++ CHIP SDK (FFI) or run
`python-matter-server` as a sidecar.

## Goals

1. Pure-Rust controller usable on `std` hosts (Linux, macOS) and embedded
   `no_std` targets that have BLE + IPv6 stacks.
2. API surface bit-compatible with `python-matter-server`'s controller
   methods, so hosts already integrated with PMS over WebSocket can swap
   to this implementation with minimal churn.
3. Layered cleanly on top of rs-matter's existing primitives
   (`crate::crypto`, `crate::tlv`, `crate::cert`, `crate::fabric`,
   `crate::im`, `crate::sc::pase`, `crate::sc::case`) — no duplication,
   no fork of the device-side code.
4. Upstream contribution: each finished sub-module lands as a PR against
   `project-chip/rs-matter`. This fork is a staging area, not a long-lived
   divergent branch.

## Reference implementations consulted

| Source | Used for |
|---|---|
| **Matter Core Spec 1.4** (`Matter-1.4-Core-Specification.pdf`) | Wire-level protocol semantics. Source of truth. Section references inline in each module. |
| **CHIP SDK** (`project-chip/connectedhomeip`, C++) | Clarification when the spec is ambiguous. Read, not source-translated. |
| **python-matter-server** (`home-assistant-libs/python-matter-server`, Python) | API shape, command vocabulary, device-state caching strategy. Translated as ergonomic Rust traits/methods, not line-by-line. PMS itself wraps the CHIP SDK via Python bindings — it isn't the protocol source. |

## Module map (work plan)

Code lives under `rs-matter/src/controller/`.

| Module | Responsibility | Matter spec § | PMS analogue |
|---|---|---|---|
| `mod.rs` | Top-level `Controller` handle | — | `MatterServer` |
| `ble.rs` | BLE GATT discovery + BTP transport | §5.4.2.2, §5.4.3.4, §5.4.4 | (via CHIP SDK BLE layer) |
| `commissioner.rs` | End-to-end commissioning state machine | §5.5 | `device_controller.py::commission_with_code` |
| `operational.rs` | CASE sessions + IM client (read/write/subscribe/invoke) | §4.13, §4.14, §8 | `device_controller.py::{read_attribute, send_command, subscribe_attribute}` |
| `network.rs` | Thread/Wi-Fi credential delivery | §11.9 | `ha-thread` integration + `device_controller.set_wifi_credentials` |
| `store.rs` | Persistence of commissioned nodes | — | `storage.py` |
| `error.rs` | `ControllerError` enum | — | `errors.py` |

## Implementation phases

This is the order each PR will land upstream.

### Phase A — Scaffolding *(this commit)*
- Module structure under `controller/`
- Public API traits, struct/enum shells with `unimplemented!`-equivalent stubs
- Doc comments on every type referencing the spec section and PMS source
- `lib.rs` exports the module
- Compiles cleanly (`cargo build -p rs-matter --features std`)

### Phase B — Operational client (no commissioning yet)
- Assume devices are already commissioned (a CHIP-tool-paired test fixture
  or a manually-provisioned NOC blob). Implement:
  - mDNS-SD operational discovery (§4.13) — find `_matter._tcp` records,
    extract fabric+node IDs
  - CASE handshake (§4.14) — uses existing `sc::case` primitives if
    available, or implements them
  - IM client invocation, read, write, subscribe (§8)
- This is independently useful: lets a Rust host *control* devices that
  someone else commissioned (e.g. devices commissioned by HomeKit, where
  zman is a second admin via `open_commissioning_window`).
- Validates the existing IM/SC machinery from the client side.

### Phase C — Network commissioning provider
- `network.rs` `OtbrLocalProvider` against a co-resident `otbr-agent`:
  - D-Bus path: `org.openthread.BorderRouter.wpan0`, method
    `GetActiveDatasetTlvs` (preferred)
  - `ot-ctl` unix-socket fallback: `/run/openthread-wpan0.sock`
- Returns a `ThreadDataset` ready to ship to a Thread accessory via
  the NetworkCommissioning cluster.

### Phase D — BLE transport
- Linux: `bluer` crate (BlueZ D-Bus). Scan for Matter Service UUID
  `0xFFF6`, parse advertisement data per §5.4.3.4, GATT-connect, run BTP
  per §5.4.4 (segmentation/handshake/MTU negotiation).
- macOS (dev only): `btleplug` for CoreBluetooth.
- Embedded: trait stays the same, host plugs in their HCI driver.

### Phase E — Commissioning state machine
- The state machine from `commissioner.rs` module docs. Drives a device
  end-to-end: BLE discover → PASE → ArmFailSafe → ReadVendorInfo →
  AttestationVerify → CSR → NOC issuance → AddTrustedRoot → AddNOC →
  NetworkCommissioning → CommissioningComplete → operational discovery →
  CASE → persist.
- Each step has its own unit test using a mock transport before going
  on-device.

### Phase F — Multi-admin
- `open_commissioning_window` for re-pairing already-commissioned devices
  as a second admin. Useful for "zman wants to control a device HomeKit
  already owns."

### Phase G — Upstream PRs
- Each phase merged as its own PR against `project-chip/rs-matter`.
- Phase A first; subsequent phases when functional.
- Issues tracked on `project-chip/rs-matter` to coordinate with upstream
  maintainers who may already have in-flight controller work
  (see e.g. `IM Client improvements (#447)`).

## Open questions

- BLE crate choice — `bluer` (Linux-only, D-Bus, mature) vs. `btleplug`
  (cross-platform, less mature). Likely `bluer` for the production
  target and `btleplug` behind a feature flag for development.
- Attestation chain verification — do we ship a DCL (Distributed
  Compliance Ledger) snapshot, or expose a trait so hosts plug in their
  own CD verification? CSA's DCL is publicly browsable; a baked
  snapshot is reasonable.
- Persistence — `StoredNode` uses `heapless::String<64>` for embedded
  compatibility. On `std` hosts this is wasteful. Consider a generic
  string type or two parallel structs.

## Status

- Phase A: ✓ this commit
- Phase B–G: not started.

Consumers using this controller as a dependency before Phase E is complete
should hold off on full commissioning flows — Phase B (operational client
against pre-commissioned devices) is the first stable target.
