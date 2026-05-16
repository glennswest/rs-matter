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

//! Onboarding payload decoders — the inverse of [`crate::pairing`].
//!
//! Matter accessories present commissioners with a setup credential in
//! one of two forms (Matter Core Spec §5.1 "Onboarding Payload"):
//!
//! 1. **Manual pairing code** — 11 decimal digits, often pretty-printed
//!    with dashes (`1234-567-8910` → `12345678910`). Carries the *short*
//!    discriminator (4 high bits of the 12-bit one) and the 27-bit
//!    passcode plus a Verhoeff check digit.
//! 2. **QR-code payload** — a base-38-encoded string prefixed with
//!    `MT:`. Carries the full payload: version, vendor/product IDs,
//!    commissioning flow, discovery capabilities, full 12-bit
//!    discriminator, passcode, and optional TLV add-ons.
//!
//! This module produces a [`SetupPayload`] from either form. The
//! commissioner state machine in [`super::commissioner`] consumes it.
//!
//! The encoders (device side) live in [`crate::pairing::code`] and
//! [`crate::pairing::qr`]; this module is their inverse.

use verhoeff::Verhoeff;

/// Decoded onboarding payload as carried in either a manual pairing
/// code or a QR-code string.
///
/// Fields the manual code can't supply (vendor/product IDs, discovery
/// capabilities, *full* 12-bit discriminator) are `None` when the source
/// was a manual code. The commissioner state machine treats those as
/// "unknown, fall back to defaults / scan for any matching short
/// discriminator."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupPayload {
    /// Payload version. `0` for current Matter spec.
    pub version: u8,
    /// 16-bit Vendor ID. `None` if not present in the source (manual code
    /// without `VID_PID_PRESENT` flag).
    pub vendor_id: Option<u16>,
    /// 16-bit Product ID. `None` mirrors `vendor_id`.
    pub product_id: Option<u16>,
    /// Commissioning flow — 0 standard, 1 user-intent, 2 custom.
    /// `None` if absent (manual codes don't carry it).
    pub commissioning_flow: Option<u8>,
    /// Discovery capabilities bitmap — bit 0 = SoftAP, bit 1 = BLE,
    /// bit 2 = On-network. `None` for manual codes.
    pub discovery_capabilities: Option<u8>,
    /// 12-bit discriminator. For manual codes only the top 4 bits ("short
    /// discriminator") are known; the lower 8 bits are zero and the
    /// commissioner must filter BLE adverts by the matching short value.
    pub discriminator: u16,
    /// Whether `discriminator` is the full 12-bit value or just the
    /// 4-bit short form padded with zeros.
    pub short_discriminator: bool,
    /// 27-bit setup passcode for PASE Spake2+ verifier derivation.
    pub passcode: u32,
}

/// Errors returned by setup-code parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupCodeError {
    /// Input string had the wrong length after dash-stripping.
    /// Manual codes are 11 digits; QR codes start with `MT:` and have
    /// at least one base-38 character.
    BadLength,
    /// Manual code contained non-digit characters.
    NonDigit,
    /// Verhoeff check digit didn't match the body.
    BadChecksum,
    /// Decoded passcode is in the reserved set (00000000, 11111111, …,
    /// 12345678, 87654321) — spec §5.1.7 forbids commissioning these.
    InvalidPasscode,
    /// QR payload didn't start with the `MT:` prefix.
    NotAQrCode,
    /// QR payload decoding is not yet wired up in this build.
    QrNotSupported,
}

/// Strip dashes from a pretty-formatted pairing code (`1234-567-8910` →
/// `12345678910`).
fn strip_dashes_inplace(input: &str, buf: &mut heapless::String<13>) {
    for ch in input.chars() {
        if ch != '-' && ch != ' ' {
            let _ = buf.push(ch);
        }
    }
}

/// Decode an 11-digit manual pairing code (with or without dashes).
///
/// The packing (mirror of [`crate::pairing::code`]):
/// - digit\[0\] holds: bit 7 = `VID_PID_PRESENT` flag, bits 0-1 = top 2
///   bits of the short discriminator. (The current rs-matter encoder
///   always emits `VID_PID_PRESENT = 0`; if a peer accessory carries
///   VID/PID via a 21-digit code, that's not yet supported here.)
/// - digits\[1..6\] hold a 16-bit value: bits 14-15 = next 2 bits of the
///   short discriminator, bits 0-13 = low 14 bits of the passcode.
/// - digits\[6..10\] hold a 4-digit decimal value = passcode >> 14.
/// - digit\[10\] = Verhoeff check over the first 10 digits.
///
/// Reserved passcodes per §5.1.7 are rejected.
pub fn parse_manual_pairing_code(input: &str) -> Result<SetupPayload, SetupCodeError> {
    let mut stripped: heapless::String<13> = heapless::String::new();
    strip_dashes_inplace(input, &mut stripped);
    let digits = stripped.as_str();

    if digits.len() != 11 {
        return Err(SetupCodeError::BadLength);
    }
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(SetupCodeError::NonDigit);
    }

    // Verhoeff check over the first 10 digits, last digit must match.
    let body = &digits[..10];
    let provided_check = digits.as_bytes()[10] - b'0';
    if body.calculate_verhoeff_check_digit() != provided_check {
        return Err(SetupCodeError::BadChecksum);
    }

    // Parse each field.
    let d0: u8 = body[..1].parse().map_err(|_| SetupCodeError::NonDigit)?;
    let d1_5: u16 = body[1..6].parse().map_err(|_| SetupCodeError::NonDigit)?;
    let d6_9: u32 = body[6..10].parse().map_err(|_| SetupCodeError::NonDigit)?;

    // d0: bits 0-1 = top 2 bits of short discriminator; bit 2 reserved /
    // VID-PID-present flag.
    let disc_hi2 = (d0 & 0x03) as u16; // bits going into discriminator[2..4]
    let vid_pid_present = (d0 & 0x04) != 0;
    if vid_pid_present {
        // 21-digit codes carry VID + PID after the first 11 — not yet
        // wired in this build.
        return Err(SetupCodeError::QrNotSupported);
    }

    // d1_5: top 2 bits = next 2 of short discriminator; bottom 14 bits =
    // passcode low 14 bits.
    let disc_lo2 = ((d1_5 >> 14) & 0x03) as u16;
    let passcode_lo14 = (d1_5 & 0x3FFF) as u32;

    // d6_9: top 13 bits of the 27-bit passcode.
    let passcode_hi13 = d6_9;

    // Short discriminator: 4 bits, layout [hi2 | lo2].
    let short_disc = (disc_hi2 << 2) | disc_lo2;

    // Manual code only knows the short discriminator — emit it in the
    // top 4 bits of a 12-bit value (the rest are zeros, meaning "unknown
    // — match the top-4-bit short discriminator during BLE scan").
    let discriminator = short_disc << 8;

    let passcode = (passcode_hi13 << 14) | passcode_lo14;

    if is_reserved_passcode(passcode) {
        return Err(SetupCodeError::InvalidPasscode);
    }

    Ok(SetupPayload {
        version: 0,
        vendor_id: None,
        product_id: None,
        commissioning_flow: None,
        discovery_capabilities: None,
        discriminator,
        short_discriminator: true,
        passcode,
    })
}

/// Decode a QR-code onboarding payload string (`MT:...`).
///
/// Not yet implemented — base-38 decoding + bit-packed field extraction
/// is the inverse of [`crate::pairing::qr::QrPayload`] and tracked for
/// a follow-up commit. Manual codes are sufficient for most "scan with
/// your phone and type the code" UX flows; full QR support adds VID/PID,
/// full 12-bit discriminator, and the discovery-capabilities bitmap.
pub fn parse_qr_payload(input: &str) -> Result<SetupPayload, SetupCodeError> {
    if !input.starts_with("MT:") {
        return Err(SetupCodeError::NotAQrCode);
    }
    Err(SetupCodeError::QrNotSupported)
}

/// Auto-detect the input shape (digits → manual code; `MT:` prefix → QR)
/// and dispatch to the right parser.
pub fn parse_setup_code(input: &str) -> Result<SetupPayload, SetupCodeError> {
    if input.starts_with("MT:") {
        parse_qr_payload(input)
    } else {
        parse_manual_pairing_code(input)
    }
}

/// Spec §5.1.7 — these passcodes are forbidden for commissioning even
/// though they decode cleanly, to discourage trivial PINs on shipped
/// devices.
fn is_reserved_passcode(p: u32) -> bool {
    matches!(
        p,
        0 | 11111111
            | 22222222
            | 33333333
            | 44444444
            | 55555555
            | 66666666
            | 77777777
            | 88888888
            | 99999999
            | 12345678
            | 87654321
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_rs_matter_example_1() {
        // From `crate::pairing::code::tests::can_compute_pairing_code` —
        // password=123456, discriminator=250 → "00876800071".
        // Our parser sees only the short (top 4 bits) of the discriminator,
        // which is (250 >> 8) & 0xF = 0, so the reconstructed short
        // value is 0 and the 12-bit field is 0 << 8 = 0.
        let p = parse_manual_pairing_code("00876800071").unwrap();
        assert_eq!(p.passcode, 123456);
        assert!(p.short_discriminator);
        // 12-bit field, with short value in top 4 bits.
        // For disc=250: top 4 bits of 12-bit disc = 250 >> 8 = 0.
        assert_eq!(p.discriminator, 0);
    }

    #[test]
    fn round_trip_rs_matter_example_2() {
        // password=34567890, discriminator=2976 → "26318621095".
        let p = parse_manual_pairing_code("26318621095").unwrap();
        assert_eq!(p.passcode, 34567890);
        // disc=2976 = 0xBA0, top 4 bits = 0xB.
        assert_eq!(p.discriminator >> 8, 0x0B);
    }

    #[test]
    fn accepts_dashed_pretty_form() {
        // `0087-6800-071` is the dashed form of "00876800071".
        let p = parse_manual_pairing_code("0087-6800-071").unwrap();
        assert_eq!(p.passcode, 123456);
    }

    #[test]
    fn rejects_bad_checksum() {
        // Flip the last digit (Verhoeff check).
        let r = parse_manual_pairing_code("00876800072");
        assert_eq!(r, Err(SetupCodeError::BadChecksum));
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(parse_manual_pairing_code("12345"), Err(SetupCodeError::BadLength));
        assert_eq!(
            parse_manual_pairing_code("123456789012"),
            Err(SetupCodeError::BadLength)
        );
    }

    #[test]
    fn rejects_non_digit() {
        assert_eq!(
            parse_manual_pairing_code("abcdefghijk"),
            Err(SetupCodeError::NonDigit)
        );
    }

    #[test]
    fn qr_not_yet_supported_returns_clear_error() {
        assert_eq!(
            parse_qr_payload("MT:Y.K9042C00KA0648G00"),
            Err(SetupCodeError::QrNotSupported)
        );
    }

    #[test]
    fn parse_setup_code_dispatches_correctly() {
        // Manual path works.
        assert!(parse_setup_code("00876800071").is_ok());
        // QR path errors with the right reason.
        assert_eq!(
            parse_setup_code("MT:Y.K9042C00KA0648G00"),
            Err(SetupCodeError::QrNotSupported)
        );
    }
}
