/*
 * SPDX-License-Identifier: Apache-2.0
 */

//! Per-connection BoringSSL settings of the upstream ClientHello: the static ones
//! of the interception client config and the ones copied from the browser ClientHello

use std::ffi::{CStr, CString};

use anyhow::anyhow;
use openssl::foreign_types::ForeignTypeRef;
use openssl::ssl::Ssl;

use super::browser_hello::EXT_TRUST_ANCHORS;
use super::{BrowserClientHello, MirrorReport};
use crate::net::TlsAlpn;

/// HTTP/2 SETTINGS payload that Chrome puts into ALPS for h2, the same
/// settings the h2 interception client sends with the chrome profile
const CHROME_H2_ALPS_SETTINGS: [u8; 24] = crate::net::ChromeH2Settings::settings_payload();

/// Extensions the upstream ClientHello sends when the browser does
/// (some always, some by the settings copied here)
const SUPPORTED_EXTENSIONS: [u16; 22] = [
    0x0000, // server_name
    0x0005, // status_request
    0x000a, // supported_groups
    0x000b, // ec_point_formats
    0x000d, // signature_algorithms
    0x0010, // application_layer_protocol_negotiation
    0x0012, // signed_certificate_timestamp
    0x0015, // padding
    0x0017, // extended_master_secret
    0x001b, // compress_certificate
    0x0023, // session_ticket
    0x0029, // pre_shared_key
    0x002b, // supported_versions
    0x002c, // cookie
    0x002d, // psk_key_exchange_modes
    0x0033, // key_share
    0x4469, // application_settings (old codepoint)
    0x44cd, // application_settings
    0xca34, // trust_anchors
    0xfe0d, // encrypted_client_hello
    0xff01, // renegotiation_info
    0x0031, // post_handshake_auth
];

const TLS1_3_VERSION: u16 = 0x0304;

/// TLS_EMPTY_RENEGOTIATION_INFO_SCSV and TLS_FALLBACK_SCSV, added by the library itself
const SIGNALING_CIPHER_SUITES: [u16; 2] = [0x00ff, 0x5600];

/// Add ALPS for `proto` (with Chrome's h2 SETTINGS for h2, empty otherwise)
pub(super) fn add_application_settings(
    ssl: &mut Ssl,
    proto: &[u8],
    new_codepoint: bool,
) -> anyhow::Result<()> {
    let settings: &[u8] = if proto == b"h2" {
        &CHROME_H2_ALPS_SETTINGS
    } else {
        &[]
    };
    let ssl_ptr = ssl.as_ptr();
    // SAFETY: ssl_ptr is valid, BoringSSL copies both buffers before returning
    let r = unsafe {
        openssl_sys::SSL_add_application_settings(
            ssl_ptr,
            proto.as_ptr(),
            proto.len(),
            settings.as_ptr(),
            settings.len(),
        )
    };
    if r != 1 {
        return Err(anyhow!(
            "failed to add application settings for {}",
            String::from_utf8_lossy(proto)
        ));
    }
    // SAFETY: ssl_ptr is a valid SSL owned by `ssl` for the whole call
    unsafe { openssl_sys::SSL_set_alps_use_new_codepoint(ssl_ptr, new_codepoint as _) };
    Ok(())
}

/// Check the wire format of a trust anchor ID list: a series of IDs, each
/// prefixed by an 8-bit length, no empty ID, no ID past the end of the list
pub(super) fn validate_trust_anchor_ids(ids: &[u8]) -> anyhow::Result<()> {
    let mut offset = 0usize;
    while offset < ids.len() {
        let len = ids[offset] as usize;
        if len == 0 {
            return Err(anyhow!(
                "invalid trust_anchor_ids: empty ID at byte offset {offset}"
            ));
        }
        let left = ids.len() - offset - 1;
        if len > left {
            return Err(anyhow!(
                "invalid trust_anchor_ids: ID at byte offset {offset} needs {len} bytes, only {left} left"
            ));
        }
        offset += 1 + len;
    }
    Ok(())
}

/// Request these trust anchor IDs (wire format) in the trust_anchors extension;
/// BoringSSL doesn't check the list, a broken one makes peers abort the handshake
pub(super) fn set_trust_anchors(ssl: &mut Ssl, ids: &[u8]) -> anyhow::Result<()> {
    // SAFETY: the pointer is a valid SSL, BoringSSL copies the buffer
    let r = unsafe {
        openssl_sys::SSL_set1_requested_trust_anchors(ssl.as_ptr(), ids.as_ptr(), ids.len())
    };
    if r != 1 {
        return Err(anyhow!("invalid trust anchor IDs"));
    }
    Ok(())
}

pub(super) fn enable_ocsp_stapling(ssl: &mut Ssl) {
    // SAFETY: the pointer is a valid SSL owned by `ssl`
    unsafe { openssl_sys::SSL_enable_ocsp_stapling(ssl.as_ptr()) };
}

pub(super) fn enable_signed_cert_timestamps(ssl: &mut Ssl) {
    // SAFETY: the pointer is a valid SSL owned by `ssl`
    unsafe { openssl_sys::SSL_enable_signed_cert_timestamps(ssl.as_ptr()) };
}

pub(super) fn set_ech_grease(ssl: &mut Ssl, enable: bool) {
    // SAFETY: the pointer is a valid SSL owned by `ssl`
    unsafe { openssl_sys::SSL_set_enable_ech_grease(ssl.as_ptr(), enable as _) };
}

/// Probing calls with rejected values leave errors on the thread error queue
fn clear_errors() {
    // SAFETY: only touches the error queue of this thread
    unsafe { openssl_sys::ERR_clear_error() };
}

/// Copy the browser ClientHello to `ssl`. Values BoringSSL doesn't know are
/// dropped; a list with nothing left keeps the static value of the SSL_CTX.
/// `enable_grease` is the static GREASE setting, which only exists on SSL_CTX.
pub(super) fn apply_browser_hello(
    ssl: &mut Ssl,
    alpn_ext: Option<&TlsAlpn>,
    browser: &BrowserClientHello,
    enable_grease: bool,
) -> anyhow::Result<MirrorReport> {
    let mut report = MirrorReport {
        grease_mismatch: browser.grease != enable_grease,
        ..Default::default()
    };

    set_cipher_suites(ssl, &browser.cipher_suites, &mut report)?;
    let groups = set_groups(ssl, &browser.groups, &mut report)?;
    if groups.is_empty() {
        // with the static groups the browser key shares can't be sent
        report
            .dropped_key_share_groups
            .extend_from_slice(&browser.key_share_groups);
    } else {
        set_key_shares(ssl, &groups, &browser.key_share_groups, &mut report)?;
    }
    set_signature_algorithms(ssl, &browser.signature_algorithms, &mut report)?;

    let upstream_alpn = |p: &[u8]| alpn_ext.is_some_and(|alpn| alpn.contains(p));
    // BoringSSL would send a repeated protocol twice
    let mut added: Vec<&[u8]> = Vec::new();
    for proto in browser.alps_protocols.iter().filter(|p| upstream_alpn(p)) {
        if added.contains(&proto.as_slice()) {
            continue;
        }
        add_application_settings(ssl, proto, browser.alps_new_codepoint)?;
        added.push(proto);
    }
    set_ech_grease(ssl, browser.ech);
    if let Some(ids) = &browser.trust_anchors {
        if validate_trust_anchor_ids(ids).is_ok() {
            set_trust_anchors(ssl, ids)?;
        } else {
            report.unsupported_extensions.push(EXT_TRUST_ANCHORS);
        }
    }
    if browser.status_request {
        enable_ocsp_stapling(ssl);
    }
    if browser.signed_cert_timestamps {
        enable_signed_cert_timestamps(ssl);
    }

    report.unsupported_extensions.extend(
        browser
            .extensions
            .iter()
            .filter(|t| !SUPPORTED_EXTENSIONS.contains(t)),
    );
    Ok(report)
}

/// TLS 1.2 cipher suites in browser order; TLS 1.3 ones are fixed in BoringSSL
fn set_cipher_suites(
    ssl: &mut Ssl,
    suites: &[u16],
    report: &mut MirrorReport,
) -> anyhow::Result<()> {
    let mut names = Vec::new();
    let mut seen = Vec::with_capacity(suites.len());
    for &id in suites {
        if SIGNALING_CIPHER_SUITES.contains(&id) {
            continue;
        }
        // a repeated value can't be sent twice, so it's dropped as well
        if seen.contains(&id) {
            report.dropped_cipher_suites.push(id);
            continue;
        }
        seen.push(id);
        // SAFETY: a lookup in the static cipher table, no pointer arguments
        let cipher = unsafe { openssl_sys::SSL_get_cipher_by_value(id) };
        if cipher.is_null() {
            report.dropped_cipher_suites.push(id);
            continue;
        }
        // SAFETY: cipher points to the static table
        let min_version = unsafe { openssl_sys::SSL_CIPHER_get_min_version(cipher) };
        // the cipher list doesn't take TLS 1.3 suites, BoringSSL always sends its own
        if min_version >= TLS1_3_VERSION {
            continue;
        }
        // SAFETY: cipher points to the static table, its name is a static C string
        let name = unsafe { CStr::from_ptr(openssl_sys::SSL_CIPHER_get_name(cipher)) };
        names.push(name.to_string_lossy());
    }
    if names.is_empty() {
        report.fallback.push("cipher_suites");
        return Ok(());
    }
    let list =
        CString::new(names.join(":")).map_err(|_| anyhow!("cipher name contains a NUL byte"))?;
    // SAFETY: valid SSL and C string, BoringSSL parses the string before returning
    let r = unsafe { openssl_sys::SSL_set_strict_cipher_list(ssl.as_ptr(), list.as_ptr()) };
    if r != 1 {
        return Err(anyhow!(
            "failed to set cipher list {}",
            list.to_string_lossy()
        ));
    }
    Ok(())
}

/// Set the groups BoringSSL knows, in browser order, and return them
fn set_groups(
    ssl: &mut Ssl,
    groups: &[u16],
    report: &mut MirrorReport,
) -> anyhow::Result<Vec<u16>> {
    let ssl_ptr = ssl.as_ptr();
    let mut known = Vec::with_capacity(groups.len());
    for &g in groups {
        // a repeated value can't be sent twice, so it's dropped as well
        // SAFETY: valid SSL, a one element array; an unknown group is rejected
        let ok =
            !known.contains(&g) && unsafe { openssl_sys::SSL_set1_group_ids(ssl_ptr, &g, 1) } == 1;
        if ok {
            known.push(g);
        } else {
            report.dropped_groups.push(g);
        }
    }
    clear_errors();
    if known.is_empty() {
        report.fallback.push("supported_groups");
        return Ok(known);
    }
    // SAFETY: valid SSL and array of `known.len()` elements
    let r = unsafe { openssl_sys::SSL_set1_group_ids(ssl_ptr, known.as_ptr(), known.len()) };
    if r != 1 {
        return Err(anyhow!("failed to set groups {known:04x?}"));
    }
    Ok(known)
}

/// Send key shares for the browser key_share groups. RFC 8446 §4.2.8 wants them in
/// the supported_groups order and BoringSSL checks it (`validate_key_shares`), so
/// entries out of that order are dropped rather than reordered
fn set_key_shares(
    ssl: &mut Ssl,
    groups: &[u16],
    key_shares: &[u16],
    report: &mut MirrorReport,
) -> anyhow::Result<()> {
    let mut shares = Vec::with_capacity(key_shares.len());
    let mut next = 0;
    for &g in key_shares {
        match groups[next..].iter().position(|v| *v == g) {
            Some(i) => {
                shares.push(g);
                next += i + 1;
            }
            None => report.dropped_key_share_groups.push(g),
        }
    }
    if shares.is_empty() {
        return Ok(());
    }
    // SAFETY: valid SSL and array of `shares.len()` elements, groups already set
    let r = unsafe {
        openssl_sys::SSL_set1_client_key_shares(ssl.as_ptr(), shares.as_ptr(), shares.len())
    };
    if r != 1 {
        return Err(anyhow!("failed to set key shares {shares:04x?}"));
    }
    Ok(())
}

/// Signature algorithms of the ClientHello, which BoringSSL takes from the verify prefs
fn set_signature_algorithms(
    ssl: &mut Ssl,
    sigalgs: &[u16],
    report: &mut MirrorReport,
) -> anyhow::Result<()> {
    let ssl_ptr = ssl.as_ptr();
    let mut known = Vec::with_capacity(sigalgs.len());
    for &s in sigalgs {
        // a repeated value can't be sent twice, so it's dropped as well
        // SAFETY: valid SSL, a one element array; an unknown algorithm is rejected
        let ok = !known.contains(&s)
            && unsafe { openssl_sys::SSL_set_verify_algorithm_prefs(ssl_ptr, &s, 1) } == 1;
        if ok {
            known.push(s);
        } else {
            report.dropped_signature_algorithms.push(s);
        }
    }
    clear_errors();
    if known.is_empty() {
        report.fallback.push("signature_algorithms");
        return Ok(());
    }
    // SAFETY: valid SSL and array of `known.len()` elements
    let r = unsafe {
        openssl_sys::SSL_set_verify_algorithm_prefs(ssl_ptr, known.as_ptr(), known.len())
    };
    if r != 1 {
        return Err(anyhow!("failed to set signature algorithms {known:04x?}"));
    }
    Ok(())
}
