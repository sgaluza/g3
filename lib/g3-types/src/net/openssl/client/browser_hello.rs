/*
 * SPDX-License-Identifier: Apache-2.0
 */

//! Fields of the browser ClientHello that the interception client copies
//! to the upstream ClientHello when `mirror_client_hello` is enabled

use std::fmt;

use anyhow::anyhow;

const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_SIGNED_CERT_TIMESTAMP: u16 = 0x0012;
pub(super) const EXT_PRE_SHARED_KEY: u16 = 0x0029;

/// Extensions that differ between connections of one browser build
const PER_CONNECTION_EXTENSIONS: [u16; 7] = [
    0x0000, // server_name, absent for IP hosts
    0x0010, // ALPN
    0x0015, // padding
    EXT_PRE_SHARED_KEY,
    0x002a, // early_data
    EXT_ALPS_OLD,
    EXT_ALPS_NEW,
];

/// Bytes of the sha256 in `profile_key`: 12 hex characters
const PROFILE_KEY_BYTES: usize = 6;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_ALPS_OLD: u16 = 0x4469;
const EXT_ALPS_NEW: u16 = 0x44cd;
pub(super) const EXT_TRUST_ANCHORS: u16 = 0xca34;
const EXT_ECH: u16 = 0xfe0d;

/// RFC 8701 GREASE value: 0x?A?A with equal bytes
pub(super) fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
}

/// What the upstream ClientHello takes from the browser one, GREASE values removed
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BrowserClientHello {
    /// Cipher suites in wire order
    pub cipher_suites: Vec<u16>,
    /// supported_groups in wire order
    pub groups: Vec<u16>,
    /// Groups of the key_share entries in wire order
    pub key_share_groups: Vec<u16>,
    /// signature_algorithms in wire order
    pub signature_algorithms: Vec<u16>,
    /// ALPS protocols, if the browser sent ALPS
    pub alps_protocols: Vec<Vec<u8>>,
    /// ALPS uses the new codepoint 0x44cd instead of 0x4469
    pub alps_new_codepoint: bool,
    /// An encrypted_client_hello extension (GREASE or real) is present
    pub ech: bool,
    /// trust_anchors body without the outer length, if present
    pub trust_anchors: Option<Vec<u8>>,
    pub status_request: bool,
    pub signed_cert_timestamps: bool,
    /// The browser uses GREASE (seen in cipher suites, groups, sigalgs or extensions)
    pub grease: bool,
    /// Extension types in wire order
    pub extensions: Vec<u16>,
}

/// Body of a list prefixed by a 16-bit length, which must fill `data` exactly
fn u16_prefixed<'a>(data: &'a [u8], what: &str) -> anyhow::Result<&'a [u8]> {
    if data.len() < 2 {
        return Err(anyhow!("{what}: no list length"));
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() != 2 + len {
        return Err(anyhow!(
            "{what}: list length {len} does not match body of {} bytes",
            data.len() - 2
        ));
    }
    Ok(&data[2..])
}

impl BrowserClientHello {
    /// The browser resumes a session of its own (sends pre_shared_key)
    pub fn resumes_session(&self) -> bool {
        self.extensions.contains(&EXT_PRE_SHARED_KEY)
    }

    /// Short key of the browser build, the same for all its connections: a hash
    /// of cipher suites and extension types (sorted, as Chrome permutes them),
    /// signature algorithms and groups (in order). Extensions that depend on the
    /// connection are left out: server_name, ALPN, ALPS (only with h2 in ALPN),
    /// padding, pre_shared_key and early_data.
    pub fn profile_key(&self) -> String {
        let mut suites = self.cipher_suites.clone();
        suites.sort_unstable();
        let mut extensions: Vec<u16> = self
            .extensions
            .iter()
            .copied()
            .filter(|t| !PER_CONNECTION_EXTENSIONS.contains(t))
            .collect();
        extensions.sort_unstable();

        let mut canonical = Vec::new();
        for (tag, list) in [
            (b'c', &suites),
            (b'e', &extensions),
            (b's', &self.signature_algorithms),
            (b'g', &self.groups),
        ] {
            canonical.push(tag);
            canonical.extend_from_slice(&(list.len() as u16).to_be_bytes());
            for v in list {
                canonical.extend_from_slice(&v.to_be_bytes());
            }
        }
        openssl::sha::sha256(&canonical)[..PROFILE_KEY_BYTES]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Parse from the cipher_suites body and the extensions body (both without
    /// their outer length prefix) of a ClientHello
    pub fn parse(cipher_suites: &[u8], extensions: Option<&[u8]>) -> anyhow::Result<Self> {
        let mut hello = BrowserClientHello::default();
        hello.cipher_suites = hello.u16_values(cipher_suites, "cipher suites")?;

        let mut data = extensions.unwrap_or_default();
        while !data.is_empty() {
            if data.len() < 4 {
                return Err(anyhow!("truncated extension header"));
            }
            let ext_type = u16::from_be_bytes([data[0], data[1]]);
            let len = u16::from_be_bytes([data[2], data[3]]) as usize;
            let Some(body) = data.get(4..4 + len) else {
                return Err(anyhow!(
                    "extension {ext_type:04x}: length {len} past the end of extensions"
                ));
            };
            data = &data[4 + len..];
            if is_grease(ext_type) {
                hello.grease = true;
                continue;
            }
            hello.parse_extension(ext_type, body)?;
            hello.extensions.push(ext_type);
        }
        Ok(hello)
    }

    fn parse_extension(&mut self, ext_type: u16, body: &[u8]) -> anyhow::Result<()> {
        match ext_type {
            EXT_SUPPORTED_GROUPS => {
                let list = u16_prefixed(body, "supported_groups")?;
                self.groups = self.u16_values(list, "supported_groups")?;
            }
            EXT_SIGNATURE_ALGORITHMS => {
                let list = u16_prefixed(body, "signature_algorithms")?;
                self.signature_algorithms = self.u16_values(list, "signature_algorithms")?;
            }
            EXT_KEY_SHARE => {
                let mut list = u16_prefixed(body, "key_share")?;
                while !list.is_empty() {
                    if list.len() < 4 {
                        return Err(anyhow!("key_share: truncated entry"));
                    }
                    let group = u16::from_be_bytes([list[0], list[1]]);
                    let key_len = u16::from_be_bytes([list[2], list[3]]) as usize;
                    if list.len() < 4 + key_len {
                        return Err(anyhow!("key_share: key of group {group:04x} truncated"));
                    }
                    list = &list[4 + key_len..];
                    if is_grease(group) {
                        self.grease = true;
                    } else {
                        self.key_share_groups.push(group);
                    }
                }
            }
            EXT_ALPS_OLD | EXT_ALPS_NEW => {
                let mut list = u16_prefixed(body, "application_settings")?;
                // BoringSSL sends ALPS on one codepoint only: with both, the last one wins
                let mut protocols = Vec::new();
                while let Some((&len, rest)) = list.split_first() {
                    let len = len as usize;
                    if len == 0 || rest.len() < len {
                        return Err(anyhow!("application_settings: broken protocol name"));
                    }
                    protocols.push(rest[..len].to_vec());
                    list = &rest[len..];
                }
                self.alps_protocols = protocols;
                self.alps_new_codepoint = ext_type == EXT_ALPS_NEW;
            }
            EXT_TRUST_ANCHORS => {
                let ids = u16_prefixed(body, "trust_anchors")?;
                self.trust_anchors = Some(ids.to_vec());
            }
            EXT_ECH => self.ech = true,
            EXT_STATUS_REQUEST => self.status_request = true,
            EXT_SIGNED_CERT_TIMESTAMP => self.signed_cert_timestamps = true,
            _ => {}
        }
        Ok(())
    }

    /// u16 values in wire order; GREASE values are skipped and noted
    fn u16_values(&mut self, data: &[u8], what: &str) -> anyhow::Result<Vec<u16>> {
        if data.len() & 1 != 0 {
            return Err(anyhow!("{what}: odd length {}", data.len()));
        }
        let mut values = Vec::with_capacity(data.len() / 2);
        for c in data.chunks_exact(2) {
            let v = u16::from_be_bytes([c[0], c[1]]);
            if is_grease(v) {
                self.grease = true;
            } else {
                values.push(v);
            }
        }
        Ok(values)
    }
}

/// What could not be copied from the browser ClientHello
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MirrorReport {
    pub dropped_cipher_suites: Vec<u16>,
    pub dropped_groups: Vec<u16>,
    pub dropped_key_share_groups: Vec<u16>,
    pub dropped_signature_algorithms: Vec<u16>,
    /// Browser extensions the upstream ClientHello can't carry
    pub unsupported_extensions: Vec<u16>,
    /// Fields where nothing usable was left and the static config was used
    pub fallback: Vec<&'static str>,
    /// GREASE use of the browser differs from the enable_grease config
    pub grease_mismatch: bool,
    /// Copying failed and the static ClientHello was sent instead
    pub mirror_error: Option<String>,
}

impl MirrorReport {
    pub fn is_empty(&self) -> bool {
        *self == MirrorReport::default()
    }
}

impl fmt::Display for MirrorReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        let lists = [
            ("dropped cipher suites", &self.dropped_cipher_suites),
            ("dropped groups", &self.dropped_groups),
            ("dropped key shares", &self.dropped_key_share_groups),
            (
                "dropped signature algorithms",
                &self.dropped_signature_algorithms,
            ),
            ("unsupported extensions", &self.unsupported_extensions),
        ];
        for (name, values) in lists {
            if !values.is_empty() {
                let values: Vec<String> = values.iter().map(|v| format!("{v:04x}")).collect();
                parts.push(format!("{name}: {}", values.join(",")));
            }
        }
        if !self.fallback.is_empty() {
            parts.push(format!("static fallback: {}", self.fallback.join(",")));
        }
        if self.grease_mismatch {
            parts.push("GREASE use differs from enable_grease".to_string());
        }
        if let Some(e) = &self.mirror_error {
            parts.push(format!("mirror failed, static ClientHello sent: {e}"));
        }
        f.write_str(&parts.join("; "))
    }
}
