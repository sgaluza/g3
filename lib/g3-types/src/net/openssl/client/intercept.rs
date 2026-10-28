/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::time::Duration;

use anyhow::anyhow;
use log::warn;
use openssl::ssl::{Ssl, SslConnector, SslContext, SslContextBuilder, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use openssl::x509::store::X509StoreBuilder;

use super::{
    DEFAULT_HANDSHAKE_TIMEOUT, MINIMAL_HANDSHAKE_TIMEOUT, OpensslClientSessionCache,
    OpensslSessionCacheConfig,
};
use crate::net::{TlsAlpn, TlsServerName, TlsVersion, UpstreamAddr};

/// HTTP/2 SETTINGS payload that Chrome puts into ALPS for h2, the same
/// settings the h2 interception client sends with the chrome profile
#[cfg(boringssl)]
const CHROME_H2_ALPS_SETTINGS: [u8; 24] = crate::net::ChromeH2Settings::settings_payload();

#[derive(Clone)]
struct ContextPair {
    ssl_context: SslContext,
    session_cache: Option<OpensslClientSessionCache>,
    #[cfg(boringssl)]
    enable_ech_grease: bool,
    #[cfg(boringssl)]
    enable_alps: bool,
}

impl ContextPair {
    /// Per-connection BoringSSL options that can't be set on SslContext:
    /// GREASE ECH and ALPS for h2 (new codepoint, as current Chrome does)
    #[cfg(boringssl)]
    fn set_browser_extensions(
        &self,
        ssl: &mut Ssl,
        alpn_ext: Option<&TlsAlpn>,
    ) -> anyhow::Result<()> {
        use openssl::foreign_types::ForeignTypeRef;

        let ssl_ptr = ssl.as_ptr();
        if self.enable_ech_grease {
            // SAFETY: ssl_ptr is a valid SSL owned by `ssl` for the whole call
            unsafe { openssl_sys::SSL_set_enable_ech_grease(ssl_ptr, 1) };
        }

        let offers_h2 = alpn_ext.is_some_and(|alpn| alpn.contains(b"h2"));
        if self.enable_alps && offers_h2 {
            let proto = b"h2";
            // SAFETY: ssl_ptr is valid, BoringSSL copies both buffers before returning
            let r = unsafe {
                openssl_sys::SSL_add_application_settings(
                    ssl_ptr,
                    proto.as_ptr(),
                    proto.len(),
                    CHROME_H2_ALPS_SETTINGS.as_ptr(),
                    CHROME_H2_ALPS_SETTINGS.len(),
                )
            };
            if r != 1 {
                return Err(anyhow!("failed to add h2 application settings"));
            }
            // SAFETY: ssl_ptr is a valid SSL owned by `ssl` for the whole call
            unsafe { openssl_sys::SSL_set_alps_use_new_codepoint(ssl_ptr, 1) };
        }
        Ok(())
    }

    pub fn build_ssl(
        &self,
        server_name: Option<&TlsServerName>,
        upstream: &UpstreamAddr,
        alpn_ext: Option<&TlsAlpn>,
    ) -> anyhow::Result<Ssl> {
        let mut ssl =
            Ssl::new(&self.ssl_context).map_err(|e| anyhow!("failed to get new Ssl state: {e}"))?;
        if let Some(name) = server_name {
            let verify_param = ssl.param_mut();
            verify_param
                .set_host(name.as_ref())
                .map_err(|e| anyhow!("failed to set cert verify domain: {e}"))?;
            ssl.set_hostname(name.as_ref())
                .map_err(|e| anyhow!("failed to set sni hostname: {e}"))?;
        }
        if let Some(cache) = &self.session_cache {
            cache.find_and_set_cache(&mut ssl, upstream.host(), upstream.port())?;
        }
        if let Some(v) = alpn_ext {
            ssl.set_alpn_protos(v.wired_list_sequence())
                .map_err(|e| anyhow!("failed to set alpn protocols: {e}"))?;
        }
        #[cfg(boringssl)]
        self.set_browser_extensions(&mut ssl, alpn_ext)?;
        Ok(ssl)
    }
}

#[derive(Clone)]
pub struct OpensslInterceptionClientConfig {
    ssl_context_pair: ContextPair,
    #[cfg(tongsuo)]
    tlcp_context_pair: ContextPair,
    pub insecure: bool,
    pub handshake_timeout: Duration,
}

impl OpensslInterceptionClientConfig {
    pub fn build_ssl(
        &self,
        server_name: Option<&TlsServerName>,
        upstream: &UpstreamAddr,
        alpn_ext: Option<&TlsAlpn>,
    ) -> anyhow::Result<Ssl> {
        self.ssl_context_pair
            .build_ssl(server_name, upstream, alpn_ext)
    }

    #[cfg(tongsuo)]
    pub fn build_tlcp(
        &self,
        server_name: Option<&TlsServerName>,
        upstream: &UpstreamAddr,
        alpn_ext: Option<&TlsAlpn>,
    ) -> anyhow::Result<Ssl> {
        self.tlcp_context_pair
            .build_ssl(server_name, upstream, alpn_ext)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpensslInterceptionClientConfigBuilder {
    min_tls_version: Option<TlsVersion>,
    max_tls_version: Option<TlsVersion>,
    ca_certs: Vec<Vec<u8>>,
    no_default_ca_certs: bool,
    handshake_timeout: Duration,
    session_cache: OpensslSessionCacheConfig,
    supported_groups: String,
    use_ocsp_stapling: bool,
    #[cfg(not(libressl))]
    enable_sct: bool,
    #[cfg(any(awslc, boringssl))]
    enable_grease: bool,
    #[cfg(any(awslc, boringssl))]
    permute_extensions: bool,
    cipher_list: String,
    #[cfg(boringssl)]
    enable_ech_grease: bool,
    #[cfg(boringssl)]
    enable_alps: bool,
    insecure: bool,
}

impl Default for OpensslInterceptionClientConfigBuilder {
    fn default() -> Self {
        OpensslInterceptionClientConfigBuilder {
            min_tls_version: None,
            max_tls_version: None,
            ca_certs: Vec::new(),
            no_default_ca_certs: false,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            session_cache: OpensslSessionCacheConfig::new_for_many(),
            supported_groups: String::default(),
            use_ocsp_stapling: false,
            #[cfg(not(libressl))]
            enable_sct: false,
            #[cfg(any(awslc, boringssl))]
            enable_grease: false,
            #[cfg(any(awslc, boringssl))]
            permute_extensions: false,
            cipher_list: String::default(),
            #[cfg(boringssl)]
            enable_ech_grease: false,
            #[cfg(boringssl)]
            enable_alps: false,
            insecure: false,
        }
    }
}

impl OpensslInterceptionClientConfigBuilder {
    pub fn check(&mut self) -> anyhow::Result<()> {
        if self.handshake_timeout < MINIMAL_HANDSHAKE_TIMEOUT {
            self.handshake_timeout = MINIMAL_HANDSHAKE_TIMEOUT;
        }

        Ok(())
    }

    pub fn set_min_tls_version(&mut self, version: TlsVersion) {
        self.min_tls_version = Some(version);
    }

    pub fn set_max_tls_version(&mut self, version: TlsVersion) {
        self.max_tls_version = Some(version);
    }

    pub fn set_ca_certificates(&mut self, certs: Vec<X509>) -> anyhow::Result<()> {
        let mut all_der = Vec::with_capacity(certs.len());
        for (i, cert) in certs.into_iter().enumerate() {
            let bytes = cert
                .to_der()
                .map_err(|e| anyhow!("failed to encode ca certificate #{i}: {e}"))?;
            all_der.push(bytes);
        }
        self.ca_certs = all_der;
        Ok(())
    }

    pub fn set_no_default_ca_certificates(&mut self) {
        self.no_default_ca_certs = true;
    }

    pub fn set_handshake_timeout(&mut self, timeout: Duration) {
        self.handshake_timeout = timeout;
    }

    #[inline]
    pub fn set_no_session_cache(&mut self) {
        self.session_cache.set_no_session_cache();
    }

    #[inline]
    pub fn set_session_cache_sites_count(&mut self, max: usize) {
        self.session_cache.set_sites_count(max);
    }

    #[inline]
    pub fn set_session_cache_each_capacity(&mut self, cap: usize) {
        self.session_cache.set_each_capacity(cap);
    }

    #[inline]
    pub fn set_supported_groups(&mut self, groups: String) {
        self.supported_groups = groups;
    }

    #[inline]
    pub fn set_use_ocsp_stapling(&mut self, enable: bool) {
        self.use_ocsp_stapling = enable;
    }

    #[inline]
    #[cfg(not(libressl))]
    pub fn set_enable_sct(&mut self, enable: bool) {
        self.enable_sct = enable;
    }

    #[inline]
    #[cfg(libressl)]
    pub fn set_enable_sct(&mut self, _enable: bool) {
        warn!("SCT can not be enabled for LibreSSL");
    }

    #[inline]
    #[cfg(any(awslc, boringssl))]
    pub fn set_enable_grease(&mut self, enable: bool) {
        self.enable_grease = enable;
    }

    #[cfg(not(any(awslc, boringssl)))]
    pub fn set_enable_grease(&mut self, _enable: bool) {
        warn!("grease can only be set for BoringSSL variants");
    }

    #[cfg(any(awslc, boringssl))]
    pub fn set_permute_extensions(&mut self, enable: bool) {
        self.permute_extensions = enable;
    }

    #[cfg(not(any(awslc, boringssl)))]
    pub fn set_permute_extensions(&mut self, _enable: bool) {
        warn!("permute extensions can only be set for BoringSSL variants");
    }

    /// Cipher list for TLS 1.2 and below, in OpenSSL cipher string format
    #[inline]
    pub fn set_cipher_list(&mut self, ciphers: String) {
        self.cipher_list = ciphers;
    }

    #[cfg(boringssl)]
    pub fn set_enable_ech_grease(&mut self, enable: bool) {
        self.enable_ech_grease = enable;
    }

    #[cfg(not(boringssl))]
    pub fn set_enable_ech_grease(&mut self, _enable: bool) {
        warn!("ECH GREASE can only be set for BoringSSL");
    }

    /// Send ALPS (application_settings) with Chrome's HTTP/2 SETTINGS when h2 is offered
    #[cfg(boringssl)]
    pub fn set_enable_alps(&mut self, enable: bool) {
        self.enable_alps = enable;
    }

    #[cfg(not(boringssl))]
    pub fn set_enable_alps(&mut self, _enable: bool) {
        warn!("ALPS can only be set for BoringSSL");
    }

    pub fn set_insecure(&mut self, enable: bool) {
        self.insecure = enable;
    }

    fn set_verify(&self, builder: &mut SslContextBuilder) {
        if self.insecure {
            warn!(
                "Tls Insecure Mode: Tls Peer (server) cert vertification is no longer enforced for this Context!"
            );
            builder.set_verify(SslVerifyMode::NONE);
        } else {
            builder.set_verify(SslVerifyMode::PEER);
        }
    }

    fn build_set_tls_version(&self, ctx_builder: &mut SslContextBuilder) -> anyhow::Result<()> {
        if let Some(version) = self.min_tls_version {
            ctx_builder
                .set_min_proto_version(Some(version.into()))
                .map_err(|e| anyhow!("failed to set min ssl version to {version}: {e}"))?;
        }
        if let Some(version) = self.max_tls_version {
            ctx_builder
                .set_max_proto_version(Some(version.into()))
                .map_err(|e| anyhow!("failed to set max ssl version to {version}: {e}"))?;
        }
        Ok(())
    }

    fn build_set_cipher_list(&self, ctx_builder: &mut SslContextBuilder) -> anyhow::Result<()> {
        if !self.cipher_list.is_empty() {
            ctx_builder
                .set_cipher_list(&self.cipher_list)
                .map_err(|e| anyhow!("failed to set cipher list: {e}"))?;
        }
        Ok(())
    }

    fn build_set_verify_cert_store(
        &self,
        ctx_builder: &mut SslContextBuilder,
    ) -> anyhow::Result<()> {
        let mut store_builder = X509StoreBuilder::new()
            .map_err(|e| anyhow!("failed to create ca cert store builder: {e}"))?;
        if !self.no_default_ca_certs {
            store_builder
                .set_default_paths()
                .map_err(|e| anyhow!("failed to load default ca certs: {e}"))?;
        }
        for (i, cert) in self.ca_certs.iter().enumerate() {
            let ca_cert = X509::from_der(cert.as_slice()).unwrap();
            store_builder
                .add_cert(ca_cert)
                .map_err(|e| anyhow!("failed to add ca certificate #{i}: {e}"))?;
        }
        #[cfg(not(libressl))]
        ctx_builder
            .set_verify_cert_store(store_builder.build())
            .map_err(|e| anyhow!("failed to set verify ca certs: {e}"))?;
        #[cfg(libressl)]
        ctx_builder.set_cert_store(store_builder.build());
        Ok(())
    }

    #[cfg(any(awslc, boringssl, tongsuo))]
    fn build_set_cert_compression(
        &self,
        ctx_builder: &mut SslContextBuilder,
    ) -> anyhow::Result<()> {
        use openssl::ssl::CertCompressionAlgorithm;

        ctx_builder
            .add_cert_decompression_alg(CertCompressionAlgorithm::BROTLI, |in_buf, out_buf| {
                use std::io::Read;

                brotli::Decompressor::new(in_buf, 4096)
                    .read(out_buf)
                    .unwrap_or(0)
            })
            .map_err(|e| anyhow!("failed to set brotli cert decompression algorithm: {e}"))?;

        Ok(())
    }

    #[cfg(any(awslc, boringssl))]
    fn build_ssl_context(&self) -> anyhow::Result<ContextPair> {
        let mut ctx_builder = SslConnector::builder(SslMethod::tls_client())
            .map_err(|e| anyhow!("failed to create ssl context builder: {e}"))?;

        self.set_verify(&mut ctx_builder);

        self.build_set_tls_version(&mut ctx_builder)?;

        if !self.supported_groups.is_empty() {
            ctx_builder
                .set_groups_list(&self.supported_groups)
                .map_err(|e| anyhow!("failed to set supported elliptic curve groups: {e}"))?;
        }

        if self.use_ocsp_stapling {
            ctx_builder.enable_ocsp_stapling();
            // TODO check OCSP response
        }

        if self.enable_sct {
            ctx_builder.enable_signed_cert_timestamps();
            // TODO check SCT list for AWS-LC or BoringSSL
        }

        if self.enable_grease {
            ctx_builder.set_grease_enabled(true);
        }
        if self.permute_extensions {
            ctx_builder.set_permute_extensions(true);
        }

        self.build_set_cipher_list(&mut ctx_builder)?;

        self.build_set_cert_compression(&mut ctx_builder)?;

        self.build_set_verify_cert_store(&mut ctx_builder)?;

        let session_cache = self.session_cache.set_for_client(&mut ctx_builder)?;

        Ok(ContextPair {
            ssl_context: ctx_builder.build().into_context(),
            session_cache,
            #[cfg(boringssl)]
            enable_ech_grease: self.enable_ech_grease,
            #[cfg(boringssl)]
            enable_alps: self.enable_alps,
        })
    }

    #[cfg(libressl)]
    fn build_ssl_context(&self) -> anyhow::Result<ContextPair> {
        use openssl::ssl::StatusType;

        let mut ctx_builder = SslConnector::builder(SslMethod::tls_client())
            .map_err(|e| anyhow!("failed to create ssl context builder: {e}"))?;

        self.set_verify(&mut ctx_builder);

        self.build_set_tls_version(&mut ctx_builder)?;

        if !self.supported_groups.is_empty() {
            ctx_builder
                .set_groups_list(&self.supported_groups)
                .map_err(|e| anyhow!("failed to set supported elliptic curve groups: {e}"))?;
        }

        if self.use_ocsp_stapling {
            ctx_builder
                .set_status_type(StatusType::OCSP)
                .map_err(|e| anyhow!("failed to enable OCSP status request: {e}"))?;
            // TODO check OCSP response
        }

        self.build_set_cipher_list(&mut ctx_builder)?;

        self.build_set_verify_cert_store(&mut ctx_builder)?;

        let session_cache = self.session_cache.set_for_client(&mut ctx_builder)?;

        Ok(ContextPair {
            ssl_context: ctx_builder.build().into_context(),
            session_cache,
        })
    }

    #[cfg(not(any(awslc, boringssl, libressl)))]
    fn build_ssl_context(&self) -> anyhow::Result<ContextPair> {
        use openssl::ssl::{SslCtValidationMode, StatusType};

        let mut ctx_builder = SslConnector::builder(SslMethod::tls_client())
            .map_err(|e| anyhow!("failed to create ssl context builder: {e}"))?;

        self.set_verify(&mut ctx_builder);

        self.build_set_tls_version(&mut ctx_builder)?;

        if !self.supported_groups.is_empty() {
            ctx_builder
                .set_groups_list(&self.supported_groups)
                .map_err(|e| anyhow!("failed to set supported elliptic curve groups: {e}"))?;
        }

        if self.use_ocsp_stapling {
            ctx_builder
                .set_status_type(StatusType::OCSP)
                .map_err(|e| anyhow!("failed to enable OCSP status request: {e}"))?;
            // TODO check OCSP response
        }

        if self.enable_sct {
            ctx_builder
                .enable_ct(SslCtValidationMode::PERMISSIVE)
                .map_err(|e| anyhow!("failed to enable SCT: {e}"))?;
        }

        self.build_set_cipher_list(&mut ctx_builder)?;

        #[cfg(tongsuo)]
        self.build_set_cert_compression(&mut ctx_builder)?;

        self.build_set_verify_cert_store(&mut ctx_builder)?;

        let session_cache = self.session_cache.set_for_client(&mut ctx_builder)?;

        Ok(ContextPair {
            ssl_context: ctx_builder.build().into_context(),
            session_cache,
        })
    }

    #[cfg(tongsuo)]
    fn build_tlcp_context(&self) -> anyhow::Result<ContextPair> {
        use openssl::ssl::{SslCtValidationMode, StatusType};

        let mut ctx_builder = SslConnector::builder(SslMethod::ntls_client())
            .map_err(|e| anyhow!("failed to create tlcp context builder: {e}"))?;

        self.set_verify(&mut ctx_builder);

        if !self.supported_groups.is_empty() {
            ctx_builder
                .set_groups_list(&self.supported_groups)
                .map_err(|e| anyhow!("failed to set supported elliptic curve groups: {e}"))?;
        }

        if self.use_ocsp_stapling {
            ctx_builder
                .set_status_type(StatusType::OCSP)
                .map_err(|e| anyhow!("failed to enable OCSP status request: {e}"))?;
            // TODO check OCSP response
        }

        if self.enable_sct {
            ctx_builder
                .enable_ct(SslCtValidationMode::PERMISSIVE)
                .map_err(|e| anyhow!("failed to enable SCT: {e}"))?;
        }

        self.build_set_cert_compression(&mut ctx_builder)?;

        self.build_set_verify_cert_store(&mut ctx_builder)?;

        let session_cache = self.session_cache.set_for_client(&mut ctx_builder)?;

        Ok(ContextPair {
            ssl_context: ctx_builder.build().into_context(),
            session_cache,
        })
    }

    pub fn build(&self) -> anyhow::Result<OpensslInterceptionClientConfig> {
        Ok(OpensslInterceptionClientConfig {
            ssl_context_pair: self.build_ssl_context()?,
            #[cfg(tongsuo)]
            tlcp_context_pair: self.build_tlcp_context()?,
            insecure: self.insecure,
            handshake_timeout: self.handshake_timeout,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};

    use super::*;

    /// TLS 1.2 cipher list sent by Chrome; the library prepends its own TLS 1.3 suites
    const CHROME_CIPHER_LIST: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
        ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
        ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
        ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:\
        AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";

    const CHROME_TLS12_SUITES: [u16; 12] = [
        0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
        0x0035,
    ];

    const EXT_ALPS_NEW_CODEPOINT: u16 = 17613;
    const EXT_ECH: u16 = 0xfe0d;

    /// Stream that records everything written and never yields data,
    /// so the handshake stops right after the ClientHello is sent
    struct ClientHelloRecorder {
        written: Vec<u8>,
    }

    impl Read for ClientHelloRecorder {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    impl Write for ClientHelloRecorder {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct ClientHello {
        cipher_suites: Vec<u16>,
        extensions: Vec<u16>,
    }

    fn is_grease(v: u16) -> bool {
        v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
    }

    fn read_u16(buf: &[u8], offset: usize) -> u16 {
        u16::from_be_bytes([buf[offset], buf[offset + 1]])
    }

    /// TLS_EMPTY_RENEGOTIATION_INFO_SCSV, a signaling value OpenSSL adds to the cipher list
    const RENEGOTIATION_INFO_SCSV: u16 = 0x00ff;

    /// Parse cipher suites (GREASE and SCSV skipped) and extension types (GREASE skipped)
    /// from a ClientHello record
    fn parse_client_hello(record: &[u8]) -> ClientHello {
        assert_eq!(record[0], 0x16, "not a handshake record");
        assert_eq!(record[5], 0x01, "not a ClientHello");
        // record header (5) + handshake header (4) + legacy_version (2) + random (32)
        let mut offset = 5 + 4 + 2 + 32;
        offset += 1 + record[offset] as usize; // session id

        let suites_len = read_u16(record, offset) as usize;
        offset += 2;
        let cipher_suites = (0..suites_len / 2)
            .map(|i| read_u16(record, offset + i * 2))
            .filter(|v| !is_grease(*v) && *v != RENEGOTIATION_INFO_SCSV)
            .collect();
        offset += suites_len;
        offset += 1 + record[offset] as usize; // compression methods

        let ext_end = offset + 2 + read_u16(record, offset) as usize;
        offset += 2;
        let mut extensions = Vec::new();
        while offset < ext_end {
            let ext_type = read_u16(record, offset);
            let ext_len = read_u16(record, offset + 2) as usize;
            if !is_grease(ext_type) {
                extensions.push(ext_type);
            }
            offset += 4 + ext_len;
        }
        ClientHello {
            cipher_suites,
            extensions,
        }
    }

    /// Build Ssl from the builder and capture the ClientHello it sends with the given ALPN list
    fn capture_client_hello(
        builder: &OpensslInterceptionClientConfigBuilder,
        alpn_protocols: &[&str],
    ) -> ClientHello {
        let config = builder.build().unwrap();
        let upstream = UpstreamAddr::from_host_str_and_port("www.example.com", 443).unwrap();
        let mut wired = vec![0u8, 0u8];
        for p in alpn_protocols {
            wired.push(p.len() as u8);
            wired.extend_from_slice(p.as_bytes());
        }
        let list_len = (wired.len() - 2) as u16;
        wired[..2].copy_from_slice(&list_len.to_be_bytes());
        let alpn = TlsAlpn::from_extension_value(&wired).unwrap();

        let ssl = config.build_ssl(None, &upstream, Some(&alpn)).unwrap();
        let recorder = ClientHelloRecorder {
            written: Vec::new(),
        };
        let mid = match ssl.connect(recorder) {
            Err(openssl::ssl::HandshakeError::WouldBlock(mid)) => mid,
            _ => panic!("handshake should stop waiting for ServerHello"),
        };
        parse_client_hello(&mid.get_ref().written)
    }

    fn chrome_like_builder() -> OpensslInterceptionClientConfigBuilder {
        let mut builder = OpensslInterceptionClientConfigBuilder::default();
        builder.set_cipher_list(CHROME_CIPHER_LIST.to_string());
        builder.set_enable_ech_grease(true);
        builder.set_enable_alps(true);
        builder
    }

    #[test]
    fn cipher_list_matches_chrome() {
        let hello = capture_client_hello(&chrome_like_builder(), &["h2", "http/1.1"]);

        assert_eq!(hello.cipher_suites.len(), 15);
        let mut tls13 = hello.cipher_suites[..3].to_vec();
        tls13.sort_unstable();
        assert_eq!(tls13, [0x1301, 0x1302, 0x1303]);
        assert_eq!(hello.cipher_suites[3..], CHROME_TLS12_SUITES);
    }

    #[test]
    #[cfg(boringssl)]
    fn ech_grease_and_alps_sent_when_enabled() {
        let hello = capture_client_hello(&chrome_like_builder(), &["h2", "http/1.1"]);

        assert!(hello.extensions.contains(&EXT_ECH));
        assert!(hello.extensions.contains(&EXT_ALPS_NEW_CODEPOINT));
    }

    #[test]
    #[cfg(boringssl)]
    fn alps_skipped_without_h2() {
        let hello = capture_client_hello(&chrome_like_builder(), &["http/1.1"]);

        assert!(hello.extensions.contains(&EXT_ECH));
        assert!(!hello.extensions.contains(&EXT_ALPS_NEW_CODEPOINT));
    }

    #[test]
    fn ech_grease_and_alps_absent_by_default() {
        let builder = OpensslInterceptionClientConfigBuilder::default();
        let hello = capture_client_hello(&builder, &["h2", "http/1.1"]);

        assert!(!hello.extensions.contains(&EXT_ECH));
        assert!(!hello.extensions.contains(&EXT_ALPS_NEW_CODEPOINT));
    }
}
