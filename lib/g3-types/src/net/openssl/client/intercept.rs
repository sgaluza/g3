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
    signature_algorithms: String,
    #[cfg(boringssl)]
    enable_ech_grease: bool,
    #[cfg(boringssl)]
    enable_alps: bool,
    #[cfg(boringssl)]
    trust_anchor_ids: Option<Vec<u8>>,
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
            signature_algorithms: String::default(),
            #[cfg(boringssl)]
            enable_ech_grease: false,
            #[cfg(boringssl)]
            enable_alps: false,
            #[cfg(boringssl)]
            trust_anchor_ids: None,
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

    /// Signature algorithms sent in ClientHello, colon separated TLS 1.3 names
    /// (`rsa_pss_rsae_sha256`, `mldsa44`, ...)
    #[cfg(boringssl)]
    pub fn set_signature_algorithms(&mut self, sigalgs: String) {
        self.signature_algorithms = sigalgs;
    }

    #[cfg(not(boringssl))]
    pub fn set_signature_algorithms(&mut self, _sigalgs: String) {
        warn!("signature algorithms can only be set for BoringSSL");
    }

    /// Send the trust_anchors extension with these trust anchor IDs, in wire format
    /// (each ID prefixed by an 8-bit length); an empty list still sends the extension
    #[cfg(boringssl)]
    pub fn set_trust_anchor_ids(&mut self, ids: Vec<u8>) {
        self.trust_anchor_ids = Some(ids);
    }

    #[cfg(not(boringssl))]
    pub fn set_trust_anchor_ids(&mut self, _ids: Vec<u8>) {
        warn!("trust anchor IDs can only be set for BoringSSL");
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

    /// Signature algorithms sent in ClientHello, BoringSSL only
    /// (the variant-ssl wrapper is gated by cfg(ossl110), not set for BoringSSL)
    #[cfg(boringssl)]
    fn build_set_signature_algorithms(
        &self,
        ctx_builder: &mut SslContextBuilder,
    ) -> anyhow::Result<()> {
        if self.signature_algorithms.is_empty() {
            return Ok(());
        }
        let sigalgs = std::ffi::CString::new(self.signature_algorithms.as_str())
            .map_err(|_| anyhow!("signature algorithms contain a NUL byte"))?;
        // SAFETY: the pointer is a valid SSL_CTX owned by ctx_builder, sigalgs is a C string
        let r = unsafe {
            openssl_sys::SSL_CTX_set1_sigalgs_list(ctx_builder.as_ptr(), sigalgs.as_ptr())
        };
        if r != 1 {
            return Err(anyhow!(
                "failed to set signature algorithms {}",
                self.signature_algorithms
            ));
        }
        Ok(())
    }

    /// The trust_anchors extension, BoringSSL only
    #[cfg(boringssl)]
    fn build_set_trust_anchors(&self, ctx_builder: &mut SslContextBuilder) -> anyhow::Result<()> {
        let Some(ids) = &self.trust_anchor_ids else {
            return Ok(());
        };
        // SAFETY: the pointer is a valid SSL_CTX, BoringSSL copies the buffer
        let r = unsafe {
            openssl_sys::SSL_CTX_set1_requested_trust_anchors(
                ctx_builder.as_ptr(),
                ids.as_ptr(),
                ids.len(),
            )
        };
        if r != 1 {
            return Err(anyhow!("invalid trust anchor IDs"));
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
            // BoringSSL keeps GREASE in signature_algorithms behind its own flag for now.
            // SAFETY: the pointer is a valid SSL_CTX owned by ctx_builder
            #[cfg(boringssl)]
            unsafe {
                openssl_sys::SSL_CTX_set_grease_sigalgs_enabled(ctx_builder.as_ptr(), 1)
            };
        }
        if self.permute_extensions {
            ctx_builder.set_permute_extensions(true);
        }

        self.build_set_cipher_list(&mut ctx_builder)?;

        #[cfg(boringssl)]
        self.build_set_signature_algorithms(&mut ctx_builder)?;
        #[cfg(boringssl)]
        self.build_set_trust_anchors(&mut ctx_builder)?;

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
    const EXT_SERVER_NAME: u16 = 0x0000;
    const EXT_ALPN: u16 = 0x0010;
    const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
    const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
    const EXT_TRUST_ANCHORS: u16 = 0xca34;

    // Reference: stock Chrome 156.0.8078.47 from the sandbrowser web-agent image,
    // captured directly (no proxy) on tls.peet.ws. Re-capture on a Chrome update.

    /// signature_algorithms of Chrome 156: ML-DSA-44/65/87 first, no SHA-1
    #[cfg(boringssl)]
    const CHROME_156_SIGNATURE_ALGORITHMS: &str = "mldsa44:mldsa65:mldsa87:\
        ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
        ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:\
        rsa_pss_rsae_sha512:rsa_pkcs1_sha512";

    const CHROME_156_SIGALG_CODES: [u16; 11] = [
        0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];

    /// trust_anchors extension body of Chrome 156 without the outer u16 length:
    /// trust anchor IDs, each prefixed by an 8-bit length
    #[cfg(boringssl)]
    const CHROME_156_TRUST_ANCHOR_IDS: &str = "0582df1302010582df1302060582df13020d0582df13020e\
        0582df13020f0582df1302120582df1302130582df13021408839a648c9b2d010708839a648c9b2d0108\
        08839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08839a648c9b2d010c08839a648c9b\
        2d010d08839a648c9b2d011208839a648c9b2d011304d679090104d679090404d679090504d679090604\
        d679090704d679090804d679090a04d679090b04d679090c04d679090d04d679090f";

    const CHROME_156_JA4: &str = "t13d1517h2_8daaf6152771_cb7bf5808d99";

    /// Groups as configured in production, also those of Chrome 156
    #[cfg(boringssl)]
    const CHROME_SUPPORTED_GROUPS: &str = "X25519MLKEM768:X25519:P-256:P-384";

    #[cfg(boringssl)]
    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

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
        /// Body of every non-GREASE extension, in wire order
        extension_data: Vec<(u16, Vec<u8>)>,
    }

    impl ClientHello {
        fn extension(&self, ext_type: u16) -> Option<&[u8]> {
            self.extension_data
                .iter()
                .find(|(t, _)| *t == ext_type)
                .map(|(_, d)| d.as_slice())
        }

        /// u16 values of a list extension body with the given length prefix size
        fn u16_list(&self, ext_type: u16, len_prefix: usize) -> Vec<u16> {
            let data = self.extension(ext_type).unwrap_or_default();
            data.get(len_prefix..)
                .unwrap_or_default()
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect()
        }

        /// Signature algorithms including GREASE values, in wire order
        fn signature_algorithms(&self) -> Vec<u16> {
            self.u16_list(EXT_SIGNATURE_ALGORITHMS, 2)
        }

        /// JA4 TLS client fingerprint (FoxIO spec) of this ClientHello
        fn ja4(&self) -> String {
            let version = self
                .u16_list(EXT_SUPPORTED_VERSIONS, 1)
                .into_iter()
                .filter(|v| !is_grease(*v))
                .max()
                .unwrap_or(0x0303);
            let version = match version {
                0x0304 => "13",
                0x0303 => "12",
                _ => "00",
            };
            let sni = if self.extension(EXT_SERVER_NAME).is_some() {
                'd'
            } else {
                'i'
            };
            let alpn = self
                .extension(EXT_ALPN)
                .and_then(|d| d.get(3..3 + *d.get(2)? as usize))
                .map(|p| format!("{}{}", p[0] as char, p[p.len() - 1] as char))
                .unwrap_or_else(|| "00".to_string());

            let hash = |s: String| -> String {
                openssl::sha::sha256(s.as_bytes())
                    .iter()
                    .take(6)
                    .map(|b| format!("{b:02x}"))
                    .collect()
            };
            let join = |mut v: Vec<u16>, sort: bool| -> String {
                if sort {
                    v.sort_unstable();
                }
                v.iter()
                    .map(|x| format!("{x:04x}"))
                    .collect::<Vec<_>>()
                    .join(",")
            };

            let exts: Vec<u16> = self
                .extensions
                .iter()
                .copied()
                .filter(|t| *t != EXT_SERVER_NAME && *t != EXT_ALPN)
                .collect();
            let sigalgs: Vec<u16> = self
                .signature_algorithms()
                .into_iter()
                .filter(|v| !is_grease(*v))
                .collect();
            format!(
                "t{version}{sni}{:02}{:02}{alpn}_{}_{}",
                self.cipher_suites.len(),
                self.extensions.len(),
                hash(join(self.cipher_suites.clone(), true)),
                hash(format!("{}_{}", join(exts, true), join(sigalgs, false))),
            )
        }
    }

    fn is_grease(v: u16) -> bool {
        v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
    }

    fn read_u16(buf: &[u8], offset: usize) -> u16 {
        u16::from_be_bytes([buf[offset], buf[offset + 1]])
    }

    #[test]
    fn is_grease_values() {
        // RFC 8701: 0x?A?A with equal bytes
        for v in [0x0a0a, 0x1a1a, 0xfafa] {
            assert!(is_grease(v), "{v:04x}");
        }
        for v in [0x0a1a, 0x1a0a, 0x0a0b, 0x0000, 0x00ff] {
            assert!(!is_grease(v), "{v:04x}");
        }
    }

    #[test]
    fn parse_client_hello_fixture() {
        // ClientHello body: legacy_version, random, session id of 3 bytes,
        // cipher suites with GREASE and SCSV, one compression method,
        // extensions: GREASE (empty), server_name (5 bytes), 0xca34 (empty)
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&[0x03, 0xaa, 0xbb, 0xcc]);
        body.extend_from_slice(&[0x00, 0x08, 0x2a, 0x2a, 0x13, 0x01, 0xc0, 0x2b, 0x00, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]);
        let exts = [
            0x3a, 0x3a, 0x00, 0x00, // GREASE
            0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, // server_name
            0xca, 0x34, 0x00, 0x00, // trust_anchors
        ];
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut handshake = vec![0x01, 0x00];
        handshake.extend_from_slice(&(body.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&body);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        let hello = parse_client_hello(&record);
        assert_eq!(hello.cipher_suites, [0x1301, 0xc02b]);
        assert_eq!(hello.extensions, [0x0000, 0xca34]);
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
        let mut extension_data = Vec::new();
        while offset < ext_end {
            let ext_type = read_u16(record, offset);
            let ext_len = read_u16(record, offset + 2) as usize;
            if !is_grease(ext_type) {
                extensions.push(ext_type);
                extension_data.push((ext_type, record[offset + 4..offset + 4 + ext_len].to_vec()));
            }
            offset += 4 + ext_len;
        }
        ClientHello {
            cipher_suites,
            extensions,
            extension_data,
        }
    }

    /// Build Ssl from the builder and capture the ClientHello it sends with the given ALPN list
    fn capture_client_hello(
        builder: &OpensslInterceptionClientConfigBuilder,
        alpn_protocols: &[&str],
    ) -> ClientHello {
        capture_client_hello_with_sni(builder, alpn_protocols, None)
    }

    /// Same as `capture_client_hello`, with an optional SNI host name
    fn capture_client_hello_with_sni(
        builder: &OpensslInterceptionClientConfigBuilder,
        alpn_protocols: &[&str],
        sni: Option<&str>,
    ) -> ClientHello {
        let server_name = sni.map(|host| {
            // server_name extension body: list length, name type 0, name length, name
            let mut ext = Vec::new();
            ext.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
            ext.push(0);
            ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
            ext.extend_from_slice(host.as_bytes());
            TlsServerName::from_extension_value(&ext).unwrap()
        });
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

        let ssl = config
            .build_ssl(server_name.as_ref(), &upstream, Some(&alpn))
            .unwrap();
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
        assert!(!hello.extensions.contains(&EXT_TRUST_ANCHORS));
    }

    /// Everything the production config sets, with the Chrome 156 reference values
    #[cfg(boringssl)]
    fn chrome_156_builder() -> OpensslInterceptionClientConfigBuilder {
        let mut builder = chrome_like_builder();
        builder.set_min_tls_version(TlsVersion::TLS1_2);
        builder.set_max_tls_version(TlsVersion::TLS1_3);
        builder.set_supported_groups(CHROME_SUPPORTED_GROUPS.to_string());
        builder.set_use_ocsp_stapling(true);
        builder.set_enable_sct(true);
        builder.set_enable_grease(true);
        builder.set_permute_extensions(true);
        builder.set_signature_algorithms(CHROME_156_SIGNATURE_ALGORITHMS.to_string());
        builder.set_trust_anchor_ids(hex_decode(CHROME_156_TRUST_ANCHOR_IDS));
        builder
    }

    #[test]
    #[cfg(boringssl)]
    fn signature_algorithms_like_chrome_156() {
        let hello = capture_client_hello(&chrome_156_builder(), &["h2", "http/1.1"]);
        let sigalgs = hello.signature_algorithms();

        // GREASE first, like Chrome
        assert!(is_grease(sigalgs[0]), "no GREASE in {sigalgs:04x?}");
        assert_eq!(sigalgs[1..], CHROME_156_SIGALG_CODES);
    }

    #[test]
    #[cfg(boringssl)]
    fn trust_anchors_like_chrome_156() {
        let hello = capture_client_hello(&chrome_156_builder(), &["h2", "http/1.1"]);
        let ids = hex_decode(CHROME_156_TRUST_ANCHOR_IDS);

        let mut expected = (ids.len() as u16).to_be_bytes().to_vec();
        expected.extend_from_slice(&ids);
        assert_eq!(
            hello.extension(EXT_TRUST_ANCHORS),
            Some(expected.as_slice())
        );
    }

    #[test]
    #[cfg(boringssl)]
    fn empty_trust_anchor_ids_still_send_extension() {
        let mut builder = OpensslInterceptionClientConfigBuilder::default();
        builder.set_trust_anchor_ids(Vec::new());
        let hello = capture_client_hello(&builder, &["h2", "http/1.1"]);

        // only the zero 16-bit length of the ID list
        assert_eq!(
            hello.extension(EXT_TRUST_ANCHORS),
            Some([0u8, 0].as_slice())
        );
    }

    #[test]
    fn ja4_helper_matches_chrome_156_raw_fingerprint() {
        // Lists from ja4_r of the Chrome 156 reference capture
        let ciphers = [
            0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014, 0xc02b, 0xc02c,
            0xc02f, 0xc030, 0xcca8, 0xcca9,
        ];
        let other_exts = [
            0x0005, 0x000a, 0x000b, 0x000d, 0x0012, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033,
            0x44cd, 0xca34, 0xfe0d, 0xff01,
        ];
        let mut sigalgs = vec![0x00, 0x16];
        for c in CHROME_156_SIGALG_CODES {
            sigalgs.extend_from_slice(&c.to_be_bytes());
        }
        let mut extension_data: Vec<(u16, Vec<u8>)> = other_exts
            .iter()
            .map(|t| match *t {
                EXT_SIGNATURE_ALGORITHMS => (*t, sigalgs.clone()),
                EXT_SUPPORTED_VERSIONS => (*t, vec![0x04, 0x03, 0x04, 0x03, 0x03]),
                _ => (*t, Vec::new()),
            })
            .collect();
        extension_data.push((EXT_SERVER_NAME, b"\x00\x00".to_vec()));
        extension_data.push((EXT_ALPN, b"\x00\x03\x02h2".to_vec()));
        let hello = ClientHello {
            cipher_suites: ciphers.to_vec(),
            extensions: extension_data.iter().map(|(t, _)| *t).collect(),
            extension_data,
        };

        assert_eq!(hello.ja4(), CHROME_156_JA4);
    }

    #[test]
    #[cfg(boringssl)]
    fn ja4_matches_chrome_156() {
        let hello = capture_client_hello_with_sni(
            &chrome_156_builder(),
            &["h2", "http/1.1"],
            Some("tls.peet.ws"),
        );

        assert_eq!(hello.ja4(), CHROME_156_JA4);
    }
}
