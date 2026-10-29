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

#[cfg(boringssl)]
use super::mirror;
use super::{
    BrowserClientHello, DEFAULT_HANDSHAKE_TIMEOUT, MINIMAL_HANDSHAKE_TIMEOUT, MirrorReport,
    OpensslClientSessionCache, OpensslSessionCacheConfig,
};
use crate::net::{TlsAlpn, TlsServerName, TlsVersion, UpstreamAddr};

/// Static per-connection BoringSSL settings: set on each Ssl rather than the
/// SslContext, so that a mirrored ClientHello can leave them out
#[cfg(boringssl)]
#[derive(Clone)]
struct StaticHello {
    enable_grease: bool,
    use_ocsp_stapling: bool,
    enable_sct: bool,
    enable_ech_grease: bool,
    enable_alps: bool,
    trust_anchor_ids: Option<Vec<u8>>,
    mirror_client_hello: bool,
}

#[derive(Clone)]
struct ContextPair {
    ssl_context: SslContext,
    session_cache: Option<OpensslClientSessionCache>,
    #[cfg(boringssl)]
    hello: StaticHello,
}

impl ContextPair {
    /// Static per-connection options: OCSP, SCT, trust anchors, GREASE ECH
    /// and ALPS for h2 (new codepoint, as current Chrome does)
    #[cfg(boringssl)]
    fn set_static_hello(&self, ssl: &mut Ssl, alpn_ext: Option<&TlsAlpn>) -> anyhow::Result<()> {
        let hello = &self.hello;
        if hello.use_ocsp_stapling {
            mirror::enable_ocsp_stapling(ssl);
        }
        if hello.enable_sct {
            mirror::enable_signed_cert_timestamps(ssl);
        }
        if let Some(ids) = &hello.trust_anchor_ids {
            mirror::set_trust_anchors(ssl, ids)?;
        }
        if hello.enable_ech_grease {
            mirror::set_ech_grease(ssl, true);
        }
        let offers_h2 = alpn_ext.is_some_and(|alpn| alpn.contains(b"h2"));
        if hello.enable_alps && offers_h2 {
            mirror::add_application_settings(ssl, b"h2", true)?;
        }
        Ok(())
    }

    pub fn build_ssl(
        &self,
        server_name: Option<&TlsServerName>,
        upstream: &UpstreamAddr,
        alpn_ext: Option<&TlsAlpn>,
    ) -> anyhow::Result<Ssl> {
        let ssl = self.new_ssl(server_name, upstream, alpn_ext, true)?;
        #[cfg(boringssl)]
        let ssl = {
            let mut ssl = ssl;
            self.set_static_hello(&mut ssl, alpn_ext)?;
            ssl
        };
        Ok(ssl)
    }

    /// Ssl copying the browser ClientHello, see `mirror::apply_browser_hello`
    #[cfg(boringssl)]
    fn build_mirror_ssl(
        &self,
        server_name: Option<&TlsServerName>,
        upstream: &UpstreamAddr,
        alpn_ext: Option<&TlsAlpn>,
        browser: &BrowserClientHello,
    ) -> anyhow::Result<(Ssl, MirrorReport)> {
        // resume a cached upstream session only if the browser resumes its own,
        // a fresh browser with a resumed upstream session is not like a browser
        let resume = browser.resumes_session();
        let mut ssl = self.new_ssl(server_name, upstream, alpn_ext, resume)?;
        let report =
            mirror::apply_browser_hello(&mut ssl, alpn_ext, browser, self.hello.enable_grease)?;
        Ok((ssl, report))
    }

    /// Ssl with SNI, verify host name, session cache and ALPN set;
    /// a cached session is only resumed if `resume` is true
    fn new_ssl(
        &self,
        server_name: Option<&TlsServerName>,
        upstream: &UpstreamAddr,
        alpn_ext: Option<&TlsAlpn>,
        resume: bool,
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
            if resume {
                cache.find_and_set_cache(&mut ssl, upstream.host(), upstream.port())?;
            } else {
                // still cache new sessions of this connection for later resumption
                #[cfg(boringssl)]
                cache.set_cache_key(&mut ssl, upstream.host(), upstream.port())?;
            }
        }
        if let Some(v) = alpn_ext {
            ssl.set_alpn_protos(v.wired_list_sequence())
                .map_err(|e| anyhow!("failed to set alpn protocols: {e}"))?;
        }
        Ok(ssl)
    }
}

/// Keep the mirrored Ssl, or if copying the browser ClientHello failed, use a
/// fresh static one (the failed Ssl may be half configured) and report why
#[cfg(boringssl)]
fn mirror_or_static(
    mirror: anyhow::Result<(Ssl, MirrorReport)>,
    static_ssl: impl FnOnce() -> anyhow::Result<Ssl>,
) -> anyhow::Result<(Ssl, MirrorReport)> {
    match mirror {
        Ok(v) => Ok(v),
        Err(e) => {
            let report = MirrorReport {
                mirror_error: Some(e.to_string()),
                ..Default::default()
            };
            Ok((static_ssl()?, report))
        }
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

    /// Whether `build_mirror_ssl` copies the browser ClientHello
    #[cfg(boringssl)]
    pub fn mirror_client_hello(&self) -> bool {
        self.ssl_context_pair.hello.mirror_client_hello
    }

    #[cfg(not(boringssl))]
    pub fn mirror_client_hello(&self) -> bool {
        false
    }

    /// Like `build_ssl`; with `mirror_client_hello` enabled and a browser
    /// ClientHello given, the upstream ClientHello copies the browser one and
    /// the report tells what could not be copied
    #[cfg(boringssl)]
    pub fn build_mirror_ssl(
        &self,
        server_name: Option<&TlsServerName>,
        upstream: &UpstreamAddr,
        alpn_ext: Option<&TlsAlpn>,
        browser: Option<&BrowserClientHello>,
    ) -> anyhow::Result<(Ssl, MirrorReport)> {
        match browser {
            Some(b) if self.mirror_client_hello() => mirror_or_static(
                self.ssl_context_pair
                    .build_mirror_ssl(server_name, upstream, alpn_ext, b),
                || self.build_ssl(server_name, upstream, alpn_ext),
            ),
            _ => {
                let ssl = self.build_ssl(server_name, upstream, alpn_ext)?;
                Ok((ssl, MirrorReport::default()))
            }
        }
    }

    #[cfg(not(boringssl))]
    pub fn build_mirror_ssl(
        &self,
        server_name: Option<&TlsServerName>,
        upstream: &UpstreamAddr,
        alpn_ext: Option<&TlsAlpn>,
        _browser: Option<&BrowserClientHello>,
    ) -> anyhow::Result<(Ssl, MirrorReport)> {
        let ssl = self.build_ssl(server_name, upstream, alpn_ext)?;
        Ok((ssl, MirrorReport::default()))
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
    #[cfg(boringssl)]
    mirror_client_hello: bool,
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
            #[cfg(boringssl)]
            mirror_client_hello: false,
            insecure: false,
        }
    }
}

impl OpensslInterceptionClientConfigBuilder {
    pub fn check(&mut self) -> anyhow::Result<()> {
        if self.handshake_timeout < MINIMAL_HANDSHAKE_TIMEOUT {
            self.handshake_timeout = MINIMAL_HANDSHAKE_TIMEOUT;
        }

        #[cfg(boringssl)]
        self.check_signature_algorithms_and_trust_anchors()?;

        Ok(())
    }

    /// Validate values that BoringSSL only checks when the SSL context is built
    /// (or never checks), so that a broken config fails on parse and `g3proxy -t`
    #[cfg(boringssl)]
    fn check_signature_algorithms_and_trust_anchors(&self) -> anyhow::Result<()> {
        if !self.signature_algorithms.is_empty() {
            let mut ctx_builder = SslContextBuilder::new(SslMethod::tls_client())
                .map_err(|e| anyhow!("failed to create ssl context builder: {e}"))?;
            // keep the cause: an unknown name and a NUL byte are reported differently
            self.build_set_signature_algorithms(&mut ctx_builder)
                .map_err(|e| anyhow!("invalid signature_algorithms: {e}"))?;
        }
        if let Some(ids) = &self.trust_anchor_ids {
            mirror::validate_trust_anchor_ids(ids)?;
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

    /// Copy cipher suites, groups, signature algorithms and extensions of the
    /// browser ClientHello to the upstream one on every connection; the static
    /// values above are used where the browser one has nothing usable
    #[cfg(boringssl)]
    pub fn set_mirror_client_hello(&mut self, enable: bool) {
        self.mirror_client_hello = enable;
    }

    #[cfg(not(boringssl))]
    pub fn set_mirror_client_hello(&mut self, _enable: bool) {
        warn!("ClientHello mirroring can only be set for BoringSSL");
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

        // BoringSSL sets OCSP and SCT on each Ssl, see ContextPair::set_static_hello
        #[cfg(awslc)]
        if self.use_ocsp_stapling {
            ctx_builder.enable_ocsp_stapling();
            // TODO check OCSP response
        }

        #[cfg(awslc)]
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

        self.build_set_cert_compression(&mut ctx_builder)?;

        self.build_set_verify_cert_store(&mut ctx_builder)?;

        let session_cache = self.session_cache.set_for_client(&mut ctx_builder)?;

        Ok(ContextPair {
            ssl_context: ctx_builder.build().into_context(),
            session_cache,
            #[cfg(boringssl)]
            hello: StaticHello {
                enable_grease: self.enable_grease,
                use_ocsp_stapling: self.use_ocsp_stapling,
                enable_sct: self.enable_sct,
                enable_ech_grease: self.enable_ech_grease,
                enable_alps: self.enable_alps,
                trust_anchor_ids: self.trust_anchor_ids.clone(),
                mirror_client_hello: self.mirror_client_hello,
            },
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
    #[cfg(boringssl)]
    use crate::net::openssl::client::browser_hello::EXT_PRE_SHARED_KEY;
    use crate::net::openssl::client::browser_hello::is_grease;

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
            let values = data.get(len_prefix..).unwrap_or_default();
            // a truncated value means broken test data, fail loudly instead of dropping it
            assert!(
                values.len() & 1 == 0,
                "extension {ext_type:04x}: odd length {} of u16 values",
                values.len()
            );
            values
                .chunks_exact(2)
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
        let (record, _) = capture_mirror_record(builder, alpn_protocols, sni, None);
        parse_client_hello(&record)
    }

    /// Build Ssl with `build_mirror_ssl` for the given browser ClientHello and
    /// capture the raw ClientHello record it sends, with the mirror report
    fn capture_mirror_record(
        builder: &OpensslInterceptionClientConfigBuilder,
        alpn_protocols: &[&str],
        sni: Option<&str>,
        browser: Option<&BrowserClientHello>,
    ) -> (Vec<u8>, MirrorReport) {
        let config = builder.build().unwrap();
        capture_record_with_config(&config, alpn_protocols, sni, browser)
    }

    /// Upstream of every captured ClientHello, also the session cache key
    fn test_upstream() -> UpstreamAddr {
        UpstreamAddr::from_host_str_and_port("www.example.com", 443).unwrap()
    }

    /// Same as `capture_mirror_record` with an already built config,
    /// whose session cache is kept between calls
    fn capture_record_with_config(
        config: &OpensslInterceptionClientConfig,
        alpn_protocols: &[&str],
        sni: Option<&str>,
        browser: Option<&BrowserClientHello>,
    ) -> (Vec<u8>, MirrorReport) {
        let server_name = sni.map(|host| {
            // server_name extension body: list length, name type 0, name length, name
            let mut ext = Vec::new();
            ext.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
            ext.push(0);
            ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
            ext.extend_from_slice(host.as_bytes());
            TlsServerName::from_extension_value(&ext).unwrap()
        });
        let upstream = test_upstream();
        let mut wired = vec![0u8, 0u8];
        for p in alpn_protocols {
            wired.push(p.len() as u8);
            wired.extend_from_slice(p.as_bytes());
        }
        let list_len = (wired.len() - 2) as u16;
        wired[..2].copy_from_slice(&list_len.to_be_bytes());
        let alpn = TlsAlpn::from_extension_value(&wired).unwrap();

        let (ssl, report) = config
            .build_mirror_ssl(server_name.as_ref(), &upstream, Some(&alpn), browser)
            .unwrap();
        let recorder = ClientHelloRecorder {
            written: Vec::new(),
        };
        let mid = match ssl.connect(recorder) {
            Err(openssl::ssl::HandshakeError::WouldBlock(mid)) => mid,
            _ => panic!("handshake should stop waiting for ServerHello"),
        };
        (mid.get_ref().written.clone(), report)
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

    /// check() runs when the config is parsed (also for `g3proxy -t`)
    #[test]
    #[cfg(boringssl)]
    fn check_rejects_unknown_signature_algorithm() {
        let mut builder = OpensslInterceptionClientConfigBuilder::default();
        builder.set_signature_algorithms("mldsa44:rsa_pss_rsae_sha265".to_string());

        let e = builder.check().unwrap_err().to_string();
        assert!(e.contains("signature_algorithms"), "{e}");
        assert!(e.contains("rsa_pss_rsae_sha265"), "{e}");
    }

    #[test]
    #[cfg(boringssl)]
    fn check_rejects_broken_trust_anchor_ids() {
        // zero length ID, length past the end of the list, truncated second entry
        for ids in [
            vec![0x00],
            vec![0x05, 0x82, 0xdf],
            vec![0x02, 0xaa, 0xbb, 0x03, 0xcc],
        ] {
            let mut builder = OpensslInterceptionClientConfigBuilder::default();
            builder.set_trust_anchor_ids(ids.clone());
            let e = builder.check().unwrap_err().to_string();
            assert!(e.contains("trust_anchor_ids"), "{ids:02x?}: {e}");
        }
    }

    #[test]
    #[cfg(boringssl)]
    fn check_accepts_chrome_156_reference() {
        let mut builder = chrome_156_builder();
        builder.check().unwrap();

        let mut builder = OpensslInterceptionClientConfigBuilder::default();
        builder.set_trust_anchor_ids(Vec::new());
        builder.check().unwrap();
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

    /// Raw ClientHello record of the same Chrome 156 (web-agent:0.1.167-cpu),
    /// `--headless=new` against a local listener with SNI fixture.test
    const CHROME_156_CLIENT_HELLO: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/chrome156-client-hello.bin"
    ));

    /// Chrome 156 order on the wire, GREASE removed
    const CHROME_156_CIPHER_SUITES: [u16; 15] = [
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
        0x009c, 0x009d, 0x002f, 0x0035,
    ];
    /// X25519MLKEM768, X25519, P-256, P-384
    const CHROME_156_GROUPS: [u16; 4] = [0x11ec, 0x001d, 0x0017, 0x0018];

    /// cipher_suites and extensions bodies of a ClientHello record, without length prefixes
    fn hello_parts(record: &[u8]) -> (&[u8], Option<&[u8]>) {
        let mut offset = 5 + 4 + 2 + 32;
        offset += 1 + record[offset] as usize;
        let suites_len = read_u16(record, offset) as usize;
        let suites = &record[offset + 2..offset + 2 + suites_len];
        offset += 2 + suites_len;
        offset += 1 + record[offset] as usize;
        if offset >= record.len() {
            return (suites, None);
        }
        let ext_len = read_u16(record, offset) as usize;
        (suites, Some(&record[offset + 2..offset + 2 + ext_len]))
    }

    fn browser_hello(record: &[u8]) -> BrowserClientHello {
        let (suites, exts) = hello_parts(record);
        BrowserClientHello::parse(suites, exts).unwrap()
    }

    #[test]
    fn chrome_156_fixture_is_the_reference() {
        let hello = parse_client_hello(CHROME_156_CLIENT_HELLO);
        assert_eq!(hello.ja4(), CHROME_156_JA4);
    }

    #[test]
    fn browser_hello_parses_chrome_156() {
        let b = browser_hello(CHROME_156_CLIENT_HELLO);

        assert_eq!(b.cipher_suites, CHROME_156_CIPHER_SUITES);
        assert_eq!(b.groups, CHROME_156_GROUPS);
        assert_eq!(b.key_share_groups, [0x11ec, 0x001d]);
        assert_eq!(b.signature_algorithms, CHROME_156_SIGALG_CODES);
        assert_eq!(b.alps_protocols, [b"h2".to_vec()]);
        assert!(b.alps_new_codepoint);
        assert!(b.ech);
        assert!(b.status_request);
        assert!(b.signed_cert_timestamps);
        assert!(b.grease);
        let anchors = b.trust_anchors.as_deref().unwrap();
        assert_eq!(anchors.len(), 184);
        assert_eq!(&anchors[..6], [0x05, 0x82, 0xdf, 0x13, 0x02, 0x01]);
        assert_eq!(b.extensions.len(), 17);
        assert!(b.extensions.iter().all(|t| !is_grease(*t)));
    }

    #[test]
    fn browser_hello_old_alps_codepoint_and_no_grease() {
        // cipher suites without GREASE; ALPS on the old codepoint 0x4469 with h2
        let suites = [0xc0, 0x2b, 0x00, 0x2f];
        let exts = [0x44, 0x69, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2'];
        let b = BrowserClientHello::parse(&suites, Some(&exts)).unwrap();

        assert_eq!(b.cipher_suites, [0xc02b, 0x002f]);
        assert_eq!(b.alps_protocols, [b"h2".to_vec()]);
        assert!(!b.alps_new_codepoint);
        assert!(!b.grease);
        assert!(!b.ech);
        assert_eq!(b.trust_anchors, None);
    }

    #[test]
    fn browser_hello_rejects_broken_lengths() {
        // odd cipher suites body
        assert!(BrowserClientHello::parse(&[0xc0, 0x2b, 0x00], None).is_err());
        // extension longer than the extensions body
        assert!(
            BrowserClientHello::parse(&[0xc0, 0x2b], Some(&[0x00, 0x0a, 0x00, 0x08, 0x00]))
                .is_err()
        );
        // supported_groups list length past the extension body
        let exts = [0x00, 0x0a, 0x00, 0x04, 0x00, 0x08, 0x00, 0x1d];
        assert!(BrowserClientHello::parse(&[0xc0, 0x2b], Some(&exts)).is_err());
    }

    /// Mirror mode on top of a config with nothing Chrome-like but GREASE
    #[cfg(boringssl)]
    fn mirror_builder() -> OpensslInterceptionClientConfigBuilder {
        let mut builder = OpensslInterceptionClientConfigBuilder::default();
        builder.set_enable_grease(true);
        builder.set_permute_extensions(true);
        builder.set_mirror_client_hello(true);
        builder
    }

    #[test]
    #[cfg(boringssl)]
    fn mirror_reproduces_chrome_156() {
        let browser = browser_hello(CHROME_156_CLIENT_HELLO);
        let (record, report) = capture_mirror_record(
            &mirror_builder(),
            &["h2", "http/1.1"],
            Some("fixture.test"),
            Some(&browser),
        );
        let hello = parse_client_hello(&record);

        assert!(report.is_empty(), "{report}");
        assert_eq!(hello.ja4(), CHROME_156_JA4);
        assert_eq!(hello.cipher_suites, CHROME_156_CIPHER_SUITES);
        let sigalgs = hello.signature_algorithms();
        assert!(is_grease(sigalgs[0]), "no GREASE in {sigalgs:04x?}");
        assert_eq!(sigalgs[1..], CHROME_156_SIGALG_CODES);
        let mirrored = browser_hello(&record);
        assert_eq!(mirrored.groups, CHROME_156_GROUPS);
        assert_eq!(mirrored.key_share_groups, [0x11ec, 0x001d]);
        assert_eq!(mirrored.trust_anchors, browser.trust_anchors);
    }

    #[test]
    #[cfg(boringssl)]
    fn mirror_follows_a_different_client() {
        // a client unlike Chrome: other ciphers, groups and sigalgs, no ALPS, ECH, trust anchors
        let mut other = OpensslInterceptionClientConfigBuilder::default();
        other
            .set_cipher_list("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256".to_string());
        other.set_supported_groups("P-256:X25519".to_string());
        other.set_signature_algorithms("rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256".to_string());
        let (other_record, _) =
            capture_mirror_record(&other, &["http/1.1"], Some("fixture.test"), None);
        let expected = parse_client_hello(&other_record);

        // the static Chrome 156 values must not leak into the mirrored hello
        let mut builder = chrome_156_builder();
        builder.set_mirror_client_hello(true);
        let browser = browser_hello(&other_record);
        let (record, _) = capture_mirror_record(
            &builder,
            &["http/1.1"],
            Some("fixture.test"),
            Some(&browser),
        );
        let hello = parse_client_hello(&record);

        assert_eq!(hello.ja4(), expected.ja4());
        assert_eq!(hello.cipher_suites, expected.cipher_suites);
        let mirrored = browser_hello(&record);
        assert_eq!(mirrored.groups, [0x0017, 0x001d]);
        assert_eq!(mirrored.signature_algorithms, [0x0804, 0x0403]);
        assert!(!mirrored.ech);
        assert!(mirrored.alps_protocols.is_empty());
        assert_eq!(mirrored.trust_anchors, None);
        assert!(!mirrored.status_request);
    }

    #[test]
    #[cfg(boringssl)]
    fn mirror_reports_what_it_cannot_copy() {
        let mut browser = browser_hello(CHROME_156_CLIENT_HELLO);
        browser.cipher_suites.push(0xfe01);
        browser.groups.push(0x7777);
        browser.signature_algorithms.push(0x0999);
        browser.extensions.push(0x7a7b);
        let (record, report) = capture_mirror_record(
            &mirror_builder(),
            &["h2", "http/1.1"],
            Some("fixture.test"),
            Some(&browser),
        );

        // unknown values are dropped, the rest is still Chrome 156
        assert_eq!(parse_client_hello(&record).ja4(), CHROME_156_JA4);
        assert_eq!(report.dropped_cipher_suites, [0xfe01]);
        assert_eq!(report.dropped_groups, [0x7777]);
        assert_eq!(report.dropped_signature_algorithms, [0x0999]);
        assert_eq!(report.unsupported_extensions, [0x7a7b]);
        assert!(report.fallback.is_empty());
        let text = report.to_string();
        assert!(text.contains("fe01") && text.contains("7a7b"), "{text}");
    }

    #[test]
    #[cfg(boringssl)]
    fn mirror_falls_back_to_static_values() {
        let mut browser = browser_hello(CHROME_156_CLIENT_HELLO);
        // only TLS 1.3 suites and unknown ones: nothing to set for TLS 1.2
        browser.cipher_suites = vec![0x1301, 0x1302, 0x1303, 0xfe01];
        browser.groups.clear();
        browser.key_share_groups.clear();
        let mut builder = mirror_builder();
        builder.set_cipher_list(CHROME_CIPHER_LIST.to_string());
        builder.set_supported_groups(CHROME_SUPPORTED_GROUPS.to_string());
        let (record, report) = capture_mirror_record(
            &builder,
            &["h2", "http/1.1"],
            Some("fixture.test"),
            Some(&browser),
        );
        let hello = parse_client_hello(&record);

        assert_eq!(hello.cipher_suites[3..], CHROME_TLS12_SUITES);
        assert_eq!(browser_hello(&record).groups, CHROME_156_GROUPS);
        assert_eq!(report.fallback, ["cipher_suites", "supported_groups"]);
        assert!(!report.grease_mismatch);
    }

    #[test]
    #[cfg(boringssl)]
    fn mirror_reports_grease_mismatch() {
        let browser = browser_hello(CHROME_156_CLIENT_HELLO);
        let mut builder = OpensslInterceptionClientConfigBuilder::default();
        builder.set_mirror_client_hello(true);
        let (_, report) =
            capture_mirror_record(&builder, &["h2"], Some("fixture.test"), Some(&browser));

        assert!(report.grease_mismatch);
        assert!(report.to_string().contains("GREASE"), "{report}");
    }

    #[test]
    #[cfg(boringssl)]
    fn mirror_off_keeps_static_hello() {
        let mut other = OpensslInterceptionClientConfigBuilder::default();
        other.set_cipher_list("ECDHE-RSA-AES128-GCM-SHA256".to_string());
        let (other_record, _) =
            capture_mirror_record(&other, &["http/1.1"], Some("tls.peet.ws"), None);
        let browser = browser_hello(&other_record);

        let config = chrome_156_builder().build().unwrap();
        assert!(!config.mirror_client_hello());
        let (record, report) = capture_mirror_record(
            &chrome_156_builder(),
            &["h2", "http/1.1"],
            Some("tls.peet.ws"),
            Some(&browser),
        );

        assert!(report.is_empty());
        assert_eq!(parse_client_hello(&record).ja4(), CHROME_156_JA4);
    }

    /// Self-signed P-256 certificate and key for a local test server
    #[cfg(boringssl)]
    fn test_server_cert() -> (X509, openssl::pkey::PKey<openssl::pkey::Private>) {
        use openssl::asn1::Asn1Time;
        use openssl::ec::{EcGroup, EcKey};
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::x509::X509NameBuilder;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "www.example.com").unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        (cert.build(), key)
    }

    /// Run one real TLS 1.3 handshake of `config` against a local server, so
    /// that the session cache of `config` gets a session for `test_upstream()`
    #[cfg(boringssl)]
    fn prime_session_cache(config: &OpensslInterceptionClientConfig) {
        use std::net::{TcpListener, TcpStream};

        let (cert, key) = test_server_cert();
        let mut server_ctx = SslContextBuilder::new(SslMethod::tls_server()).unwrap();
        server_ctx.set_certificate(&cert).unwrap();
        server_ctx.set_private_key(&key).unwrap();
        let server_ctx = server_ctx.build();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut tls = Ssl::new(&server_ctx).unwrap().accept(tcp).unwrap();
            // the first write also sends the NewSessionTicket messages
            tls.write_all(b"x").unwrap();
            let _ = tls.read(&mut [0u8; 1]);
        });

        let host = b"www.example.com";
        let mut sni = ((host.len() + 3) as u16).to_be_bytes().to_vec();
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        let server_name = TlsServerName::from_extension_value(&sni).unwrap();
        let ssl = config
            .build_ssl(Some(&server_name), &test_upstream(), None)
            .unwrap();
        let mut tls = ssl.connect(TcpStream::connect(addr).unwrap()).unwrap();
        // reading processes the tickets, which go to the session cache
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).unwrap();
        drop(tls);
        server.join().unwrap();
    }

    /// A browser that resumes its own session sends pre_shared_key, a fresh one doesn't;
    /// the upstream ClientHello resumes the cached session only in the first case
    #[test]
    #[cfg(boringssl)]
    fn mirror_resumes_only_if_browser_resumes() {
        let mut builder = mirror_builder();
        builder.set_insecure(true);
        let config = builder.build().unwrap();
        prime_session_cache(&config);

        let fresh = browser_hello(CHROME_156_CLIENT_HELLO);
        assert!(!fresh.extensions.contains(&EXT_PRE_SHARED_KEY));
        let (record, _) =
            capture_record_with_config(&config, &["h2"], Some("www.example.com"), Some(&fresh));
        let hello = parse_client_hello(&record);
        assert!(!hello.extensions.contains(&EXT_PRE_SHARED_KEY));

        // the cached session was not used up by the fresh browser
        let mut resuming = fresh.clone();
        resuming.extensions.push(EXT_PRE_SHARED_KEY);
        let (record, _) =
            capture_record_with_config(&config, &["h2"], Some("www.example.com"), Some(&resuming));
        let hello = parse_client_hello(&record);
        assert!(hello.extensions.contains(&EXT_PRE_SHARED_KEY));
    }

    /// Without mirroring the cached session is resumed as before
    #[test]
    #[cfg(boringssl)]
    fn static_hello_resumes_cached_session() {
        let mut builder = chrome_156_builder();
        builder.set_insecure(true);
        let config = builder.build().unwrap();
        prime_session_cache(&config);

        let (record, _) =
            capture_record_with_config(&config, &["h2"], Some("www.example.com"), None);
        let hello = parse_client_hello(&record);
        assert!(hello.extensions.contains(&EXT_PRE_SHARED_KEY));
    }

    /// An error while copying the browser ClientHello must not fail the connection
    #[test]
    #[cfg(boringssl)]
    fn mirror_error_falls_back_to_static_hello() {
        let config = chrome_156_builder().build().unwrap();
        let (ssl, report) = mirror_or_static(Err(anyhow!("copy failed")), || {
            config.build_ssl(None, &test_upstream(), None)
        })
        .unwrap();

        assert_eq!(report.mirror_error.as_deref(), Some("copy failed"));
        assert!(report.to_string().contains("copy failed"), "{report}");
        drop(ssl);

        // a mirror build that worked is kept as is
        let mirrored = config.build_ssl(None, &test_upstream(), None).unwrap();
        let (_, report) = mirror_or_static(Ok((mirrored, MirrorReport::default())), || {
            panic!("static build must not run")
        })
        .unwrap();
        assert!(report.is_empty());
    }

    #[test]
    #[cfg(boringssl)]
    fn mirror_reports_unknown_tls13_range_cipher() {
        let mut browser = browser_hello(CHROME_156_CLIENT_HELLO);
        // 0x13ff looks like a TLS 1.3 suite but isn't one
        browser.cipher_suites.push(0x13ff);
        let (record, report) = capture_mirror_record(
            &mirror_builder(),
            &["h2", "http/1.1"],
            Some("fixture.test"),
            Some(&browser),
        );

        assert_eq!(report.dropped_cipher_suites, [0x13ff]);
        assert_eq!(parse_client_hello(&record).ja4(), CHROME_156_JA4);
    }

    #[test]
    #[cfg(boringssl)]
    fn mirror_reports_duplicates_once() {
        let mut browser = browser_hello(CHROME_156_CLIENT_HELLO);
        browser.groups.push(0x001d);
        browser.signature_algorithms.push(0x0403);
        let (record, report) = capture_mirror_record(
            &mirror_builder(),
            &["h2", "http/1.1"],
            Some("fixture.test"),
            Some(&browser),
        );

        assert_eq!(report.dropped_groups, [0x001d]);
        assert_eq!(report.dropped_signature_algorithms, [0x0403]);
        assert_eq!(parse_client_hello(&record).ja4(), CHROME_156_JA4);
    }

    #[test]
    #[cfg(boringssl)]
    fn mirror_flag_reaches_config() {
        let config = mirror_builder().build().unwrap();
        assert!(config.mirror_client_hello());
    }
}
