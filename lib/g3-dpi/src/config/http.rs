/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::fmt;
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H1InterceptionConfig {
    pub pipeline_size: NonZeroUsize,
    pub pipeline_read_idle_timeout: Duration,
    pub req_head_recv_timeout: Duration,
    pub rsp_head_recv_timeout: Duration,
    pub req_head_max_size: usize,
    pub rsp_head_max_size: usize,
    pub body_line_max_len: usize,
    pub steal_forwarded_for: bool,
}

impl Default for H1InterceptionConfig {
    fn default() -> Self {
        H1InterceptionConfig {
            pipeline_size: NonZeroUsize::new(10).unwrap(),
            pipeline_read_idle_timeout: Duration::from_secs(300),
            req_head_recv_timeout: Duration::from_secs(30),
            rsp_head_recv_timeout: Duration::from_secs(60),
            req_head_max_size: 65536,
            rsp_head_max_size: 65536,
            body_line_max_len: 8192,
            steal_forwarded_for: false,
        }
    }
}

/// How the h2 client to the upstream presents itself
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum H2UpstreamProfile {
    /// Connection settings from this config, h2 default request framing
    #[default]
    Default,
    /// SETTINGS, WINDOW_UPDATE, pseudo header order and HEADERS priority as Chrome
    Chrome,
    /// The same as the client's first flight, Chrome values for what it didn't send
    Mirror,
}

impl H2UpstreamProfile {
    /// Name of the profile as written in the config
    pub fn as_str(&self) -> &'static str {
        match self {
            H2UpstreamProfile::Default => "default",
            H2UpstreamProfile::Chrome => "chrome",
            H2UpstreamProfile::Mirror => "mirror",
        }
    }
}

impl fmt::Display for H2UpstreamProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for H2UpstreamProfile {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "default" => Ok(H2UpstreamProfile::Default),
            "chrome" => Ok(H2UpstreamProfile::Chrome),
            "mirror" => Ok(H2UpstreamProfile::Mirror),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2InterceptionConfig {
    pub upstream_profile: H2UpstreamProfile,
    pub max_header_list_size: u32,
    pub max_concurrent_streams: u32,
    stream_window_size: u32,
    connection_window_size: u32,
    max_frame_size: u32,
    pub max_send_buffer_size: usize,
    pub upstream_handshake_timeout: Duration,
    pub upstream_stream_open_timeout: Duration,
    pub client_handshake_timeout: Duration,
    pub ping_interval: Duration,
    pub rsp_head_recv_timeout: Duration,
    pub silent_drop_expect_header: bool,
}

impl Default for H2InterceptionConfig {
    fn default() -> Self {
        H2InterceptionConfig {
            upstream_profile: H2UpstreamProfile::Default,
            max_header_list_size: 64 * 1024, // 64KB
            max_concurrent_streams: 128,
            stream_window_size: 1024 * 1024,         // 1MiB
            connection_window_size: 2 * 1024 * 1024, // 2MiB
            max_frame_size: 256 * 1024,              // 256KiB
            max_send_buffer_size: 8 * 1024 * 1024,   // 8MiB
            upstream_handshake_timeout: Duration::from_secs(10),
            upstream_stream_open_timeout: Duration::from_secs(10),
            client_handshake_timeout: Duration::from_secs(4),
            ping_interval: Duration::from_secs(60),
            rsp_head_recv_timeout: Duration::from_secs(60),
            silent_drop_expect_header: false,
        }
    }
}

impl H2InterceptionConfig {
    #[inline]
    pub fn max_frame_size(&self) -> u32 {
        self.max_frame_size
    }

    pub fn set_max_frame_size(&mut self, size: u32) {
        self.max_frame_size = size.clamp(1 << 14, (1 << 24) - 1);
    }

    #[inline]
    pub fn stream_window_size(&self) -> u32 {
        self.stream_window_size
    }

    pub fn set_stream_window_size(&mut self, size: u32) {
        self.stream_window_size = size.max(65536);
    }

    #[inline]
    pub fn connection_window_size(&self) -> u32 {
        self.connection_window_size
    }

    pub fn set_connection_window_size(&mut self, size: u32) {
        self.connection_window_size = size.max(65536);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h2_upstream_profile_display_round_trip() {
        for profile in [H2UpstreamProfile::Default, H2UpstreamProfile::Chrome] {
            let s = profile.to_string();
            assert_eq!(s, profile.as_str());
            assert_eq!(s.parse::<H2UpstreamProfile>(), Ok(profile));
        }
        assert_eq!(H2UpstreamProfile::Chrome.to_string(), "chrome");
        assert_eq!(H2UpstreamProfile::Default.to_string(), "default");
    }
}
