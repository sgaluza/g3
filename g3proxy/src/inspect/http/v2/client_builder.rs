/*
 * SPDX-License-Identifier: Apache-2.0
 */

use std::fmt;
use std::time::Duration;

use h2::client::PseudoHeader;

use g3_dpi::parser::h2::{H2ClientPreface, H2PseudoHeader};
use g3_dpi::{H2InterceptionConfig, H2UpstreamProfile};
use g3_types::net::ChromeH2Settings;

/// Chrome marks every request HEADERS with an exclusive dependency on stream 0, weight 256
const CHROME_HEADERS_PRIORITY_WEIGHT: u16 = 256;

/// Initial flow control window of an h2 connection (RFC 9113 section 6.9.2)
const DEFAULT_CONNECTION_WINDOW: u32 = 65_535;
/// Largest flow control window and initial window size (RFC 9113 section 6.9.1)
const MAX_WINDOW_SIZE: u32 = (1 << 31) - 1;
/// Allowed SETTINGS_MAX_FRAME_SIZE values (RFC 9113 section 6.5.2)
const MAX_FRAME_SIZE_RANGE: std::ops::RangeInclusive<u32> = (1 << 14)..=((1 << 24) - 1);

/// Order of :method, :scheme, :authority, :path when the client didn't show one
const DEFAULT_PSEUDO_ORDER: [PseudoHeader; 4] = [
    PseudoHeader::Method,
    PseudoHeader::Scheme,
    PseudoHeader::Authority,
    PseudoHeader::Path,
];

/// What the mirror profile could not copy from the client first flight
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct H2MirrorReport {
    /// No client first flight was given, the chrome profile was used
    pub(super) no_preface: bool,
    /// SETTINGS ids the h2 client can't send
    pub(super) unknown_settings: Vec<u16>,
    /// SETTINGS not in ascending id order, the h2 client sends them ascending
    pub(super) settings_reordered: bool,
    /// PRIORITY frames sent by the client, the h2 client sends none
    pub(super) priority_frames: usize,
    /// No request in the first flight: Chrome pseudo header order and priority
    pub(super) no_request: bool,
}

impl H2MirrorReport {
    pub(super) fn is_empty(&self) -> bool {
        *self == H2MirrorReport::default()
    }

    /// Worth a warning: anything but a first flight without a request, which
    /// Chrome preconnects send all the time and which gets Chrome framing, and
    /// no first flight at all, from a client that closes or fails the h2
    /// handshake anyway
    pub(super) fn is_notable(&self) -> bool {
        !H2MirrorReport {
            no_request: false,
            no_preface: false,
            ..self.clone()
        }
        .is_empty()
    }
}

impl fmt::Display for H2MirrorReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.no_preface {
            parts.push("no client first flight, chrome profile used".to_string());
        }
        if !self.unknown_settings.is_empty() {
            let ids: Vec<String> = self
                .unknown_settings
                .iter()
                .map(|id| format!("{id:04x}"))
                .collect();
            parts.push(format!("SETTINGS not sent: {}", ids.join(",")));
        }
        if self.settings_reordered {
            parts.push("client SETTINGS order not kept, sent in ascending id order".to_string());
        }
        if self.priority_frames > 0 {
            parts.push(format!("{} PRIORITY frames not sent", self.priority_frames));
        }
        if self.no_request {
            parts.push("no request in the first flight, Chrome request framing".to_string());
        }
        f.write_str(&parts.join("; "))
    }
}

/// Settings and request framing of Chrome
fn set_chrome(builder: &mut h2::client::Builder) {
    // no MAX_CONCURRENT_STREAMS and MAX_FRAME_SIZE: Chrome doesn't send them
    builder
        .header_table_size(ChromeH2Settings::HEADER_TABLE_SIZE)
        .enable_push(ChromeH2Settings::ENABLE_PUSH)
        .initial_window_size(ChromeH2Settings::INITIAL_WINDOW_SIZE)
        .max_header_list_size(ChromeH2Settings::MAX_HEADER_LIST_SIZE)
        .initial_connection_window_size(ChromeH2Settings::CONNECTION_WINDOW_SIZE);
    set_chrome_request_framing(builder);
}

/// Pseudo header order and HEADERS priority of Chrome
fn set_chrome_request_framing(builder: &mut h2::client::Builder) {
    builder
        .pseudo_header_authority_first(true)
        .headers_priority(0, CHROME_HEADERS_PRIORITY_WEIGHT, true);
}

fn pseudo_header(h: H2PseudoHeader) -> PseudoHeader {
    match h {
        H2PseudoHeader::Method => PseudoHeader::Method,
        H2PseudoHeader::Scheme => PseudoHeader::Scheme,
        H2PseudoHeader::Authority => PseudoHeader::Authority,
        H2PseudoHeader::Path => PseudoHeader::Path,
    }
}

/// The client order, then what it didn't send in the default order
fn pseudo_order(client: &[H2PseudoHeader]) -> [PseudoHeader; 4] {
    let mut order = DEFAULT_PSEUDO_ORDER;
    let mut seen = Vec::with_capacity(4);
    for h in client.iter().copied().map(pseudo_header) {
        if !seen.contains(&h) {
            seen.push(h);
        }
    }
    for h in DEFAULT_PSEUDO_ORDER {
        if !seen.contains(&h) {
            seen.push(h);
        }
    }
    order.copy_from_slice(&seen[..4]);
    order
}

/// Client SETTINGS the h2 client can send, as it sends them
struct MirroredSettings {
    /// (id, value) in ascending id order, the last value of a repeated id
    sent: Vec<(u16, u32)>,
    /// Ids not supported or with a value out of range
    unsupported: Vec<u16>,
    /// The client didn't send them in ascending id order
    reordered: bool,
}

/// Pick the client SETTINGS the h2 client supports with valid values (the h2
/// builder panics on some out of range values); h2 sends ids 1 to 6 ascending
fn mirrored_settings(settings: &[(u16, u32)]) -> MirroredSettings {
    let mut values: [Option<u32>; 6] = [None; 6];
    let mut unsupported = Vec::new();
    let mut reordered = false;
    let mut last_id = 0;
    for &(id, value) in settings {
        reordered |= id < last_id;
        last_id = last_id.max(id);
        let valid = match id {
            0x1 | 0x3 | 0x6 => true,
            0x2 => value <= 1,
            0x4 => value <= MAX_WINDOW_SIZE,
            0x5 => MAX_FRAME_SIZE_RANGE.contains(&value),
            _ => false,
        };
        if valid {
            values[id as usize - 1] = Some(value);
        } else {
            unsupported.push(id);
        }
    }
    let sent = (1u16..)
        .zip(values)
        .filter_map(|(id, v)| v.map(|v| (id, v)))
        .collect();
    MirroredSettings {
        sent,
        unsupported,
        reordered,
    }
}

/// Settings and request framing copied from the client first flight
fn set_mirror(builder: &mut h2::client::Builder, preface: &H2ClientPreface) -> H2MirrorReport {
    let mut report = H2MirrorReport::default();

    let settings = mirrored_settings(&preface.settings);
    report.unknown_settings = settings.unsupported;
    report.settings_reordered = settings.reordered;
    for (id, value) in settings.sent {
        match id {
            0x1 => builder.header_table_size(value),
            0x2 => builder.enable_push(value == 1),
            0x3 => builder.max_concurrent_streams(value),
            0x4 => builder.initial_window_size(value),
            0x5 => builder.max_frame_size(value),
            _ => builder.max_header_list_size(value),
        };
    }

    // the connection WINDOW_UPDATE increment is the window above the default one
    if let Some(increment) = preface.window_update {
        let window = DEFAULT_CONNECTION_WINDOW
            .saturating_add(increment)
            .min(MAX_WINDOW_SIZE);
        builder.initial_connection_window_size(window);
    }
    report.priority_frames = preface.priority_frames;

    match &preface.headers {
        Some(headers) => {
            builder.pseudo_header_order(pseudo_order(&headers.pseudo_order));
            if let Some(p) = headers.priority {
                builder.headers_priority(p.dependency, p.weight, p.exclusive);
            }
        }
        None => {
            set_chrome_request_framing(builder);
            report.no_request = true;
        }
    }
    report
}

/// SETTINGS payload the mirror profile sends upstream for this first flight,
/// as h2 encodes it, for the ALPS of later upstream TLS connections
pub(super) fn mirror_alps_settings(preface: &H2ClientPreface) -> Vec<u8> {
    let sent = mirrored_settings(&preface.settings).sent;
    let mut payload = Vec::with_capacity(sent.len() * 6);
    for (id, value) in sent {
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());
    }
    payload
}

/// Time left of `budget` after `spent`, for a timeout shared by two steps
pub(super) fn remaining_budget(budget: Duration, spent: Duration) -> Duration {
    budget.saturating_sub(spent)
}

/// Builder of the h2 client connection to the upstream server.
///
/// The chrome profile replaces the settings of `http_config` that are visible
/// on the wire (SETTINGS, WINDOW_UPDATE, pseudo header order, HEADERS priority)
/// with Chrome's, so that the HTTP/2 fingerprint matches the TLS one. The mirror
/// profile takes them from the client first flight instead.
pub(super) fn upstream_client_builder(
    http_config: &H2InterceptionConfig,
    preface: Option<&H2ClientPreface>,
) -> (h2::client::Builder, H2MirrorReport) {
    let mut builder = h2::client::Builder::new();
    builder.max_send_buffer_size(http_config.max_send_buffer_size);

    let mut report = H2MirrorReport::default();
    match http_config.upstream_profile {
        H2UpstreamProfile::Default => {
            builder
                .enable_push(false) // server push is deprecated by chrome and nginx
                .max_header_list_size(http_config.max_header_list_size)
                .max_concurrent_streams(0)
                .max_frame_size(http_config.max_frame_size())
                .initial_window_size(http_config.stream_window_size())
                .initial_connection_window_size(http_config.connection_window_size());
        }
        H2UpstreamProfile::Chrome => set_chrome(&mut builder),
        H2UpstreamProfile::Mirror => match preface {
            Some(p) => report = set_mirror(&mut builder, p),
            None => {
                set_chrome(&mut builder);
                report.no_preface = true;
            }
        },
    }
    (builder, report)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::Request;
    use tokio::io::{AsyncReadExt, DuplexStream};

    use super::*;

    const PREFACE_LEN: usize = 24;
    const FRAME_PRIORITY: u8 = 0x2;
    const FRAME_HEADERS: u8 = 0x1;
    const FRAME_SETTINGS: u8 = 0x4;
    const FRAME_WINDOW_UPDATE: u8 = 0x8;
    const FLAG_PRIORITY: u8 = 0x20;

    /// What the server sees from the client before the first response
    struct Fingerprint {
        /// Akamai HTTP/2 fingerprint: SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo headers
        akamai: String,
        /// Priority block of the request HEADERS frame, if the PRIORITY flag is set
        headers_priority: Option<[u8; 5]>,
    }

    /// Decode an HPACK prefix integer, returns (value, bytes used)
    fn hpack_int(buf: &[u8], prefix_bits: u8) -> (usize, usize) {
        let mask = (1u16 << prefix_bits) as usize - 1;
        let mut value = buf[0] as usize & mask;
        if value < mask {
            return (value, 1);
        }
        let mut shift = 0;
        let mut used = 1;
        loop {
            let b = buf[used] as usize;
            used += 1;
            value += (b & 0x7f) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                return (value, used);
            }
        }
    }

    /// Pseudo header order ("m,a,s,p") from the start of an HPACK header block.
    /// Only static table names are expected, which holds for the first request.
    fn pseudo_order(mut block: &[u8]) -> String {
        let mut order = Vec::new();
        while !block.is_empty() {
            let b = block[0];
            let (name_index, used, has_literal_value) = if b & 0x80 != 0 {
                let (i, n) = hpack_int(block, 7);
                (i, n, false)
            } else if b & 0x40 != 0 {
                let (i, n) = hpack_int(block, 6);
                (i, n, true)
            } else if b & 0x20 != 0 {
                // dynamic table size update
                let (_, n) = hpack_int(block, 5);
                block = &block[n..];
                continue;
            } else {
                let (i, n) = hpack_int(block, 4);
                (i, n, true)
            };
            let letter = match name_index {
                1 => "a",
                2 | 3 => "m",
                4 | 5 => "p",
                6 | 7 => "s",
                _ => break, // regular header field, pseudo headers are over
            };
            order.push(letter);
            block = &block[used..];
            if has_literal_value {
                let (len, n) = hpack_int(block, 7);
                block = &block[n + len..];
            }
        }
        order.join(",")
    }

    /// Read client frames until the request HEADERS frame
    async fn read_fingerprint(srv: &mut DuplexStream) -> Fingerprint {
        let mut preface = [0u8; PREFACE_LEN];
        srv.read_exact(&mut preface).await.unwrap();

        let mut settings = Vec::new();
        let mut window_update = 0u32;
        let mut priority_frames = 0usize;
        loop {
            let mut head = [0u8; 9];
            srv.read_exact(&mut head).await.unwrap();
            let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
            let (kind, flags) = (head[3], head[4]);
            let mut payload = vec![0u8; len];
            srv.read_exact(&mut payload).await.unwrap();

            match kind {
                FRAME_SETTINGS => {
                    for s in payload.chunks(6) {
                        let id = u16::from_be_bytes([s[0], s[1]]);
                        let value = u32::from_be_bytes([s[2], s[3], s[4], s[5]]);
                        settings.push(format!("{id}:{value}"));
                    }
                }
                FRAME_WINDOW_UPDATE => {
                    window_update =
                        u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                            & 0x7fff_ffff;
                }
                FRAME_PRIORITY => priority_frames += 1,
                FRAME_HEADERS => {
                    let (headers_priority, block) = if flags & FLAG_PRIORITY != 0 {
                        let mut p = [0u8; 5];
                        p.copy_from_slice(&payload[..5]);
                        (Some(p), &payload[5..])
                    } else {
                        (None, &payload[..])
                    };
                    let akamai = format!(
                        "{}|{}|{}|{}",
                        settings.join(";"),
                        window_update,
                        priority_frames,
                        pseudo_order(block)
                    );
                    return Fingerprint {
                        akamai,
                        headers_priority,
                    };
                }
                _ => {}
            }
        }
    }

    async fn capture(config: &H2InterceptionConfig) -> Fingerprint {
        capture_mirror(config, None).await.0
    }

    /// Fingerprint of the upstream client built for the given client first flight
    async fn capture_mirror(
        config: &H2InterceptionConfig,
        preface: Option<&H2ClientPreface>,
    ) -> (Fingerprint, H2MirrorReport) {
        let (builder, report) = upstream_client_builder(config, preface);
        (capture_builder(builder).await, report)
    }

    async fn capture_builder(builder: h2::client::Builder) -> Fingerprint {
        let (io, mut srv) = tokio::io::duplex(64 * 1024);
        let (mut client, conn) = builder.handshake::<_, Bytes>(io).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let request = Request::get("https://example.com/").body(()).unwrap();
        let _response = client.send_request(request, true).unwrap();

        read_fingerprint(&mut srv).await
    }

    #[test]
    fn hpack_int_prefix_and_continuation() {
        // fits into the prefix
        assert_eq!(hpack_int(&[0x0a], 5), (10, 1));
        // RFC 7541 C.1.2: 1337 with a 5-bit prefix
        assert_eq!(hpack_int(&[0x1f, 0x9a, 0x0a], 5), (1337, 3));
        // bits above the prefix (H flag, representation type) are ignored
        assert_eq!(hpack_int(&[0x8c], 7), (12, 1));
    }

    #[test]
    fn pseudo_order_skips_size_update_and_huffman_values() {
        let block = [
            0x3f, 0xe1, 0x1f, // dynamic table size update to 4096
            0x82, // :method GET, indexed
            0x41, 0x8c, // :authority, literal with indexing, Huffman, 12 bytes
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4,
            0xff, // www.example.com
            0x87, // :scheme https, indexed
            0x84, // :path /, indexed
            0x40, 0x03, b'f', b'o', b'o', 0x03, b'b', b'a', b'r', // regular header, new name
        ];
        assert_eq!(pseudo_order(&block), "m,a,s,p");

        // literal without indexing and never indexed representations
        let block = [0x82, 0x04, 0x01, b'/', 0x87, 0x11, 0x02, b'h', b'1'];
        assert_eq!(pseudo_order(&block), "m,p,s,a");
    }

    #[tokio::test]
    async fn default_profile_unchanged() {
        let config = H2InterceptionConfig::default();
        let fp = capture(&config).await;

        assert_eq!(
            fp.akamai,
            "2:0;3:0;4:1048576;5:262144;6:65536|2031617|0|m,s,a,p"
        );
        assert!(fp.headers_priority.is_none());
    }

    #[tokio::test]
    async fn chrome_profile_matches_chrome() {
        let mut config = H2InterceptionConfig::default();
        config.upstream_profile = H2UpstreamProfile::Chrome;
        let fp = capture(&config).await;

        assert_eq!(
            fp.akamai,
            "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
        );
        // exclusive dependency on stream 0, weight 256
        assert_eq!(fp.headers_priority, Some([0x80, 0x00, 0x00, 0x00, 0xff]));
    }

    use g3_dpi::parser::h2::H2PseudoHeader::*;
    use g3_dpi::parser::h2::{H2FirstHeaders, H2HeadersPriority};

    const CHROME_AKAMAI: &str = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";
    const FIREFOX_AKAMAI: &str = "1:65536;4:131072;5:16384|12517377|0|m,p,a,s";

    fn mirror_config() -> H2InterceptionConfig {
        let mut config = H2InterceptionConfig::default();
        config.upstream_profile = H2UpstreamProfile::Mirror;
        config
    }

    /// First flight of Chrome 156, as parsed from the g3-dpi fixture
    fn chrome_preface() -> H2ClientPreface {
        H2ClientPreface {
            settings: vec![(1, 65536), (2, 0), (4, 6291456), (6, 262144)],
            window_update: Some(15663105),
            priority_frames: 0,
            headers: Some(H2FirstHeaders {
                priority: Some(H2HeadersPriority {
                    exclusive: true,
                    dependency: 0,
                    weight: 256,
                }),
                pseudo_order: vec![Method, Authority, Scheme, Path],
            }),
        }
    }

    /// Firefox-like first flight: other SETTINGS and window, no PRIORITY, m,p,a,s
    fn firefox_preface() -> H2ClientPreface {
        H2ClientPreface {
            settings: vec![(1, 65536), (4, 131072), (5, 16384)],
            window_update: Some(12517377),
            priority_frames: 0,
            headers: Some(H2FirstHeaders {
                priority: None,
                pseudo_order: vec![Method, Path, Authority, Scheme],
            }),
        }
    }

    #[tokio::test]
    async fn mirror_copies_chrome() {
        let (fp, report) = capture_mirror(&mirror_config(), Some(&chrome_preface())).await;

        assert!(report.is_empty(), "{report}");
        assert_eq!(fp.akamai, CHROME_AKAMAI);
        assert_eq!(fp.headers_priority, Some([0x80, 0x00, 0x00, 0x00, 0xff]));
    }

    #[tokio::test]
    async fn mirror_copies_a_different_client() {
        let (fp, report) = capture_mirror(&mirror_config(), Some(&firefox_preface())).await;

        assert!(report.is_empty(), "{report}");
        assert_eq!(fp.akamai, FIREFOX_AKAMAI);
        assert_eq!(fp.headers_priority, None);
    }

    #[tokio::test]
    async fn mirror_copies_headers_priority() {
        let mut preface = firefox_preface();
        preface.headers.as_mut().unwrap().priority = Some(H2HeadersPriority {
            exclusive: false,
            dependency: 0,
            weight: 42,
        });
        let (fp, _) = capture_mirror(&mirror_config(), Some(&preface)).await;

        assert_eq!(fp.headers_priority, Some([0x00, 0x00, 0x00, 0x00, 41]));
    }

    #[tokio::test]
    async fn mirror_without_request_uses_chrome_framing() {
        let mut preface = firefox_preface();
        preface.headers = None;
        let (fp, report) = capture_mirror(&mirror_config(), Some(&preface)).await;

        // SETTINGS and window of the client, request framing of Chrome
        assert_eq!(fp.akamai, "1:65536;4:131072;5:16384|12517377|0|m,a,s,p");
        assert_eq!(fp.headers_priority, Some([0x80, 0x00, 0x00, 0x00, 0xff]));
        assert!(report.no_request);
    }

    #[tokio::test]
    async fn mirror_without_window_update_sends_none() {
        let mut preface = firefox_preface();
        preface.window_update = None;
        let (fp, _) = capture_mirror(&mirror_config(), Some(&preface)).await;

        assert_eq!(fp.akamai, "1:65536;4:131072;5:16384|0|0|m,p,a,s");
    }

    #[tokio::test]
    async fn mirror_reports_what_it_cannot_copy() {
        let mut preface = firefox_preface();
        // NO_RFC7540_PRIORITIES and a GREASE id, then out of order
        preface.settings = vec![(4, 131072), (1, 65536), (9, 1), (0x0a0a, 0)];
        preface.priority_frames = 2;
        let (fp, report) = capture_mirror(&mirror_config(), Some(&preface)).await;

        assert_eq!(fp.akamai, "1:65536;4:131072|12517377|0|m,p,a,s");
        assert_eq!(report.unknown_settings, [9, 0x0a0a]);
        assert!(report.settings_reordered);
        assert_eq!(report.priority_frames, 2);
        let text = report.to_string();
        assert!(text.contains("0009") && text.contains("PRIORITY"), "{text}");
    }

    #[test]
    fn preconnect_alone_is_not_notable() {
        // Chrome preconnects without a request, and its framing is used then anyway
        let preconnect = H2MirrorReport {
            no_request: true,
            ..Default::default()
        };
        assert!(!preconnect.is_notable());

        // a client that closes before its SETTINGS fails the h2 handshake anyway
        let no_preface = H2MirrorReport {
            no_preface: true,
            ..Default::default()
        };
        assert!(!no_preface.is_notable());

        let reordered = H2MirrorReport {
            no_request: true,
            settings_reordered: true,
            ..Default::default()
        };
        assert!(reordered.is_notable());
        assert!(!H2MirrorReport::default().is_notable());
    }

    #[test]
    fn alps_settings_of_chrome_are_chrome() {
        assert_eq!(
            mirror_alps_settings(&chrome_preface()),
            ChromeH2Settings::settings_payload()
        );
    }

    /// ALPS carries what the upstream SETTINGS frame carries: supported ids and
    /// valid values only, in the ascending order h2 sends them
    #[test]
    fn alps_settings_are_the_sent_ones() {
        let mut preface = firefox_preface();
        preface.settings = vec![(4, 131072), (1, 65536), (9, 1), (0x0a0a, 0), (5, 100)];

        let mut expected = Vec::new();
        for (id, value) in [(1u16, 65536u32), (4, 131072)] {
            expected.extend_from_slice(&id.to_be_bytes());
            expected.extend_from_slice(&value.to_be_bytes());
        }
        assert_eq!(mirror_alps_settings(&preface), expected);
    }

    #[test]
    fn remaining_budget_after_preface() {
        use std::time::Duration;

        let budget = Duration::from_secs(4);
        assert_eq!(
            remaining_budget(budget, Duration::from_millis(1500)),
            Duration::from_millis(2500)
        );
        assert_eq!(
            remaining_budget(budget, Duration::from_secs(5)),
            Duration::ZERO
        );
    }

    #[tokio::test]
    async fn mirror_without_preface_is_chrome() {
        let (fp, report) = capture_mirror(&mirror_config(), None).await;

        assert_eq!(fp.akamai, CHROME_AKAMAI);
        assert!(report.no_preface);
    }

    #[tokio::test]
    async fn chrome_profile_ignores_preface() {
        let mut config = H2InterceptionConfig::default();
        config.upstream_profile = H2UpstreamProfile::Chrome;
        let (fp, report) = capture_mirror(&config, Some(&firefox_preface())).await;

        assert_eq!(fp.akamai, CHROME_AKAMAI);
        assert!(report.is_empty());
    }
}
