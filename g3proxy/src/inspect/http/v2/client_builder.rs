/*
 * SPDX-License-Identifier: Apache-2.0
 */

use g3_dpi::{H2InterceptionConfig, H2UpstreamProfile};
use g3_types::net::ChromeH2Settings;

/// Chrome marks every request HEADERS with an exclusive dependency on stream 0, weight 256
const CHROME_HEADERS_PRIORITY_WEIGHT: u16 = 256;

/// Builder of the h2 client connection to the upstream server.
///
/// The chrome profile replaces the settings of `http_config` that are visible
/// on the wire (SETTINGS, WINDOW_UPDATE, pseudo header order, HEADERS priority)
/// with Chrome's, so that the HTTP/2 fingerprint matches the TLS one.
pub(super) fn upstream_client_builder(http_config: &H2InterceptionConfig) -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder.max_send_buffer_size(http_config.max_send_buffer_size);

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
        H2UpstreamProfile::Chrome => {
            // no MAX_CONCURRENT_STREAMS and MAX_FRAME_SIZE: Chrome doesn't send them
            builder
                .header_table_size(ChromeH2Settings::HEADER_TABLE_SIZE)
                .enable_push(ChromeH2Settings::ENABLE_PUSH)
                .initial_window_size(ChromeH2Settings::INITIAL_WINDOW_SIZE)
                .max_header_list_size(ChromeH2Settings::MAX_HEADER_LIST_SIZE)
                .initial_connection_window_size(ChromeH2Settings::CONNECTION_WINDOW_SIZE)
                .pseudo_header_authority_first(true)
                .headers_priority(0, CHROME_HEADERS_PRIORITY_WEIGHT, true);
        }
    }
    builder
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
        let (io, mut srv) = tokio::io::duplex(64 * 1024);
        let (mut client, conn) = upstream_client_builder(config)
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
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
}
