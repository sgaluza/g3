/*
 * SPDX-License-Identifier: Apache-2.0
 */

//! The first flight of an HTTP/2 client (connection preface, SETTINGS and the
//! frames sent with it), for copying its fingerprint to the upstream connection

use thiserror::Error;

/// A request pseudo-header
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum H2PseudoHeader {
    Method,
    Scheme,
    Authority,
    Path,
}

/// Stream dependency of a HEADERS frame with the PRIORITY flag
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H2HeadersPriority {
    pub exclusive: bool,
    pub dependency: u32,
    /// 1 to 256
    pub weight: u16,
}

/// What the first request HEADERS frame tells about the client
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct H2FirstHeaders {
    pub priority: Option<H2HeadersPriority>,
    /// Pseudo-headers in wire order
    pub pseudo_order: Vec<H2PseudoHeader>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum H2PrefaceParseError {
    #[error("no HTTP/2 connection preface")]
    NoPreface,
    #[error("the first frame is not SETTINGS")]
    NoSettings,
    #[error("invalid SETTINGS length {0}")]
    InvalidSettingsLength(usize),
    #[error("invalid {0} frame")]
    InvalidFrame(&'static str),
}

/// The first flight of an HTTP/2 client
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct H2ClientPreface {
    /// SETTINGS (id, value) in wire order
    pub settings: Vec<(u16, u32)>,
    /// Connection WINDOW_UPDATE increment, if sent in the first flight
    pub window_update: Option<u32>,
    /// Number of PRIORITY frames before the first HEADERS
    pub priority_frames: usize,
    /// The first request, if it came in the first flight
    pub headers: Option<H2FirstHeaders>,
}

const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER_LEN: usize = 9;

const FRAME_HEADERS: u8 = 0x1;
const FRAME_PRIORITY: u8 = 0x2;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_WINDOW_UPDATE: u8 = 0x8;

/// Largest flow control window (RFC 9113 section 6.9.1)
const MAX_WINDOW_SIZE: u32 = 0x7fff_ffff;

const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

/// One complete frame: type, flags, stream id and payload
struct Frame<'a> {
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: &'a [u8],
}

/// The complete frame at the start of `buf` and the bytes after it, `None` if incomplete
fn next_frame(buf: &[u8]) -> Option<(Frame<'_>, &[u8])> {
    let head = buf.get(..FRAME_HEADER_LEN)?;
    let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let payload = buf.get(FRAME_HEADER_LEN..FRAME_HEADER_LEN + len)?;
    let frame = Frame {
        kind: head[3],
        flags: head[4],
        stream_id: u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff,
        payload,
    };
    Some((frame, &buf[FRAME_HEADER_LEN + len..]))
}

impl H2ClientPreface {
    /// Parse the start of a client connection. `Ok(None)` if the first SETTINGS
    /// frame is not complete yet; frames after it are taken as far as they came.
    pub fn parse(buf: &[u8]) -> Result<Option<Self>, H2PrefaceParseError> {
        let checked = buf.len().min(CONNECTION_PREFACE.len());
        if buf[..checked] != CONNECTION_PREFACE[..checked] {
            return Err(H2PrefaceParseError::NoPreface);
        }
        let Some(rest) = buf.get(CONNECTION_PREFACE.len()..) else {
            return Ok(None);
        };
        // only the frame type is needed to reject a flight without SETTINGS first
        if rest.len() > 3 && rest[3] != FRAME_SETTINGS {
            return Err(H2PrefaceParseError::NoSettings);
        }
        let Some((settings, mut rest)) = next_frame(rest) else {
            return Ok(None);
        };
        if settings.flags & FLAG_ACK != 0 || settings.stream_id != 0 {
            return Err(H2PrefaceParseError::NoSettings);
        }

        let mut preface = H2ClientPreface {
            settings: parse_settings(settings.payload)?,
            ..Default::default()
        };
        while let Some((frame, next)) = next_frame(rest) {
            rest = next;
            match frame.kind {
                FRAME_WINDOW_UPDATE if frame.stream_id == 0 => {
                    let increment = <[u8; 4]>::try_from(frame.payload)
                        .map_err(|_| H2PrefaceParseError::InvalidFrame("WINDOW_UPDATE"))?;
                    // increments add up (RFC 9113 section 6.9), up to the largest window
                    let increment = u32::from_be_bytes(increment) & MAX_WINDOW_SIZE;
                    let total = preface.window_update.unwrap_or(0).saturating_add(increment);
                    preface.window_update = Some(total.min(MAX_WINDOW_SIZE));
                }
                FRAME_PRIORITY => preface.priority_frames += 1,
                FRAME_HEADERS => {
                    // a header block split into CONTINUATION frames is left out
                    if frame.flags & FLAG_END_HEADERS != 0 {
                        preface.headers = Some(parse_headers(&frame)?);
                    }
                    break;
                }
                _ => {}
            }
        }
        Ok(Some(preface))
    }

    /// SETTINGS frame payload with the same settings in the same order, as used for ALPS
    pub fn settings_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(self.settings.len() * 6);
        for (id, value) in &self.settings {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&value.to_be_bytes());
        }
        payload
    }
}

fn parse_settings(payload: &[u8]) -> Result<Vec<(u16, u32)>, H2PrefaceParseError> {
    // `% 6` rather than is_multiple_of, stable only since Rust 1.87 (MSRV 1.86)
    if payload.len() % 6 != 0 {
        return Err(H2PrefaceParseError::InvalidSettingsLength(payload.len()));
    }
    Ok(payload
        .chunks_exact(6)
        .map(|s| {
            (
                u16::from_be_bytes([s[0], s[1]]),
                u32::from_be_bytes([s[2], s[3], s[4], s[5]]),
            )
        })
        .collect())
}

/// PRIORITY and pseudo-header order of a HEADERS frame with END_HEADERS
fn parse_headers(frame: &Frame<'_>) -> Result<H2FirstHeaders, H2PrefaceParseError> {
    let invalid = || H2PrefaceParseError::InvalidFrame("HEADERS");
    let mut block = frame.payload;
    let mut pad_len = 0;
    if frame.flags & FLAG_PADDED != 0 {
        let (&len, rest) = block.split_first().ok_or_else(invalid)?;
        pad_len = len as usize;
        block = rest;
    }
    let mut headers = H2FirstHeaders::default();
    if frame.flags & FLAG_PRIORITY != 0 {
        let p = block.get(..5).ok_or_else(invalid)?;
        let dep = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
        headers.priority = Some(H2HeadersPriority {
            exclusive: dep >> 31 == 1,
            dependency: dep & 0x7fff_ffff,
            weight: p[4] as u16 + 1,
        });
        block = &block[5..];
    }
    let block_len = block.len().checked_sub(pad_len).ok_or_else(invalid)?;
    headers.pseudo_order = pseudo_order(&block[..block_len]);
    Ok(headers)
}

/// HPACK integer with an N-bit prefix (RFC 7541 section 5.1): value and bytes used
fn hpack_int(buf: &[u8], prefix_bits: u8) -> Option<(usize, usize)> {
    let mask = (1usize << prefix_bits) - 1;
    let mut value = *buf.first()? as usize & mask;
    if value < mask {
        return Some((value, 1));
    }
    let mut used = 1;
    for shift in (0..28).step_by(7) {
        let b = *buf.get(used)?;
        used += 1;
        value += ((b & 0x7f) as usize) << shift;
        if b & 0x80 == 0 {
            return Some((value, used));
        }
    }
    None
}

/// Pseudo-headers at the start of the first header block, by the static table
/// index of their names (RFC 7541 appendix A): the dynamic table is still empty
fn pseudo_order(mut block: &[u8]) -> Vec<H2PseudoHeader> {
    let mut order = Vec::with_capacity(4);
    while let Some(&b) = block.first() {
        let (index, used) = if b & 0x80 != 0 {
            // indexed header field
            let Some(v) = hpack_int(block, 7) else { break };
            v
        } else if b & 0xe0 == 0x20 {
            // dynamic table size update
            let Some((_, n)) = hpack_int(block, 5) else {
                break;
            };
            block = &block[n..];
            continue;
        } else {
            // literal, with incremental indexing (6-bit prefix) or not (4-bit)
            let prefix = if b & 0x40 != 0 { 6 } else { 4 };
            let Some((i, n)) = hpack_int(block, prefix) else {
                break;
            };
            let Some((len, m)) = block.get(n..).and_then(|v| hpack_int(v, 7)) else {
                break;
            };
            (i, n + m + len)
        };
        let header = match index {
            1 => H2PseudoHeader::Authority,
            2 | 3 => H2PseudoHeader::Method,
            4 | 5 => H2PseudoHeader::Path,
            6 | 7 => H2PseudoHeader::Scheme,
            // a regular header field: the pseudo-headers are over
            _ => break,
        };
        order.push(header);
        let Some(rest) = block.get(used..) else { break };
        block = rest;
    }
    order
}

#[cfg(test)]
mod tests {
    use super::H2PseudoHeader::*;
    use super::*;

    /// First flight of Chrome 156.0.8078.47 (web-agent:0.1.167-cpu) and Chrome
    /// 150.0.7871.128 (screen-tracker), decrypted by a local h2 TLS server
    const CHROME_156: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/chrome156-h2-first-flight.bin"
    ));
    const CHROME_150: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/chrome150-h2-first-flight.bin"
    ));

    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    const CHROME_SETTINGS: [(u16, u32); 4] = [(1, 65536), (2, 0), (4, 6291456), (6, 262144)];

    /// A frame with a 9 byte header
    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        f.push(kind);
        f.push(flags);
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// Byte offset of the end of the frames before the first HEADERS
    fn before_headers(flight: &[u8]) -> usize {
        let mut off = PREFACE.len();
        loop {
            let len = u32::from_be_bytes([0, flight[off], flight[off + 1], flight[off + 2]]);
            if flight[off + 3] == 0x1 {
                return off;
            }
            off += 9 + len as usize;
        }
    }

    fn assert_chrome(p: &H2ClientPreface) {
        assert_eq!(p.settings, CHROME_SETTINGS);
        assert_eq!(p.window_update, Some(15663105));
        assert_eq!(p.priority_frames, 0);
        let headers = p
            .headers
            .as_ref()
            .expect("first request in the first flight");
        assert_eq!(
            headers.priority,
            Some(H2HeadersPriority {
                exclusive: true,
                dependency: 0,
                weight: 256
            })
        );
        assert_eq!(headers.pseudo_order, [Method, Authority, Scheme, Path]);
    }

    #[test]
    fn parses_chrome_156() {
        assert_chrome(&H2ClientPreface::parse(CHROME_156).unwrap().unwrap());
    }

    #[test]
    fn parses_chrome_150() {
        assert_chrome(&H2ClientPreface::parse(CHROME_150).unwrap().unwrap());
    }

    #[test]
    fn settings_payload_is_chrome_alps() {
        let p = H2ClientPreface::parse(CHROME_156).unwrap().unwrap();
        assert_eq!(
            p.settings_payload(),
            g3_types::net::ChromeH2Settings::settings_payload()
        );
    }

    #[test]
    fn preconnect_without_request() {
        let flight = &CHROME_156[..before_headers(CHROME_156)];
        let p = H2ClientPreface::parse(flight).unwrap().unwrap();

        assert_eq!(p.settings, CHROME_SETTINGS);
        assert_eq!(p.window_update, Some(15663105));
        assert_eq!(p.headers, None);
    }

    #[test]
    fn window_updates_add_up() {
        // RFC 9113 section 6.9: increments are additive, the window can't pass 2^31-1
        let mut flight = PREFACE.to_vec();
        flight.extend(frame(0x4, 0, 0, &[]));
        flight.extend(frame(0x8, 0, 0, &100u32.to_be_bytes()));
        flight.extend(frame(0x8, 0, 3, &7u32.to_be_bytes())); // a stream window, not counted
        flight.extend(frame(0x8, 0, 0, &200u32.to_be_bytes()));
        let p = H2ClientPreface::parse(&flight).unwrap().unwrap();
        assert_eq!(p.window_update, Some(300));

        let mut flight = PREFACE.to_vec();
        flight.extend(frame(0x4, 0, 0, &[]));
        flight.extend(frame(0x8, 0, 0, &0x7fff_ffffu32.to_be_bytes()));
        flight.extend(frame(0x8, 0, 0, &0x7fff_ffffu32.to_be_bytes()));
        let p = H2ClientPreface::parse(&flight).unwrap().unwrap();
        assert_eq!(p.window_update, Some(0x7fff_ffff));
    }

    #[test]
    fn incomplete_settings_needs_more_data() {
        for end in [0, 10, PREFACE.len(), PREFACE.len() + 9, PREFACE.len() + 20] {
            assert_eq!(
                H2ClientPreface::parse(&CHROME_156[..end]),
                Ok(None),
                "{end}"
            );
        }
    }

    #[test]
    fn incomplete_headers_is_left_out() {
        let end = before_headers(CHROME_156) + 12;
        let p = H2ClientPreface::parse(&CHROME_156[..end]).unwrap().unwrap();
        assert_eq!(p.headers, None);
    }

    #[test]
    fn firefox_like_flight() {
        // SETTINGS 1:65536;4:131072;5:16384, WINDOW_UPDATE, HEADERS without
        // PRIORITY with :method GET, :path /, :authority (literal), :scheme https
        let mut flight = PREFACE.to_vec();
        let mut settings = Vec::new();
        for (id, v) in [(1u16, 65536u32), (4, 131072), (5, 16384)] {
            settings.extend_from_slice(&id.to_be_bytes());
            settings.extend_from_slice(&v.to_be_bytes());
        }
        flight.extend(frame(0x4, 0, 0, &settings));
        flight.extend(frame(0x8, 0, 0, &12517377u32.to_be_bytes()));
        let block = [0x82, 0x84, 0x41, 0x03, b'a', b'.', b'b', 0x87];
        flight.extend(frame(0x1, 0x4 | 0x1, 1, &block));

        let p = H2ClientPreface::parse(&flight).unwrap().unwrap();
        assert_eq!(p.settings, [(1, 65536), (4, 131072), (5, 16384)]);
        assert_eq!(p.window_update, Some(12517377));
        let headers = p.headers.unwrap();
        assert_eq!(headers.priority, None);
        assert_eq!(headers.pseudo_order, [Method, Path, Authority, Scheme]);
    }

    #[test]
    fn counts_priority_frames_and_skips_padding() {
        let mut flight = PREFACE.to_vec();
        flight.extend(frame(0x4, 0, 0, &[]));
        flight.extend(frame(0x2, 0, 3, &[0, 0, 0, 0, 200]));
        flight.extend(frame(0x2, 0, 5, &[0, 0, 0, 0, 100]));
        // PADDED: pad length 2, HPACK size update 0x20 then :method GET, then padding
        let block = [0x02, 0x20, 0x82, 0x87, 0x84, 0x41, 0x01, b'x', 0, 0];
        flight.extend(frame(0x1, 0x8 | 0x4 | 0x1, 1, &block));

        let p = H2ClientPreface::parse(&flight).unwrap().unwrap();
        assert_eq!(p.settings, []);
        assert_eq!(p.window_update, None);
        assert_eq!(p.priority_frames, 2);
        assert_eq!(
            p.headers.unwrap().pseudo_order,
            [Method, Scheme, Path, Authority]
        );
    }

    #[test]
    fn rejects_broken_flights() {
        assert_eq!(
            H2ClientPreface::parse(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
            Err(H2PrefaceParseError::NoPreface)
        );

        let mut not_settings = PREFACE.to_vec();
        not_settings.extend(frame(0x8, 0, 0, &1u32.to_be_bytes()));
        assert_eq!(
            H2ClientPreface::parse(&not_settings),
            Err(H2PrefaceParseError::NoSettings)
        );

        let mut odd_settings = PREFACE.to_vec();
        odd_settings.extend(frame(0x4, 0, 0, &[0, 1, 0, 0, 0]));
        assert_eq!(
            H2ClientPreface::parse(&odd_settings),
            Err(H2PrefaceParseError::InvalidSettingsLength(5))
        );
    }
}
