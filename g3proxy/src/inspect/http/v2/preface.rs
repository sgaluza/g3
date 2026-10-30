/*
 * SPDX-License-Identifier: Apache-2.0
 */

use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::Instant;

use g3_dpi::parser::h2::H2ClientPreface;
use g3_io_ext::OnceBufReader;

/// Room for one read: a TLS record, larger than a whole Chrome first flight
const READ_CHUNK: usize = 16 * 1024;

/// Read the client first flight up to the end of its first SETTINGS frame and
/// parse it, without waiting for more. All bytes read stay in the returned
/// reader for the h2 server. `None` if the stream is not an h2 preface, ends
/// early, fails or reaches `max_size` before the SETTINGS frame is complete;
/// the h2 server then reports the error itself.
/// With `request_wait` it reads on for at most that long after SETTINGS for
/// the first request HEADERS too, as Chrome may send it in a later TLS record
/// than SETTINGS: for learning the request framing of a client. A preconnect
/// holds the connection open without a request: then SETTINGS alone are
/// returned when the wait is over.
pub(super) async fn read_client_preface<R>(
    clt_r: OnceBufReader<R>,
    max_size: usize,
    request_wait: Option<Duration>,
) -> (OnceBufReader<R>, Option<H2ClientPreface>)
where
    R: AsyncRead + Unpin,
{
    let (buf, mut inner) = clt_r.into_parts();
    let mut data = buf.map(|b| BytesMut::from(&b[..])).unwrap_or_default();
    // SETTINGS already parsed, kept if the request never comes
    let mut parsed = None;
    // set once SETTINGS are parsed: no reads for the request after it
    let mut wait_deadline: Option<Instant> = None;
    loop {
        match H2ClientPreface::parse(&data) {
            Ok(Some(preface)) if request_wait.is_none() || preface.headers.is_some() => {
                return (OnceBufReader::new(inner, data), Some(preface));
            }
            Ok(Some(preface)) => {
                parsed = Some(preface);
                if wait_deadline.is_none() {
                    wait_deadline = request_wait.map(|wait| Instant::now() + wait);
                }
            }
            Ok(None) => {}
            Err(_) => return (OnceBufReader::new(inner, data), None),
        }
        if data.len() >= max_size {
            return (OnceBufReader::new(inner, data), parsed);
        }
        // never read past `max_size`, what is left stays in `inner`; with room
        // reserved one read takes all that already came, the request included
        let limit = max_size - data.len();
        data.reserve(limit.min(READ_CHUNK));
        let mut limited = (&mut inner).take(limit as u64);
        let read = limited.read_buf(&mut data);
        let read = match wait_deadline {
            // a read cut by the deadline consumed nothing: read_buf is cancel safe
            Some(deadline) => match tokio::time::timeout_at(deadline, read).await {
                Ok(r) => r,
                Err(_) => return (OnceBufReader::new(inner, data), parsed),
            },
            None => read.await,
        };
        match read {
            Ok(n) if n > 0 => {}
            _ => return (OnceBufReader::new(inner, data), parsed),
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;

    const CHROME_156: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../lib/g3-dpi/tests/fixtures/chrome156-h2-first-flight.bin"
    ));
    const MAX_SIZE: usize = 64 * 1024;
    const REQUEST_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

    /// Everything the h2 server would read from the returned reader
    async fn replayed(mut r: OnceBufReader<DuplexStream>) -> Vec<u8> {
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        out
    }

    /// Reader with `buffered` already taken by protocol detection and `rest`
    /// still in the stream, closed after it
    async fn reader(buffered: &[u8], rest: &[u8]) -> OnceBufReader<DuplexStream> {
        let (mut w, r) = tokio::io::duplex(MAX_SIZE);
        w.write_all(rest).await.unwrap();
        drop(w);
        OnceBufReader::with_bytes(r, Bytes::copy_from_slice(buffered))
    }

    #[tokio::test]
    async fn parses_chrome_first_flight_and_replays_it() {
        // protocol detection read the preface and a part of SETTINGS
        let r = reader(&CHROME_156[..30], &CHROME_156[30..]).await;
        let (r, preface) = read_client_preface(r, MAX_SIZE, None).await;

        let preface = preface.expect("Chrome first flight");
        assert_eq!(preface.window_update, Some(15663105));
        assert!(preface.headers.is_some());
        assert_eq!(replayed(r).await, CHROME_156);
    }

    #[tokio::test]
    async fn waits_for_the_rest_of_settings_only() {
        // the stream stays open: reading must stop at the end of SETTINGS
        let (mut w, r) = tokio::io::duplex(MAX_SIZE);
        let settings_end = 24 + 9 + 24;
        w.write_all(&CHROME_156[..settings_end]).await.unwrap();
        let r = OnceBufReader::with_no_buf(r);

        let (mut r, preface) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read_client_preface(r, MAX_SIZE, None),
        )
        .await
        .expect("no wait after SETTINGS");
        let preface = preface.unwrap();
        assert_eq!(preface.settings.len(), 4);
        assert_eq!(preface.headers, None);

        w.write_all(&CHROME_156[settings_end..]).await.unwrap();
        drop(w);
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, CHROME_156);
    }

    #[tokio::test]
    async fn not_h2_is_left_to_the_server() {
        let data = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        let (r, preface) = read_client_preface(reader(b"", data).await, MAX_SIZE, None).await;

        assert_eq!(preface, None);
        assert_eq!(replayed(r).await, data);
    }

    #[tokio::test]
    async fn early_end_is_left_to_the_server() {
        let data = &CHROME_156[..40];
        let (r, preface) = read_client_preface(reader(b"", data).await, MAX_SIZE, None).await;

        assert_eq!(preface, None);
        assert_eq!(replayed(r).await, data);
    }

    #[tokio::test]
    async fn too_large_is_left_to_the_server() {
        let (r, preface) = read_client_preface(reader(b"", CHROME_156).await, 30, None).await;

        assert_eq!(preface, None);
        assert_eq!(replayed(r).await, CHROME_156);
    }

    /// Chrome may send its request in a later TLS record: wait for it when asked
    #[tokio::test]
    async fn waits_for_the_request_when_asked() {
        let (mut w, r) = tokio::io::duplex(MAX_SIZE);
        let settings_end = 24 + 9 + 24;
        w.write_all(&CHROME_156[..settings_end]).await.unwrap();
        let rest = CHROME_156[settings_end..].to_vec();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            w.write_all(&rest).await.unwrap();
        });

        let (r, preface) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read_client_preface(OnceBufReader::with_no_buf(r), MAX_SIZE, Some(REQUEST_WAIT)),
        )
        .await
        .expect("the request comes in 100ms");
        assert!(preface.unwrap().headers.is_some());
        assert_eq!(replayed(r).await, CHROME_156);
    }

    /// A preconnect keeps the connection open without a request: the wait for
    /// it is short, then the first flight is used without one
    #[tokio::test]
    async fn preconnect_held_open_ends_the_request_wait() {
        let (mut w, r) = tokio::io::duplex(MAX_SIZE);
        let settings_end = 24 + 9 + 24;
        w.write_all(&CHROME_156[..settings_end]).await.unwrap();

        let started = std::time::Instant::now();
        let (mut r, preface) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read_client_preface(
                OnceBufReader::with_no_buf(r),
                MAX_SIZE,
                Some(std::time::Duration::from_millis(200)),
            ),
        )
        .await
        .expect("no hang until the handshake timeout");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        let preface = preface.expect("SETTINGS came");
        assert_eq!(preface.headers, None);

        // what comes later still reaches the h2 server
        w.write_all(&CHROME_156[settings_end..]).await.unwrap();
        drop(w);
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, CHROME_156);
    }

    /// A client that ends after SETTINGS still has its SETTINGS learned
    #[tokio::test]
    async fn waiting_for_the_request_keeps_settings_on_end() {
        let settings_end = 24 + 9 + 24;
        let data = &CHROME_156[..settings_end];
        let (r, preface) =
            read_client_preface(reader(b"", data).await, MAX_SIZE, Some(REQUEST_WAIT)).await;

        let preface = preface.expect("SETTINGS came");
        assert_eq!(preface.settings.len(), 4);
        assert_eq!(preface.headers, None);
        assert_eq!(replayed(r).await, data);
    }
}
