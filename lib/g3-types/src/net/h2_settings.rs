/*
 * SPDX-License-Identifier: Apache-2.0
 */

/// HTTP/2 connection settings Chrome sends, as one source for every place that
/// must look like Chrome: the h2 client of the interception and ALPS in TLS.
pub struct ChromeH2Settings;

impl ChromeH2Settings {
    /// SETTINGS_HEADER_TABLE_SIZE (0x1)
    pub const HEADER_TABLE_SIZE: u32 = 65536;
    /// SETTINGS_ENABLE_PUSH (0x2)
    pub const ENABLE_PUSH: bool = false;
    /// SETTINGS_INITIAL_WINDOW_SIZE (0x4)
    pub const INITIAL_WINDOW_SIZE: u32 = 6 * 1024 * 1024;
    /// SETTINGS_MAX_HEADER_LIST_SIZE (0x6)
    pub const MAX_HEADER_LIST_SIZE: u32 = 256 * 1024;
    /// Connection flow-control window: the default 65535 plus the WINDOW_UPDATE
    /// increment Chrome sends right after SETTINGS
    pub const CONNECTION_WINDOW_SIZE: u32 = 15 * 1024 * 1024;

    /// SETTINGS frame payload in the order Chrome sends it (also used for ALPS)
    pub const fn settings_payload() -> [u8; 24] {
        const fn entry(id: u16, value: u32) -> [u8; 6] {
            let id = id.to_be_bytes();
            let v = value.to_be_bytes();
            [id[0], id[1], v[0], v[1], v[2], v[3]]
        }

        let entries = [
            entry(0x1, Self::HEADER_TABLE_SIZE),
            entry(0x2, Self::ENABLE_PUSH as u32),
            entry(0x4, Self::INITIAL_WINDOW_SIZE),
            entry(0x6, Self::MAX_HEADER_LIST_SIZE),
        ];
        let mut payload = [0u8; 24];
        let mut i = 0;
        while i < payload.len() {
            payload[i] = entries[i / 6][i % 6];
            i += 1;
        }
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_payload() {
        // HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=6291456,
        // MAX_HEADER_LIST_SIZE=262144, each as 16-bit id + 32-bit value
        assert_eq!(
            ChromeH2Settings::settings_payload(),
            [
                0x00, 0x01, 0x00, 0x01, 0x00, 0x00, //
                0x00, 0x02, 0x00, 0x00, 0x00, 0x00, //
                0x00, 0x04, 0x00, 0x60, 0x00, 0x00, //
                0x00, 0x06, 0x00, 0x04, 0x00, 0x00, //
            ]
        );
    }

    #[test]
    fn connection_window_update() {
        // Chrome sends WINDOW_UPDATE 15663105 on stream 0 right after SETTINGS
        assert_eq!(ChromeH2Settings::CONNECTION_WINDOW_SIZE - 65535, 15663105);
    }
}
