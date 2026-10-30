/*
 * SPDX-License-Identifier: Apache-2.0
 */

//! Calibration of the client profile for strict mirroring: who this g3proxy
//! serves (for log events) and the readiness file for the browser

use std::io::{self, Write};
use std::path::Path;
use std::sync::OnceLock;

/// Environment variables naming what this g3proxy serves, with their log names
const IDENTITY_VARS: [(&str, &str); 4] = [
    ("SESSION_ID", "session"),
    ("BOT_ID", "bot"),
    ("POD_NAME", "pod"),
    ("NODE_NAME", "node"),
];

/// Pod identity for events: SESSION_ID, BOT_ID, POD_NAME and NODE_NAME, only
/// those set, `-` if none
pub(super) fn identity_from(var: impl Fn(&str) -> Option<String>) -> String {
    let parts: Vec<String> = IDENTITY_VARS
        .iter()
        .filter_map(|(env, name)| var(env).map(|v| format!("{name}={v}")))
        .collect();
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(" ")
    }
}

/// Pod identity of this process, read once
pub(super) fn identity() -> &'static str {
    static IDENTITY: OnceLock<String> = OnceLock::new();
    IDENTITY.get_or_init(|| identity_from(|name| std::env::var(name).ok()))
}

/// Append the key of a newly calibrated client to the readiness file
pub(super) fn mark_calibrated(path: &Path, client: &str) -> io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{client}")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn identity_lists_what_is_set() {
        let all = vars(&[
            ("SESSION_ID", "s-1"),
            ("BOT_ID", "b-2"),
            ("POD_NAME", "bot-abc"),
            ("NODE_NAME", "node-3"),
        ]);
        assert_eq!(
            identity_from(all),
            "session=s-1 bot=b-2 pod=bot-abc node=node-3"
        );

        let some = vars(&[("BOT_ID", "b-2"), ("POD_NAME", "bot-abc")]);
        assert_eq!(identity_from(some), "bot=b-2 pod=bot-abc");

        assert_eq!(identity_from(vars(&[])), "-");
    }

    #[test]
    fn calibrated_clients_are_appended() {
        let dir = std::env::temp_dir().join(format!("g3proxy-calib-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("calibrated");
        let _ = std::fs::remove_file(&path);

        mark_calibrated(&path, "0123456789ab").unwrap();
        mark_calibrated(&path, "ba9876543210@bot-1").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "0123456789ab\nba9876543210@bot-1\n");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
