/*
 * SPDX-License-Identifier: Apache-2.0
 */

//! Calibration of the client profile for strict mirroring: who this g3proxy
//! serves (for log events) and the readiness file for the browser

use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use log::warn;
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;

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

/// Mark a newly calibrated client in the readiness file in a task of its own:
/// the connection goes on at once, even if the shared volume hangs. A failed
/// write is logged as a warning.
pub(super) fn spawn_mark_calibrated(path: PathBuf, client: String) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = mark_calibrated(&path, &client).await {
            warn!("failed to write calibrated file {}: {e}", path.display());
        }
    })
}

/// Append the key of a newly calibrated client to the readiness file, in one
/// write so concurrent calibrations don't interleave
async fn mark_calibrated(path: &Path, client: &str) -> io::Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    file.write_all(format!("{client}\n").as_bytes()).await?;
    file.flush().await
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

    /// Written off the async worker threads: the file may be on a slow shared volume
    #[tokio::test]
    async fn calibrated_clients_are_appended() {
        let dir = std::env::temp_dir().join(format!("g3proxy-calib-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("calibrated");
        let _ = std::fs::remove_file(&path);

        mark_calibrated(&path, "0123456789ab").await.unwrap();
        mark_calibrated(&path, "ba9876543210@bot-1").await.unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "0123456789ab\nba9876543210@bot-1\n");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The caller doesn't wait for the file: the write runs in a task, done
    /// when the task is
    #[tokio::test]
    async fn calibrated_client_is_marked_in_a_task() {
        let dir = std::env::temp_dir().join(format!("g3proxy-calib-task-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("calibrated");
        let _ = std::fs::remove_file(&path);

        spawn_mark_calibrated(path.clone(), "0123456789ab".to_string())
            .await
            .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "0123456789ab\n");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A write that fails ends the task without a panic
    #[tokio::test]
    async fn failed_mark_ends_the_task() {
        let path = std::env::temp_dir()
            .join(format!("g3proxy-calib-missing-{}", std::process::id()))
            .join("calibrated");

        spawn_mark_calibrated(path, "0123456789ab".to_string())
            .await
            .unwrap();
    }
}
