/*
 * SPDX-License-Identifier: Apache-2.0
 */

//! What the interception client learns about each client (browser build and
//! proxy user): the HTTP/2 SETTINGS for ALPS and the request framing of h2

use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use lru::LruCache;

use super::BrowserClientHello;
use crate::net::{ChromeH2Settings, H2FirstHeaders};

/// Profiles kept at a time, far more than browser builds behind one proxy
pub(super) const CLIENT_PROFILES_CAPACITY: NonZeroUsize = NonZeroUsize::new(64).unwrap();

/// A client: its browser build, by the ClientHello, and its proxy user
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientProfileKey {
    /// `BrowserClientHello::profile_key`
    pub hello: String,
    pub user: Option<String>,
}

impl ClientProfileKey {
    pub fn new(browser: &BrowserClientHello, user: Option<&str>) -> Self {
        ClientProfileKey {
            hello: browser.profile_key(),
            user: user.map(|u| u.to_string()),
        }
    }
}

impl fmt::Display for ClientProfileKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.user {
            Some(user) => write!(f, "{}@{user}", self.hello),
            None => f.write_str(&self.hello),
        }
    }
}

/// What is learned about a client from its h2 connections
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientProfile {
    /// SETTINGS payload the upstream connections send for it, also its ALPS
    pub h2_settings: Option<Vec<u8>>,
    /// Pseudo-header order and HEADERS priority of its requests
    pub request: Option<H2FirstHeaders>,
    /// Both are known: the client may go to real sites in strict mode
    pub calibrated: bool,
}

/// Result of `ClientProfiles::learn_h2`
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LearnedH2 {
    /// The ALPS SETTINGS of the client changed (from Chrome's before any)
    pub settings_changed: bool,
    /// The client became calibrated with this connection
    pub newly_calibrated: bool,
}

/// Profiles by client, shared by all connections of an interception client config
pub(super) struct ClientProfiles {
    lru: Mutex<LruCache<ClientProfileKey, ClientProfile>>,
}

impl ClientProfiles {
    pub(super) fn new(capacity: NonZeroUsize) -> Self {
        ClientProfiles {
            lru: Mutex::new(LruCache::new(capacity)),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LruCache<ClientProfileKey, ClientProfile>> {
        self.lru.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(super) fn get(&self, key: &ClientProfileKey) -> Option<ClientProfile> {
        self.lock().get(key).cloned()
    }

    /// Learn from an h2 connection of the client: the SETTINGS sent upstream
    /// and, if its first flight had a request, the request framing
    pub(super) fn learn_h2(
        &self,
        key: &ClientProfileKey,
        settings: &[u8],
        request: Option<&H2FirstHeaders>,
    ) -> LearnedH2 {
        let mut lru = self.lock();
        let profile = lru.get_or_insert_mut(key.clone(), ClientProfile::default);

        // ALPS carried Chrome's SETTINGS while nothing was learned
        let chrome = ChromeH2Settings::settings_payload();
        let previous = profile.h2_settings.as_deref().unwrap_or(&chrome);
        let settings_changed = previous != settings;
        profile.h2_settings = Some(settings.to_vec());
        if let Some(request) = request {
            profile.request = Some(request.clone());
        }

        let newly_calibrated = !profile.calibrated && profile.request.is_some();
        profile.calibrated |= newly_calibrated;
        LearnedH2 {
            settings_changed,
            newly_calibrated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::H2PseudoHeader;

    fn key(hello: &str) -> ClientProfileKey {
        ClientProfileKey {
            hello: hello.to_string(),
            user: None,
        }
    }

    fn request() -> H2FirstHeaders {
        H2FirstHeaders {
            priority: None,
            pseudo_order: vec![
                H2PseudoHeader::Method,
                H2PseudoHeader::Path,
                H2PseudoHeader::Authority,
                H2PseudoHeader::Scheme,
            ],
        }
    }

    const OTHER_SETTINGS: [u8; 6] = [0x00, 0x01, 0x00, 0x01, 0x00, 0x00];

    #[test]
    fn calibrated_once_settings_and_request_are_known() {
        let profiles = ClientProfiles::new(CLIENT_PROFILES_CAPACITY);
        let k = key("aaaaaaaaaaaa");
        assert_eq!(profiles.get(&k), None);

        // a preconnect: SETTINGS without a request
        let learned = profiles.learn_h2(&k, &OTHER_SETTINGS, None);
        assert!(learned.settings_changed);
        assert!(!learned.newly_calibrated);
        let p = profiles.get(&k).unwrap();
        assert_eq!(p.h2_settings.as_deref(), Some(OTHER_SETTINGS.as_slice()));
        assert!(!p.calibrated);

        // a connection with a request completes the profile
        let learned = profiles.learn_h2(&k, &OTHER_SETTINGS, Some(&request()));
        assert!(!learned.settings_changed);
        assert!(learned.newly_calibrated);
        let p = profiles.get(&k).unwrap();
        assert_eq!(p.request, Some(request()));
        assert!(p.calibrated);

        // calibration is reported once
        let learned = profiles.learn_h2(&k, &OTHER_SETTINGS, Some(&request()));
        assert_eq!(learned, LearnedH2::default());
    }

    #[test]
    fn chrome_settings_are_no_change_for_a_new_client() {
        // ALPS carried Chrome's SETTINGS before anything was learned
        let profiles = ClientProfiles::new(CLIENT_PROFILES_CAPACITY);
        let learned = profiles.learn_h2(
            &key("bbbbbbbbbbbb"),
            &ChromeH2Settings::settings_payload(),
            Some(&request()),
        );
        assert!(!learned.settings_changed);
        assert!(learned.newly_calibrated);
    }

    #[test]
    fn clients_have_their_own_profiles() {
        let profiles = ClientProfiles::new(CLIENT_PROFILES_CAPACITY);
        profiles.learn_h2(&key("aaaaaaaaaaaa"), &OTHER_SETTINGS, Some(&request()));

        assert!(profiles.get(&key("aaaaaaaaaaaa")).unwrap().calibrated);
        assert_eq!(profiles.get(&key("bbbbbbbbbbbb")), None);
        let mut with_user = key("aaaaaaaaaaaa");
        with_user.user = Some("bot-1".to_string());
        assert_eq!(profiles.get(&with_user), None);
    }

    #[test]
    fn least_recently_used_profile_is_dropped() {
        let profiles = ClientProfiles::new(NonZeroUsize::new(2).unwrap());
        for k in ["aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"] {
            profiles.learn_h2(&key(k), &OTHER_SETTINGS, Some(&request()));
        }
        assert_eq!(profiles.get(&key("aaaaaaaaaaaa")), None);
        assert!(profiles.get(&key("cccccccccccc")).is_some());
    }

    #[test]
    fn key_display_has_hello_and_user() {
        let mut k = key("0123456789ab");
        assert_eq!(k.to_string(), "0123456789ab");
        k.user = Some("bot-1".to_string());
        assert_eq!(k.to_string(), "0123456789ab@bot-1");
    }
}
