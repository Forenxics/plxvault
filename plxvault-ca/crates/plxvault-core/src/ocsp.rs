//! OCSP (Online Certificate Status Protocol) responder

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificateStatus {
    Good,
    Revoked,
    Unknown,
}

pub struct OcspResponder {
    revoked_serials: HashSet<String>,
}

impl OcspResponder {
    pub fn new() -> Self {
        Self {
            revoked_serials: HashSet::new(),
        }
    }

    pub fn add_revoked(&mut self, serial: String) {
        self.revoked_serials.insert(serial);
    }

    pub fn remove_revoked(&mut self, serial: &str) {
        self.revoked_serials.remove(serial);
    }

    pub fn check_status(&self, serial: &str) -> CertificateStatus {
        if self.revoked_serials.contains(serial) {
            CertificateStatus::Revoked
        } else {
            CertificateStatus::Good
        }
    }

    pub fn is_revoked(&self, serial: &str) -> bool {
        self.revoked_serials.contains(serial)
    }

    pub fn revoked_count(&self) -> usize {
        self.revoked_serials.len()
    }
}

impl Default for OcspResponder {
    fn default() -> Self {
        Self::new()
    }
}
