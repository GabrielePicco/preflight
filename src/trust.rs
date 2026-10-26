//! Trust list: absolute path -> SHA-256 of the content you approved.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TrustStore {
    #[serde(default)]
    pub files: BTreeMap<String, TrustEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEntry {
    pub sha256: String,
    pub trusted_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustState {
    Trusted,
    New,
    Changed,
}

impl TrustState {
    pub fn as_str(self) -> &'static str {
        match self {
            TrustState::Trusted => "trusted",
            TrustState::New => "new",
            TrustState::Changed => "changed",
        }
    }
}

impl TrustStore {
    pub fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(s) => {
                serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_string_pretty(self)? + "\n")?;
        fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))
    }

    pub fn state(&self, path: &Path, sha256: &str) -> TrustState {
        match self.files.get(&key(path)) {
            None => TrustState::New,
            Some(e) if e.sha256 == sha256 => TrustState::Trusted,
            Some(_) => TrustState::Changed,
        }
    }

    pub fn trust(&mut self, path: &Path, sha256: &str) {
        let entry = TrustEntry {
            sha256: sha256.to_string(),
            trusted_at: crate::now(),
        };
        self.files.insert(key(path), entry);
    }
}

pub fn key(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn sha256_file(path: &Path) -> Result<String> {
    Ok(sha256_bytes(
        &fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_trusted_changed() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("AGENTS.md");
        fs::write(&f, "v1").unwrap();
        let store_path = t.path().join("cfg/trusted.json");
        let mut store = TrustStore::load(&store_path).unwrap();
        let h1 = sha256_file(&f).unwrap();
        assert_eq!(store.state(&f, &h1), TrustState::New);
        store.trust(&f, &h1);
        store.save(&store_path).unwrap();

        let store = TrustStore::load(&store_path).unwrap();
        assert_eq!(store.state(&f, &h1), TrustState::Trusted);
        fs::write(&f, "v2").unwrap();
        assert_eq!(
            store.state(&f, &sha256_file(&f).unwrap()),
            TrustState::Changed
        );
    }

    #[test]
    fn sha256_known_value() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
