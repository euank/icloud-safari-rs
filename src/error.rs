use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed protobuf: {0}")]
    Protobuf(&'static str),
    #[error("malformed DER: {0}")]
    Der(&'static str),
    #[error("cryptographic integrity check failed")]
    Integrity,
    #[error("unsupported protocol feature: {0}")]
    Unsupported(&'static str),
    #[error("ambiguous four-byte PCS key identifier")]
    AmbiguousKeyId,
    #[error("invalid fixture: {0}")]
    Fixture(String),
    #[error("state file has unsafe permissions: {0}")]
    UnsafePermissions(PathBuf),
    #[error("no cached {0} dataset; fetch it explicitly or provide a fixture directory")]
    MissingDataset(&'static str),
    #[error("authentication is required")]
    AuthenticationRequired,
    #[error("Apple authentication failed: {0}")]
    Authentication(String),
    #[error("Anisette operation failed: {0}")]
    Anisette(String),
    #[error("network operation failed: {0}")]
    Network(String),
    #[error("I/O operation failed")]
    Io(#[from] std::io::Error),
    #[error("JSON operation failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("property-list operation failed: {0}")]
    Plist(#[from] plist::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
