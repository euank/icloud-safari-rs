#![forbid(unsafe_code)]
//! Read, decrypt, and safely prepare updates to Safari data stored in iCloud.

pub mod account;
pub mod anisette;
pub mod auth;
pub mod ckks;
pub mod cloudkit;
pub mod crypto;
pub mod der;
pub mod error;
pub mod fixture;
pub mod keychain;
pub mod model;
pub mod pcs;
pub mod state;
pub mod wire;
pub mod write;

pub use error::{Error, Result};
pub use fixture::{DecryptionReport, OfflineReader};
pub use model::{Dataset, SafariSnapshot};
pub use write::{
    NewBookmark, NewTab, PreparedCreate, PreparedDelete, PreparedFieldUpdate, SaveSemantics,
    WriteWorkspace,
};
