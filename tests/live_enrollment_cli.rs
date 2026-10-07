//! Opt-in, mutating enrollment E2E test. Never run against an account without
//! explicit permission and a known correct escrow-device password/passcode.
//!
//! Run from a terminal so Apple 2FA prompts can read stdin:
//! `cargo test --test live_enrollment_cli -- --ignored --nocapture`
//!
//! Required environment:
//! - `ICLOUD_E2E_CONFIRM=join-existing-circle`
//! - `ICLOUD_E2E_STATE_DIR=/absolute/private/durable-state`
//! - `ICLOUD_E2E_BOTTLE_ID=<exact viable bottle UUID>`
//! - `ICLOUD_E2E_AWS_REGION=<region>` (fresh recovery only)
//! - `ICLOUD_E2E_APPLE_PASSWORD_PARAMETER=<SSM parameter name[:version]>`
//! - `ICLOUD_E2E_DEVICE_PASSWORD_PARAMETER=<SSM parameter name[:version]>`
//!
//! Optional: `ICLOUD_E2E_BOOTSTRAP_STATE=/private/existing-state` copies only
//! device/session and Anisette state into a fresh target, refusing already
//! enrolled source sessions. `ICLOUD_E2E_APPLE_USERNAME` supplies a username
//! for a completely fresh login; `ICLOUD_E2E_SMS=1` selects SMS verification.
//! `ICLOUD_E2E_RECOVER_AGAIN=1` additionally exercises `keys recover`.
//! `ICLOUD_E2E_RETRY_ESCROW=1` explicitly allows one further recovery attempt
//! after investigating an unresolved prior attempt; never set this automatically.
//!
//! A saved pending peer/recovered bottle resumes without fetching secrets or
//! spending another escrow attempt. An unresolved attempt marker is a hard
//! stop. Durable enrollment state is retained on every failure; only temporary
//! password files are removed. No automatic retry is performed.

#![cfg(feature = "experimental-live-writes")]

use icloud_safari::state::FileStateStore;
use serde::Deserialize;
use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn required(name: &str) -> TestResult<String> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("set {name} before running this test").into())
}

fn cli(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_icloud-safari"));
    command.arg("--state-dir").arg(root).stdin(Stdio::inherit());
    command
}

fn run(command: &mut Command, stage: &str) -> TestResult {
    if !command.status()?.success() {
        return Err(format!(
            "{stage} failed; preserve the durable state and investigate; no retry was attempted"
        )
        .into());
    }
    Ok(())
}

fn read_json(path: &Path) -> TestResult<serde_json::Value> {
    let bytes = Zeroizing::new(fs::read(path)?);
    Ok(serde_json::from_slice(&bytes)?)
}

fn copy_private_tree(source: &Path, destination: &FileStateStore, relative: &Path) -> TestResult {
    let path = source.join(relative);
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() {
        return Err("bootstrap refuses symlinks".into());
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            copy_private_tree(source, destination, &relative.join(entry?.file_name()))?;
        }
    } else if metadata.is_file() {
        let bytes = Zeroizing::new(fs::read(path)?);
        destination.write_bytes(relative, &bytes)?;
    } else {
        return Err("bootstrap refuses non-regular files".into());
    }
    Ok(())
}

fn bootstrap(store: &FileStateStore) -> TestResult {
    if store.root().join("live/session.json").try_exists()? {
        return Ok(());
    }
    let Some(source) = env::var_os("ICLOUD_E2E_BOOTSTRAP_STATE") else {
        return Ok(());
    };
    if store.root().join("live/device.json").try_exists()? {
        return Err(
            "partial target state exists; refusing to overwrite its device identity".into(),
        );
    }
    let source = PathBuf::from(source);
    // Validate the source root and ancestors without changing its permissions.
    let source_store = FileStateStore::new(&source);
    let session: serde_json::Value = source_store.read_json("live/session.json")?;
    if session.get("octagon").is_some_and(|value| !value.is_null()) {
        return Err("bootstrap session already contains an Octagon identity".into());
    }
    for relative in ["live/device.json", "live/session.json", "anisette"] {
        copy_private_tree(&source, store, Path::new(relative))?;
    }
    Ok(())
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct ParameterResponse {
    #[serde(rename = "Parameter")]
    parameter: Parameter,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct Parameter {
    #[serde(rename = "Value")]
    value: String,
}

fn fetch_secret(parameter_env: &str) -> TestResult<Zeroizing<Vec<u8>>> {
    let region = required("ICLOUD_E2E_AWS_REGION")?;
    let parameter = required(parameter_env)?;
    let output = Command::new("aws")
        .args([
            "ssm",
            "get-parameter",
            "--region",
            &region,
            "--name",
            &parameter,
            "--with-decryption",
            "--output",
            "json",
        ])
        .env("AWS_PAGER", "")
        .stdin(Stdio::null())
        .output()?;
    let stdout = Zeroizing::new(output.stdout);
    let _stderr = Zeroizing::new(output.stderr);
    if !output.status.success() {
        return Err(format!("SSM retrieval failed for {parameter_env}; output withheld").into());
    }
    let response: ParameterResponse = serde_json::from_slice(&stdout)
        .map_err(|_| "SSM returned an invalid response; output withheld")?;
    if response.parameter.value.is_empty() {
        return Err("SSM returned an empty secret".into());
    }
    Ok(Zeroizing::new(response.parameter.value.as_bytes().to_vec()))
}

fn password_file(root: &Path, secret: &[u8]) -> TestResult<tempfile::NamedTempFile> {
    let mut file = tempfile::Builder::new()
        .prefix(".e2e-password-")
        .tempfile_in(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(secret)?;
    file.as_file().sync_all()?;
    Ok(file)
}

fn enrollment_command(root: &Path, bottle: &str) -> Command {
    let mut command = cli(root);
    command.args([
        "octagon",
        "enroll",
        "--bottle-id",
        bottle,
        "--confirm-escrow-recovery",
        bottle,
    ]);
    if env::var("ICLOUD_E2E_SMS").as_deref() == Ok("1") {
        command.arg("--sms");
    }
    if env::var("ICLOUD_E2E_RETRY_ESCROW").as_deref() == Ok("1") {
        command.arg("--retry-escrow-recovery");
    }
    command
}

fn optional_bytes(path: &Path) -> TestResult<Option<Zeroizing<Vec<u8>>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[test]
#[ignore = "mutates a real Apple trust circle; requires explicit environment confirmation and known device passcode"]
fn login_enroll_recover_and_resume_without_replaying_escrow() -> TestResult {
    if env::var("ICLOUD_E2E_CONFIRM").as_deref() != Ok("join-existing-circle") {
        return Err(
            "set ICLOUD_E2E_CONFIRM=join-existing-circle to authorize live enrollment".into(),
        );
    }
    let root = PathBuf::from(required("ICLOUD_E2E_STATE_DIR")?);
    if !root.is_absolute() || root.parent().is_none() {
        return Err("ICLOUD_E2E_STATE_DIR must be an absolute dedicated state directory".into());
    }
    let bottle = required("ICLOUD_E2E_BOTTLE_ID")?;
    let store = FileStateStore::new(&root);
    store.ensure()?;
    bootstrap(&store)?;
    let resumable = root.join("enrollment/pending.json").try_exists()?
        || root.join("enrollment/recovery.json").try_exists()?;
    if !resumable
        && root.join("enrollment/attempt.json").try_exists()?
        && env::var("ICLOUD_E2E_RETRY_ESCROW").as_deref() != Ok("1")
    {
        return Err(
            "an unresolved escrow attempt exists; refusing secret fetches or another attempt"
                .into(),
        );
    }
    let mut secrets = None;
    if !resumable {
        if root.join("live/session.json").try_exists()?
            && read_json(&root.join("live/session.json"))?
                .get("octagon")
                .is_some()
        {
            return Err("existing unrelated enrollment is not a fresh E2E target".into());
        }
        let apple = fetch_secret("ICLOUD_E2E_APPLE_PASSWORD_PARAMETER")?;
        let device = fetch_secret("ICLOUD_E2E_DEVICE_PASSWORD_PARAMETER")?;
        let apple_file = password_file(&root, &apple)?;
        let device_file = password_file(&root, &device)?;
        let mut login = cli(&root);
        login
            .arg("login")
            .arg("--password-file")
            .arg(apple_file.path());
        if let Ok(username) = env::var("ICLOUD_E2E_APPLE_USERNAME") {
            login.arg("--username").arg(username);
        }
        if env::var("ICLOUD_E2E_SMS").as_deref() == Ok("1") {
            login.arg("--sms");
        }
        run(&mut login, "login")?;
        secrets = Some((apple_file, device_file));
    }
    let output = cli(&root)
        .args(["escrow", "list"])
        .stderr(Stdio::inherit())
        .output()?;
    let bottles = Zeroizing::new(output.stdout);
    if !output.status.success() {
        return Err("escrow listing failed; no enrollment attempted".into());
    }
    let listed: serde_json::Value = serde_json::from_slice(&bottles)?;
    let count = listed
        .as_array()
        .ok_or("escrow list did not return an array")?
        .iter()
        .filter(|entry| entry["bottle_id"].as_str() == Some(bottle.as_str()))
        .count();
    if count != 1 {
        return Err("requested bottle is missing or ambiguous; no enrollment attempted".into());
    }
    let mut enroll = enrollment_command(&root, &bottle);
    if let Some((apple, device)) = &secrets {
        enroll
            .arg("--password-file")
            .arg(apple.path())
            .arg("--device-passcode-file")
            .arg(device.path());
    }
    run(&mut enroll, "enrollment/key recovery")?;
    // Remove only this run's secret files before the replay-safety check.
    drop(secrets);
    let session = read_json(&root.join("live/session.json"))?;
    if session["octagon"]["joined"].as_bool() != Some(true) {
        return Err("peer was not marked joined".into());
    }
    let peer_id = session["octagon"]["peer_id"]
        .as_str()
        .ok_or("joined peer ID missing")?
        .to_owned();
    let identities = fs::read_dir(root.join("pcs-identities"))?
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "der")
        })
        .count();
    if identities == 0 {
        return Err("no recovered PCS identities were saved".into());
    }
    let attempt_path = root.join("enrollment/attempt.json");
    let recovery_path = root.join("enrollment/recovery.json");
    let attempt = optional_bytes(&attempt_path)?;
    let recovery = optional_bytes(&recovery_path)?;
    run(&mut enrollment_command(&root, &bottle), "enrollment resume")?;
    if optional_bytes(&attempt_path)? != attempt || optional_bytes(&recovery_path)? != recovery {
        return Err("resume changed escrow recovery checkpoints".into());
    }
    let resumed = read_json(&root.join("live/session.json"))?;
    if resumed["octagon"]["joined"].as_bool() != Some(true)
        || resumed["octagon"]["peer_id"].as_str() != Some(peer_id.as_str())
    {
        return Err("resume did not preserve the joined peer".into());
    }
    if env::var("ICLOUD_E2E_RECOVER_AGAIN").as_deref() == Ok("1") {
        run(
            cli(&root).args(["keys", "recover"]),
            "explicit key recovery",
        )?;
    }
    for arguments in [
        vec!["list-tabs", "--json"],
        vec!["list-bookmarks", "--json"],
        vec!["list-history", "--json"],
        vec!["passwords", "list", "--json"],
    ] {
        let output = cli(&root).args(&arguments).output()?;
        let stdout = Zeroizing::new(output.stdout);
        let _stderr = Zeroizing::new(output.stderr);
        if !output.status.success() {
            return Err(
                format!("{} failed after enrollment; output withheld", arguments[0]).into(),
            );
        }
        let value: serde_json::Value = serde_json::from_slice(&stdout)
            .map_err(|_| "read command returned invalid JSON; output withheld")?;
        if arguments[0] == "passwords" {
            let records = value
                .as_array()
                .ok_or("password listing was not an array")?;
            if records
                .iter()
                .any(|record| record["password"].as_str() != Some("********"))
            {
                return Err(
                    "password listing did not redact every password; output withheld".into(),
                );
            }
        }
        eprintln!("Verified {} successfully (output withheld).", arguments[0]);
    }
    eprintln!(
        "Live enrollment and no-replay resume passed; {identities} PCS identity files present. Durable state retained."
    );
    Ok(())
}
