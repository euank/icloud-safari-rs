//! Opt-in CLI CRUD on an already enrolled disposable-test account.
//! `ICLOUD_CLI_CRUD_CONFIRM=disposable-records ICLOUD_LIVE_STATE_DIR=/private/state
//! cargo test --test live_cli_crud -- --ignored --nocapture`
//!
//! All CLI output is captured, never printed. Passwords are random synthetic
//! values supplied in private temporary files. Before each create, a durable
//! journal records its unique marker; IDs are discovered through authenticated
//! JSON reads. Cleanup independently checks ownership and attempts every started
//! dataset, even after another cleanup fails. A kill/network outage can prevent
//! cleanup: preserve `e2e/cli-crud-*.json` and investigate; do not blindly retry.
//! Optional `ICLOUD_CLI_CRUD_RESUME=1` first converts the already-joined
//! `enrollment/sponsored-pending.json` to a standard checkpoint and verifies
//! CLI resume preserves all keys without creating an escrow attempt marker.
#![cfg(feature = "experimental-live-writes")]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use icloud_safari::{cloudkit::SessionState, enrollment::Enrollment, state::FileStateStore};
use serde::{Deserialize, Serialize};
use std::{
    env,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Bookmarks,
    Tabs,
    Passwords,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Bookmarks => "bookmarks",
            Self::Tabs => "tabs",
            Self::Passwords => "passwords",
        }
    }
}
#[derive(Serialize)]
struct Target {
    kind: Kind,
    started: bool,
    record: Option<String>,
}
#[derive(Serialize)]
struct Journal {
    marker: String,
    targets: Vec<Target>,
    completed: bool,
}
impl Journal {
    fn save(&self, store: &FileStateStore) -> TestResult {
        let _guard = store.try_lock()?;
        store.write_json(format!("e2e/cli-crud-{}.json", self.marker), self)?;
        Ok(())
    }
    fn domain(&self) -> String {
        format!("{}.example.invalid", self.marker)
    }
    fn url(&self) -> String {
        format!("https://{}/disposable", self.domain())
    }
    fn updated(&self) -> String {
        format!("{} updated", self.marker)
    }
}

fn command(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_icloud-safari"));
    command.arg("--state-dir").arg(root).stdin(Stdio::null());
    command
}
fn run(command: &mut Command, stage: &str) -> TestResult<Zeroizing<Vec<u8>>> {
    let output = command.output()?;
    let stdout = Zeroizing::new(output.stdout);
    let _stderr = Zeroizing::new(output.stderr);
    if !output.status.success() {
        return Err(format!("{stage} failed; output withheld; no retry attempted").into());
    }
    Ok(stdout)
}

#[derive(Serialize, Deserialize)]
struct PendingEnrollment {
    dsid: String,
    bottle_id: String,
    enrollment: Enrollment,
}

fn verify_sponsored_cli_resume(store: &FileStateStore) -> TestResult {
    const BOTTLE: &str = "sponsored-existing-keys";
    let expected = {
        let _guard = store.try_lock()?;
        if store.root().join("enrollment/attempt.json").try_exists()? {
            return Err("resume check requires state without an escrow attempt marker".into());
        }
        let session: SessionState = store.read_json("live/session.json")?;
        let before: Enrollment = serde_json::from_value(
            session
                .extra
                .get("octagon")
                .ok_or("missing joined enrollment")?
                .clone(),
        )?;
        let source: Enrollment = store.read_json("enrollment/sponsored-pending.json")?;
        let expected = Zeroizing::new(serde_json::to_vec(&before)?);
        let source_bytes = Zeroizing::new(serde_json::to_vec(&source)?);
        if !before.joined || *source_bytes != *expected {
            return Err(
                "sponsored checkpoint differs from the saved joined peer; refusing overwrite"
                    .into(),
            );
        }
        if store.root().join("enrollment/pending.json").try_exists()? {
            let pending: PendingEnrollment = store.read_json("enrollment/pending.json")?;
            let encoded = Zeroizing::new(serde_json::to_vec(&pending.enrollment)?);
            if pending.dsid != session.mme.dsid
                || pending.bottle_id != BOTTLE
                || *encoded != *expected
            {
                return Err("standard pending checkpoint differs; refusing overwrite".into());
            }
        } else {
            store.write_json(
                "enrollment/pending.json",
                &PendingEnrollment {
                    dsid: session.mme.dsid.clone(),
                    bottle_id: BOTTLE.into(),
                    enrollment: source,
                },
            )?;
        }
        expected
    };
    run(
        command(store.root()).args([
            "octagon",
            "enroll",
            "--bottle-id",
            BOTTLE,
            "--confirm-escrow-recovery",
            BOTTLE,
        ]),
        "already-joined CLI resume",
    )?;
    let session: SessionState = store.read_json("live/session.json")?;
    let after: Enrollment = serde_json::from_value(
        session
            .extra
            .get("octagon")
            .ok_or("resumed enrollment missing")?
            .clone(),
    )?;
    let actual = Zeroizing::new(serde_json::to_vec(&after)?);
    if !after.joined
        || *actual != *expected
        || store.root().join("enrollment/attempt.json").try_exists()?
    {
        return Err(
            "CLI resume changed peer/key material or created an escrow attempt marker".into(),
        );
    }
    eprintln!("Already-joined CLI resume verified; identity unchanged, no escrow attempt marker.");
    Ok(())
}
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct SafariRow {
    id: String,
    title: Option<String>,
    url: Option<String>,
}
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct PasswordRow {
    record_name: String,
    domain: String,
    username: String,
    title: String,
    password: String,
}
fn safari_rows(root: &Path, kind: Kind) -> TestResult<Vec<SafariRow>> {
    let name = match kind {
        Kind::Bookmarks => "list-bookmarks",
        Kind::Tabs => "list-tabs",
        Kind::Passwords => return Err("wrong Safari dataset".into()),
    };
    let bytes = run(command(root).args([name, "--json"]), "Safari JSON read")?;
    serde_json::from_slice(&bytes).map_err(|_| "invalid Safari JSON; output withheld".into())
}
fn password_rows(root: &Path, plaintext: bool) -> TestResult<Vec<PasswordRow>> {
    let mut cmd = command(root);
    cmd.args(["passwords", "list", "--json"]);
    if plaintext {
        cmd.arg("--show-passwords");
    }
    let bytes = run(&mut cmd, "password JSON read")?;
    let rows: Vec<PasswordRow> =
        serde_json::from_slice(&bytes).map_err(|_| "invalid password JSON; output withheld")?;
    if !plaintext && rows.iter().any(|row| row.password != "********") {
        return Err("password JSON was not redacted".into());
    }
    Ok(rows)
}
fn ownership(
    root: &Path,
    journal: &Journal,
    target: &Target,
    expected_title: Option<&str>,
) -> TestResult<Option<String>> {
    let ids: Vec<String> = match target.kind {
        Kind::Passwords => {
            let rows = password_rows(root, false)?;
            if let Some(id) = &target.record
                && let Some(row) = rows.iter().find(|row| &row.record_name == id)
                && (row.domain != journal.domain()
                    || row.username != journal.marker
                    || row.title != journal.marker)
            {
                return Err("password ownership marker changed; refusing mutation".into());
            }
            rows.iter()
                .filter(|row| {
                    row.domain == journal.domain()
                        && row.username == journal.marker
                        && row.title == journal.marker
                })
                .map(|row| row.record_name.clone())
                .collect()
        }
        kind => {
            let rows = safari_rows(root, kind)?;
            let owned = |row: &SafariRow| {
                row.url.as_deref() == Some(journal.url().as_str())
                    && (row.title.as_deref() == Some(journal.marker.as_str())
                        || row.title.as_deref() == Some(journal.updated().as_str()))
            };
            if let Some(id) = &target.record
                && let Some(row) = rows.iter().find(|row| &row.id == id)
                && !owned(row)
            {
                return Err("Safari ownership marker changed; refusing mutation".into());
            }
            let matching: Vec<_> = rows.iter().filter(|row| owned(row)).collect();
            if expected_title.is_some_and(|title| {
                matching
                    .iter()
                    .any(|row| row.title.as_deref() != Some(title))
            }) {
                return Err("Safari title failed exact authenticated verification".into());
            }
            matching.iter().map(|row| row.id.clone()).collect()
        }
    };
    if ids.len() > 1 {
        return Err("ambiguous ownership marker; refusing mutation".into());
    }
    let id = ids.into_iter().next();
    if let (Some(expected), Some(actual)) = (&target.record, &id)
        && expected != actual
    {
        return Err("ownership marker belongs to an unexpected identifier".into());
    }
    Ok(id)
}
fn secret_file(root: &Path) -> TestResult<(Zeroizing<String>, tempfile::NamedTempFile)> {
    let secret = Zeroizing::new(uuid::Uuid::new_v4().to_string());
    let mut file = tempfile::Builder::new()
        .prefix(".cli-crud-password-")
        .tempfile_in(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(secret.as_bytes())?;
    file.as_file().sync_all()?;
    Ok((secret, file))
}
fn keyed_string(value: &str) -> TestResult<String> {
    let mut top = plist::Dictionary::new();
    top.insert("root".into(), plist::Value::Uid(plist::Uid::new(1)));
    let mut archive = plist::Dictionary::new();
    archive.insert("$archiver".into(), "NSKeyedArchiver".into());
    archive.insert("$version".into(), 100000u64.into());
    archive.insert("$top".into(), plist::Value::Dictionary(top));
    archive.insert(
        "$objects".into(),
        plist::Value::Array(vec!["$null".into(), value.into()]),
    );
    let mut bytes = Vec::new();
    plist::Value::Dictionary(archive).to_writer_binary(&mut bytes)?;
    Ok(STANDARD.encode(bytes))
}
fn verify_password(root: &Path, journal: &Journal, id: &str, expected: &str) -> TestResult {
    let rows = password_rows(root, true)?;
    if !rows.iter().any(|row| {
        row.record_name == id
            && row.domain == journal.domain()
            && row.username == journal.marker
            && row.title == journal.marker
            && row.password == expected
    }) {
        return Err("disposable CLI password failed exact authenticated verification".into());
    }
    Ok(())
}
fn exercise(store: &FileStateStore, journal: &mut Journal, index: usize) -> TestResult {
    let root = store.root();
    let kind = journal.targets[index].kind;
    // The generated marker must be absent before any create, not merely have an
    // unknown ID. This permits safe reconciliation if create loses its reply.
    if ownership(root, journal, &journal.targets[index], None)?.is_some() {
        return Err("new test marker already exists".into());
    }
    journal.targets[index].started = true;
    journal.save(store)?;
    if matches!(kind, Kind::Passwords) {
        let (initial, initial_file) = secret_file(root)?;
        let (updated, updated_file) = secret_file(root)?;
        run(
            command(root)
                .args([
                    "passwords",
                    "create",
                    "--domain",
                    &journal.domain(),
                    "--username",
                    &journal.marker,
                    "--title",
                    &journal.marker,
                    "--confirm-write-to-icloud",
                    "--password-file",
                ])
                .arg(initial_file.path()),
            "password creation",
        )?;
        let id = ownership(root, journal, &journal.targets[index], None)?
            .ok_or("created password is missing")?;
        journal.targets[index].record = Some(id.clone());
        journal.save(store)?;
        verify_password(root, journal, &id, &initial)?;
        run(
            command(root)
                .args([
                    "passwords",
                    "update",
                    "--record",
                    &id,
                    "--confirm-write-to-icloud",
                    "--password-file",
                ])
                .arg(updated_file.path()),
            "password update",
        )?;
        verify_password(root, journal, &id, &updated)?;
    } else {
        run(
            command(root).args([
                "write",
                "create",
                "--dataset",
                kind.name(),
                "--title",
                &journal.marker,
                "--url",
                &journal.url(),
                "--confirm-write-to-icloud",
            ]),
            "Safari creation",
        )?;
        let id = ownership(
            root,
            journal,
            &journal.targets[index],
            Some(&journal.marker),
        )?
        .ok_or("created Safari record is missing")?;
        journal.targets[index].record = Some(id.clone());
        journal.save(store)?;
        let plan = root.join(format!(
            "e2e/cli-crud-{}-{}-update.json",
            journal.marker,
            kind.name()
        ));
        let mut prepare = command(root);
        prepare
            .args([
                "write",
                "update",
                "--dataset",
                kind.name(),
                "--record",
                &id,
                "--field",
                "Title",
                "--output",
            ])
            .arg(&plan);
        if matches!(kind, Kind::Tabs) {
            prepare.args(["--value-base64", &keyed_string(&journal.updated())?]);
        } else {
            prepare.args(["--value", &journal.updated()]);
        }
        run(&mut prepare, "Safari update preparation")?;
        run(
            command(root)
                .args(["write", "apply-update", "--plan"])
                .arg(&plan)
                .args(["--confirm-record", &id, "--confirm-write-to-icloud"]),
            "Safari update",
        )?;
        if ownership(
            root,
            journal,
            &journal.targets[index],
            Some(&journal.updated()),
        )?
        .as_deref()
            != Some(&id)
        {
            return Err("updated Safari record missing".into());
        }
    }
    Ok(())
}
fn cleanup_target(store: &FileStateStore, journal: &mut Journal, index: usize) -> TestResult {
    if !journal.targets[index].started {
        return Ok(());
    }
    let root = store.root();
    let Some(id) = ownership(root, journal, &journal.targets[index], None)? else {
        return Ok(());
    };
    journal.targets[index].record = Some(id.clone());
    journal.save(store)?;
    let kind = journal.targets[index].kind;
    if matches!(kind, Kind::Passwords) {
        run(
            command(root).args([
                "passwords",
                "delete",
                "--record",
                &id,
                "--confirm-record",
                &id,
                "--confirm-write-to-icloud",
            ]),
            "password deletion",
        )?;
    } else {
        let plan = root.join(format!(
            "e2e/cli-crud-{}-{}-delete.json",
            journal.marker,
            kind.name()
        ));
        run(
            command(root)
                .args([
                    "write",
                    "delete",
                    "--dataset",
                    kind.name(),
                    "--record",
                    &id,
                    "--output",
                ])
                .arg(&plan),
            "Safari deletion preparation",
        )?;
        run(
            command(root)
                .args(["write", "apply-delete", "--plan"])
                .arg(&plan)
                .args(["--confirm-record", &id, "--confirm-write-to-icloud"]),
            "Safari deletion",
        )?;
    }
    if ownership(root, journal, &journal.targets[index], None)?.is_some() {
        return Err("disposable record remains after CLI deletion".into());
    }
    Ok(())
}

#[test]
#[ignore = "live CLI CRUD creates disposable records; explicit consent required"]
fn disposable_cli_crud() -> TestResult {
    if env::var("ICLOUD_CLI_CRUD_CONFIRM").as_deref() != Ok("disposable-records") {
        return Err("set ICLOUD_CLI_CRUD_CONFIRM=disposable-records".into());
    }
    let root = PathBuf::from(env::var("ICLOUD_LIVE_STATE_DIR")?);
    if !root.is_absolute() || root.parent().is_none() {
        return Err("use an absolute dedicated enrolled state directory".into());
    }
    let store = FileStateStore::new(root);
    let session: serde_json::Value = store.read_json("live/session.json")?;
    if session.get("octagon").is_none() {
        return Err("enroll this state before CLI CRUD".into());
    }
    if env::var("ICLOUD_CLI_CRUD_RESUME").as_deref() == Ok("1") {
        verify_sponsored_cli_resume(&store)?;
    }
    run(
        command(store.root()).args(["keys", "recover"]),
        "PCS key recovery",
    )?;
    let mut journal = Journal {
        marker: format!("icloud-cli-e2e-{}", uuid::Uuid::new_v4()),
        targets: [Kind::Bookmarks, Kind::Tabs, Kind::Passwords]
            .into_iter()
            .map(|kind| Target {
                kind,
                started: false,
                record: None,
            })
            .collect(),
        completed: false,
    };
    journal.save(&store)?;
    let outcome: TestResult = (|| {
        for index in 0..journal.targets.len() {
            exercise(&store, &mut journal, index)?;
        }
        Ok(())
    })();
    let mut cleanup_failed = false;
    for index in 0..journal.targets.len() {
        if cleanup_target(&store, &mut journal, index).is_err() {
            cleanup_failed = true;
            let target = &journal.targets[index];
            eprintln!(
                "Cleanup needs investigation: {} test-created ID {} (private journal retained)",
                target.kind.name(),
                target.record.as_deref().unwrap_or("not yet discovered")
            );
        }
    }
    journal.completed = outcome.is_ok() && !cleanup_failed;
    journal.save(&store)?;
    if cleanup_failed {
        return Err("CLI cleanup incomplete; preserve the private journal".into());
    }
    outcome?;
    eprintln!("CLI CRUD verified: 1 bookmark, 1 tab, 1 password; all disposable records removed.");
    Ok(())
}
