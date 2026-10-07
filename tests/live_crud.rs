//! Explicitly opted-in library CRUD against an already enrolled test account.
//! `ICLOUD_CRUD_CONFIRM=disposable-records ICLOUD_LIVE_STATE_DIR=/private/state
//! cargo test --test live_crud -- --ignored --nocapture`
//! Creates only uniquely marked disposable records, journals identifiers before
//! Safari saves, and attempts ownership-checked cleanup on ordinary failures.
//! No existing user record is updated/deleted. Preserve `e2e/crud-*.json` after
//! any failure or interruption; cleanup cannot run after a process kill.
#![cfg(feature = "experimental-live-writes")]

use icloud_safari::{
    Dataset, NewBookmark, NewTab, OfflineReader, WriteWorkspace,
    account::AccountClient,
    anisette::LocalOrHttpAnisette,
    cloudkit::{Client, DeviceState, FetchedDataset, ReqwestTransport, SessionState},
    keychain::{KeychainClient, NewPassword},
    model::SafariSnapshot,
    state::FileStateStore,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{env, path::PathBuf};
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type SafariClient = Client<ReqwestTransport, LocalOrHttpAnisette>;
type PasswordClient = KeychainClient<ReqwestTransport, LocalOrHttpAnisette>;

#[derive(Serialize)]
struct OwnedSafari {
    dataset: Dataset,
    record_name: String,
}
#[derive(Serialize)]
struct Journal {
    marker: String,
    safari: Vec<OwnedSafari>,
    password_started: bool,
    password_record: Option<String>,
    completed: bool,
}
impl Journal {
    fn save(&self, store: &FileStateStore) -> TestResult {
        store.write_json(format!("e2e/crud-{}.json", self.marker), self)?;
        Ok(())
    }
    fn url(&self) -> String {
        format!("https://{}.example.invalid/disposable", self.marker)
    }
    fn domain(&self) -> String {
        format!("{}.example.invalid", self.marker)
    }
    fn updated_title(&self) -> String {
        format!("{} updated", self.marker)
    }
}

fn save_snapshot(
    store: &FileStateStore,
    dataset: Dataset,
    snapshot: &FetchedDataset,
) -> TestResult {
    store.write_json(
        format!("safari-cloudkit/{}.json", dataset.as_str()),
        snapshot,
    )?;
    Ok(())
}
fn decoded(store: &FileStateStore, dataset: Dataset) -> TestResult<SafariSnapshot> {
    Ok(OfflineReader::open(store.root())?
        .decrypt_datasets(&[dataset])?
        .0)
}
fn projected<'a>(
    snapshot: &'a SafariSnapshot,
    target: &OwnedSafari,
) -> Option<(Option<&'a str>, Option<&'a str>)> {
    match target.dataset {
        Dataset::Bookmarks => snapshot
            .bookmarks
            .iter()
            .find(|record| record.id == target.record_name)
            .map(|record| (record.title.as_deref(), record.url.as_deref())),
        Dataset::Tabs => snapshot
            .tabs
            .iter()
            .find(|record| record.id == target.record_name)
            .map(|record| (record.title.as_deref(), record.url.as_deref())),
        Dataset::History => None,
    }
}
fn verify_owned(
    snapshot: &SafariSnapshot,
    target: &OwnedSafari,
    journal: &Journal,
    title: &str,
) -> TestResult {
    if projected(snapshot, target) != Some((Some(title), Some(journal.url().as_str()))) {
        return Err(
            "disposable Safari record failed exact authenticated title/URL verification".into(),
        );
    }
    Ok(())
}
fn keyed_string(value: &str) -> TestResult<Vec<u8>> {
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
    Ok(bytes)
}

async fn safari_crud(
    store: &FileStateStore,
    client: &mut SafariClient,
    journal: &mut Journal,
    dataset: Dataset,
) -> TestResult {
    save_snapshot(store, dataset, &client.fetch(dataset).await?)?;
    let workspace = WriteWorkspace::open(store.root())?;
    let url = journal.url();
    let plan = match dataset {
        Dataset::Bookmarks => workspace.prepare_bookmark_create(NewBookmark {
            title: &journal.marker,
            url: &url,
            parent_id: None,
        })?,
        Dataset::Tabs => workspace.prepare_tab_create(NewTab {
            title: &journal.marker,
            url: &url,
            owning_device_id: None,
        })?,
        Dataset::History => return Err("history is not in disposable CRUD scope".into()),
    };
    journal.safari.push(OwnedSafari {
        dataset,
        record_name: plan.record_name.clone(),
    });
    journal.save(store)?;
    let target = journal.safari.last().ok_or("missing journal target")?;
    let created = client.apply_prepared_create(&plan).await?;
    save_snapshot(store, dataset, &created)?;
    verify_owned(&decoded(store, dataset)?, target, journal, &journal.marker)?;
    let changed_title = journal.updated_title();
    let update = match dataset {
        Dataset::Bookmarks => workspace.prepare_string_update(
            dataset,
            &target.record_name,
            "Title",
            &changed_title,
        )?,
        Dataset::Tabs => workspace.prepare_bytes_update(
            dataset,
            &target.record_name,
            "Title",
            &keyed_string(&changed_title)?,
        )?,
        Dataset::History => unreachable!(),
    };
    let updated = client
        .apply_prepared_update(&update, &target.record_name)
        .await?;
    save_snapshot(store, dataset, &updated)?;
    workspace.verify_applied_update(&update)?;
    verify_owned(&decoded(store, dataset)?, target, journal, &changed_title)?;
    let deletion = workspace.prepare_delete(dataset, &target.record_name)?;
    client
        .apply_prepared_delete(&deletion, &target.record_name)
        .await?;
    let independent = client.fetch(dataset).await?;
    if independent
        .pages
        .iter()
        .flat_map(|page| &page.records)
        .any(|record| record.name == target.record_name)
    {
        return Err("disposable Safari record remains after deletion".into());
    }
    save_snapshot(store, dataset, &independent)?;
    Ok(())
}

async fn password_crud(
    store: &FileStateStore,
    client: &PasswordClient,
    journal: &mut Journal,
) -> TestResult {
    let domain = journal.domain();
    let (_, before) = client.fetch_and_decrypt_passwords().await?;
    if before
        .iter()
        .any(|record| record.domain == domain || record.username == journal.marker)
    {
        return Err("disposable password marker unexpectedly exists; refusing mutation".into());
    }
    let initial = Zeroizing::new(uuid::Uuid::new_v4().to_string());
    let changed = Zeroizing::new(uuid::Uuid::new_v4().to_string());
    // Password creation allocates the record ID internally. Persist the unique
    // absent-before-create marker first, then its returned ID when available.
    journal.password_started = true;
    journal.save(store)?;
    let created = client
        .create_password(NewPassword {
            domain: &domain,
            username: &journal.marker,
            password: &initial,
            title: Some(&journal.marker),
        })
        .await?;
    journal.password_record = Some(created.record_name.clone());
    journal.save(store)?;
    let (_, records) = client.fetch_and_decrypt_passwords().await?;
    let actual = records
        .iter()
        .find(|record| record.record_name == created.record_name)
        .ok_or("new disposable password is missing")?;
    if actual.password != *initial
        || actual.domain != domain
        || actual.username != journal.marker
        || actual.title != journal.marker
    {
        return Err("new disposable password did not authenticate exactly".into());
    }
    client
        .update_password(&created.record_name, &changed)
        .await?;
    let (_, records) = client.fetch_and_decrypt_passwords().await?;
    let actual = records
        .iter()
        .find(|record| record.record_name == created.record_name)
        .ok_or("updated disposable password is missing")?;
    if actual.password != *changed
        || actual.domain != domain
        || actual.username != journal.marker
        || actual.title != journal.marker
    {
        return Err("updated disposable password did not authenticate exactly".into());
    }
    client.delete_password(&created.record_name).await?;
    let (_, records) = client.fetch_and_decrypt_passwords().await?;
    if records
        .iter()
        .any(|record| record.record_name == created.record_name)
    {
        return Err("disposable password remains after deletion".into());
    }
    Ok(())
}

async fn cleanup(
    store: &FileStateStore,
    safari: &mut SafariClient,
    passwords: &PasswordClient,
    journal: &Journal,
) -> TestResult {
    for target in &journal.safari {
        let fresh = safari.fetch(target.dataset).await?;
        save_snapshot(store, target.dataset, &fresh)?;
        if !fresh
            .pages
            .iter()
            .flat_map(|page| &page.records)
            .any(|record| record.name == target.record_name)
        {
            continue;
        }
        let snapshot = decoded(store, target.dataset)?;
        let title = projected(&snapshot, target)
            .and_then(|value| value.0)
            .ok_or("cleanup could not authenticate disposable title")?;
        if title != journal.marker && title != journal.updated_title() {
            return Err("cleanup refused a changed ownership marker".into());
        }
        verify_owned(&snapshot, target, journal, title)?;
        let plan = WriteWorkspace::open(store.root())?
            .prepare_delete(target.dataset, &target.record_name)?;
        safari
            .apply_prepared_delete(&plan, &target.record_name)
            .await?;
    }
    if journal.password_started {
        let (_, records) = passwords.fetch_and_decrypt_passwords().await?;
        if let Some(id) = &journal.password_record
            && let Some(record) = records.iter().find(|record| &record.record_name == id)
            && (record.domain != journal.domain()
                || record.username != journal.marker
                || record.title != journal.marker)
        {
            return Err("cleanup refused a password whose ownership marker changed".into());
        }
        let matching = records
            .iter()
            .filter(|record| {
                record.domain == journal.domain()
                    && record.username == journal.marker
                    && record.title == journal.marker
            })
            .count();
        if matching > 1 {
            return Err("cleanup refused ambiguous disposable password markers".into());
        }
        for record in records.iter().filter(|record| {
            record.domain == journal.domain()
                && record.username == journal.marker
                && record.title == journal.marker
        }) {
            if journal
                .password_record
                .as_ref()
                .is_some_and(|id| id != &record.record_name)
            {
                return Err("cleanup refused an unexpected password identifier".into());
            }
            passwords.delete_password(&record.record_name).await?;
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "creates/updates/deletes uniquely marked disposable Safari and password records; explicit consent required"]
async fn disposable_library_crud() -> TestResult {
    if env::var("ICLOUD_CRUD_CONFIRM").as_deref() != Ok("disposable-records") {
        return Err("set ICLOUD_CRUD_CONFIRM=disposable-records".into());
    }
    let root = PathBuf::from(env::var("ICLOUD_LIVE_STATE_DIR")?);
    if !root.is_absolute() || root.parent().is_none() {
        return Err("use an absolute dedicated enrolled state directory".into());
    }
    let store = FileStateStore::new(root);
    let _guard = store.try_lock()?;
    let mut session: SessionState = store.read_json("live/session.json")?;
    if !session.extra.contains_key("octagon") {
        return Err("state has no enrollment; enroll before CRUD".into());
    }
    let device: DeviceState = store.read_json("live/device.json")?;
    let provider = LocalOrHttpAnisette::open(store.root(), None).await?;
    AccountClient::new(
        ReqwestTransport::default(),
        provider.clone(),
        device.clone(),
    )
    .refresh_session(&mut session)
    .await?;
    let passwords = KeychainClient::initialize(
        ReqwestTransport::default(),
        provider.clone(),
        device.clone(),
        session,
    )
    .await?;
    store.write_json("live/session.json", passwords.session())?;
    let keys = passwords.recover_pcs_identities().await?;
    if keys.is_empty() {
        return Err("PCS recovery returned no identities".into());
    }
    for key in keys {
        store.write_bytes(
            format!("pcs-identities/{}.der", hex::encode(Sha256::digest(&*key))),
            &key,
        )?;
    }
    let mut safari = Client::new(
        ReqwestTransport::default(),
        provider,
        device,
        passwords.session().clone(),
    );
    let mut journal = Journal {
        marker: format!("icloud-rust-e2e-{}", uuid::Uuid::new_v4()),
        safari: vec![],
        password_started: false,
        password_record: None,
        completed: false,
    };
    journal.save(&store)?;
    let outcome: TestResult = async {
        safari_crud(&store, &mut safari, &mut journal, Dataset::Bookmarks).await?;
        safari_crud(&store, &mut safari, &mut journal, Dataset::Tabs).await?;
        password_crud(&store, &passwords, &mut journal).await?;
        Ok(())
    }
    .await;
    let cleanup_result = cleanup(&store, &mut safari, &passwords, &journal).await;
    store.write_json("live/session.json", &safari.session)?;
    journal.completed = outcome.is_ok() && cleanup_result.is_ok();
    journal.save(&store)?;
    if cleanup_result.is_err() {
        eprintln!(
            "Cleanup requires investigation; only these test-created Safari IDs are in scope:"
        );
        for target in &journal.safari {
            eprintln!("{} {}", target.dataset.as_str(), target.record_name);
        }
        if let Some(id) = &journal.password_record {
            eprintln!("password {id}");
        }
        return Err("cleanup incomplete; preserve the private CRUD journal".into());
    }
    outcome?;
    eprintln!(
        "Library CRUD verified: 1 bookmark, 1 tab, 1 password; all disposable records removed."
    );
    Ok(())
}
