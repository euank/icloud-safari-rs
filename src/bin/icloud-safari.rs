use clap::{Args, Parser, Subcommand};
use icloud_safari::{
    Error, OfflineReader, Result, WriteWorkspace,
    account::{AccountClient, SecondFactor},
    anisette::LocalOrHttpAnisette,
    cloudkit::{Client, DeviceState, ReqwestTransport, SessionState},
    model::Dataset,
    state::FileStateStore,
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
#[cfg(feature = "experimental-live-writes")]
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "icloud-safari",
    about = "Read, export, and prepare updates to Safari data stored in iCloud"
)]
struct Cli {
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[arg(long, global = true)]
    fixture_dir: Option<PathBuf>,
    /// Use an HTTP Anisette provider instead of the self-contained local provider.
    #[arg(long, global = true)]
    anisette_url: Option<String>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Debug, Subcommand)]
enum Command {
    /// Sign in interactively and save refreshable local credentials.
    Login {
        #[arg(long)]
        username: Option<String>,
        /// Request an SMS code instead of notifying trusted Apple devices.
        #[arg(long)]
        sms: bool,
    },
    /// Refresh saved account tokens and service settings.
    Refresh,
    /// Show local authentication and encryption-key setup without contacting Apple.
    Status,
    VerifyFixtures,
    ListTabs(ListArgs),
    ListDevices(ListArgs),
    ListBookmarks(ListArgs),
    ListHistory(ListArgs),
    /// Fetch and decrypt iCloud Keychain login passwords.
    ListPasswords(PasswordListArgs),
    /// Read and modify iCloud Keychain login passwords.
    Passwords {
        #[command(subcommand)]
        command: PasswordCommand,
    },
    Export {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum)]
        dataset: Option<Dataset>,
        /// Read the local cache without contacting iCloud.
        #[arg(long, conflicts_with = "fetch")]
        offline: bool,
        /// Compatibility alias; online is now the default.
        #[arg(long, hide = true)]
        fetch: bool,
    },
    Fetch {
        #[arg(value_enum)]
        dataset: Option<Dataset>,
    },
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    Escrow {
        #[command(subcommand)]
        command: EscrowCommand,
    },
    Octagon {
        #[command(subcommand)]
        command: OctagonCommand,
    },
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Prepare explicitly selected write operations without network I/O.
    Write {
        #[command(subcommand)]
        command: WriteCommand,
    },
}
#[derive(Debug, Args)]
struct ListArgs {
    #[arg(long)]
    json: bool,
    /// Read the local cache without contacting iCloud.
    #[arg(long, conflicts_with = "fetch")]
    offline: bool,
    /// Compatibility alias; online is now the default.
    #[arg(long, hide = true)]
    fetch: bool,
}

#[derive(Debug, Args)]
struct PasswordListArgs {
    /// Include plaintext passwords in output.
    #[arg(long)]
    show_passwords: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum PasswordCommand {
    List(PasswordListArgs),
    #[cfg(feature = "experimental-live-writes")]
    Create {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        title: Option<String>,
        /// Read the password from this file. The first trailing newline is removed.
        #[arg(long)]
        password_file: Option<PathBuf>,
        #[arg(long, required = true)]
        confirm_write_to_icloud: bool,
    },
    #[cfg(feature = "experimental-live-writes")]
    Update {
        #[arg(long)]
        record: String,
        /// Read the new password from this file. The first trailing newline is removed.
        #[arg(long)]
        password_file: Option<PathBuf>,
        #[arg(long, required = true)]
        confirm_write_to_icloud: bool,
    },
    #[cfg(feature = "experimental-live-writes")]
    Delete {
        #[arg(long)]
        record: String,
        /// Must exactly match --record.
        #[arg(long)]
        confirm_record: String,
        #[arg(long, required = true)]
        confirm_write_to_icloud: bool,
    },
}
#[derive(Debug, Subcommand)]
enum DeviceCommand {
    Init,
}
#[derive(Debug, Subcommand)]
enum AuthCommand {
    Login,
    Refresh,
}
#[derive(Debug, Subcommand)]
enum EscrowCommand {
    List,
}
#[derive(Debug, Subcommand)]
enum OctagonCommand {
    Enroll {
        #[arg(long)]
        bottle_id: String,
        #[arg(long)]
        confirm_escrow_recovery: Option<String>,
    },
}
#[derive(Debug, Subcommand)]
enum KeysCommand {
    Recover,
}

#[derive(Debug, Subcommand)]
enum WriteCommand {
    /// Re-encrypt one field in one fetched record and emit a lossless plan.
    Update {
        #[arg(long, value_enum)]
        dataset: Dataset,
        #[arg(long)]
        record: String,
        #[arg(long)]
        field: String,
        #[arg(
            long,
            conflicts_with = "value_base64",
            required_unless_present = "value_base64"
        )]
        value: Option<String>,
        #[arg(long, conflicts_with = "value")]
        value_base64: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Emit the exact record identifier and conflict metadata needed to delete.
    Delete {
        #[arg(long, value_enum)]
        dataset: Dataset,
        #[arg(long)]
        record: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Create and authenticate a new bookmark or cloud tab.
    #[cfg(feature = "experimental-live-writes")]
    Create {
        #[arg(long, value_enum)]
        dataset: Dataset,
        #[arg(long)]
        title: String,
        #[arg(long)]
        url: String,
        /// Bookmark parent; defaults to Safari's top-level bookmarks folder.
        #[arg(long, conflicts_with = "owning_device_id")]
        parent_id: Option<String>,
        /// CloudTabDevice record; defaults to the first synchronized device.
        #[arg(long, conflicts_with = "parent_id")]
        owning_device_id: Option<String>,
        #[arg(long, required = true)]
        confirm_write_to_icloud: bool,
    },
    /// Apply and post-verify an update (experimental feature only).
    #[cfg(feature = "experimental-live-writes")]
    ApplyUpdate {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        confirm_record: String,
        #[arg(long, required = true)]
        confirm_write_to_icloud: bool,
    },
    /// Apply and post-verify a delete (experimental feature only).
    #[cfg(feature = "experimental-live-writes")]
    ApplyDelete {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        confirm_record: String,
        #[arg(long, required = true)]
        confirm_write_to_icloud: bool,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("error: {error}");
        std::process::exit(1)
    }
}

async fn run(cli: Cli) -> Result<()> {
    let state_root = cli.state_dir.unwrap_or_else(default_state_dir);
    let store = FileStateStore::new(&state_root);
    match cli.command {
        Command::Device {
            command: DeviceCommand::Init,
        } => {
            store.ensure()?;
            let path = Path::new("live/device.json");
            if store.root().join(path).exists() {
                return Err(Error::Fixture(
                    "device identity already exists; it must be reused".into(),
                ));
            }
            store.write_json(path, &DeviceState::generate())?;
            println!("initialized persistent device identity")
        }
        Command::VerifyFixtures => {
            let report = reader(&cli.fixture_dir, &state_root)?.verify_expected()?;
            println!(
                "verified {} PCS objects, {} unwrapped, {} authenticated fields",
                report.pcs_objects, report.unwrapped_objects, report.authenticated_fields
            )
        }
        Command::ListTabs(args) => {
            if should_fetch(args.offline, args.fetch, &cli.fixture_dir) {
                fetch(&store, cli.anisette_url.as_deref(), Some(Dataset::Tabs)).await?
            }
            let (s, r) =
                reader(&cli.fixture_dir, &state_root)?.decrypt_datasets(&[Dataset::Tabs])?;
            status(&r);
            output(&s.tabs, args.json)?
        }
        Command::ListDevices(args) => {
            if should_fetch(args.offline, args.fetch, &cli.fixture_dir) {
                fetch(&store, cli.anisette_url.as_deref(), Some(Dataset::Tabs)).await?
            }
            let (s, r) =
                reader(&cli.fixture_dir, &state_root)?.decrypt_datasets(&[Dataset::Tabs])?;
            status(&r);
            output(&s.devices, args.json)?
        }
        Command::ListBookmarks(args) => {
            if should_fetch(args.offline, args.fetch, &cli.fixture_dir) {
                fetch(
                    &store,
                    cli.anisette_url.as_deref(),
                    Some(Dataset::Bookmarks),
                )
                .await?
            }
            let (s, r) =
                reader(&cli.fixture_dir, &state_root)?.decrypt_datasets(&[Dataset::Bookmarks])?;
            status(&r);
            output(&s.bookmarks, args.json)?
        }
        Command::ListHistory(args) => {
            if should_fetch(args.offline, args.fetch, &cli.fixture_dir) {
                fetch(&store, cli.anisette_url.as_deref(), Some(Dataset::History)).await?
            }
            let (s, r) =
                reader(&cli.fixture_dir, &state_root)?.decrypt_datasets(&[Dataset::History])?;
            status(&r);
            output(&s.history, args.json)?
        }
        Command::ListPasswords(args) => {
            list_passwords(&store, cli.anisette_url.as_deref(), args).await?;
        }
        Command::Passwords { command } => match command {
            PasswordCommand::List(args) => {
                list_passwords(&store, cli.anisette_url.as_deref(), args).await?;
            }
            #[cfg(feature = "experimental-live-writes")]
            PasswordCommand::Create {
                domain,
                username,
                title,
                password_file,
                confirm_write_to_icloud: _,
            } => {
                let password = read_password(password_file.as_deref(), "Password: ")?;
                let client = keychain_client(&store, cli.anisette_url.as_deref()).await?;
                let entry = client
                    .create_password(icloud_safari::keychain::NewPassword {
                        domain: &domain,
                        username: &username,
                        password: &password,
                        title: title.as_deref(),
                    })
                    .await?;
                println!(
                    "created and authenticated password record {}",
                    entry.record_name
                );
            }
            #[cfg(feature = "experimental-live-writes")]
            PasswordCommand::Update {
                record,
                password_file,
                confirm_write_to_icloud: _,
            } => {
                let password = read_password(password_file.as_deref(), "New password: ")?;
                let client = keychain_client(&store, cli.anisette_url.as_deref()).await?;
                client.update_password(&record, &password).await?;
                println!("updated password record {record}");
            }
            #[cfg(feature = "experimental-live-writes")]
            PasswordCommand::Delete {
                record,
                confirm_record,
                confirm_write_to_icloud: _,
            } => {
                if record != confirm_record {
                    return Err(Error::Fixture(
                        "--confirm-record must exactly match --record".into(),
                    ));
                }
                let client = keychain_client(&store, cli.anisette_url.as_deref()).await?;
                client.delete_password(&record).await?;
                println!("deleted password record {record}");
            }
        },
        Command::Export {
            output: destination,
            dataset,
            offline,
            fetch: force_fetch,
        } => {
            if should_fetch(offline, force_fetch, &cli.fixture_dir) {
                fetch(&store, cli.anisette_url.as_deref(), dataset).await?
            }
            let selected = dataset
                .map(|d| vec![d])
                .unwrap_or_else(|| Dataset::ALL.to_vec());
            let (snapshot, report) =
                reader(&cli.fixture_dir, &state_root)?.decrypt_datasets(&selected)?;
            write_secure_json(&destination, &snapshot)?;
            status(&report);
            println!("exported decoded JSON to {}", destination.display())
        }
        Command::Fetch { dataset } => fetch(&store, cli.anisette_url.as_deref(), dataset).await?,
        Command::Login { username, sms } => {
            login(&store, cli.anisette_url.as_deref(), username, sms).await?
        }
        Command::Refresh => refresh(&store, cli.anisette_url.as_deref()).await?,
        Command::Status => {
            let session: Option<SessionState> = read_optional_state(&store, "live/session.json")?;
            print_setup_status(&store, session.as_ref())?;
        }
        Command::Write { command } => {
            let root = cli.fixture_dir.as_deref().unwrap_or(&state_root);
            let writer = WriteWorkspace::open(root)?;
            match command {
                WriteCommand::Update {
                    dataset,
                    record,
                    field,
                    value,
                    value_base64,
                    output,
                } => {
                    let plan = if let Some(value) = value {
                        writer.prepare_string_update(dataset, &record, &field, &value)?
                    } else {
                        use base64::{Engine as _, engine::general_purpose::STANDARD};
                        let plaintext = STANDARD.decode(value_base64.unwrap()).map_err(|_| {
                            Error::Fixture("--value-base64 is not valid base64".into())
                        })?;
                        writer.prepare_bytes_update(dataset, &record, &field, &plaintext)?
                    };
                    write_secure_json(&output, &plan)?;
                    println!(
                        "prepared one-field update for {:?} in {} (no network request sent)",
                        record,
                        output.display()
                    );
                }
                WriteCommand::Delete {
                    dataset,
                    record,
                    output,
                } => {
                    let plan = writer.prepare_delete(dataset, &record)?;
                    write_secure_json(&output, &plan)?;
                    println!(
                        "prepared delete metadata for {:?} in {} (no network request sent)",
                        record,
                        output.display()
                    );
                }
                #[cfg(feature = "experimental-live-writes")]
                WriteCommand::Create {
                    dataset,
                    title,
                    url,
                    parent_id,
                    owning_device_id,
                    confirm_write_to_icloud: _,
                } => {
                    if cli.fixture_dir.is_some() {
                        return Err(Error::Unsupported("live creation cannot use --fixture-dir"));
                    }
                    fetch(&store, cli.anisette_url.as_deref(), Some(dataset)).await?;
                    let writer = WriteWorkspace::open(&state_root)?;
                    let plan = match dataset {
                        Dataset::Bookmarks => {
                            if owning_device_id.is_some() {
                                return Err(Error::Fixture(
                                    "--owning-device-id is valid only for tabs".into(),
                                ));
                            }
                            writer.prepare_bookmark_create(icloud_safari::NewBookmark {
                                title: &title,
                                url: &url,
                                parent_id: parent_id.as_deref(),
                            })?
                        }
                        Dataset::Tabs => {
                            if parent_id.is_some() {
                                return Err(Error::Fixture(
                                    "--parent-id is valid only for bookmarks".into(),
                                ));
                            }
                            writer.prepare_tab_create(icloud_safari::NewTab {
                                title: &title,
                                url: &url,
                                owning_device_id: owning_device_id.as_deref(),
                            })?
                        }
                        Dataset::History => {
                            return Err(Error::Unsupported(
                                "creation supports only bookmarks and tabs",
                            ));
                        }
                    };
                    let after = apply_create(&store, cli.anisette_url.as_deref(), &plan).await?;
                    store
                        .write_json(format!("safari-cloudkit/{}.json", dataset.as_str()), &after)?;
                    println!("created and authenticated {:?}", plan.record_name);
                }
                #[cfg(feature = "experimental-live-writes")]
                WriteCommand::ApplyUpdate {
                    plan,
                    confirm_record,
                    confirm_write_to_icloud: _,
                } => {
                    let plan: icloud_safari::PreparedFieldUpdate =
                        serde_json::from_slice(&fs::read(plan)?)?;
                    let after =
                        apply_update(&store, cli.anisette_url.as_deref(), &plan, &confirm_record)
                            .await?;
                    store.write_json(
                        format!("safari-cloudkit/{}.json", plan.metadata.dataset.as_str()),
                        &after,
                    )?;
                    WriteWorkspace::open(&state_root)?.verify_applied_update(&plan)?;
                    println!("updated and authenticated {:?}", plan.metadata.record_name);
                }
                #[cfg(feature = "experimental-live-writes")]
                WriteCommand::ApplyDelete {
                    plan,
                    confirm_record,
                    confirm_write_to_icloud: _,
                } => {
                    let plan: icloud_safari::PreparedDelete =
                        serde_json::from_slice(&fs::read(plan)?)?;
                    let after =
                        apply_delete(&store, cli.anisette_url.as_deref(), &plan, &confirm_record)
                            .await?;
                    store.write_json(
                        format!("safari-cloudkit/{}.json", plan.metadata.dataset.as_str()),
                        &after,
                    )?;
                    println!(
                        "deleted and confirmed absent {:?}",
                        plan.metadata.record_name
                    );
                }
            }
        }
        Command::Auth {
            command: AuthCommand::Login,
        } => login(&store, cli.anisette_url.as_deref(), None, false).await?,
        Command::Auth {
            command: AuthCommand::Refresh,
        } => refresh(&store, cli.anisette_url.as_deref()).await?,
        Command::Escrow { .. } | Command::Octagon { .. } | Command::Keys { .. } => {
            return Err(Error::Unsupported(
                "Octagon enrollment is not yet available; supply existing PCS identities",
            ));
        }
    }
    Ok(())
}
fn reader<'a>(fixture: &'a Option<PathBuf>, state: &'a Path) -> Result<OfflineReader> {
    OfflineReader::open(fixture.as_deref().unwrap_or(state))
}
fn should_fetch(offline: bool, force_fetch: bool, fixture: &Option<PathBuf>) -> bool {
    force_fetch || (!offline && fixture.is_none())
}
fn default_state_dir() -> PathBuf {
    directories::ProjectDirs::from("dev", "icloud-safari", "icloud-safari")
        .and_then(|p| p.state_dir().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from(".icloud-safari"))
}
async fn login(
    store: &FileStateStore,
    anisette_url: Option<&str>,
    username: Option<String>,
    prefer_sms: bool,
) -> Result<()> {
    use zeroize::Zeroizing;

    store.ensure()?;
    let previous: Option<SessionState> = read_optional_state(store, "live/session.json")?;
    let prior: Option<DeviceState> = read_optional_state(store, "live/device.json")?;
    if previous.is_some() && prior.is_none() {
        return Err(Error::Authentication(
            "saved session has no device state; restore live/device.json or use a separate --state-dir".into(),
        ));
    }
    let username = match username {
        Some(value) if !value.trim().is_empty() => value.trim().to_owned(),
        Some(_) => {
            return Err(Error::Authentication(
                "Apple Account cannot be empty".into(),
            ));
        }
        None => match &previous {
            Some(session) => session.username.clone(),
            None => prompt_line("Apple Account: ")?,
        },
    };
    eprintln!("Signing in as {username}");
    let provider = LocalOrHttpAnisette::open(store.root(), anisette_url).await?;
    let device = provider.device_state(prior.clone()).await?;
    if let Some(prior) = &prior {
        if previous.is_some()
            && (prior.device_uuid != device.device_uuid
                || prior.local_user_uuid != device.local_user_uuid)
        {
            return Err(Error::Authentication(
                "Anisette identity differs from the saved device; restore the original provider/state or use a separate --state-dir".into(),
            ));
        }
    } else {
        // Persist the provisioned identity before prompting, so a cancelled
        // or failed first login resumes with the same device next time.
        store.write_json("live/device.json", &device)?;
    }
    let password = Zeroizing::new(
        rpassword::prompt_password("Password: ")
            .map_err(|error| Error::Authentication(error.to_string()))?,
    );
    if password.is_empty() {
        return Err(Error::Authentication(
            "login cancelled: password was empty".into(),
        ));
    }
    let account = AccountClient::new(ReqwestTransport::default(), provider, device.clone());
    let mut outcome = account.authenticate(&username, password.as_bytes()).await?;
    if let Some(server_factor) = outcome.second_factor {
        let mut factor = if prefer_sms {
            SecondFactor::Sms
        } else {
            server_factor
        };
        account
            .trigger_second_factor(factor, &outcome.credentials)
            .await?;
        if factor == SecondFactor::TrustedDevice {
            eprintln!("Check a trusted Apple device, or type sms below to request a text message.");
        }
        let code = loop {
            let prompt = match factor {
                SecondFactor::TrustedDevice => "Verification code (or sms; blank cancels): ",
                SecondFactor::Sms => "SMS verification code (blank cancels): ",
            };
            let input = Zeroizing::new(rpassword::prompt_password(prompt)?);
            let code = Zeroizing::new(input.trim().to_owned());
            if code.is_empty() {
                return Err(Error::Authentication("login cancelled".into()));
            }
            if factor == SecondFactor::TrustedDevice && code.eq_ignore_ascii_case("sms") {
                account
                    .trigger_second_factor(SecondFactor::Sms, &outcome.credentials)
                    .await?;
                factor = SecondFactor::Sms;
                continue;
            }
            if code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()) {
                break code;
            }
            eprintln!("Enter the six-digit verification code.");
        };
        account
            .submit_second_factor(factor, &code, &outcome.credentials)
            .await?;
        outcome = account.authenticate(&username, password.as_bytes()).await?;
        if outcome.second_factor.is_some() {
            return Err(Error::Authentication(
                "Apple requested another second-factor challenge after verification".into(),
            ));
        }
    }
    let session = account
        .complete_login(&username, &outcome.credentials, previous.as_ref())
        .await?;
    store.write_json("live/device.json", &device)?;
    store.write_json("live/session.json", &session)?;
    println!("Signed in. Credentials saved; online commands refresh them automatically.");
    print_setup_status(store, Some(&session))?;
    Ok(())
}

fn read_optional_state<T: serde::de::DeserializeOwned>(
    store: &FileStateStore,
    path: &str,
) -> Result<Option<T>> {
    match store.read_json(path) {
        Ok(value) => Ok(Some(value)),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn print_setup_status(store: &FileStateStore, session: Option<&SessionState>) -> Result<()> {
    println!("State directory: {}", store.root().display());
    let Some(session) = session else {
        println!("Not signed in. Run login to authenticate.");
        return Ok(());
    };
    println!(
        "Account: {} (saved credentials; status does not check token validity)",
        session.username
    );
    let identities = store.root().join("pcs-identities");
    let has_identities = match fs::read_dir(&identities) {
        Ok(entries) => {
            let mut found = false;
            for entry in entries {
                let path = entry?.path();
                found |=
                    path.extension().is_some_and(|extension| extension == "der") && path.is_file();
            }
            found
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    println!(
        "Safari keys: {}",
        if has_identities {
            "identity files present (not verified)"
        } else {
            "missing"
        }
    );
    let has_octagon = session.extra.contains_key("octagon");
    let has_user = session
        .mme
        .extra
        .get("cloudKitUserId")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.is_empty());
    println!(
        "Password enrollment: {}",
        if has_octagon && has_user {
            "saved state present (not verified)"
        } else {
            "missing"
        }
    );
    if !has_identities || !has_octagon || !has_user {
        println!(
            "Authentication alone does not recover encryption keys. Fresh-account enrollment is not implemented yet; see README.md (Encryption-key setup)."
        );
    }
    Ok(())
}

async fn refresh(store: &FileStateStore, anisette_url: Option<&str>) -> Result<()> {
    live_context(store, anisette_url).await?;
    println!("refreshed saved account tokens and service settings");
    Ok(())
}

async fn live_context(
    store: &FileStateStore,
    anisette_url: Option<&str>,
) -> Result<(LocalOrHttpAnisette, DeviceState, SessionState)> {
    let mut session: SessionState = read_optional_state(store, "live/session.json")?
        .ok_or_else(|| Error::Authentication("not signed in; run login first".into()))?;
    let device: DeviceState = read_optional_state(store, "live/device.json")?.ok_or_else(|| {
        Error::Authentication("saved session has no device state; restore live/device.json".into())
    })?;
    let provider = LocalOrHttpAnisette::open(store.root(), anisette_url).await?;
    AccountClient::new(
        ReqwestTransport::default(),
        provider.clone(),
        device.clone(),
    )
    .refresh_session(&mut session)
    .await?;
    store.write_json("live/session.json", &session)?;
    Ok((provider, device, session))
}

async fn fetch(
    store: &FileStateStore,
    anisette_url: Option<&str>,
    dataset: Option<Dataset>,
) -> Result<()> {
    let (provider, device, session) = live_context(store, anisette_url).await?;
    let mut client = Client::new(ReqwestTransport::default(), provider, device, session);
    for selected in dataset
        .map(|d| vec![d])
        .unwrap_or_else(|| Dataset::ALL.to_vec())
    {
        let result = client.fetch(selected).await?;
        store.write_json(
            format!("safari-cloudkit/{}.json", selected.as_str()),
            &result,
        )?;
        eprintln!(
            "fetched {} page(s) for {}",
            result.pages.len(),
            selected.as_str()
        )
    }
    store.write_json("live/session.json", &client.session)?;
    Ok(())
}

async fn fetch_passwords(
    store: &FileStateStore,
    anisette_url: Option<&str>,
) -> Result<Vec<icloud_safari::keychain::PasswordEntry>> {
    let (provider, device, session) = live_context(store, anisette_url).await?;
    let client = icloud_safari::keychain::KeychainClient::new(
        ReqwestTransport::default(),
        provider,
        device,
        session,
    )?;
    let (snapshot, passwords) = client.fetch_and_decrypt_passwords().await?;
    store.write_json("keychain/all-views.json", &snapshot)?;
    eprintln!(
        "authenticated {} password(s) from {} CKKS zone(s)",
        passwords.len(),
        snapshot.zones.len()
    );
    Ok(passwords)
}

async fn list_passwords(
    store: &FileStateStore,
    anisette_url: Option<&str>,
    args: PasswordListArgs,
) -> Result<()> {
    let passwords = fetch_passwords(store, anisette_url).await?;
    let visible: Vec<_> = passwords
        .into_iter()
        .map(|password| {
            serde_json::json!({
                "record_name": password.record_name,
                "domain": password.domain,
                "username": password.username,
                "password": if args.show_passwords { password.password } else { "********".into() },
                "title": password.title,
            })
        })
        .collect();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&visible)?);
    } else {
        for entry in visible {
            println!(
                "{}\t{}\t{}",
                entry["domain"].as_str().unwrap_or_default(),
                entry["username"].as_str().unwrap_or_default(),
                entry["password"].as_str().unwrap_or_default()
            );
        }
    }
    Ok(())
}

#[cfg(feature = "experimental-live-writes")]
async fn keychain_client(
    store: &FileStateStore,
    anisette_url: Option<&str>,
) -> Result<icloud_safari::keychain::KeychainClient<ReqwestTransport, LocalOrHttpAnisette>> {
    let (provider, device, session) = live_context(store, anisette_url).await?;
    icloud_safari::keychain::KeychainClient::new(
        ReqwestTransport::default(),
        provider,
        device,
        session,
    )
}

#[cfg(feature = "experimental-live-writes")]
fn read_password(path: Option<&Path>, prompt: &str) -> Result<Zeroizing<String>> {
    let mut password = if let Some(path) = path {
        String::from_utf8(fs::read(path)?)
            .map_err(|_| Error::Fixture("password file is not UTF-8".into()))?
    } else {
        rpassword::prompt_password(prompt)?
    };
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    if password.is_empty() {
        return Err(Error::Fixture("password must not be empty".into()));
    }
    Ok(Zeroizing::new(password))
}

#[cfg(feature = "experimental-live-writes")]
async fn apply_update(
    store: &FileStateStore,
    anisette_url: Option<&str>,
    plan: &icloud_safari::PreparedFieldUpdate,
    confirmation: &str,
) -> Result<icloud_safari::cloudkit::FetchedDataset> {
    let (provider, device, session) = live_context(store, anisette_url).await?;
    let mut client = Client::new(ReqwestTransport::default(), provider, device, session);
    let result = client.apply_prepared_update(plan, confirmation).await?;
    store.write_json("live/session.json", &client.session)?;
    Ok(result)
}

#[cfg(feature = "experimental-live-writes")]
async fn apply_delete(
    store: &FileStateStore,
    anisette_url: Option<&str>,
    plan: &icloud_safari::PreparedDelete,
    confirmation: &str,
) -> Result<icloud_safari::cloudkit::FetchedDataset> {
    let (provider, device, session) = live_context(store, anisette_url).await?;
    let mut client = Client::new(ReqwestTransport::default(), provider, device, session);
    let result = client.apply_prepared_delete(plan, confirmation).await?;
    store.write_json("live/session.json", &client.session)?;
    Ok(result)
}

#[cfg(feature = "experimental-live-writes")]
async fn apply_create(
    store: &FileStateStore,
    anisette_url: Option<&str>,
    plan: &icloud_safari::PreparedCreate,
) -> Result<icloud_safari::cloudkit::FetchedDataset> {
    let (provider, device, session) = live_context(store, anisette_url).await?;
    let mut client = Client::new(ReqwestTransport::default(), provider, device, session);
    let result = client.apply_prepared_create(plan).await?;
    store.write_json("live/session.json", &client.session)?;
    Ok(result)
}
fn status(report: &icloud_safari::DecryptionReport) {
    eprintln!(
        "PCS: {} discovered, {} unwrapped; {} encrypted fields authenticated",
        report.pcs_objects, report.unwrapped_objects, report.authenticated_fields
    )
}
fn output<T: serde::Serialize + std::fmt::Debug>(value: &T, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?)
    } else {
        println!("{value:#?}")
    }
    Ok(())
}
fn write_secure_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(Error::Authentication(
            "Apple Account cannot be empty".into(),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_login_fails_before_anisette_or_network() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FileStateStore::new(temporary.path().join("missing"));
        let result = live_context(&store, Some("http://127.0.0.1:1")).await;
        assert!(
            matches!(result, Err(Error::Authentication(message)) if message.contains("run login"))
        );
        assert!(!store.root().exists());
    }

    #[test]
    fn malformed_saved_state_is_not_treated_as_a_new_account() {
        let temporary = tempfile::tempdir().unwrap();
        let store = FileStateStore::new(temporary.path());
        store
            .write_json("live/session.json", &serde_json::json!({"broken": true}))
            .unwrap();
        assert!(read_optional_state::<SessionState>(&store, "live/session.json").is_err());
        assert!(
            read_optional_state::<SessionState>(&store, "missing.json")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn online_is_the_default_but_explicit_offline_sources_win() {
        assert!(should_fetch(false, false, &None));
        assert!(!should_fetch(true, false, &None));
        assert!(!should_fetch(
            false,
            false,
            &Some(PathBuf::from("fixtures"))
        ));
        assert!(should_fetch(false, true, &Some(PathBuf::from("fixtures"))));
    }
}
