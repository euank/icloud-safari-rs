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
        /// Read the Apple Account password from an owner-only file, not argv.
        #[arg(long)]
        password_file: Option<PathBuf>,
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
    #[cfg(feature = "experimental-live-writes")]
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
#[cfg(feature = "experimental-live-writes")]
#[derive(Debug, Subcommand)]
enum OctagonCommand {
    /// Recover an escrow bottle and join the existing trust circle.
    #[cfg(feature = "experimental-live-writes")]
    Enroll {
        #[arg(long)]
        bottle_id: String,
        #[arg(long)]
        confirm_escrow_recovery: Option<String>,
        /// Request SMS during the fresh authentication needed for escrow.
        #[arg(long)]
        sms: bool,
        /// Read the Apple Account password from an owner-only file.
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// Read the known device passcode from an owner-only file. Never guess.
        #[arg(long)]
        device_passcode_file: Option<PathBuf>,
        /// Refresh a stale pending peer's trust data, preserving its identity.
        #[arg(long)]
        refresh_trust: bool,
        /// Explicitly authorize one more escrow attempt after an unresolved failure.
        #[arg(long)]
        retry_escrow_recovery: bool,
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
    if cli.fixture_dir.is_some()
        && !matches!(
            &cli.command,
            Command::VerifyFixtures
                | Command::ListTabs(_)
                | Command::ListDevices(_)
                | Command::ListBookmarks(_)
                | Command::ListHistory(_)
                | Command::Export { .. }
                | Command::Write {
                    command: WriteCommand::Update { .. } | WriteCommand::Delete { .. }
                }
        )
    {
        return Err(Error::Unsupported(
            "--fixture-dir is only valid for offline Safari reads, verification and write-plan preparation; remove it to explicitly use a live command",
        ));
    }
    let state_root = cli.state_dir.unwrap_or_else(default_state_dir);
    let store = FileStateStore::new(&state_root);
    let writes_state = match &cli.command {
        Command::Status | Command::VerifyFixtures => false,
        Command::ListTabs(args)
        | Command::ListDevices(args)
        | Command::ListBookmarks(args)
        | Command::ListHistory(args) => should_fetch(args.offline, args.fetch, &cli.fixture_dir),
        Command::Export { offline, fetch, .. } => should_fetch(*offline, *fetch, &cli.fixture_dir),
        _ => true,
    };
    let _state_lock = if writes_state {
        Some(store.try_lock()?)
    } else {
        None
    };
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
        Command::Login {
            username,
            sms,
            password_file,
        } => {
            login(
                &store,
                cli.anisette_url.as_deref(),
                username,
                sms,
                password_file.as_deref(),
            )
            .await?
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
        } => login(&store, cli.anisette_url.as_deref(), None, false, None).await?,
        Command::Auth {
            command: AuthCommand::Refresh,
        } => refresh(&store, cli.anisette_url.as_deref()).await?,
        Command::Escrow {
            command: EscrowCommand::List,
        } => {
            let client = enrollment_client(&store, cli.anisette_url.as_deref()).await?;
            let bottles = icloud_safari::enrollment::list_bottles(&client).await?;
            let summaries: Vec<_> = bottles.iter().map(|bottle| serde_json::json!({
                "label": bottle.label, "bottle_id": bottle.bottle_id, "peer_id": bottle.peer_id
            })).collect();
            println!("{}", serde_json::to_string_pretty(&summaries)?);
        }
        Command::Keys {
            command: KeysCommand::Recover,
        } => {
            recover_safari_keys(&store, cli.anisette_url.as_deref()).await?;
        }
        #[cfg(feature = "experimental-live-writes")]
        Command::Octagon {
            command:
                OctagonCommand::Enroll {
                    bottle_id,
                    confirm_escrow_recovery,
                    sms,
                    password_file,
                    device_passcode_file,
                    refresh_trust,
                    retry_escrow_recovery,
                },
        } => {
            if !cfg!(feature = "experimental-live-writes") {
                return Err(Error::Unsupported(
                    "enrollment requires the experimental-live-writes feature",
                ));
            }
            if confirm_escrow_recovery.as_deref() != Some(&bottle_id) {
                return Err(Error::Authentication("--confirm-escrow-recovery must exactly match --bottle-id; recovery spends a rate-limited passcode attempt and joins the trust circle".into()));
            }
            enroll(
                &store,
                cli.anisette_url.as_deref(),
                &bottle_id,
                sms,
                password_file.as_deref(),
                device_passcode_file.as_deref(),
                EnrollmentOptions {
                    refresh_trust,
                    retry_escrow_recovery,
                },
            )
            .await?;
        }
    }
    Ok(())
}
fn reader<'a>(fixture: &'a Option<PathBuf>, state: &'a Path) -> Result<OfflineReader> {
    OfflineReader::open(fixture.as_deref().unwrap_or(state))
}
fn should_fetch(offline: bool, _force_fetch: bool, fixture: &Option<PathBuf>) -> bool {
    !offline && fixture.is_none()
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
    password_file: Option<&Path>,
) -> Result<()> {
    login_credentials(store, anisette_url, username, prefer_sms, password_file).await?;
    Ok(())
}

async fn login_credentials(
    store: &FileStateStore,
    anisette_url: Option<&str>,
    username: Option<String>,
    prefer_sms: bool,
    password_file: Option<&Path>,
) -> Result<icloud_safari::account::GrandSlamCredentials> {
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
    let password = read_password(password_file, "Password: ")?;
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
    Ok(outcome.credentials)
}

type EnrollmentClient =
    icloud_safari::keychain::KeychainClient<ReqwestTransport, LocalOrHttpAnisette>;

async fn enrollment_client(
    store: &FileStateStore,
    anisette_url: Option<&str>,
) -> Result<EnrollmentClient> {
    let (provider, device, session) = live_context(store, anisette_url).await?;
    let client =
        EnrollmentClient::initialize(ReqwestTransport::default(), provider, device, session)
            .await?;
    store.write_json("live/session.json", client.session())?;
    Ok(client)
}

async fn recover_safari_keys(store: &FileStateStore, anisette_url: Option<&str>) -> Result<()> {
    use sha2::{Digest, Sha256};
    let client = enrollment_client(store, anisette_url).await?;
    let identities = client.recover_pcs_identities().await?;
    // Validate the whole recovery before touching files. Hash names are stable
    // across retries and do not reveal a service label or private key.
    for identity in &identities {
        store.write_bytes(
            format!(
                "pcs-identities/{}.der",
                hex::encode(Sha256::digest(&**identity))
            ),
            identity,
        )?;
    }
    println!(
        "Recovered and saved {} authenticated PCS identities.",
        identities.len()
    );
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PendingEnrollment {
    dsid: String,
    bottle_id: String,
    enrollment: icloud_safari::enrollment::Enrollment,
}

fn checkpoint_matches_account(session: &SessionState, checkpoint_dsid: &str) -> bool {
    if checkpoint_dsid.is_empty() {
        return false;
    }
    if checkpoint_dsid == session.mme.dsid {
        return true;
    }
    // Historical sessions stored ADSID in the top-level DSID slot. Only
    // accept that alias when bound by authenticated account settings.
    session
        .mme
        .extra
        .get("accountSettings")
        .and_then(|settings| settings.get("appleAccountInfo"))
        .and_then(|info| info.get("aDsID"))
        .and_then(serde_json::Value::as_str)
        == Some(checkpoint_dsid)
}

fn validate_pending_session(session: &SessionState, pending: &PendingEnrollment) -> Result<()> {
    if !checkpoint_matches_account(session, &pending.dsid) {
        return Err(Error::Authentication(
            "saved enrollment checkpoint belongs to another account".into(),
        ));
    }
    if let Some(existing) = session.extra.get("octagon") {
        use base64::Engine as _;
        let mismatch = || {
            Error::Authentication("saved session and pending enrollment contain different identities; refusing to overwrite either identity".into())
        };
        let existing: icloud_safari::enrollment::Enrollment =
            serde_json::from_value(existing.clone()).map_err(|_| mismatch())?;
        let candidate = &pending.enrollment;
        if existing.peer_id != candidate.peer_id
            || existing.keys.signing_priv_x963 != candidate.keys.signing_priv_x963
            || existing.keys.encryption_priv_x963 != candidate.keys.encryption_priv_x963
            || existing.sponsor.peer_id != candidate.sponsor.peer_id
            || existing.sponsor.signing_priv_x963 != candidate.sponsor.signing_priv_x963
            || existing.sponsor.encryption_priv_x963 != candidate.sponsor.encryption_priv_x963
            || existing.recovery_identities.len() != candidate.recovery_identities.len()
            || existing
                .recovery_identities
                .iter()
                .zip(&candidate.recovery_identities)
                .any(|(a, b)| {
                    a.peer_id != b.peer_id || a.encryption_priv_x963 != b.encryption_priv_x963
                })
        {
            return Err(mismatch());
        }
        if existing.peer_base64 != candidate.peer_base64 {
            let decode = |encoded: &str| {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| mismatch())?;
                icloud_safari::wire::Message::parse(&bytes).map_err(|_| mismatch())
            };
            let old = decode(&existing.peer_base64)?;
            let new = decode(&candidate.peer_base64)?;
            // Refresh may change stable/dynamic metadata, never identity,
            // signed permanent information, or the sponsor's voucher.
            for field in [1, 2, 5] {
                if old.first_bytes(field).is_none()
                    || old.values(field).collect::<Vec<_>>()
                        != new.values(field).collect::<Vec<_>>()
                {
                    return Err(mismatch());
                }
            }
        }
    }
    Ok(())
}

#[cfg(feature = "experimental-live-writes")]
#[derive(serde::Serialize, serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct RecoveryCheckpoint {
    dsid: String,
    adsid: String,
    #[zeroize(skip)]
    bottle: icloud_safari::enrollment::Bottle,
    entropy_base64: String,
}

#[cfg(feature = "experimental-live-writes")]
struct EnrollmentOptions {
    refresh_trust: bool,
    retry_escrow_recovery: bool,
}

#[cfg(feature = "experimental-live-writes")]
async fn enroll(
    store: &FileStateStore,
    anisette_url: Option<&str>,
    bottle_id: &str,
    sms: bool,
    password_file: Option<&Path>,
    device_passcode_file: Option<&Path>,
    options: EnrollmentOptions,
) -> Result<()> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let mut client = enrollment_client(store, anisette_url).await?;
    let pending: Option<PendingEnrollment> = read_optional_state(store, "enrollment/pending.json")?;
    let mut pending = if let Some(pending) = pending {
        validate_pending_session(client.session(), &pending)?;
        if pending.bottle_id != bottle_id {
            return Err(Error::Authentication("saved pending enrollment belongs to another account or bottle; resume it using its original --bottle-id".into()));
        }
        eprintln!("Resuming the saved peer; escrow recovery will not be repeated.");
        pending
    } else {
        if client.session().extra.contains_key("octagon") {
            return Err(Error::Authentication("Octagon identity already exists; use keys recover instead of creating another peer".into()));
        }
        let recovery: Option<RecoveryCheckpoint> =
            read_optional_state(store, "enrollment/recovery.json")?;
        let recovery = if let Some(recovery) = recovery {
            if !checkpoint_matches_account(client.session(), &recovery.dsid)
                || recovery.bottle.bottle_id != bottle_id
            {
                return Err(Error::Authentication("saved recovery belongs to another account or bottle; use its original --bottle-id".into()));
            }
            eprintln!("Resuming the saved recovered bottle; no passcode attempt will be repeated.");
            recovery
        } else {
            let previous_attempt: Option<serde_json::Value> =
                read_optional_state(store, "enrollment/attempt.json")?;
            if let Some(attempt) = &previous_attempt {
                if !attempt["dsid"]
                    .as_str()
                    .is_some_and(|dsid| checkpoint_matches_account(client.session(), dsid))
                    || attempt["bottle_id"].as_str() != Some(bottle_id)
                {
                    return Err(Error::Authentication(
                        "previous escrow attempt belongs to another account or bottle".into(),
                    ));
                }
                if !options.retry_escrow_recovery {
                    return Err(Error::Authentication("a prior escrow attempt has no saved recovery result; refusing another attempt. Investigate first; --retry-escrow-recovery explicitly authorizes one more rate-limited attempt and preserves its history".into()));
                }
            }
            let bottles = icloud_safari::enrollment::list_bottles(&client).await?;
            let mut selected = bottles
                .into_iter()
                .filter(|bottle| bottle.bottle_id == bottle_id);
            let bottle = selected.next().ok_or(Error::Authentication(
                "bottle is not viable; run escrow list".into(),
            ))?;
            if selected.next().is_some() {
                return Err(Error::Authentication(
                    "bottle selection is ambiguous".into(),
                ));
            }
            icloud_safari::enrollment::fetch_directory(&client).await?;
            eprintln!(
                "Fresh Apple Account authentication is required for escrow. The device passcode will be requested separately."
            );
            let credentials =
                login_credentials(store, anisette_url, None, sms, password_file).await?;
            let (provider, device, session) = live_context(store, anisette_url).await?;
            // Container initialization was preserved by same-account login.
            let escrow = icloud_safari::enrollment::escrow::EscrowClient::new(
                ReqwestTransport::default(),
                provider.clone(),
                device.clone(),
                &session,
                &credentials,
            )?;
            // Verify the exact record label still exists before spending an attempt.
            let records = escrow.records().await?;
            if let Some(model) = icloud_safari::enrollment::escrow::record_model(
                &records,
                &bottle.label,
                &bottle.bottle_id,
            )? {
                eprintln!("Escrow device model: {model}");
            }
            eprintln!(
                "Recovering bottle {}. Enter the passcode/password of the device that created this record. One recovery attempt will be made.",
                bottle.bottle_id
            );
            let passcode = read_password(
                device_passcode_file,
                "Device passcode/password (blank cancels): ",
            )?;
            if passcode.is_empty() {
                return Err(Error::Authentication("enrollment cancelled".into()));
            }
            if let Some(attempt) = previous_attempt {
                store.write_json(
                    format!("enrollment/attempt-history/{}.json", uuid::Uuid::new_v4()),
                    &attempt,
                )?;
            }
            let mut attempt = serde_json::json!({
                "dsid": session.mme.dsid, "bottle_id": bottle_id,
                "started_at": chrono::Utc::now().to_rfc3339(),
            });
            store.write_json("enrollment/attempt.json", &attempt)?;
            let entropy = match escrow.recover(&bottle.label, passcode.as_bytes()).await {
                Ok(entropy) => entropy,
                Err(error) => {
                    attempt["last_error"] = serde_json::Value::String(error.to_string());
                    store.write_json("enrollment/attempt.json", &attempt)?;
                    return Err(error);
                }
            };
            let recovery = RecoveryCheckpoint {
                dsid: session.mme.dsid.clone(),
                adsid: credentials.adsid.clone(),
                bottle,
                entropy_base64: STANDARD.encode(&*entropy),
            };
            // Persist successful recovery before any parsing, policy or join work.
            store.write_json("enrollment/recovery.json", &recovery)?;
            recovery
        };
        client = enrollment_client(store, anisette_url).await?;
        let directory = icloud_safari::enrollment::fetch_directory(&client).await?;
        let device: DeviceState = store.read_json("live/device.json")?;
        let entropy = Zeroizing::new(
            STANDARD
                .decode(&recovery.entropy_base64)
                .map_err(|_| Error::Integrity)?,
        );
        let enrollment = icloud_safari::enrollment::prepare_enrollment(
            &recovery.bottle,
            &entropy,
            &recovery.adsid,
            &device,
            &directory,
        )?;
        let pending = PendingEnrollment {
            dsid: client.session().mme.dsid.clone(),
            bottle_id: bottle_id.into(),
            enrollment,
        };
        store.write_json("enrollment/pending.json", &pending)?;
        pending
    };
    // A crash may occur after pending.json was committed but before session.json.
    if options.refresh_trust {
        let directory = icloud_safari::enrollment::fetch_directory(&client).await?;
        icloud_safari::enrollment::refresh_enrollment(&mut pending.enrollment, &directory)?;
        store.write_json("enrollment/pending.json", &pending)?;
    }
    let mut session = client.session().clone();
    session
        .extra
        .insert("octagon".into(), serde_json::to_value(&pending.enrollment)?);
    store.write_json("live/session.json", &session)?;
    client = enrollment_client(store, anisette_url).await?;
    icloud_safari::enrollment::join(&client, &mut pending.enrollment).await?;
    store.write_json("enrollment/pending.json", &pending)?;
    let mut session = client.session().clone();
    session
        .extra
        .insert("octagon".into(), serde_json::to_value(&pending.enrollment)?);
    store.write_json("live/session.json", &session)?;
    println!("Octagon enrollment confirmed.");
    recover_safari_keys(store, anisette_url).await
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
    let pending: Option<PendingEnrollment> = read_optional_state(store, "enrollment/pending.json")?;
    let joined = session
        .extra
        .get("octagon")
        .and_then(|peer| peer.get("joined"))
        .and_then(serde_json::Value::as_bool)
        == Some(true);
    if let Some(pending) = &pending {
        validate_pending_session(session, pending)?;
        if !joined {
            println!(
                "Octagon join pending. Resume octagon enroll with --bottle-id {} and matching --confirm-escrow-recovery.",
                pending.bottle_id
            );
        }
    } else if store.root().join("enrollment/recovery.json").try_exists()? {
        println!(
            "Recovered bottle checkpoint present; rerun octagon enroll to prepare and join without another passcode attempt."
        );
    } else if store.root().join("enrollment/attempt.json").try_exists()? {
        println!(
            "Escrow attempt has no recovery checkpoint. Automatic retry is blocked; inspect the previous failure before authorizing another attempt."
        );
    }
    let has_user = session
        .mme
        .extra
        .get("cloudKitUserId")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.is_empty());
    println!(
        "Password enrollment: {}",
        if has_octagon && has_user && joined {
            "joined state present (not verified online)"
        } else if has_octagon {
            "saved identity present; join not confirmed"
        } else {
            "missing"
        }
    );
    if !has_identities || !has_octagon || !has_user {
        println!(
            "Authentication alone does not recover encryption keys. Use escrow list and octagon enroll for a new peer, or keys recover for existing enrollment; see README.md (Encryption-key setup)."
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

fn read_password(path: Option<&Path>, prompt: &str) -> Result<Zeroizing<String>> {
    use std::io::Read;
    let mut password = if let Some(path) = path {
        if fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(Error::UnsafePermissions(path.into()));
        }
        let mut file = fs::File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(Error::UnsafePermissions(path.into()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::UnsafePermissions(path.into()));
            }
        }
        let mut secret = Zeroizing::new(String::new());
        file.read_to_string(&mut secret)?;
        secret
    } else {
        Zeroizing::new(rpassword::prompt_password(prompt)?)
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
    Ok(password)
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
    // Serialize before touching the destination: a failing serializer must not
    // truncate an existing export. Only the private replacement inode is written.
    let mut bytes = Zeroizing::new(serde_json::to_vec_pretty(value)?);
    bytes.push(b'\n');
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| Error::Fixture("output path must name a file".into()))?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
            return Err(Error::UnsafePermissions(path.into()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        name.to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        // This unique temporary path was created by this invocation. A successful
        // rename already removed it; never remove the destination on failure.
        let _ = fs::remove_file(&temporary);
    }
    result
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

    #[test]
    fn failed_export_serialization_preserves_existing_output() {
        struct InvalidExport;
        impl serde::Serialize for InvalidExport {
            fn serialize<S: serde::Serializer>(
                &self,
                _: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("synthetic serialization failure"))
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("output.json");
        fs::write(&path, b"original").unwrap();
        assert!(write_secure_json(&path, &InvalidExport).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"original");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn export_refuses_directory_targets() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("existing-directory");
        fs::create_dir(&target).unwrap();
        assert!(write_secure_json(&target, &serde_json::json!({"value": "private"})).is_err());
        assert!(target.is_dir());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn exports_replace_privately_and_atomically_without_chmod_parent() {
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let path = temp.path().join("output.json");
        fs::write(&path, b"original").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let mut old = fs::File::open(&path).unwrap();
        write_secure_json(&path, &serde_json::json!({"value": "private"})).unwrap();
        let mut original = Vec::new();
        old.read_to_end(&mut original).unwrap();
        assert_eq!(original, b"original");
        let updated: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(updated["value"], "private");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(temp.path()).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn exports_reject_symlinks_without_modifying_targets() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.json");
        let link = temp.path().join("link.json");
        fs::write(&target, b"original").unwrap();
        symlink(&target, &link).unwrap();
        assert!(write_secure_json(&link, &serde_json::json!({"value": "private"})).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"original");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn failed_export_rename_cleans_only_its_temporary_file() {
        let temp = tempfile::tempdir().unwrap();
        let unrelated = temp.path().join("keep");
        fs::write(&unrelated, b"unchanged").unwrap();
        // A trailing slash requires a directory at rename time. The destination
        // is absent, so the file rename fails after its temporary file is saved.
        let target = temp.path().join("not-a-directory/");
        assert!(write_secure_json(&target, &serde_json::json!({"value": "private"})).is_err());
        assert_eq!(fs::read(&unrelated).unwrap(), b"unchanged");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn pending_peer_cannot_overwrite_another_saved_identity() {
        let mut session: SessionState = serde_json::from_value(serde_json::json!({
            "username":"test@example.invalid", "dsid":"123",
            "mme":{"dsid":"123", "mmeAuthToken":"synthetic", "tokens":{}}
        }))
        .unwrap();
        let pending: PendingEnrollment = serde_json::from_value(serde_json::json!({
            "dsid":"123", "bottle_id":"synthetic", "enrollment": {
                "peer_id":"new-peer", "keys":{"signing_priv_x963":"", "encryption_priv_x963":""},
                "sponsor":{"peer_id":"sponsor", "signing_priv_x963":"", "encryption_priv_x963":""},
                "joined":false, "peer_base64":""
            }
        }))
        .unwrap();
        assert!(validate_pending_session(&session, &pending).is_ok());
        session.extra.insert(
            "octagon".into(),
            serde_json::json!({"peer_id":"different-peer"}),
        );
        assert!(validate_pending_session(&session, &pending).is_err());
        session.extra.insert(
            "octagon".into(),
            serde_json::to_value(&pending.enrollment).unwrap(),
        );
        assert!(validate_pending_session(&session, &pending).is_ok());
        for (section, field) in [
            ("keys", "signing_priv_x963"),
            ("keys", "encryption_priv_x963"),
            ("sponsor", "peer_id"),
            ("sponsor", "signing_priv_x963"),
            ("sponsor", "encryption_priv_x963"),
        ] {
            let mut altered = serde_json::to_value(&pending.enrollment).unwrap();
            altered[section][field] = serde_json::json!("different");
            session.extra.insert("octagon".into(), altered);
            assert!(validate_pending_session(&session, &pending).is_err());
        }
        session.extra.insert(
            "octagon".into(),
            serde_json::to_value(&pending.enrollment).unwrap(),
        );
        session.mme.dsid = "456".into();
        assert!(validate_pending_session(&session, &pending).is_err());
    }

    #[test]
    fn checkpoints_accept_only_authenticated_legacy_account_alias() {
        let mut session: SessionState = serde_json::from_value(serde_json::json!({
            "username":"test@example.invalid", "dsid":"untrusted-alias",
            "mme":{"dsid":"123", "mmeAuthToken":"synthetic", "tokens":{},
                "accountSettings":{"appleAccountInfo":{"aDsID":"legacy-adsid"}}}
        }))
        .unwrap();
        assert!(checkpoint_matches_account(&session, "123"));
        assert!(checkpoint_matches_account(&session, "legacy-adsid"));
        assert!(!checkpoint_matches_account(&session, "untrusted-alias"));
        assert!(!checkpoint_matches_account(&session, ""));
        session.dsid = "123".into();
        assert!(checkpoint_matches_account(&session, "legacy-adsid"));
        session.mme.extra.clear();
        assert!(!checkpoint_matches_account(&session, "legacy-adsid"));
    }

    #[test]
    fn pending_refresh_preserves_immutable_peer_fields() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let mut session: SessionState = serde_json::from_value(serde_json::json!({
            "username":"test@example.invalid", "dsid":"123",
            "mme":{"dsid":"123", "mmeAuthToken":"synthetic", "tokens":{}}
        }))
        .unwrap();
        let peer = |changed: u32| {
            let mut bytes = Vec::new();
            for field in 1..=5 {
                icloud_safari::wire::encode_bytes(
                    field,
                    if field == changed {
                        b"changed"
                    } else {
                        b"original"
                    },
                    &mut bytes,
                );
            }
            STANDARD.encode(bytes)
        };
        let mut pending: PendingEnrollment = serde_json::from_value(serde_json::json!({
            "dsid":"123", "bottle_id":"synthetic", "enrollment": {
                "peer_id":"new-peer", "keys":{"signing_priv_x963":"", "encryption_priv_x963":""},
                "sponsor":{"peer_id":"sponsor", "signing_priv_x963":"", "encryption_priv_x963":""},
                "joined":false, "peer_base64":peer(0)
            }
        }))
        .unwrap();
        session.extra.insert(
            "octagon".into(),
            serde_json::to_value(&pending.enrollment).unwrap(),
        );
        for field in 1..=5 {
            pending.enrollment.peer_base64 = peer(field);
            assert_eq!(
                validate_pending_session(&session, &pending).is_ok(),
                matches!(field, 3 | 4)
            );
        }
        pending.enrollment.peer_base64 = peer(0);
        pending.enrollment.joined = true;
        assert!(validate_pending_session(&session, &pending).is_ok());
        pending
            .enrollment
            .recovery_identities
            .push(icloud_safari::enrollment::RecoveryIdentity {
                peer_id: "unexpected".into(),
                encryption_priv_x963: "synthetic".into(),
            });
        assert!(validate_pending_session(&session, &pending).is_err());
    }

    #[tokio::test]
    async fn fixture_flag_rejects_live_commands_before_creating_state() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("must-not-exist");
        for args in [
            vec!["login"],
            vec!["refresh"],
            vec!["passwords", "list"],
            vec!["escrow", "list"],
            vec!["keys", "recover"],
        ] {
            let mut argv = vec![
                "icloud-safari",
                "--state-dir",
                root.to_str().unwrap(),
                "--fixture-dir",
                "fixtures/private",
            ];
            argv.extend(args);
            let parsed = Cli::try_parse_from(argv).unwrap();
            assert!(matches!(run(parsed).await, Err(Error::Unsupported(_))));
            assert!(!root.exists());
        }
    }

    #[test]
    fn file_password_preserves_content_and_rejects_empty() {
        let temp = tempfile::tempdir().unwrap();
        let store = FileStateStore::new(temp.path());
        store.write_bytes("password", b" spaces stay \r\n").unwrap();
        assert_eq!(
            &*read_password(Some(&temp.path().join("password")), "unused").unwrap(),
            " spaces stay "
        );
        store.write_bytes("password", b"\n").unwrap();
        assert!(read_password(Some(&temp.path().join("password")), "unused").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn file_password_rejects_public_permissions_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let store = FileStateStore::new(temp.path());
        store.write_bytes("password", b"synthetic").unwrap();
        let path = temp.path().join("password");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            read_password(Some(&path), "unused"),
            Err(Error::UnsafePermissions(_))
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&path, temp.path().join("link")).unwrap();
        assert!(matches!(
            read_password(Some(&temp.path().join("link")), "unused"),
            Err(Error::UnsafePermissions(_))
        ));
    }

    #[cfg(not(feature = "experimental-live-writes"))]
    #[test]
    fn readonly_cli_does_not_expose_enrollment() {
        assert!(
            Cli::try_parse_from(["icloud-safari", "octagon", "enroll", "--bottle-id", "test"])
                .is_err()
        );
    }

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
        assert!(!should_fetch(false, true, &Some(PathBuf::from("fixtures"))));
    }
}
