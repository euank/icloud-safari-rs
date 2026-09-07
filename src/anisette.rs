//! Local Anisette provisioning and an optional HTTP compatibility provider.

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use omnisette::{
    AnisetteConfiguration, AnisetteHeaders, AnisetteHeadersProviderType,
    anisette_headers_provider::AnisetteHeadersProvider as OmnisetteProvider,
};
use tokio::{io::AsyncWriteExt, sync::Mutex};

use crate::{
    Error, Result,
    cloudkit::{AnisetteProvider, DeviceState, HttpAnisetteProvider},
};

pub const IDENTITY_HEADER_NAMES: &[&str] = &[
    "X-Apple-I-MD",
    "X-Apple-I-MD-M",
    "X-Apple-I-MD-RINFO",
    "X-Apple-I-MD-LU",
    "X-Apple-I-SRL-NO",
    "X-Mme-Device-Id",
    "X-Apple-I-Client-Time",
    "X-Apple-I-TimeZone",
    "X-Apple-Locale",
];

pub const APPLE_MUSIC_APK_URL: &str =
    "https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk";
const MAX_APK_BYTES: u64 = 256 * 1024 * 1024;
const MAX_LIBRARY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone)]
pub enum LocalOrHttpAnisette {
    Local(LocalAnisette),
    Http(HttpAnisetteProvider),
}

#[async_trait::async_trait]
impl AnisetteProvider for LocalOrHttpAnisette {
    async fn headers(&self) -> Result<BTreeMap<String, String>> {
        match self {
            Self::Local(provider) => provider.headers().await,
            Self::Http(provider) => provider.headers().await,
        }
    }
}

impl LocalOrHttpAnisette {
    pub async fn open(state_root: &Path, http_url: Option<&str>) -> Result<Self> {
        if let Some(url) = http_url {
            return Ok(Self::Http(HttpAnisetteProvider::new(url)));
        }
        Ok(Self::Local(LocalAnisette::open(state_root).await?))
    }

    /// Reconcile the persisted CloudKit device identity with the identity
    /// supplied by the provisioned Anisette backend.
    pub async fn device_state(&self, prior: Option<DeviceState>) -> Result<DeviceState> {
        let headers = self.headers().await?;
        let mut device = prior.unwrap_or_else(DeviceState::generate);
        if let Some(value) = header(&headers, "X-Mme-Device-Id") {
            device.device_uuid = value.to_owned();
        }
        if let Some(value) = header(&headers, "X-Apple-I-MD-LU") {
            device.local_user_uuid = value.to_owned();
        }
        if let Some(value) = header(&headers, "X-Apple-I-SRL-NO") {
            device.serial = value.to_owned();
        }
        Ok(device)
    }
}

/// Build the stable Apple device identity headers and overlay fresh Anisette
/// values. Only known identity headers are accepted from a provider.
pub async fn identity_headers<A: AnisetteProvider>(
    provider: &A,
    device: &DeviceState,
) -> Result<Vec<(String, String)>> {
    let mut values = BTreeMap::from([
        (
            "X-Apple-I-Client-Time".to_owned(),
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        ),
        ("X-Apple-I-TimeZone".to_owned(), "UTC".to_owned()),
        ("X-Apple-Locale".to_owned(), "en_US".to_owned()),
        ("X-Apple-I-MD-RINFO".to_owned(), "17106176".to_owned()),
        ("X-Apple-I-MD-LU".to_owned(), device.local_user_uuid.clone()),
        ("X-Apple-I-SRL-NO".to_owned(), device.serial.clone()),
        ("X-Mme-Device-Id".to_owned(), device.device_uuid.clone()),
    ]);
    for (name, value) in provider.headers().await? {
        if let Some(canonical) = IDENTITY_HEADER_NAMES
            .iter()
            .find(|allowed| name.eq_ignore_ascii_case(allowed))
        {
            values.insert((*canonical).to_owned(), value);
        }
    }
    if !values.contains_key("X-Apple-I-MD") || !values.contains_key("X-Apple-I-MD-M") {
        return Err(Error::Anisette(
            "Anisette provider omitted mandatory machine headers".into(),
        ));
    }
    Ok(values.into_iter().collect())
}

#[derive(Clone)]
pub struct LocalAnisette {
    provider: Arc<Mutex<Box<dyn OmnisetteProvider>>>,
    state_root: Arc<PathBuf>,
}

impl LocalAnisette {
    pub async fn open(state_root: &Path) -> Result<Self> {
        let root = state_root.join("anisette");
        ensure_dir(&root)?;
        #[cfg(not(target_os = "macos"))]
        ensure_apple_libraries(&root).await?;

        let configuration = AnisetteConfiguration::new().set_configuration_path(root.clone());
        let selected = AnisetteHeaders::get_anisette_headers_provider(configuration)
            .map_err(|error| Error::Anisette(error.to_string()))?;
        if !matches!(selected.provider_type, AnisetteHeadersProviderType::Local) {
            return Err(Error::Anisette(
                "local Anisette initialization failed; refusing an implicit remote provider".into(),
            ));
        }
        harden_tree(&root)?;
        Ok(Self {
            provider: Arc::new(Mutex::new(selected.provider)),
            state_root: Arc::new(root),
        })
    }
}

#[async_trait::async_trait]
impl AnisetteProvider for LocalAnisette {
    async fn headers(&self) -> Result<BTreeMap<String, String>> {
        let headers = self
            .provider
            .lock()
            .await
            .get_authentication_headers()
            .await
            .map_err(|error| Error::Anisette(error.to_string()))?;
        harden_tree(&self.state_root)?;
        Ok(headers.into_iter().collect())
    }
}

fn header<'a>(headers: &'a BTreeMap<String, String>, wanted: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| value.as_str())
}

#[cfg(not(target_os = "macos"))]
async fn ensure_apple_libraries(root: &Path) -> Result<()> {
    let architecture = android_architecture()?;
    let library_dir = root.join("lib").join(architecture);
    ensure_dir(&library_dir)?;
    let names = ["libstoreservicescore.so", "libCoreADI.so"];
    if names.iter().all(|name| library_dir.join(name).is_file()) {
        return Ok(());
    }

    tracing::info!("downloading Apple Music APK for local Anisette provisioning");
    let temporary = root.join(format!(".applemusic-{}.apk", uuid::Uuid::new_v4()));
    if let Err(error) = download_apple_music_apk(&temporary).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error);
    }

    let apk = temporary.clone();
    let destination = library_dir.clone();
    let extraction = tokio::task::spawn_blocking(move || extract_libraries(&apk, &destination))
        .await
        .map_err(|_| Error::Anisette("Anisette library extraction task failed".into()))?;
    let cleanup = tokio::fs::remove_file(&temporary).await;
    extraction?;
    cleanup?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
async fn download_apple_music_apk(temporary: &Path) -> Result<()> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut output = options.open(&temporary).await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()
        .map_err(|error| Error::Network(error.to_string()))?;
    let mut response = client
        .get(APPLE_MUSIC_APK_URL)
        .send()
        .await
        .map_err(|error| Error::Network(error.to_string()))?
        .error_for_status()
        .map_err(|error| Error::Network(error.to_string()))?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_APK_BYTES)
    {
        return Err(Error::Anisette(
            "Apple Music APK exceeds the size limit".into(),
        ));
    }
    let mut downloaded = 0u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| Error::Network(error.to_string()))?
    {
        downloaded += chunk.len() as u64;
        if downloaded > MAX_APK_BYTES {
            return Err(Error::Anisette(
                "Apple Music APK exceeds the size limit".into(),
            ));
        }
        output.write_all(&chunk).await?;
    }
    output.sync_all().await?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn extract_libraries(apk: &Path, destination: &Path) -> Result<()> {
    let architecture = android_architecture()?;
    let file = fs::File::open(apk)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| Error::Anisette(format!("invalid Apple Music APK: {error}")))?;
    for name in ["libstoreservicescore.so", "libCoreADI.so"] {
        if destination.join(name).is_file() {
            continue;
        }
        let entry_name = format!("lib/{architecture}/{name}");
        let entry = archive
            .by_name(&entry_name)
            .map_err(|_| Error::Anisette(format!("Apple Music APK omitted {entry_name}")))?;
        if entry.size() > MAX_LIBRARY_BYTES {
            return Err(Error::Anisette(format!(
                "{entry_name} exceeds the size limit"
            )));
        }
        let temporary = destination.join(format!(".{name}.tmp-{}", uuid::Uuid::new_v4()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(&temporary)?;
        let copied = std::io::copy(&mut entry.take(MAX_LIBRARY_BYTES + 1), &mut output)?;
        if copied > MAX_LIBRARY_BYTES {
            return Err(Error::Anisette(format!(
                "{entry_name} exceeds the size limit"
            )));
        }
        output.flush()?;
        output.sync_all()?;
        fs::rename(temporary, destination.join(name))?;
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn android_architecture() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("x86_64"),
        "x86" => Ok("x86"),
        "aarch64" => Ok("arm64-v8a"),
        "arm" => Ok("armeabi-v7a"),
        other => Err(Error::Anisette(format!(
            "local Anisette is unsupported on architecture {other}"
        ))),
    }
}

fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn harden_tree(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let metadata = entry.file_type()?;
        if metadata.is_symlink() {
            return Err(Error::UnsafePermissions(entry.path()));
        }
        if metadata.is_dir() {
            harden_tree(&entry.path())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o700))?;
            }
        } else if metadata.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600))?;
            }
        }
    }
    Ok(())
}
