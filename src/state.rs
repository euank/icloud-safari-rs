//! Mode-restricted, atomic CLI state storage.

use crate::{Error, Result};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct FileStateStore {
    root: PathBuf,
}

/// Exclusive advisory lock released when the guard is dropped. All cooperating
/// state writers must hold a guard for their complete read/modify/write cycle.
/// The lock file deliberately remains in place: deleting it could allow two
/// processes to lock different inodes for the same state directory.
#[derive(Debug)]
pub struct StateLock {
    _file: fs::File,
}

impl FileStateStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// Acquire the state directory without waiting for another CLI process.
    pub fn try_lock(&self) -> Result<StateLock> {
        self.ensure()?;
        let path = self.root.join(".state.lock");
        match fs::symlink_metadata(&path) {
            Ok(_) => check_file(&path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        if let Err(error) = fs2::FileExt::try_lock_exclusive(&file) {
            if error.kind() == std::io::ErrorKind::WouldBlock
                || error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
            {
                return Err(Error::Authentication(
                    "state directory is busy; wait for the other icloud-safari command to finish, or use a different --state-dir".into(),
                ));
            }
            return Err(error.into());
        }
        Ok(StateLock { _file: file })
    }
    pub fn ensure(&self) -> Result<()> {
        check_directories(&self.root, &self.root, true)?;
        set_dir_mode(&self.root)
    }
    pub fn read_json<T: DeserializeOwned>(&self, relative: impl AsRef<Path>) -> Result<T> {
        let path = self.checked_path(relative.as_ref())?;
        check_directories(
            &self.root,
            path.parent().expect("validated state path"),
            false,
        )?;
        check_file(&path)?;
        let bytes = zeroize::Zeroizing::new(fs::read(path)?);
        Ok(serde_json::from_slice(&bytes)?)
    }
    pub fn write_json<T: Serialize>(&self, relative: impl AsRef<Path>, value: &T) -> Result<()> {
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec_pretty(value)?);
        self.write_bytes(relative, &bytes)
    }

    /// Atomically persist private binary material with the same modes as JSON state.
    pub fn write_bytes(&self, relative: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
        let path = self.checked_path(relative.as_ref())?;
        self.ensure()?;
        let parent = path.parent().expect("validated state path");
        check_directories(&self.root, parent, true)?;
        // Restrict every directory inside the store, not only the leaf parent.
        let mut directory = self.root.clone();
        for component in relative
            .as_ref()
            .parent()
            .into_iter()
            .flat_map(Path::components)
        {
            directory.push(component);
            set_dir_mode(&directory)?;
        }
        match fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                return Err(Error::UnsafePermissions(path));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let name = path
            .file_name()
            .ok_or_else(|| Error::Fixture("invalid state path".into()))?;
        let temporary = path.with_file_name(format!(
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
        let mut cleanup = TemporaryFile(Some(temporary.clone()));
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &path)?;
        cleanup.0 = None;
        // Persist the rename as well as the file before callers send a join.
        sync_directory(parent)?;
        Ok(())
    }

    fn checked_path(&self, relative: &Path) -> Result<PathBuf> {
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(Error::Fixture(
                "state path must be a nonempty relative path without traversal".into(),
            ));
        }
        if relative.components().next() == Some(Component::Normal(".state.lock".as_ref())) {
            return Err(Error::Fixture(
                ".state.lock is reserved for state-directory locking".into(),
            ));
        }
        Ok(self.root.join(relative))
    }
}

struct TemporaryFile(Option<PathBuf>);

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            // Only ever remove the unique file successfully created by this write.
            let _ = fs::remove_file(path);
        }
    }
}

/// Reject symlinks at or below the store root before creating or traversing
/// any directory. These checks protect against accidental redirection, not
/// concurrent changes by the same OS user (who can already access this user's
/// credentials). Ancestors of the root are the user's choice of location and
/// may be symlinks (e.g. Fedora Atomic `/home -> var/home`, macOS
/// `/var -> private/var`); they are followed and must resolve to directories.
fn check_directories(root: &Path, path: &Path, create: bool) -> Result<()> {
    debug_assert!(path.starts_with(root));
    let ancestors = root.components().count().saturating_sub(1);
    let mut current = PathBuf::new();
    for (index, component) in path.components().enumerate() {
        if matches!(component, Component::ParentDir) {
            return Err(Error::Fixture(
                "state root must not contain parent traversal".into(),
            ));
        }
        current.push(component);
        let metadata = if index < ancestors {
            fs::metadata(&current)
        } else {
            fs::symlink_metadata(&current)
        };
        match metadata {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(Error::UnsafePermissions(current));
                }
            }
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(&current)?;
                // Flush each new directory's entry in its parent before going
                // deeper, so a nested initial save survives a system crash.
                sync_directory(
                    current
                        .parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or(Path::new(".")),
                )?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(unix)]
fn set_dir_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_dir_mode(_: &Path) -> Result<()> {
    Ok(())
}

fn check_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::UnsafePermissions(path.into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::UnsafePermissions(path.into()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusive_lock_blocks_independent_store_until_guard_drops() {
        let temp = tempfile::tempdir().unwrap();
        let store = FileStateStore::new(temp.path().join("state"));
        let other = FileStateStore::new(store.root());
        let guard = store.try_lock().unwrap();
        let error = other.try_lock().unwrap_err();
        assert!(error.to_string().contains("state directory is busy"));
        drop(guard);
        let _guard = other.try_lock().unwrap();
        assert!(store.try_lock().is_err());
    }

    #[test]
    fn lock_keeps_stale_file_and_never_truncates_it() {
        let temp = tempfile::tempdir().unwrap();
        let store = FileStateStore::new(temp.path().join("state"));
        let path = store.root().join(".state.lock");
        drop(store.try_lock().unwrap());
        fs::write(&path, b"stale lock metadata").unwrap();
        let guard = store.try_lock().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"stale lock metadata");
        drop(guard);
        assert_eq!(fs::read(&path).unwrap(), b"stale lock metadata");
        let _guard = store.try_lock().unwrap();
        assert!(store.write_bytes(".state.lock", b"replacement").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn lock_rejects_symlinks_and_unsafe_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        fs::write(&outside, b"unchanged").unwrap();
        let store = FileStateStore::new(temp.path().join("state"));
        store.ensure().unwrap();
        let lock_path = store.root().join(".state.lock");
        symlink(&outside, &lock_path).unwrap();
        assert!(store.try_lock().is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"unchanged");
        fs::remove_file(&lock_path).unwrap();
        fs::write(&lock_path, b"unchanged").unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.try_lock().is_err());
        let linked_root = temp.path().join("linked-root");
        symlink(store.root(), &linked_root).unwrap();
        assert!(FileStateStore::new(linked_root).try_lock().is_err());
    }

    #[test]
    fn rejects_absolute_and_traversal_paths_before_creating_state() {
        let temp = tempfile::tempdir().unwrap();
        let store = FileStateStore::new(temp.path().join("state"));
        for path in [
            Path::new(""),
            Path::new("../outside"),
            Path::new("nested/../../outside"),
            temp.path(),
        ] {
            assert!(store.write_bytes(path, b"private").is_err(), "{path:?}");
            assert!(
                store.read_json::<serde_json::Value>(path).is_err(),
                "{path:?}"
            );
        }
        assert!(!store.root().exists());
    }

    #[test]
    fn binary_writes_replace_without_temporary_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let store = FileStateStore::new(temp.path().join("state"));
        store
            .write_bytes("nested/deep/key.der", &[0, 1, 255])
            .unwrap();
        let path = store.root().join("nested/deep/key.der");
        let old = fs::File::open(&path).unwrap();
        store.write_bytes("nested/deep/key.der", &[255, 0]).unwrap();
        assert_eq!(fs::read(&path).unwrap(), [255, 0]);
        #[cfg(unix)]
        {
            use std::io::Read;
            use std::os::unix::fs::PermissionsExt;
            let mut old = old;
            let mut original = Vec::new();
            old.read_to_end(&mut original).unwrap();
            assert_eq!(original, [0, 1, 255], "replacement must use a new inode");
            for directory in [
                store.root().to_owned(),
                store.root().join("nested"),
                store.root().join("nested/deep"),
            ] {
                assert_eq!(
                    fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        #[cfg(not(unix))]
        drop(old);
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_roots_parents_and_targets_without_modifying_them() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(outside.join("value.json"), b"42").unwrap();
        let root_link = temp.path().join("root-link");
        symlink(&outside, &root_link).unwrap();
        let store = FileStateStore::new(&root_link);
        assert!(store.ensure().is_err());
        assert!(store.write_bytes("value.json", b"43").is_err());
        assert!(store.read_json::<u32>("value.json").is_err());
        let store = FileStateStore::new(temp.path().join("state"));
        store.ensure().unwrap();
        symlink(&outside, store.root().join("nested")).unwrap();
        symlink(outside.join("value.json"), store.root().join("value.json")).unwrap();
        for path in ["nested/value.json", "value.json"] {
            assert!(store.write_bytes(path, b"43").is_err());
            assert!(store.read_json::<u32>(path).is_err());
        }
        assert_eq!(fs::read(outside.join("value.json")).unwrap(), b"42");
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert!(!outside.join("child").exists());
    }

    #[test]
    fn follows_symlinked_ancestors_of_the_root() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let real_home = temp.path().join("var-home");
        fs::create_dir(&real_home).unwrap();
        fs::set_permissions(&real_home, fs::Permissions::from_mode(0o755)).unwrap();
        let home = temp.path().join("home");
        symlink(&real_home, &home).unwrap();
        let store = FileStateStore::new(home.join(".local/state/icloud-safari"));
        let _lock = store.try_lock().unwrap();
        store.write_json("nested/value.json", &42u32).unwrap();
        assert_eq!(store.read_json::<u32>("nested/value.json").unwrap(), 42);
        assert!(
            real_home
                .join(".local/state/icloud-safari/nested/value.json")
                .is_file()
        );
        // Only directories at or below the root are restricted.
        assert_eq!(
            fs::metadata(&real_home).unwrap().permissions().mode() & 0o777,
            0o755
        );
        // A symlink inside the root is still refused.
        symlink(&real_home, store.root().join("link")).unwrap();
        assert!(store.write_bytes("link/value.json", b"43").is_err());
    }

    #[test]
    fn unsuccessful_temporary_file_is_removed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("owned-temporary");
        fs::write(&path, b"private").unwrap();
        {
            let _cleanup = TemporaryFile(Some(path.clone()));
        }
        assert!(!path.exists());
    }

    #[test]
    fn refuses_to_replace_directory() {
        let temp = tempfile::tempdir().unwrap();
        let store = FileStateStore::new(temp.path().join("state"));
        store.ensure().unwrap();
        fs::create_dir(store.root().join("directory")).unwrap();
        assert!(store.write_bytes("directory", b"private").is_err());
        assert!(store.root().join("directory").is_dir());
        assert_eq!(fs::read_dir(store.root()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn replacement_restricts_existing_file_and_all_store_directories() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let store = FileStateStore::new(temp.path().join("state"));
        let parent = store.root().join("nested/deep");
        fs::create_dir_all(&parent).unwrap();
        for directory in [
            store.root().to_owned(),
            store.root().join("nested"),
            parent.clone(),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = parent.join("value.json");
        fs::write(&path, b"42").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.read_json::<u32>("nested/deep/value.json").is_err());
        store.write_json("nested/deep/value.json", &43).unwrap();
        assert_eq!(
            store.read_json::<u32>("nested/deep/value.json").unwrap(),
            43
        );
        for directory in [store.root().to_owned(), store.root().join("nested"), parent] {
            assert_eq!(
                fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn writes_and_reads_json_atomically() {
        let temp = tempfile::tempdir().unwrap();
        let store = FileStateStore::new(temp.path().join("state"));
        store.ensure().unwrap();
        store
            .write_json("nested/value.json", &serde_json::json!({"answer":42}))
            .unwrap();
        let value: serde_json::Value = store.read_json("nested/value.json").unwrap();
        assert_eq!(value["answer"], 42);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(store.root().join("nested/value.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}
