//! Mode-restricted, atomic CLI state storage.

use crate::{Error, Result};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct FileStateStore {
    root: PathBuf,
}

impl FileStateStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
    pub fn read_json<T: DeserializeOwned>(&self, relative: impl AsRef<Path>) -> Result<T> {
        let path = self.root.join(relative);
        check_file(&path)?;
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }
    pub fn write_json<T: Serialize>(&self, relative: impl AsRef<Path>, value: &T) -> Result<()> {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            set_dir_mode(parent)?;
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
        serde_json::to_writer_pretty(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        Ok(())
    }
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
    if metadata.file_type().is_symlink() {
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
