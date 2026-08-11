//! Private, crash-safe state-file helpers shared by native components.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn validate_private_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    max_len: usize,
) -> io::Result<()> {
    if !metadata.is_file() {
        return Err(invalid(format!(
            "private state {} is not a regular file",
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(invalid(format!(
            "private state {} is accessible by group or other users",
            path.display()
        )));
    }
    if metadata.nlink() != 1 {
        return Err(invalid(format!(
            "private state {} has more than one hard link",
            path.display()
        )));
    }
    let length = usize::try_from(metadata.len())
        .map_err(|_| invalid(format!("private state {} is too large", path.display())))?;
    if length > max_len {
        return Err(invalid(format!(
            "private state {} exceeds its {} byte limit",
            path.display(),
            max_len
        )));
    }
    Ok(())
}

/// Reads one bounded private regular file without following a final symlink.
///
/// The file must have no group/other permission bits and exactly one hard link.
/// Its size is checked before allocation and again after reading.
///
/// # Errors
///
/// Returns an error for an unsafe file type, permissions, link count, oversized
/// or concurrently changing file, or any underlying I/O failure.
pub fn read_private(path: &Path, max_len: usize) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    validate_private_metadata(path, &metadata, max_len)?;
    let expected = usize::try_from(metadata.len())
        .map_err(|_| invalid(format!("private state {} is too large", path.display())))?;
    let mut bytes = Vec::with_capacity(expected);
    file.take(u64::try_from(max_len).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() != expected {
        return Err(invalid(format!(
            "private state {} changed length while it was read",
            path.display()
        )));
    }
    Ok(bytes)
}

fn prepare_parent(path: &Path) -> io::Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let existed = parent.exists();
    fs::create_dir_all(parent)?;
    if !existed {
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    Ok(parent.to_path_buf())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

/// Creates a new private file and durably publishes its bytes.
///
/// The destination is opened with `create_new`, mode `0600`, and
/// `O_NOFOLLOW`. Existing destinations are never replaced.
///
/// # Errors
///
/// Returns an error if the parent cannot be prepared, the destination already
/// exists, or writing or synchronizing the file or its parent fails.
pub fn create_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = prepare_parent(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    sync_directory(&parent)
}

/// Atomically replaces or creates a private state file.
///
/// Existing destinations must already satisfy the private regular-file
/// invariants. Bytes are synchronized in a unique same-directory temporary
/// file before rename, followed by a parent-directory synchronization.
///
/// # Errors
///
/// Returns an error for an unsafe existing destination or any create, write,
/// synchronization, rename, or cleanup failure.
pub fn replace_private(path: &Path, bytes: &[u8], max_existing_len: usize) -> io::Result<()> {
    let parent = prepare_parent(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_metadata(path, &metadata, max_existing_len)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("private state path has no UTF-8 file name"))?;
    let temporary = parent.join(format!(".{name}.{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        sync_directory(&parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn temporary_root() -> PathBuf {
        std::env::temp_dir().join(format!("glacialcast-private-state-{}", Uuid::new_v4()))
    }

    #[test]
    fn private_state_round_trips_and_replaces_atomically() {
        let root = temporary_root();
        let path = root.join("state.bin");
        create_private(&path, b"one").unwrap();
        assert_eq!(read_private(&path, 3).unwrap(), b"one");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        replace_private(&path, b"two", 3).unwrap();
        assert_eq!(read_private(&path, 3).unwrap(), b"two");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_state_rejects_permissions_links_symlinks_and_bounds() {
        let root = temporary_root();
        fs::create_dir_all(&root).unwrap();
        let path = root.join("state.bin");
        create_private(&path, b"abcd").unwrap();
        assert!(read_private(&path, 3).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_private(&path, 4).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let hard_link = root.join("hard-link.bin");
        fs::hard_link(&path, &hard_link).unwrap();
        assert!(read_private(&path, 4).is_err());
        fs::remove_file(&hard_link).unwrap();

        let link = root.join("link.bin");
        symlink(&path, &link).unwrap();
        assert!(read_private(&link, 4).is_err());
        assert!(replace_private(&link, b"nope", 4).is_err());
        assert_eq!(read_private(&path, 4).unwrap(), b"abcd");
        fs::remove_dir_all(root).unwrap();
    }
}
