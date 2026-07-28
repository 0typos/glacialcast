//! Finding a configuration file the way a service manager expects.
//!
//! Both binaries accept `--config`, and both need to run unattended under
//! systemd, where the working directory is not something the operator chose. A
//! relative default therefore cannot be the whole story: a unit with no
//! `WorkingDirectory=` runs with `/` as its current directory, so a default of
//! `server.toml` resolves to `/server.toml`, which is neither where anyone
//! puts it nor writable to look at.
//!
//! So a path given explicitly is used exactly as given, and otherwise the
//! standard locations are searched in an order that suits both kinds of unit:
//! a user service finds its file under `$XDG_CONFIG_HOME`, and a system
//! service — which typically cannot see a home directory at all, because the
//! unit sets `ProtectHome=` — finds it under `/etc`.
//!
//! The distinction between "you named this file" and "I went looking" matters
//! for what a missing file means. Naming a path that is not there is a
//! mistake worth stopping for; finding nothing while searching is the ordinary
//! first-run case, where built-in defaults apply.

use std::path::{Path, PathBuf};

/// System-wide configuration directory, searched for service units.
pub const SYSTEM_CONFIG_DIR: &str = "/etc/glacialcast";

/// Where a configuration file came from, and what a missing one means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// The operator named this path. It has to exist.
    Explicit(PathBuf),
    /// Found by searching the standard locations, so it exists.
    Discovered(PathBuf),
    /// Nothing was found. Built-in defaults apply.
    Defaults,
}

impl ConfigSource {
    /// Returns the path, if any, this source refers to.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Explicit(path) | Self::Discovered(path) => Some(path),
            Self::Defaults => None,
        }
    }

    /// Reports whether a missing file at [`Self::path`] is an error.
    ///
    /// True only for a path the operator named. A discovered path existed when
    /// it was found; if it has since been removed, that is a race worth
    /// reporting rather than silently ignoring.
    pub fn must_exist(&self) -> bool {
        !matches!(self, Self::Defaults)
    }

    /// A short phrase naming the origin, for the line a service logs at start.
    pub fn origin(&self) -> &'static str {
        match self {
            Self::Explicit(_) => "named on the command line or in the environment",
            Self::Discovered(_) => "found in a standard location",
            Self::Defaults => "not found; built-in defaults apply",
        }
    }
}

/// Resolves which configuration file to read.
///
/// `explicit` is the operator's `--config` or `GLACIALCAST_CONFIG` value, and
/// is honoured verbatim without checking whether it exists — the caller
/// reports that, with the context that it was asked for by name.
///
/// Otherwise the standard locations are searched in order:
///
/// 1. `$XDG_CONFIG_HOME/glacialcast/<file_name>`, or
///    `$HOME/.config/glacialcast/<file_name>` when that variable is unset
/// 2. `/etc/glacialcast/<file_name>`
/// 3. `<file_name>` in the current directory
///
/// The user location comes first so a desktop publisher started by hand or by
/// a user unit prefers the operator's own file. A system service reaches `/etc`
/// because it cannot see a home directory. The relative path stays last so
/// running from a source checkout keeps working.
pub fn resolve(explicit: Option<PathBuf>, file_name: &str) -> ConfigSource {
    resolve_from(user_config_dir(), explicit, file_name)
}

/// [`resolve`] with the user directory supplied rather than read from the
/// environment, so it can be exercised without mutating process-global state.
fn resolve_from(
    user_dir: Option<PathBuf>,
    explicit: Option<PathBuf>,
    file_name: &str,
) -> ConfigSource {
    if let Some(path) = explicit {
        return ConfigSource::Explicit(path);
    }
    search_paths_from(user_dir, file_name)
        .into_iter()
        .find(|candidate| candidate.is_file())
        .map_or(ConfigSource::Defaults, ConfigSource::Discovered)
}

/// Returns the standard locations searched for `file_name`, in order.
///
/// Exposed so a binary can name them in an error message: telling an operator
/// that nothing was found is far less useful than telling them where it looked.
pub fn search_paths(file_name: &str) -> Vec<PathBuf> {
    search_paths_from(user_config_dir(), file_name)
}

fn search_paths_from(user_dir: Option<PathBuf>, file_name: &str) -> Vec<PathBuf> {
    let mut paths = Vec::with_capacity(3);
    if let Some(user) = user_dir {
        paths.push(user.join(file_name));
    }
    paths.push(Path::new(SYSTEM_CONFIG_DIR).join(file_name));
    paths.push(PathBuf::from(file_name));
    paths
}

/// Returns `$XDG_CONFIG_HOME/glacialcast`, falling back to `$HOME/.config`.
///
/// Relative values are ignored rather than joined onto the working directory,
/// which is the same reason the default cannot be relative in the first place.
fn user_config_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|home| home.join(".config"))
        })
        .map(|base| base.join("glacialcast"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_path_is_honoured_verbatim() {
        let source = resolve(Some(PathBuf::from("/tmp/somewhere.toml")), "server.toml");
        assert_eq!(
            source,
            ConfigSource::Explicit(PathBuf::from("/tmp/somewhere.toml"))
        );
        // Naming a file that is not there is a mistake, not a fallback.
        assert!(source.must_exist());
    }

    #[test]
    fn a_relative_explicit_path_is_left_alone() {
        // Deliberately not resolved against anything: an operator who passes a
        // relative path has chosen the working directory as the reference.
        let source = resolve(Some(PathBuf::from("local.toml")), "server.toml");
        assert_eq!(source.path(), Some(Path::new("local.toml")));
    }

    #[test]
    fn the_user_location_is_searched_before_the_system_one() {
        // Ordering is the whole contract: a user unit must not pick up a
        // system file when the operator has their own.
        let paths = search_paths("client.toml");
        let system = paths
            .iter()
            .position(|path| path.starts_with(SYSTEM_CONFIG_DIR))
            .expect("the system location is always searched");
        assert!(system > 0, "the user location must come first: {paths:?}");
        assert_eq!(
            paths
                .last()
                .expect("a relative fallback is always searched"),
            &PathBuf::from("client.toml"),
            "the working directory stays last so a checkout still works"
        );
    }

    #[test]
    fn nothing_found_means_defaults_rather_than_an_error() {
        let source = resolve(None, "glacialcast-nonexistent-config-file.toml");
        assert_eq!(source, ConfigSource::Defaults);
        assert!(!source.must_exist());
        assert_eq!(source.path(), None);
    }

    #[test]
    fn a_discovered_file_is_reported_as_discovered() {
        let root = std::env::temp_dir().join(format!("glacialcast-config-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("discovered.toml");
        std::fs::write(&path, "").unwrap();

        let source = resolve_from(Some(root.clone()), None, "discovered.toml");
        assert_eq!(source, ConfigSource::Discovered(path));
        assert!(
            source.must_exist(),
            "a file that was there must still be there when it is read"
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_user_directory_without_the_file_falls_through() {
        // An empty user directory must not shadow the system location.
        let empty = std::env::temp_dir().join(format!("glacialcast-empty-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        let paths = search_paths_from(Some(empty.clone()), "server.toml");
        assert_eq!(paths[0], empty.join("server.toml"));
        assert_eq!(paths[1], Path::new(SYSTEM_CONFIG_DIR).join("server.toml"));
        assert_eq!(
            resolve_from(Some(empty.clone()), None, "server.toml").path(),
            None,
            "nothing exists at any location, so defaults apply"
        );
        std::fs::remove_dir_all(empty).unwrap();
    }
}
