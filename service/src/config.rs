//! Service configuration (`service.toml`): where the service keeps its
//! state and how its logs rotate. Loaded once at startup by the SCM entry
//! point and by `console` mode.
//!
//! Landmine posture (mirrors `cf-relay`'s config): the behaviour-defining
//! fields are *required* — there is no silent default that would let a
//! typo turn into an unbounded log file or an unprotected state directory.
//! `deny_unknown_fields` rejects an injected/misspelled key outright rather
//! than ignoring it.

use serde::Deserialize;
use std::fmt;
use std::path::{Path, PathBuf};

/// The rotation stem for the service's log files: the active file is
/// `<stem>.log`, rotated generations are `<stem>.log.1` … `<stem>.log.N`.
pub const LOG_STEM: &str = "cf-service";

/// Subdirectory of `data_dir` that holds the rotating logs.
pub const LOG_SUBDIR: &str = "logs";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// The service's private working directory (logs + future state). Held
    /// to SYSTEM + Administrators only (see `crate::acl`); required so the
    /// ACL-hardened location is never left to a default.
    pub data_dir: PathBuf,
    pub log: LogConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// Rotate the active log once it reaches this many bytes. Required — an
    /// unset limit is an unbounded log file, which is a real disk-exhaustion
    /// foot-gun on a long-running LocalSystem service.
    pub max_size_bytes: u64,
    /// How many rotated generations to keep besides the active file. Must be
    /// at least 1: rotation always retains the immediately-previous file,
    /// otherwise "rotate" would just be "truncate and lose everything".
    pub keep_files: usize,
    /// `tracing` env-filter directive (e.g. `"info"`, `"cf_service=debug"`).
    /// Optional — an unset level is not a safety hole, unlike the two above,
    /// so it defaults rather than forcing every deployment to spell it out.
    #[serde(default = "default_level")]
    pub level: String,
}

fn default_level() -> String {
    "info".to_string()
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    /// Parsed cleanly but failed a semantic check (see `validate`).
    Invalid(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "could not read config file: {e}"),
            ConfigError::Parse(e) => write!(f, "could not parse config file: {e}"),
            ConfigError::Invalid(msg) => write!(f, "invalid config: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl ServiceConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        let config: ServiceConfig = toml::from_str(&text).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Checks that survive a clean parse. Kept separate so tests can build a
    /// config in memory and assert the same rejections the file path enforces.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.log.keep_files == 0 {
            return Err(ConfigError::Invalid(
                "log.keep_files must be >= 1 (rotation must retain at least one generation)",
            ));
        }
        if self.log.max_size_bytes == 0 {
            return Err(ConfigError::Invalid(
                "log.max_size_bytes must be > 0 (a zero limit would rotate on every write)",
            ));
        }
        Ok(())
    }

    /// The directory the rotating logs live in.
    pub fn log_dir(&self) -> PathBuf {
        self.data_dir.join(LOG_SUBDIR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_config(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("service.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        (dir, path)
    }

    #[test]
    fn a_complete_config_loads_and_defaults_the_level() {
        let (_dir, path) = write_config(
            r#"
            data_dir = "C:\\ProgramData\\ContentFilter"

            [log]
            max_size_bytes = 10485760
            keep_files = 5
            "#,
        );
        let config = ServiceConfig::load(&path).unwrap();
        assert_eq!(
            config.data_dir,
            PathBuf::from("C:\\ProgramData\\ContentFilter")
        );
        assert_eq!(config.log.max_size_bytes, 10_485_760);
        assert_eq!(config.log.keep_files, 5);
        // Unset level falls back rather than failing.
        assert_eq!(config.log.level, "info");
        assert_eq!(
            config.log_dir(),
            PathBuf::from("C:\\ProgramData\\ContentFilter").join(LOG_SUBDIR)
        );
    }

    #[test]
    fn a_missing_data_dir_is_rejected_at_parse_time() {
        // Landmine: there must be no default data_dir — the ACL-hardened
        // location is never left implicit. If someone makes it optional this
        // starts failing instead of silently picking a directory.
        let (_dir, path) = write_config(
            r#"
            [log]
            max_size_bytes = 1024
            keep_files = 1
            "#,
        );
        assert!(ServiceConfig::load(&path).is_err());
    }

    #[test]
    fn a_missing_log_table_is_rejected_at_parse_time() {
        let (_dir, path) = write_config(r#"data_dir = "/var/lib/cf""#);
        assert!(ServiceConfig::load(&path).is_err());
    }

    #[test]
    fn a_missing_rotation_size_is_rejected_at_parse_time() {
        // No default max_size_bytes: an unbounded log must be impossible to
        // configure by omission.
        let (_dir, path) = write_config(
            r#"
            data_dir = "/var/lib/cf"

            [log]
            keep_files = 3
            "#,
        );
        assert!(ServiceConfig::load(&path).is_err());
    }

    #[test]
    fn zero_keep_files_is_rejected_by_validation() {
        let (_dir, path) = write_config(
            r#"
            data_dir = "/var/lib/cf"

            [log]
            max_size_bytes = 1024
            keep_files = 0
            "#,
        );
        assert!(matches!(
            ServiceConfig::load(&path),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn zero_rotation_size_is_rejected_by_validation() {
        let (_dir, path) = write_config(
            r#"
            data_dir = "/var/lib/cf"

            [log]
            max_size_bytes = 0
            keep_files = 2
            "#,
        );
        assert!(matches!(
            ServiceConfig::load(&path),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn an_unknown_field_is_rejected_not_ignored() {
        // Landmine against config smuggling: a stray/misspelled key must be
        // a hard error, not silently dropped.
        let (_dir, path) = write_config(
            r#"
            data_dir = "/var/lib/cf"
            enable_backdoor = true

            [log]
            max_size_bytes = 1024
            keep_files = 2
            "#,
        );
        assert!(matches!(
            ServiceConfig::load(&path),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn missing_file_is_an_io_error() {
        let result = ServiceConfig::load(Path::new("does/not/exist/service.toml"));
        assert!(matches!(result, Err(ConfigError::Io(_))));
    }
}
