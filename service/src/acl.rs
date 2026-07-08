//! Filesystem ACL hardening for the service's private working directory
//! (`svc-skeleton` DoD: "ACLs match design section 8.5").
//!
//! # There is no design section 8.5
//!
//! Several ticket DoD lines reference a design doc that does not exist in
//! this repo (see `CLAUDE.md`; same situation as issues #16/#17/#19/#20/#21).
//! Rather than invent a doc to match, this module *defines* the ACL policy in
//! code, and the corresponding DoD box is left unchecked with a note on the
//! issue. The policy is:
//!
//! > The service's `data_dir` (logs today, protected state tomorrow) is
//! > readable and writable by **`SYSTEM`** and the **`Administrators`** group
//! > only. Inheritance from the parent is removed, so nothing an
//! > unprivileged user can influence upstream leaks in. Standard users
//! > (`Users`, `Authenticated Users`, `Everyone`) get *no* access.
//!
//! Rationale for the accountability model: the monitored user is expected to
//! be a standard (non-admin) account, and the service runs as `LocalSystem`.
//! Logs and future state (the accountability record) must not be readable or
//! tamperable by that standard user, or the anti-tamper guarantees the rest
//! of the system builds on would be undermined at the filesystem layer.
//!
//! # Why `icacls` and not the Win32 security APIs
//!
//! Applying a DACL directly means `SetNamedSecurityInfoW` and hand-built
//! ACLs via `windows-sys` — unsafe FFI that, under this repo's Smart App
//! Control constraint, cannot be run or debugged locally at all (only in
//! CI). Shelling out to `icacls` (a signed, always-present system binary) is
//! the same shape as the test harness's `netsh` firewall helpers, is fully
//! auditable as a command line, needs no extra crate, and its result is
//! verifiable by parsing `icacls` output. The trade-off (a stringly result
//! and a dependency on `icacls.exe`) is acceptable for a Windows-only
//! product control.

#[cfg(windows)]
use std::io;
#[cfg(windows)]
use std::path::Path;

/// Well-known SID for `NT AUTHORITY\SYSTEM`.
#[cfg(windows)]
const SID_LOCAL_SYSTEM: &str = "*S-1-5-18";

/// Well-known SID for the builtin `Administrators` group. Using the SID
/// rather than the name keeps this correct on non-English Windows.
#[cfg(windows)]
const SID_ADMINISTRATORS: &str = "*S-1-5-32-544";

/// `(OI)(CI)F` = object-inherit + container-inherit + Full control, so the
/// grant applies to the directory and everything created under it.
#[cfg(windows)]
const FULL_INHERITED: &str = ":(OI)(CI)F";

/// Locks `path` down to `SYSTEM` + `Administrators` only, removing inherited
/// ACEs. Idempotent: safe to run at install time and again on every service
/// start.
#[cfg(windows)]
pub fn harden_dir(path: &Path) -> io::Result<()> {
    use std::process::Command;

    let sys_grant = format!("{SID_LOCAL_SYSTEM}{FULL_INHERITED}");
    let admin_grant = format!("{SID_ADMINISTRATORS}{FULL_INHERITED}");

    // /inheritance:r  — strip inherited ACEs (protected DACL).
    // /grant:r <sid:perm>… — replace (not add to) the grant for each SID.
    // Both applied in one call, so the directory is never momentarily
    // ACL-less between removing inheritance and adding the explicit grants.
    let output = Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(&sys_grant)
        .arg(&admin_grant)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(io::Error::other(format!(
            "icacls failed to harden {}: status {}, stderr={stderr}, stdout={stdout}",
            path.display(),
            output.status
        )));
    }
    Ok(())
}

/// No-op off Windows. The product ships only on Windows; this stub exists so
/// the cross-platform service body can call `harden_dir` unconditionally and
/// so Linux CI still compiles and exercises the surrounding code.
#[cfg(not(windows))]
pub fn harden_dir(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn hardened_dir_grants_only_system_and_administrators() {
        let dir = tempfile::tempdir().unwrap();
        harden_dir(dir.path()).unwrap();

        let out = Command::new("icacls").arg(dir.path()).output().unwrap();
        assert!(out.status.success(), "icacls query failed");
        let text = String::from_utf8_lossy(&out.stdout);

        // The two allowed principals are present. (icacls resolves SIDs to
        // names; on the English CI runner these are the expected strings.)
        assert!(text.contains("SYSTEM"), "SYSTEM ACE missing:\n{text}");
        assert!(
            text.contains("Administrators"),
            "Administrators ACE missing:\n{text}"
        );

        // No broad principals. We check specific ACE forms rather than bare
        // substrings because the temp path itself is under C:\Users\… on the
        // runner, so a naive `!contains("Users")` would false-positive.
        assert!(
            !text.contains("Everyone"),
            "Everyone must have no access:\n{text}"
        );
        assert!(
            !text.contains("Authenticated Users"),
            "Authenticated Users must have no access:\n{text}"
        );
        assert!(
            !text.contains("BUILTIN\\Users:"),
            "the Users group must have no ACE:\n{text}"
        );
    }
}
