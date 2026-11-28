//! CI-only admitted NTFS adapter. No shipping entrypoint, generic grant,
//! caller-selected mutation path, or policy administration interface.
use super::{serve_fresh_sdk_mutations, AtomicBool, JournaledDomain, Operation, Phase};
use crate::{
    windows_managed_volume::{sid_bytes, valid_drive, valid_guid_root, VerifiedVolume},
    windows_mutation_pipe::MutationPipe,
    windows_opened_read::read_opened_regular,
    windows_token::{verify_scm_fixture_identity, ScmFixtureRole},
    IdentityDenied,
};
use std::{
    fs::File, os::windows::io::BorrowedHandle, os::windows::io::OwnedHandle, path::Path,
    time::Duration,
};
const DOMAIN: [u8; 32] = [7; 32];

struct Admission {
    drive: String,
    guid: String,
    service: String,
    owner: String,
}
impl Admission {
    fn parse(bytes: &[u8]) -> Result<Self, IdentityDenied> {
        if bytes.len() > 512 || !bytes.is_ascii() || bytes.contains(&0) {
            return Err(IdentityDenied);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| IdentityDenied)?;
        let fields: Vec<_> = text.lines().collect();
        let [drive, guid, service, owner] = fields.as_slice() else {
            return Err(IdentityDenied);
        };
        if fields
            .iter()
            .any(|field| field.is_empty() || field.trim() != *field)
            || service == owner
            || !valid_drive(drive)
            || !valid_guid_root(guid)
            || sid_bytes(service).is_err()
            || sid_bytes(owner).is_err()
        {
            return Err(IdentityDenied);
        }
        Ok(Self {
            drive: (*drive).into(),
            guid: (*guid).into(),
            service: (*service).into(),
            owner: (*owner).into(),
        })
    }
    fn open(&self) -> Result<JournaledDomain, IdentityDenied> {
        JournaledDomain::open_verified_windows(
            &self.drive,
            &self.guid,
            &self.service,
            &self.owner,
            DOMAIN,
        )
        .map_err(|_| IdentityDenied)
    }
    fn root(&self) -> &Path {
        Path::new(&self.guid)
    }
    fn provision(&self) -> Result<(), IdentityDenied> {
        let volume = VerifiedVolume::open(&self.drive, &self.guid, &self.service, &self.owner)
            .map_err(|_| IdentityDenied)?;
        let state = self.root().join(".jdc-state");
        std::fs::create_dir(&state).map_err(|_| IdentityDenied)?;
        let db = state.join("policy.sqlite3");
        File::create_new(&db).map_err(|_| IdentityDenied)?;
        let conn =
            rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
                .map_err(|_| IdentityDenied)?;
        super::provision_fixture_journal(&conn, DOMAIN).map_err(|_| IdentityDenied)?;
        drop(conn);
        volume.journal_path().map_err(|_| IdentityDenied)?;
        Ok(())
    }
}

/// Used exclusively by the feature-enabled fixed SCM proof. The controller
/// must protect and pin the manifest, pipe, and job before invoking this.
pub struct ScmAdmittedStorage {
    spec: Admission,
    domain: JournaledDomain,
    cancellation: bool,
}
impl ScmAdmittedStorage {
    /// Authority role is checked before reading even an already-open input.
    /// The manifest is fixed administrator provisioning metadata, not IPC.
    pub fn prepare(manifest: File, cancellation: bool) -> Result<Self, IdentityDenied> {
        verify_scm_fixture_identity(ScmFixtureRole::Authority).map_err(|_| IdentityDenied)?;
        let bytes = read_opened_regular(manifest).map_err(|_| IdentityDenied)?;
        let spec = Admission::parse(&bytes)?;
        if !cancellation {
            spec.provision()?;
        }
        let domain = spec.open()?;
        let state = domain.snapshot()?;
        if state.epoch != 1
            || if cancellation {
                state.sequence != 5
                    || state.phase != Phase::Committed
                    || std::fs::read(spec.root().join("final.txt")).map_err(|_| IdentityDenied)?
                        != b"REWRITE-LOST"
            } else {
                state.sequence != 0 || state.phase == Phase::Pending
            }
        {
            return Err(IdentityDenied);
        }
        Ok(Self {
            spec,
            domain,
            cancellation,
        })
    }
    /// Actual issuer must not be able to open the admitted journal or
    /// directory for mutation. A missing file or sharing violation is not
    /// accepted as access denial. The manifest is read-only provisioning data.
    pub fn verify_issuer_denied(manifest: File) -> Result<(), IdentityDenied> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::{
            Foundation::ERROR_ACCESS_DENIED,
            Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE,
            },
        };
        verify_scm_fixture_identity(ScmFixtureRole::Issuer).map_err(|_| IdentityDenied)?;
        let spec = Admission::parse(&read_opened_regular(manifest).map_err(|_| IdentityDenied)?)?;
        let db = spec.root().join(".jdc-state/policy.sqlite3");
        for attempt in [
            File::open(&db),
            std::fs::OpenOptions::new().write(true).open(&db),
            std::fs::OpenOptions::new()
                .access_mode(FILE_GENERIC_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(spec.root()),
        ] {
            match attempt {
                Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {}
                _ => return Err(IdentityDenied),
            }
        }
        Ok(())
    }

    /// Runs only the fixed SDK plan. An error never authorizes a different
    /// process or a fallback engine. The fixed SCM controller independently
    /// checks child/job/thread custody and pipe DACL before this call.
    pub fn serve(
        self,
        pipe: OwnedHandle,
        completion: Option<OwnedHandle>,
        child: BorrowedHandle<'_>,
        sid: &[u8],
        custody: impl Fn() -> bool,
    ) -> Result<(), IdentityDenied> {
        verify_scm_fixture_identity(ScmFixtureRole::Authority).map_err(|_| IdentityDenied)?;
        let pipe = MutationPipe::from_scm_fixture(pipe)?;
        let completion = completion.map(MutationPipe::from_scm_fixture).transpose()?;
        if self.cancellation != completion.is_some() {
            return Err(IdentityDenied);
        }
        if let Some(completion) = &completion {
            completion.connect(Duration::from_secs(10))?;
        }
        pipe.connect(Duration::from_secs(10))?;
        pipe.await_ready(child, sid)?;
        if self.cancellation {
            super::serve_fresh_sdk_cancellation(
                &self.domain,
                self.spec.root(),
                &pipe,
                child,
                sid,
                &custody,
            )?;
        } else {
            serve_fresh_sdk_mutations(&self.domain, self.spec.root(), &pipe, child, sid, &custody)?;
        }
        let Self {
            spec,
            domain,
            cancellation,
        } = self;
        let terminal = domain.snapshot()?;
        if cancellation && (terminal.sequence != 6 || terminal.phase != Phase::Rejected)
            || !cancellation && (terminal.sequence != 5 || terminal.phase != Phase::Committed)
        {
            return Err(IdentityDenied);
        }
        drop(domain);
        let reopened = spec.open()?;
        let replay = reopened.execute(
            1,
            terminal.sequence,
            if cancellation {
                Operation::Create {
                    name: "cancelled.txt",
                    bytes: b"MUST-NOT-PUBLISH",
                }
            } else {
                Operation::Append {
                    name: "final.txt",
                    bytes: b"-LOST",
                }
            },
            &AtomicBool::new(false),
            || {},
            || {},
        );
        if replay != Err(crate::managed_mutation_contract::MutationError::Denied)
            || reopened.snapshot()? != terminal
            || std::fs::read(spec.root().join("final.txt")).map_err(|_| IdentityDenied)?
                != b"REWRITE-LOST"
        {
            return Err(IdentityDenied);
        }
        if cancellation {
            if !custody()
                || spec
                    .root()
                    .join("cancelled.txt")
                    .try_exists()
                    .map_err(|_| IdentityDenied)?
                || spec
                    .root()
                    .join(".jdc-stage")
                    .try_exists()
                    .map_err(|_| IdentityDenied)?
            {
                return Err(IdentityDenied);
            }
            completion
                .ok_or(IdentityDenied)?
                .confirm_cancelled(child, sid)?;
        }
        // The final committed request has deliberately lost its response.
        drop(pipe);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_metadata_is_bounded_and_exact() {
        assert!(Admission::parse(b"R:\\\r\n\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\\r\nS-1-5-19\r\nS-1-5-32-544\r\n").is_ok());
        for bad in [
            &b""[..],
            b"R:\\nabc\nsame\nsame\n",
            b" R:\\nabc\nservice\nowner\n",
            b"R:\\nabc\nservice\nowner\nextra\n",
            &[0; 513],
        ] {
            assert!(Admission::parse(bad).is_err());
        }
    }
    #[test]
    fn ordinary_caller_cannot_prepare_admitted_scm_storage() {
        let image = std::env::current_exe().unwrap();
        assert!(ScmAdmittedStorage::prepare(File::open(image).unwrap(), false).is_err());
    }
}
