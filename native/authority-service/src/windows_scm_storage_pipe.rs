//! Fixed SCM-owned mutation channel, only in feature-enabled CI proof.
use super::{
    attributes, descriptor, owned, role_sid, sdk_read::CLIENT_RIGHTS, verify_security, Names,
};
use jdc_authority_service::{
    journaled_mutations::ScmAdmittedStorage, windows_token::ScmFixtureRole, IdentityDenied,
};
use std::{
    fs::{File, OpenOptions},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsHandle, BorrowedHandle, OwnedHandle},
    },
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{
        FILE_ALL_ACCESS, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, PIPE_ACCESS_DUPLEX,
    },
    System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    },
};
fn manifest() -> Result<File, IdentityDenied> {
    let exe = std::env::current_exe().map_err(|_| IdentityDenied)?;
    if exe.file_name().and_then(|v| v.to_str()) != Some("jdc-authority-scm-issued-proof.exe") {
        return Err(IdentityDenied);
    }
    let stage = exe.parent().ok_or(IdentityDenied)?;
    super::fixture_prefix(
        stage
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or(IdentityDenied)?,
    )?;
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(stage.join("sdk-read/scm-storage-input.txt"))
        .map_err(|_| IdentityDenied)
}
pub(super) fn verify_issuer_denied() -> Result<(), IdentityDenied> {
    ScmAdmittedStorage::verify_issuer_denied(manifest()?)
}
pub(super) struct StorageProof {
    storage: ScmAdmittedStorage,
    pipe: OwnedHandle,
    completion: Option<OwnedHandle>,
}
impl StorageProof {
    fn pipe(name: &str) -> Result<OwnedHandle, IdentityDenied> {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let sd = descriptor(
            ScmFixtureRole::Authority,
            Some((ScmFixtureRole::Issuer, CLIENT_RIGHTS)),
            FILE_ALL_ACCESS,
        )?;
        let raw = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                8192,
                8192,
                0,
                &attributes(&sd),
            )
        };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            return Err(IdentityDenied);
        }
        let pipe = owned(raw)?;
        verify_security(pipe.as_handle(), &role_sid(ScmFixtureRole::Authority)?, &sd)?;
        Ok(pipe)
    }
    pub(super) fn prepare(names: &Names, cancellation: bool) -> Result<Self, IdentityDenied> {
        let id = names
            .prefix
            .strip_prefix("Local\\JdcT011Job-")
            .ok_or(IdentityDenied)?;
        if id.len() != 32
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(IdentityDenied);
        }
        let name = format!(
            r"\\.\pipe\JDC-T011-MUTATION-SCM-{id}{}-fresh",
            if cancellation { "-cancel" } else { "" }
        );
        let storage = ScmAdmittedStorage::prepare(manifest()?, cancellation)?;
        let pipe = Self::pipe(&name)?;
        let completion = if cancellation {
            Some(Self::pipe(&format!("{name}-completion"))?)
        } else {
            None
        };
        Ok(Self {
            storage,
            pipe,
            completion,
        })
    }
    pub(super) fn serve(
        self,
        child: BorrowedHandle<'_>,
        sid: &[u8],
        custody: impl Fn() -> bool,
    ) -> Result<(), IdentityDenied> {
        self.storage
            .serve(self.pipe, self.completion, child, sid, custody)
    }
}
