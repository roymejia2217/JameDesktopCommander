//! Nonrelease Windows SDK lifecycle custody. An unnamed, noninheritable
//! job admits exactly one process at CreateProcessW time; no breakaway.
//! This local proof is not the cross-account SCM authority or a sandbox.
use crate::IdentityDenied;
use std::{
    mem::size_of,
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT},
    System::{
        JobObjects::{
            CreateJobObjectW, IsProcessInJob, JobObjectBasicAccountingInformation,
            JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Threading::{GetProcessMitigationPolicy, ProcessChildProcessPolicy},
    },
};
const LIMITS: u32 = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

pub(crate) struct SdkJob(OwnedHandle);
impl SdkJob {
    pub(crate) fn new_local() -> Result<Self, IdentityDenied> {
        let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if raw.is_null() {
            return Err(IdentityDenied);
        }
        let job = Self(unsafe { OwnedHandle::from_raw_handle(raw) });
        let mut flags = 0;
        if unsafe { GetHandleInformation(raw, &mut flags) } == 0 || flags & HANDLE_FLAG_INHERIT != 0
        {
            return Err(IdentityDenied);
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = LIMITS;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        if unsafe {
            SetInformationJobObject(
                raw,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(IdentityDenied);
        }
        job.verify_limits()?;
        job.verify_counts(0, 0)?;
        Ok(job)
    }
    pub(crate) fn as_handle(&self) -> BorrowedHandle<'_> {
        self.0.as_handle()
    }

    fn verify_limits(&self) -> Result<(), IdentityDenied> {
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let mut used = 0;
        if unsafe {
            QueryInformationJobObject(
                self.0.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                &mut used,
            )
        } == 0
            || used != size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32
            || limits.BasicLimitInformation.LimitFlags != LIMITS
            || limits.BasicLimitInformation.ActiveProcessLimit != 1
        {
            return Err(IdentityDenied);
        }
        Ok(())
    }

    fn verify_counts(&self, total: u32, active: u32) -> Result<(), IdentityDenied> {
        let mut counts = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let mut used = 0;
        if unsafe {
            QueryInformationJobObject(
                self.0.as_raw_handle(),
                JobObjectBasicAccountingInformation,
                (&mut counts as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                &mut used,
            )
        } == 0
            || used != size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32
            || counts.TotalProcesses != total
            || counts.ActiveProcesses != active
        {
            return Err(IdentityDenied);
        }
        Ok(())
    }

    pub(crate) fn verify_member(&self, child: BorrowedHandle<'_>) -> Result<(), IdentityDenied> {
        self.verify_limits()?;
        let mut member = 0;
        if unsafe { IsProcessInJob(child.as_raw_handle(), self.0.as_raw_handle(), &mut member) }
            == 0
            || member == 0
        {
            return Err(IdentityDenied);
        }
        let mut policy = 0u32;
        if unsafe {
            GetProcessMitigationPolicy(
                child.as_raw_handle(),
                ProcessChildProcessPolicy,
                (&mut policy as *mut u32).cast(),
                size_of::<u32>(),
            )
        } == 0
            || policy & 1 != 1
        {
            return Err(IdentityDenied);
        }
        self.verify_counts(1, 1)
    }

    pub(crate) fn verify_finished(&self) -> Result<(), IdentityDenied> {
        self.verify_limits()?;
        self.verify_counts(1, 0)
    }
}
