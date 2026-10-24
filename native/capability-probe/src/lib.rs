//! Isolated T011-B feasibility spike. Never expose ambient constructor to MCP callers.
use cap_std::fs::{Dir, OpenOptions};
use cap_tempfile::TempFile;
use std::path::Path;
mod secure_root;
use napi::{bindgen_prelude::Buffer, Error, Result};
#[cfg(feature = "receiver-test-fixture")]
use napi::{bindgen_prelude::{Function, JsObjectValue, Object}, Env};
use napi_derive::napi;
use std::{io::{Read, Write}, sync::Mutex};

// Initial bounded allocation limit for the experimental, synchronous API.
// Larger files require a separately tested, cancellable streaming interface.
const MAX_CAPABILITY_BYTES: usize = 32 * 1024 * 1024;

fn denied(error: std::io::Error) -> Error {
    Error::from_reason(format!("Capability operation rejected: {}", error.kind()))
}

fn require_bounded_size(byte_len: usize) -> Result<()> {
    if byte_len > MAX_CAPABILITY_BYTES {
        return Err(Error::from_reason("Capability byte limit exceeded"));
    }
    Ok(())
}

// Replacement publishes a distinct file object within the already opened
// directory capability. This avoids truncating a potentially shared hardlink.
// It does NOT establish custody for reads or append, and must remain nonrelease
// until the stronger T011 object/principal policy is independently validated.
fn replace_bounded(dir: &Dir, relative: &str, bytes: &[u8]) -> Result<()> {
    require_bounded_size(bytes.len())?;
    let path = Path::new(relative);
    let name = path.file_name()
        .ok_or_else(|| Error::from_reason("Invalid relative capability file name"))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
    let target_parent = dir.open_dir(parent).map_err(denied)?;
    let mut pending = TempFile::new(&target_parent).map_err(denied)?;
    pending.write_all(bytes).map_err(denied)?;
    pending.flush().map_err(denied)?;
    pending.as_file().sync_all().map_err(denied)?;
    // A failed publication drops/cleans the owned tempfile rather than
    // deleting the original destination or attempting a path-based fallback.
    pending.replace(name).map_err(denied)
}

fn read_bounded(file: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(MAX_CAPABILITY_BYTES as u64 + 1)
        .read_to_end(&mut bytes).map_err(denied)?;
    require_bounded_size(bytes.len())?;
    Ok(bytes)
}

// Some Windows junctions and other reparse points do not present as
// ordinary symbolic links. Check the OS reparse attribute as well as
// cap-std's cross-platform file-type classification; deny conservatively.
fn reject_special_entry(metadata: &cap_std::fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(Error::from_reason("Capability operation rejected: nonregular entry"));
    }
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::from_reason("Capability operation rejected: reparse point"));
        }
    }
    Ok(())
}

#[napi]
pub struct RootCapability { root: Mutex<Option<Dir>> }

// Exact byte count is represented as a decimal string to avoid precision
// loss when JavaScript consumers handle files larger than Number.MAX_SAFE_INTEGER.
// Only regular files and directories are reported; symbolic links and other
// special entries are rejected without following them.
#[napi(object)]
pub struct CapabilityEntryMetadata {
    pub kind: String,
    pub size_bytes: String,
}

// Create a test-only N-API-wrapped object via the supported safe wrapper.
// No additional #[napi] native class or filesystem capability is introduced.
#[cfg(feature = "receiver-test-fixture")]
#[napi]
pub fn foreign_wrapped_object(env: Env) -> Result<Object<'static>> {
    let mut object = Object::new(&env)?;
    object.wrap((), None)?;
    Ok(object)
}

// Exercises FromNapiRef conversion independently of class method dispatch.
// Test-only: a foreign wrapped object must not be treated as RootCapability.
#[cfg(feature = "receiver-test-fixture")]
#[napi]
pub fn accepts_root_argument(_capability: &RootCapability) -> bool {
    true
}

// Validate FromNapiMutRef separately; the derived mutable Rust reference
// must never be constructed from a foreign wrapped native object.
#[cfg(feature = "receiver-test-fixture")]
#[napi]
pub fn accepts_mut_root_argument(_capability: &mut RootCapability) -> bool {
    true
}

// Test-only: reenter JavaScript while a generated shared reference is live.
// GC and nested conversions must not invalidate or mutably alias the borrowed root.
#[cfg(feature = "receiver-test-fixture")]
#[napi]
pub fn probe_borrow_across_js_callback(
    capability: &RootCapability,
    callback: Function<'_, (), ()>,
) -> Result<bool> {
    callback.call(())?;
    let guard = capability.root.lock()
        .map_err(|_| Error::from_reason("Capability lock unavailable"))?;
    Ok(guard.is_some())
}

// Test-only multi-argument callbacks exercise native shared/exclusive alias guards.
#[cfg(feature = "receiver-test-fixture")]
#[napi]
pub fn probe_shared_pair(_left: &RootCapability, _right: &RootCapability) -> bool {
    true
}

#[cfg(feature = "receiver-test-fixture")]
#[napi]
pub fn probe_shared_and_mutable(_left: &RootCapability, _right: &mut RootCapability) -> bool {
    true
}

#[cfg(feature = "receiver-test-fixture")]
#[napi]
pub fn probe_mutable_pair(_left: &mut RootCapability, _right: &mut RootCapability) -> bool {
    true
}

// Test-only: exercise the exact guard that generated reference conversion uses.
// Never construct or dereference a Rust reference from the null pointer.
#[cfg(feature = "receiver-test-fixture")]
#[napi]
pub fn probe_null_native_borrow(mutable: bool) -> Result<()> {
    let borrow = napi::bindgen_prelude::acquire_native_borrow(
        std::ptr::null_mut::<RootCapability>(), mutable,
    )?;
    drop(borrow);
    Ok(())
}

#[napi]
impl RootCapability {
    #[napi(constructor)]
    pub fn new(root: String) -> Result<Self> {
        let dir = secure_root::open_root_dir(&root).map_err(denied)?;
        Ok(Self { root: Mutex::new(Some(dir)) })
    }

    #[napi]
    pub fn read_text(&self, relative: String) -> Result<String> {
        let guard = self.root.lock().map_err(|_| Error::from_reason("Capability lock unavailable"))?;
        let dir = guard.as_ref().ok_or_else(|| Error::from_reason("Capability is closed"))?;
        let file = dir.open(relative).map_err(denied)?;
        String::from_utf8(read_bounded(file)?)
            .map_err(|_| Error::from_reason("Capability operation rejected: InvalidData"))
    }

    #[napi]
    pub fn write_text(&self, relative: String, content: String) -> Result<()> {
        require_bounded_size(content.len())?;
        let guard = self.root.lock().map_err(|_| Error::from_reason("Capability lock unavailable"))?;
        let dir = guard.as_ref().ok_or_else(|| Error::from_reason("Capability is closed"))?;
        // Replacement must publish a fresh object, not truncate the inode
        // potentially shared by a hard link outside the authorized namespace.
        // cap-std-ext uses a capability-relative tempfile and atomic rename.
        replace_bounded(dir, &relative, content.as_bytes())
    }

    #[napi]
    pub fn append_text(&self, relative: String, content: String) -> Result<()> {
        require_bounded_size(content.len())?;
        let guard = self.root.lock().map_err(|_| Error::from_reason("Capability lock unavailable"))?;
        let dir = guard.as_ref().ok_or_else(|| Error::from_reason("Capability is closed"))?;
        let mut options = OpenOptions::new();
        options.append(true).create(true);
        let mut file = dir.open_with(relative, &options).map_err(denied)?;
        file.write_all(content.as_bytes()).map_err(denied)?;
        file.flush().map_err(denied)?;
        Ok(())
    }

    #[napi]
    pub fn read_bytes(&self, relative: String) -> Result<Buffer> {
        let guard = self.root.lock().map_err(|_| Error::from_reason("Capability lock unavailable"))?;
        let dir = guard.as_ref().ok_or_else(|| Error::from_reason("Capability is closed"))?;
        let file = dir.open(relative).map_err(denied)?;
        // Text and binary operations share the same bounded synchronous read.
        Ok(read_bounded(file)?.into())
    }

    #[napi]
    pub fn write_bytes(&self, relative: String, content: Buffer, mode: String) -> Result<()> {
        // Validation must precede opening the file: invalid/oversized requests
        // must never truncate an existing target or create a new one.
        require_bounded_size(content.len())?;
        if mode != "rewrite" && mode != "append" {
            return Err(Error::from_reason("Invalid capability write mode"));
        }
        let guard = self.root.lock().map_err(|_| Error::from_reason("Capability lock unavailable"))?;
        let dir = guard.as_ref().ok_or_else(|| Error::from_reason("Capability is closed"))?;
        if mode == "rewrite" {
            // Object replacement is independent from any pre-existing hard
            // link alias. Append still requires separate custody policy.
            return replace_bounded(dir, &relative, content.as_ref());
        }
        let mut options = OpenOptions::new();
        options.append(true).create(true);
        let mut file = dir.open_with(relative, &options).map_err(denied)?;
        file.write_all(content.as_ref()).map_err(denied)?;
        file.flush().map_err(denied)?;
        Ok(())
    }

    // Native directory operations must remain relative to the opened root:
    // never return validated absolute names for JavaScript to reopen.
    #[napi]
    pub fn create_directory(&self, relative: String) -> Result<()> {
        let guard = self.root.lock().map_err(|_| Error::from_reason("Capability lock unavailable"))?;
        let dir = guard.as_ref().ok_or_else(|| Error::from_reason("Capability is closed"))?;
        dir.create_dir_all(relative).map_err(denied)
    }

    #[napi]
    pub fn move_relative(&self, from: String, to: String) -> Result<()> {
        let guard = self.root.lock().map_err(|_| Error::from_reason("Capability lock unavailable"))?;
        let dir = guard.as_ref().ok_or_else(|| Error::from_reason("Capability is closed"))?;
        // cap-std resolves both names relative to the same opened directory.
        dir.rename(from, dir, to).map_err(denied)
    }

    #[napi]
    pub fn list_directory(&self, relative: String) -> Result<Vec<String>> {
        const MAX_DIRECTORY_ENTRIES: usize = 4096;
        let guard = self.root.lock().map_err(|_| Error::from_reason("Capability lock unavailable"))?;
        let dir = guard.as_ref().ok_or_else(|| Error::from_reason("Capability is closed"))?;
        let entries = dir.read_dir(relative).map_err(denied)?;
        let mut names = Vec::new();
        for entry in entries {
            // Never silently return a truncated listing.
            if names.len() >= MAX_DIRECTORY_ENTRIES {
                return Err(Error::from_reason("Capability directory entry limit exceeded"));
            }
            let entry = entry.map_err(denied)?;
            let name = entry.file_name().into_string()
                .map_err(|_| Error::from_reason("Capability directory contains a non-UTF8 name"))?;
            names.push(name);
        }
        Ok(names)
    }

    // For existing entries, query via the capability handle rather than
    // validating an absolute path and reopening it under a mutable namespace.
    #[napi]
    pub fn stat_relative(&self, relative: String) -> Result<CapabilityEntryMetadata> {
        let guard = self.root.lock().map_err(|_| Error::from_reason("Capability lock unavailable"))?;
        let dir = guard.as_ref().ok_or_else(|| Error::from_reason("Capability is closed"))?;
        let metadata = dir.symlink_metadata(relative).map_err(denied)?;
        reject_special_entry(&metadata)?;
        let kind = if metadata.is_file() {
            "file"
        } else if metadata.is_dir() {
            "directory"
        } else {
            return Err(Error::from_reason("Capability operation rejected: nonregular entry"));
        };
        Ok(CapabilityEntryMetadata {
            kind: kind.to_owned(),
            size_bytes: metadata.len().to_string(),
        })
    }

    // Intentional file removal only; directory and symlink targets are denied.
    // The final unlinked name is resolved by cap-std relative to the held root.
    #[napi]
    pub fn remove_file_relative(&self, relative: String) -> Result<()> {
        let guard = self.root.lock().map_err(|_| Error::from_reason("Capability lock unavailable"))?;
        let dir = guard.as_ref().ok_or_else(|| Error::from_reason("Capability is closed"))?;
        let metadata = dir.symlink_metadata(&relative).map_err(denied)?;
        reject_special_entry(&metadata)?;
        if !metadata.is_file() {
            return Err(Error::from_reason("Capability operation rejected: not a regular file"));
        }
        dir.remove_file(relative).map_err(denied)
    }

    // Deliberately non-recursive. Removing a nonempty directory must fail
    // without unlinking its children, including under concurrent renames.
    #[napi]
    pub fn remove_empty_directory_relative(&self, relative: String) -> Result<()> {
        let guard = self.root.lock().map_err(|_| Error::from_reason("Capability lock unavailable"))?;
        let dir = guard.as_ref().ok_or_else(|| Error::from_reason("Capability is closed"))?;
        let metadata = dir.symlink_metadata(&relative).map_err(denied)?;
        reject_special_entry(&metadata)?;
        if !metadata.is_dir() {
            return Err(Error::from_reason("Capability operation rejected: not a regular directory"));
        }
        dir.remove_dir(relative).map_err(denied)
    }

    #[napi]
    pub fn close(&self) -> Result<()> {
        let mut guard = self.root.lock().map_err(|_| Error::from_reason("Capability lock unavailable"))?;
        *guard = None;
        Ok(())
    }
}
