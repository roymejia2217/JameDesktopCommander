//! Isolated T011-B feasibility spike. Never expose ambient constructor to MCP callers.
use cap_std::fs::{Dir, OpenOptions};
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

fn read_bounded(file: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(MAX_CAPABILITY_BYTES as u64 + 1)
        .read_to_end(&mut bytes).map_err(denied)?;
    require_bounded_size(bytes.len())?;
    Ok(bytes)
}

#[napi]
pub struct RootCapability { root: Mutex<Option<Dir>> }

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
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        let mut file = dir.open_with(relative, &options).map_err(denied)?;
        file.write_all(content.as_bytes()).map_err(denied)?;
        file.flush().map_err(denied)?;
        Ok(())
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
        let mut options = OpenOptions::new();
        if mode == "append" {
            options.append(true).create(true);
        } else {
            options.write(true).create(true).truncate(true);
        }
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

    #[napi]
    pub fn close(&self) -> Result<()> {
        let mut guard = self.root.lock().map_err(|_| Error::from_reason("Capability lock unavailable"))?;
        *guard = None;
        Ok(())
    }
}
