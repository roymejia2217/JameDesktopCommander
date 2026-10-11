//! Isolated T011-B feasibility spike. Never expose ambient constructor to MCP callers.
use cap_std::{ambient_authority, fs::{Dir, OpenOptions}};
use napi::{bindgen_prelude::Buffer, Error, Result};
use napi_derive::napi;
use std::{io::{Read, Write}, sync::Mutex};

// Initial bounded allocation limit for the experimental, synchronous API.
// Larger files require a separately tested, cancellable streaming interface.
const MAX_CAPABILITY_BYTES: usize = 32 * 1024 * 1024;

fn denied(error: std::io::Error) -> Error {
    Error::from_reason(format!("Capability operation rejected: {}", error.kind()))
}
#[napi]
pub struct RootCapability { root: Mutex<Option<Dir>> }

#[napi]
impl RootCapability {
    #[napi(constructor)]
    pub fn new(root: String) -> Result<Self> {
        let dir = Dir::open_ambient_dir(root, ambient_authority()).map_err(denied)?;
        Ok(Self { root: Mutex::new(Some(dir)) })
    }

    #[napi]
    pub fn read_text(&self, relative: String) -> Result<String> {
        let guard = self.root.lock().map_err(|_| Error::from_reason("Capability lock unavailable"))?;
        let dir = guard.as_ref().ok_or_else(|| Error::from_reason("Capability is closed"))?;
        let mut file = dir.open(relative).map_err(denied)?;
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(denied)?;
        Ok(text)
    }

    #[napi]
    pub fn write_text(&self, relative: String, content: String) -> Result<()> {
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
        // Read at most one byte beyond the limit so oversized files cannot
        // allocate arbitrarily large buffers or be silently truncated.
        let mut bounded = file.take(MAX_CAPABILITY_BYTES as u64 + 1);
        let mut bytes = Vec::new();
        bounded.read_to_end(&mut bytes).map_err(denied)?;
        if bytes.len() > MAX_CAPABILITY_BYTES {
            return Err(Error::from_reason("Capability byte limit exceeded"));
        }
        Ok(bytes.into())
    }

    #[napi]
    pub fn write_bytes(&self, relative: String, content: Buffer, mode: String) -> Result<()> {
        // Validation must precede opening the file: invalid/oversized requests
        // must never truncate an existing target or create a new one.
        if content.len() > MAX_CAPABILITY_BYTES {
            return Err(Error::from_reason("Capability byte limit exceeded"));
        }
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

    #[napi]
    pub fn close(&self) -> Result<()> {
        let mut guard = self.root.lock().map_err(|_| Error::from_reason("Capability lock unavailable"))?;
        *guard = None;
        Ok(())
    }
}
