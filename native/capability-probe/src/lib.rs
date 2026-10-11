//! Isolated T011-B feasibility spike. Never expose ambient constructor to MCP callers.
use cap_std::{ambient_authority, fs::{Dir, OpenOptions}};
use napi::{Error, Result};
use napi_derive::napi;
use std::{io::{Read, Write}, sync::Mutex};

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
    pub fn close(&self) -> Result<()> {
        let mut guard = self.root.lock().map_err(|_| Error::from_reason("Capability lock unavailable"))?;
        *guard = None;
        Ok(())
    }
}
