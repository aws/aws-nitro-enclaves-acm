use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::defs;
use crate::util;
use crate::util::LockedFile;

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    ReadOnly,
    SerdeError(serde_json::error::Error),
}

#[derive(Deserialize, Serialize)]
pub struct PrivateKey {
    pub pem: String,
    pub encrypted_pem_b64: String,
    pub id: u8,
    pub label: String,
}

#[derive(Deserialize, Serialize)]
pub struct Token {
    pub label: String,
    pub private_keys: Vec<PrivateKey>,
    pub pin: String,
    /// Token expiry timestamp, in seconds. When CLOCK_MONOTONIC reaches this value, the token
    /// is no longer usable.
    pub expiry_ts: u64,
}

#[derive(Deserialize, Serialize)]
pub struct Device {
    slots: Vec<Option<Token>>,
}

/// Device config helper, used to safely access the global eVault config, stored in the file system
/// at `crate::defs::DEVICE_CONFIG_PATH`.
pub struct Config {
    device: Device,
    file: Option<LockedFile>,
}

impl Config {
    /// Create a new / default config file.
    ///
    /// Note: this is not concurrency-safe! It should only be called from a non-concurrent context,
    ///       such as at server initialization time.
    pub fn init_new() -> Result<(), Error> {
        let path = Path::new(defs::DEVICE_CONFIG_PATH);

        // It's safe to unwrap here, since we know that defs::DEVICE_CONFIG_PATH is sane.
        let dir_path = path.parent().unwrap();
        std::fs::create_dir_all(dir_path).map_err(Error::IoError)?;

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(Error::IoError)?;

        let mut device = Device {
            slots: Vec::with_capacity(defs::DEVICE_MAX_SLOTS),
        };
        for _ in 0..defs::DEVICE_MAX_SLOTS {
            device.slots.push(None);
        }

        serde_json::to_writer(BufWriter::new(file), &device).map_err(Error::SerdeError)?;

        Ok(())
    }

    /// Load the config in read-only mode.
    /// The config file lock is held only until the the data is read and parsed.
    pub fn load_ro() -> Result<Self, Error> {
        let mut file = LockedFile::open_ro(defs::DEVICE_CONFIG_PATH).map_err(Error::IoError)?;
        let device = Self::load_device(file.as_mut_file())?;
        Ok(Self { device, file: None })
    }

    /// Load the config in read-write mode.
    /// The config lock is held for the entire lifetime of the returned object.
    pub fn load_rw() -> Result<Self, Error> {
        let mut file = LockedFile::open_rw(defs::DEVICE_CONFIG_PATH).map_err(Error::IoError)?;
        let device = Self::load_device(file.as_mut_file())?;
        Ok(Self {
            device,
            file: Some(file),
        })
    }

    /// Write the config to its backing file.
    pub fn save(&mut self) -> Result<(), Error> {
        let file = self.file.as_mut().ok_or(Error::ReadOnly)?;
        file.seek(SeekFrom::Start(0)).map_err(Error::IoError)?;
        file.set_len(0).map_err(Error::IoError)?;
        let writer = BufWriter::new(file.as_mut_file());
        serde_json::to_writer(writer, &self.device).map_err(Error::SerdeError)?;
        file.flush().map_err(Error::IoError)?;
        Ok(())
    }

    pub fn slots(&self) -> &[Option<Token>] {
        &self.device.slots
    }

    pub fn slots_mut(&mut self) -> &mut [Option<Token>] {
        &mut self.device.slots
    }

    fn load_device<R: Read>(src: R) -> Result<Device, Error> {
        let mut device: Device =
            serde_json::from_reader(BufReader::new(src)).map_err(Error::SerdeError)?;
        for slot in device.slots.iter_mut() {
            let expired = slot
                .as_ref()
                .and_then(|tok| tok.expiry_ts.checked_sub(util::time::monotonic_secs()))
                .filter(|t| *t > 0)
                .is_none();
            if expired {
                slot.take();
            }
        }
        Ok(device)
    }
}
