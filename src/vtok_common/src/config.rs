use serde::{Deserialize, Serialize};
use serde_json;
use std::io::{BufReader, BufWriter, Seek, SeekFrom, Write};

use crate::defs;
use crate::util::LockedFile;

pub enum Error {
    IoError(std::io::Error),
    ReadOnly,
    SerdeError(serde_json::error::Error),
}

#[derive(Deserialize, Serialize)]
pub struct PrivateKey{
    pub pem: String,
    pub id: u8,
    pub label: String,
}

#[derive(Deserialize, Serialize)]
pub struct Token {
    pub label: String,
    pub private_keys: Vec<PrivateKey>,
    pub pin: String,
}

#[derive(Deserialize, Serialize)]
pub struct Device {
    tokens: Vec<Token>,
}

/// Device config helper, used to safely access the global eVault config, stored in the file system
/// at `crate::defs::DEVICE_CONFIG_PATH`.
pub struct Config {
    device: Device,
    file: Option<LockedFile>,
}

impl Config {
    /// Create a new / default config object, in read-write mode (i.e. with the global config file
    /// lock held).
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            device: Device { tokens: Vec::new() },
            file: Some(LockedFile::open_rw(defs::DEVICE_CONFIG_PATH).map_err(Error::IoError)?)
        })
    }

    /// Load the config in read-only mode.
    /// The config file lock is held only until the the data is read and parsed.
    pub fn load_ro() -> Result<Self, Error> {
        let mut file = LockedFile::open_ro(defs::DEVICE_CONFIG_PATH).map_err(Error::IoError)?;
        let device = serde_json::from_reader(BufReader::new(file.as_mut_file())).map_err(Error::SerdeError)?;
        Ok(Self { device, file: None })
    }

    /// Load the config in read-write mode.
    /// The config lock is held for the entire lifetime of the returned object.
    pub fn load_rw() -> Result<Self, Error> {
        let mut file = LockedFile::open_rw(defs::DEVICE_CONFIG_PATH).map_err(Error::IoError)?;
        let device = {
            let reader = BufReader::new(file.as_mut_file());
            serde_json::from_reader(reader).map_err(Error::SerdeError)?
        };
        Ok(Self { device, file: Some(file) })
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
}
