// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use libc;
use std::fs::{File, OpenOptions};
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::ops::{Deref, DerefMut};
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// Wrap an `std::fs::File` object, ensuring that its inner FD is locked
/// via `libc::flock`.
///
/// `Deref` and `DerefMut` are employed in order to easily expose the original
/// `File` interface (i.e. `LockedFile` can be derefed to `File`).
pub struct LockedFile(File);

impl LockedFile {
    /// Create a `LockedFile` from the file at `path`, opened in read-only mode.
    /// Note: the lock itself will be a read-only lock.
    pub fn open_ro<P: AsRef<Path>>(path: P) -> IoResult<Self> {
        OpenOptions::new()
            .read(true)
            .open(path)
            .and_then(|f| Self::from_file(f, libc::LOCK_SH))
    }

    /// Create a `LockedFile` from the file at `path`, opened in read-write mode.
    /// Note: the lock itself will be a read-write (i.e. exclusive) lock.
    pub fn open_rw<P: AsRef<Path>>(path: P) -> IoResult<Self> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .and_then(|f| Self::from_file(f, libc::LOCK_EX))
    }

    /// Get a mutable reference to the inner `File` object.
    pub fn as_mut_file(&mut self) -> &mut File {
        &mut self.0
    }

    fn from_file(file: File, flock_op: libc::c_int) -> IoResult<Self> {
        loop {
            let rc = unsafe { libc::flock(file.as_raw_fd(), flock_op) };
            if rc == 0 {
                break;
            }
            let err = IoError::last_os_error();

            // If our wait was interrupted, try to acquire the lock again.
            if err.kind() != ErrorKind::Interrupted {
                return Err(err);
            }
        }
        Ok(Self(file))
    }
}

impl Deref for LockedFile {
    type Target = File;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for LockedFile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for LockedFile {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
