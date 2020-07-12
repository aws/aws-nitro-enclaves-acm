extern crate libc;

use std::io::{Error as IoError, Read, Write};
use std::mem::size_of;
use std::os::raw::c_uint;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};

#[derive(Debug)]
pub enum Error {
    Accept(std::io::Error),
    BadArgs,
    BadProto,
    Bind(std::io::Error),
    Connect(std::io::Error),
    Listen(std::io::Error),
    SocketCreate(std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait Listener {
    type Stream: Read + Write;

    fn accept(&self) -> Result<Self::Stream>;
}

#[derive(Clone, Copy, Debug)]
pub struct VsockAddr {
    pub cid: c_uint,
    pub port: c_uint,
}

impl VsockAddr {
    pub fn any_cid_with_port(port: c_uint) -> Self {
        Self {
            cid: libc::VMADDR_CID_ANY,
            port,
        }
    }
}

/// An AF_VSOCK stream (client)
#[derive(Debug, Clone)]
pub struct VsockStream {
    fd: RawFd,
}

impl VsockStream {
    pub fn connect(addr: VsockAddr) -> Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(Error::SocketCreate(IoError::last_os_error()));
        }

        let sa = libc::sockaddr_vm {
            svm_family: libc::AF_VSOCK as libc::sa_family_t,
            svm_cid: addr.cid,
            svm_port: addr.port,
            svm_reserved1: 0,
            svm_zero: [0u8; 4],
        };
        let rc = unsafe {
            libc::connect(
                fd,
                &sa as *const _ as *const libc::sockaddr,
                size_of::<libc::sockaddr_vm>() as u32,
            )
        };
        if rc < 0 {
            let err = Error::Connect(IoError::last_os_error());
            unsafe { libc::close(fd) };
            return Err(err);
        }

        Ok(unsafe { VsockStream::from_raw_fd(fd) })
    }
}

impl FromRawFd for VsockStream {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self { fd }
    }
}

impl AsRawFd for VsockStream {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// VsockStream Drop
impl Drop for VsockStream {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// VsockStream Reader
impl std::io::Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let rc = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if rc < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(rc as usize)
        }
    }
}

/// VsockStream Writer
impl std::io::Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let rc = unsafe { libc::write(self.fd, buf.as_ptr() as *mut libc::c_void, buf.len()) };
        if rc < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(rc as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// An AF_VSOCK listener (server)
#[derive(Debug, Clone)]
pub struct VsockListener {
    fd: RawFd,
}

impl VsockListener {
    pub fn bind(addr: VsockAddr, backlog: std::os::raw::c_int) -> Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(Error::SocketCreate(IoError::last_os_error()));
        }

        let mut sa = libc::sockaddr_vm {
            svm_family: libc::AF_VSOCK as libc::sa_family_t,
            svm_cid: addr.cid,
            svm_port: addr.port,
            svm_reserved1: 0,
            svm_zero: [0u8; 4],
        };
        let mut rc = unsafe {
            libc::bind(
                fd,
                &mut sa as *mut _ as *mut libc::sockaddr,
                size_of::<libc::sockaddr_vm>() as u32,
            )
        };
        if rc < 0 {
            let err = Error::Bind(IoError::last_os_error());
            unsafe { libc::close(fd) };
            return Err(err);
        }
        rc = unsafe { libc::listen(fd, backlog) };
        if rc < 0 {
            let err = Error::Listen(IoError::last_os_error());
            unsafe { libc::close(fd) };
            return Err(err);
        }
        Ok(Self { fd })
    }
}

impl Listener for VsockListener {
    type Stream = VsockStream;

    /// Accept a client connection and return a client stream
    fn accept(&self) -> Result<VsockStream> {
        let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        let mut addr_len = size_of::<libc::sockaddr_vm>() as libc::socklen_t;
        let cl_fd = unsafe {
            libc::accept(
                self.fd,
                &mut addr as *mut _ as *mut libc::sockaddr,
                &mut addr_len,
            )
        };
        if cl_fd < 0 {
            return Err(Error::Accept(IoError::last_os_error()));
        }

        Ok(unsafe { VsockStream::from_raw_fd(cl_fd) })
    }
}

/// VsockListener Drop
impl Drop for VsockListener {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl Listener for UnixListener {
    type Stream = UnixStream;

    fn accept(&self) -> Result<UnixStream> {
        UnixListener::accept(self)
            .map(|(s, _)| s)
            .map_err(Error::Accept)
    }
}
