extern crate libc;

use std::io::Error as IoError;
use std::mem::size_of;
use std::os::raw::c_uint;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};

/// Supported transports
static VSOCK_OPT: &str = "vsock";
static UNIX_OPT: &str = "unix";

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

/// Generic Stream container
pub enum Stream {
    Vsock(VsockStream),
    Unix(UnixStream),
}

/// Generic Listener container
pub enum Listener {
    Vsock(VsockListener),
    Unix(UnixListener),
}

/// An AF_VSOCK stream (client)
#[derive(Debug, Clone)]
pub struct VsockStream {
    fd: RawFd,
}

impl VsockStream {
    pub fn connect(args: &VsockArgs) -> Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(Error::SocketCreate(IoError::last_os_error()));
        }

        let addr = libc::sockaddr_vm {
            svm_family: libc::AF_VSOCK as libc::sa_family_t,
            svm_cid: args.cid,
            svm_port: args.port,
            svm_reserved1: 0,
            svm_zero: [0u8; 4],
        };
        let rc = unsafe {
            libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
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
        match rc {
            rc if rc < 0 => Err(std::io::Error::last_os_error()),
            // TODO: this doesn't seem right. Why transform EOF into an io::Error?
            0 => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "Socket disconnected",
            )),
            rc => Ok(rc as usize),
        }
    }
}

/// VsockStream Writer
impl std::io::Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let rc = unsafe { libc::write(self.fd, buf.as_ptr() as *mut libc::c_void, buf.len()) };
        match rc {
            rc if rc < 0 => Err(std::io::Error::last_os_error()),
            0 => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "Socket disconnected",
            )),
            rc => Ok(rc as usize),
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
    pub fn bind(args: &VsockArgs) -> Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(Error::SocketCreate(IoError::last_os_error()));
        }

        let mut addr = libc::sockaddr_vm {
            svm_family: libc::AF_VSOCK as libc::sa_family_t,
            svm_cid: args.cid,
            svm_port: args.port,
            svm_reserved1: 0,
            svm_zero: [0u8; 4],
        };
        let mut rc = unsafe {
            libc::bind(
                fd,
                &mut addr as *mut _ as *mut libc::sockaddr,
                size_of::<libc::sockaddr_vm>() as u32,
            )
        };
        if rc < 0 {
            let err = Error::Bind(IoError::last_os_error());
            unsafe { libc::close(fd) };
            return Err(err);
        }
        rc = unsafe { libc::listen(fd, 1) };
        if rc < 0 {
            let err = Error::Listen(IoError::last_os_error());
            unsafe { libc::close(fd) };
            return Err(err);
        }
        Ok(Self { fd })
    }

    /// Accept a client connection and return a client stream
    pub fn accept(&self) -> Result<VsockStream> {
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

/// Generic Stream (Client)
///
/// Example:
///
/// fn main() {
///     let args: Vec<String> = std::env::args().collect();
///     let proto = ProvisionProto::from_args(&args[1..])?;
///     let stream = Stream::new(&proto)?;
///     stream.write(/* some data */)?;
/// }
///
impl Stream {
    pub fn new(proto: &ProvisionProto) -> Result<Self> {
        if proto.is_vsock() {
            let stream = VsockStream::connect(proto.vsock_args()?)?;
            Ok(Self::Vsock(stream))
        } else {
            UnixStream::connect(proto.unix_path()?)
                .map(|us| Self::Unix(us))
                .map_err(Error::Connect)
        }
    }

    pub fn from_vsock_stream(stream: VsockStream) -> Result<Stream> {
        Ok(Self::Vsock(stream))
    }

    pub fn from_unix_stream(stream: UnixStream) -> Result<Stream> {
        Ok(Self::Unix(stream))
    }
}

/// Generic Stream Reader
impl std::io::Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Vsock(backend) => backend.read(buf),
            Self::Unix(backend) => backend.read(buf),
        }
    }
}

/// Generic Stream Writer
impl std::io::Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Vsock(backend) => backend.write(&buf),
            Self::Unix(backend) => backend.write(&buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Vsock(backend) => backend.flush(),
            Self::Unix(backend) => backend.flush(),
        }
    }
}

/// Generic Listener (Server)
///
/// Example:
///
/// fn main() {
///     let args: Vec<String> = std::env::args().collect();
///     let proto = ProvisionProto::from_args(&args[1..])?;
///     let listener = Listener::new(&proto)?;
///     loop {
///         let mut stream = listener.accept()?;
///
///         // Process I/O with the connected stream
///     }
/// }
///
impl Listener {
    pub fn new(proto: &ProvisionProto) -> Result<Self> {
        if proto.is_vsock() {
            let listener = VsockListener::bind(proto.vsock_args()?)?;
            Ok(Self::Vsock(listener))
        } else {
            UnixListener::bind(&proto.unix_path()?)
                .map(|ul| Self::Unix(ul))
                .map_err(Error::Bind)
        }
    }

    pub fn accept(&self) -> Result<Stream> {
        match self {
            Self::Vsock(backend) => {
                let stream = backend.accept()?;
                Stream::from_vsock_stream(stream)
            }
            Self::Unix(backend) => backend
                .accept()
                .map_err(Error::Accept)
                .and_then(|ar| Stream::from_unix_stream(ar.0)),
        }
    }
}

/// AF_UNIX transport arguments
pub struct UnixArgs {
    path: String,
}

/// AF_VSOCK transport arguments
pub struct VsockArgs {
    cid: c_uint,
    port: c_uint,
}

/// Protocol container
pub enum ProvisionProto {
    ProtoVsock(VsockArgs),
    ProtoUnix(UnixArgs),
}

fn parse_vsock_args(args: &[String]) -> Result<VsockArgs> {
    match args.len() {
        2 => {
            // Server binds to the enclave CID (VMADDR_CID_ANY)
            let cid = args[0].to_string().parse::<c_uint>();
            let port = args[1].to_string().parse::<c_uint>();
            if cid.is_err() || port.is_err() {
                return Err(Error::BadArgs);
            }

            Ok(VsockArgs {
                // Safe due to the above checks
                cid: cid.unwrap(),
                port: port.unwrap(),
            })
        }
        _ => Err(Error::BadArgs),
    }
}

fn parse_unix_args(args: &[String]) -> Result<UnixArgs> {
    match args.len() {
        1 => {
            let path = args[0].to_string();
            Ok(UnixArgs { path })
        }
        _ => Err(Error::BadArgs),
    }
}

/// Protocol input parameters based on which Listeners or Streams
/// backends are created. Currently supports AF_VSOCK and AF_UNIX.
impl ProvisionProto {
    /// Parse protocol input data
    pub fn from_args(args: &[String]) -> Result<Self> {
        // Server expects: <binary> [vsock|unix] [<port> <cid>|<path>]
        // Client expects: <binary> [vsock|unix] [<port> <cid>|<path>]

        let proto = &args[0].to_string();
        if proto == VSOCK_OPT {
            Ok(Self::ProtoVsock(parse_vsock_args(&args[1..])?))
        } else if proto == UNIX_OPT {
            Ok(Self::ProtoUnix(parse_unix_args(&args[1..])?))
        } else {
            Err(Error::BadProto)
        }
    }

    /// Check if this container has an AF_VSOCK context or not
    pub fn is_vsock(&self) -> bool {
        match self {
            Self::ProtoVsock(_) => true,
            _ => false,
        }
    }

    /// Get a reference to the AF_VSOCK arguments
    pub fn vsock_args(&self) -> Result<&VsockArgs> {
        match self {
            Self::ProtoVsock(args) => Ok(args),
            _ => Err(Error::BadProto),
        }
    }

    /// Get a copy of the stored AF_UNIX path
    pub fn unix_path(&self) -> Result<String> {
        match &self {
            Self::ProtoUnix(args) => Ok(args.path.clone()),
            _ => Err(Error::BadProto),
        }
    }
}
