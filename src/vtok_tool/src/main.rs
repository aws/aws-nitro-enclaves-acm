extern crate vtok_rpc;

use std::fmt;
use std::os::unix::net::UnixStream;
use std::io::Write;
use vtok_rpc::{VsockAddr, VsockStream};

const USAGE: &str = r#"Nitro vToken Tool
    Usage:
        nitro-vtoken vsock <cid> <port>
        nitro-vtoken unix <path>
"#;

enum Error {
    ProtoError(vtok_rpc::ProtoError),
    IoError(std::io::Error),
    UsageError,
}

impl From<Error> for i32 {
    fn from(_other: Error) -> i32 {
        // NOTE: we could discriminate between errors here to provide a more specific
        // exit code.
        1
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: pretty-format error messages
        match self {
            Self::ProtoError(e) => write!(f, "{:?}", e),
            Self::IoError(e) => write!(f, "{:?}", e),
            Self::UsageError => write!(f, "{}", USAGE),
        }
    }
}

/// Parameters:
/// AF_VSOCK: <nitro-vtoken> "vsock" "16" "10000"
/// AF_UNIX:  <nitro-vtoken> "unix" "some/path"
fn rusty_main() -> Result<(), Error> {
    let mut args = std::env::args();

    args.next();

    let test_data = "Testing the client".as_bytes();

    match (
        args.next().as_ref().map(|s| s.as_str()),
        args.next().as_ref().map(|s| s.as_str()),
        args.next().as_ref().map(|s| s.as_str()),
    ) {
        (Some("vsock"), Some(cid), Some(port)) => {
            let cid = cid
                .parse::<std::os::raw::c_uint>()
                .map_err(|_| Error::UsageError)?;
            let port = port
                .parse::<std::os::raw::c_uint>()
                .map_err(|_| Error::UsageError)?;
            VsockStream::connect(VsockAddr {cid, port})
                .map_err(Error::ProtoError)
                .and_then(|mut s| s.write_all(&test_data).map_err(Error::IoError))?;
        }
        (Some("unix"), Some(path), None) => {
            UnixStream::connect(path)
                .map_err(Error::IoError)
                .and_then(|mut s| s.write_all(&test_data).map_err(Error::IoError))?;
        }
        _ => return Err(Error::UsageError),
    };

    // TODO: Lots of logic to add

    println!("Done");

    Ok(())
}

fn main() {
    match rusty_main() {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(i32::from(e))
        }
    }
}
