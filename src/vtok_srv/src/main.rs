extern crate vtok_rpc;

use std::fmt;
use std::io::Read;
use std::os::unix::net::UnixListener;
use vtok_rpc::{Listener, VsockAddr, VsockListener};

const USAGE: &str = r#"Nitro vToken database provisioning server
    Usage:
        vtoken-srv vsock <cid> <port>
        vtoken-srv unix <path>
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

fn run_server<L: Listener>(listener: L) -> Result<(), Error> {
    println!("[vToken] Provisioning server is now running");
    loop {
        let mut stream = listener.accept().map_err(Error::ProtoError)?;

        // TODO: Add vtok_rpc logic
        // We use read_exact() since we will receive protocol
        // information on the size of the received blob
        let mut data = vec![0u8; 18];

        stream.read_exact(&mut data).map_err(Error::IoError)?;

        println!("Got Data {:?}", std::str::from_utf8(&data));
    }
}

/// Parameters:
/// AF_VSOCK: <vtoken-srv> "vsock" "10000"
/// AF_UNIX:  <vtoken-srv> "unix" "some_path"
fn rusty_main() -> Result<(), Error> {
    let mut args = std::env::args();

    args.next();

    match (
        args.next().as_ref().map(|s| s.as_str()),
        args.next().as_ref().map(|s| s.as_str()),
    ) {
        (Some("vsock"), Some(port)) => {
            let port = port
                .parse::<std::os::raw::c_uint>()
                .map_err(|_| Error::UsageError)?;
            VsockListener::bind(VsockAddr::any_cid_with_port(port), 5)
                .map_err(Error::ProtoError)
                .and_then(|l| run_server(l))?;
        }
        (Some("unix"), Some(path)) => {
            UnixListener::bind(path)
                .map_err(Error::IoError)
                .and_then(|l| run_server(l))?;
        }
        (_, _) => return Err(Error::UsageError),
    };
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
