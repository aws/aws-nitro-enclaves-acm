extern crate vtok_rpc;

use std::fmt;
use std::os::unix::net::UnixListener;
use vtok_rpc::{ApiRequest, ApiResponse};
use vtok_rpc::{HttpTransport, Transport};
use vtok_rpc::{Listener, VsockAddr, VsockListener};

const USAGE: &str = r#"Nitro vToken database provisioning server
    Usage:
        vtoken-srv vsock <port>
        vtoken-srv unix <path>
"#;

enum Error {
    IoError(std::io::Error),
    UsageError,
    TransportError(vtok_rpc::transport::Error),
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
            Self::IoError(e) => write!(f, "{:?}", e),
            Self::UsageError => write!(f, "{}", USAGE),
            Self::TransportError(e) => write!(f, "{:?}", e),
        }
    }
}

fn run_server<L: Listener>(listener: L) -> Result<(), Error> {
    println!("[vToken] Provisioning server is now running");
    loop {
        let stream = listener.accept().map_err(Error::IoError)?;

        // TODO: Add vtok_rpc logic

        let mut xport = HttpTransport::new(stream, "/rpc/v1");
        let req = xport.recv_request().map_err(Error::TransportError)?;
        println!("Server got request: {:?}", req);
        let resp = match req {
            ApiRequest::Hello { sender } => ApiResponse::Hello(Ok(format!("Hello, {}!", sender))),
        };
        xport.send_response(resp).map_err(Error::TransportError)?;
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
                .map_err(Error::IoError)
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
