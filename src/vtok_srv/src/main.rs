extern crate vtok_rpc;

use std::fmt;
use std::io::Read;
use vtok_rpc::{Listener, ProvisionProto};

enum Error {
    ProtoError(vtok_rpc::ProtoError),
    IoError(std::io::Error),
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
        }
    }
}

fn print_usage() {
    let usage = r#"Nitro vToken database provisioning server
Usage:
    vtoken-srv vsock <cid> <port>
    vtoken-srv unix <path>"#;
    println!("{}", usage);
}

/// Parameters:
/// AF_VSOCK: <vtoken-srv> "vsock" "10000"
/// AF_UNIX:  <vtoken-srv> "unix" "some_path"
fn main_main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let proto = ProvisionProto::from_args(&args[1..]).map_err(Error::ProtoError)?;
    let listener = Listener::new(&proto).map_err(Error::ProtoError)?;

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

fn main() {
    match main_main() {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(i32::from(e))
        }
    }
}
