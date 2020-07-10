extern crate vtok_rpc;

use std::fmt;
use std::io::Write;
use vtok_rpc::{ProvisionProto, Stream};

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
    let usage = r#"Nitro vToken Tool
Usage:
    nitro-vtoken vsock <cid> <port>
    nitro-vtoken unix <path>"#;
    println!("{}", usage);
}

/// Parameters:
/// AF_VSOCK: <nitro-vtoken> "vsock" "16" "10000"
/// AF_UNIX:  <nitro-vtoken> "unix" "some/path"
fn main_main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    // TODO: Lots of logic to add
    //
    // Spawn a client and send some bytes
    let proto = ProvisionProto::from_args(&args[1..]).map_err(Error::ProtoError)?;
    let mut stream = Stream::new(&proto).map_err(Error::ProtoError)?;

    let data = "Testing the client".as_bytes();
    stream.write_all(&data).map_err(Error::IoError)?;

    println!("Done");

    Ok(())
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
