extern crate vtok_rpc;

use std::io::Write;
use vtok_rpc::{ProvisionProto, Stream};

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
fn main() -> Result<(), std::io::Error> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    // TODO: Lots of logic to add
    //
    // Spawn a client and send some bytes
    let proto = ProvisionProto::from_args(&args[1..])?;
    let mut stream = Stream::new(&proto)?;

    let data = "Testing the client".as_bytes();
    stream.write_all(&data)?;

    println!("Done");

    Ok(())
}
