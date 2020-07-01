extern crate vtok_rpc;

use std::io::Read;
use vtok_rpc::{Listener, ProvisionProto};

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
fn main() -> Result<(), std::io::Error> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let proto = ProvisionProto::from_args(&args[1..])?;
    let listener = Listener::new(&proto)?;

    println!("[vToken] Provisioning server is now running");
    loop {
        let mut stream = listener.accept()?;

        // TODO: Add vtok_rpc logic
        // We use read_exact() since we will receive protocol
        // information on the size of the received blob
        let mut data = vec![0u8; 18];

        stream.read_exact(&mut data)?;

        println!("Got Data {:?}", std::str::from_utf8(&data));
    }
}
