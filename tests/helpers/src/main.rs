use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::io::{Read, Write};
use std::num::Wrapping;

fn usage(binname: &String) {
    eprintln!(
        "Usage: {} <option>
Options:
\tbitflip <filename> <bit>
\tprng_file <outputpath> <filesize> <seed>
\tprng_int <seed> <startvalue> <endvalue>",
        binname
    );
}

struct Prng {
    seed: Wrapping<u32>,
}

impl Prng {
    fn new(seed: u32) -> Self {
        Self {
            seed: Wrapping(seed),
        }
    }

    fn random_u8(&mut self) -> u8 {
        let rand: u8 = (self.seed.0 & 0xff) as u8;
        self.seed = Wrapping(1103515245) * self.seed + Wrapping(1234567);
        rand
    }

    fn random_fill(&mut self, v: &mut [u8]) {
        for x in v.iter_mut() {
            *x = self.random_u8()
        }
    }

    fn random_u32(&mut self) -> u32 {
        let mut vec = [0u8; 4];
        self.random_fill(&mut vec);
        u32::from_be_bytes(vec)
    }
}

fn prng_file(filename: String, filesize: u64, seed: u32) -> Result<(), String> {
    let mut prng = Prng::new(seed);
    let mut buf = [0u8; 4096];
    let mut total_written: u64 = 0;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(filename)
        .map_err(|e| format!("Error creating file: {}", e))?;

    while total_written < filesize {
        let wsize = std::cmp::min((filesize - total_written) as usize, buf.len());
        prng.random_fill(&mut buf[..wsize]);
        file.write_all(&buf[..wsize])
            .map_err(|e| format!("Error writing file: {}", e))?;
        total_written += wsize as u64;
    }

    Ok(())
}

/// Renerate random value in range [start, end) from seed
fn prng_int(seed: u32, start: u32, end: u32) -> Result<(), String> {
    let mut prng = Prng::new(seed);
    if end <= start {
        return Err("invalid interval".to_string());
    }
    println!("{}\n", (prng.random_u32() % (end - start)) + start);

    Ok(())
}

fn bitflip(filename: String, bit: u64) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&filename)
        .map_err(|e| format!("Could not open file {}: {}", filename, e))?;
    file.seek(SeekFrom::Start(bit / 8))
        .map_err(|e| format!("Could not seek: {}", e))?;
    let mut buf = [0u8; 1];
    file.read_exact(&mut buf)
        .map_err(|e| format!("Could not read: {}", e))?;
    buf[0] ^= 1 << (bit % 8);
    file.seek(SeekFrom::Start(bit / 8))
        .map_err(|e| format!("Could not seek: {}", e))?;
    file.write_all(&mut buf)
        .map_err(|e| format!("Could not read: {}", e))?;

    Ok(())
}

fn main() -> Result<(), String> {
    let mut args = env::args();

    let binname = args.next().ok_or("Missing binary name".to_string())?;
    let command = args.next().ok_or({ "Missing option".to_string() })?;

    match command.as_str() {
        "bitflip" => {
            let filename = args.next().ok_or({ "Missing argument".to_string() })?;
            let bit: u64 = args
                .next()
                .ok_or({ "Missing argument".to_string() })?
                .parse::<u64>()
                .map_err(|e| format!("Invalid number {}", e))?;
            bitflip(filename, bit)
        }
        "prng_file" => {
            let filename = args.next().ok_or({ "Missing argument".to_string() })?;
            let filesize: u64 = args
                .next()
                .ok_or({ "Missing argument".to_string() })?
                .parse::<u64>()
                .map_err(|e| format!("Invalid number {}", e))?;
            let seed: u32 = args
                .next()
                .ok_or({ "Missing argument".to_string() })?
                .parse::<u32>()
                .map_err(|e| format!("Invalid number {}", e))?;
            prng_file(filename, filesize, seed)
        }
        "prng_int" => {
            let seed: u32 = args
                .next()
                .ok_or({ "Missing argument".to_string() })?
                .parse::<u32>()
                .map_err(|e| format!("Invalid number {}", e))?;
            let start: u32 = args
                .next()
                .ok_or({ "Missing argument".to_string() })?
                .parse::<u32>()
                .map_err(|e| format!("Invalid number {}", e))?;
            let end: u32 = args
                .next()
                .ok_or({ "Missing argument".to_string() })?
                .parse::<u32>()
                .map_err(|e| format!("Invalid number {}", e))?;
            prng_int(seed, start, end)
        }
        _ => {
            usage(&binname);
            Err("Unexpected option".to_string())
        }
    }
}
