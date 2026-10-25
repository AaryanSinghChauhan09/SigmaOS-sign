//! sigmasign CLI entry point.

use std::{env, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: sigmasign <sign|verify> <file>");
        process::exit(1);
    }
    match args[1].as_str() {
        "sign" => {
            let signer = sigmasign::Signer::new();
            if let Err(e) = signer.sign_file(&args[2]) {
                eprintln!("sigmasign: sign failed: {}", e);
                process::exit(1);
            }
            println!("Signed: {}", args[2]);
        }
        "verify" => {
            let verifier = sigmasign::Verifier::new();
            match verifier.verify_file(&args[2]) {
                Ok(true) => println!("Signature valid: {}", args[2]),
                Ok(false) => {
                    eprintln!("Signature INVALID: {}", args[2]);
                    process::exit(2);
                }
                Err(e) => {
                    eprintln!("sigmasign: verify error: {}", e);
                    process::exit(1);
                }
            }
        }
        cmd => {
            eprintln!("sigmasign: unknown command '{}'", cmd);
            process::exit(1);
        }
    }
}
