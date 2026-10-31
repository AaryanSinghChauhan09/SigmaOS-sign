//! sigmasign CLI entry point.

use std::{env, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") if args.len() == 4 => {
            let key = match sigmasign::SigningKey::generate() {
                Ok(key) => key,
                Err(error) => fail(&format!("key generation failed: {error}"), 1),
            };
            if let Err(error) = key.write_to_file(&args[2]) {
                fail(&format!("private key write failed: {error}"), 1);
            }
            if let Err(error) = key.verifying_key().write_to_file(&args[3]) {
                fail(&format!("public key write failed: {error}"), 1);
            }
            println!("Wrote private and public keys");
        }
        Some("sign") if args.len() == 4 => {
            let key = match sigmasign::SigningKey::from_file(&args[2]) {
                Ok(key) => key,
                Err(error) => fail(&format!("private key load failed: {error}"), 1),
            };
            if let Err(error) = sigmasign::Signer::with_key(key).sign_file(&args[3]) {
                fail(&format!("sign failed: {error}"), 1);
            }
            println!("Signed: {}", args[3]);
        }
        Some("verify") if args.len() == 4 => {
            let key = match sigmasign::VerifyKey::from_file(&args[2]) {
                Ok(key) => key,
                Err(error) => fail(&format!("public key load failed: {error}"), 1),
            };
            match sigmasign::Verifier::with_key(key).verify_file(&args[3]) {
                Ok(true) => println!("Signature valid: {}", args[3]),
                Ok(false) => fail(&format!("Signature INVALID: {}", args[3]), 2),
                Err(error) => fail(&format!("verify error: {error}"), 1),
            }
        }
        Some("keygen" | "sign" | "verify") | None => {
            usage();
            process::exit(1);
        }
        Some(command) => {
            eprintln!("sigmasign: unknown command '{command}'");
            usage();
            process::exit(1);
        }
    }
}

fn usage() {
    eprintln!("Usage:\n  sigmasign keygen <private-key-file> <public-key-file>\n  sigmasign sign <private-key-file> <file>\n  sigmasign verify <public-key-file> <file>");
}

fn fail(message: &str, code: i32) -> ! {
    eprintln!("sigmasign: {message}");
    process::exit(code);
}
