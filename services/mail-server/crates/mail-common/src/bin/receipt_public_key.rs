//! `receipt-public-key` — operator CLI for the routing-receipt key material.
//!
//! Prints the PUBLIC half (and its `key_id` fingerprint) of the Ed25519 seed
//! in `RECEIPT_SIGNING_KEY`, and — with `--verify` — verifies a presented
//! (payload, signature) pair against a public key. This is the "externally
//! recomputed verification" tool: it holds NO deployment state and talks to
//! nothing, so an auditor can reproduce a receipt check offline with the same
//! bytes the ledger stores.
//!
//! Usage:
//!   # publish material for the api-server's RECEIPT_PUBLIC_KEY
//!   RECEIPT_SIGNING_KEY=$(cat secrets/receipt_signing_key.txt) \
//!       receipt-public-key
//!
//!   # verify a receipt exported from the ledger (payload + signature files)
//!   receipt-public-key --verify --payload receipt.payload \
//!       --signature receipt.sig --public-key "$RECEIPT_PUBLIC_KEY"
//!
//! Exit codes: 0 ok/valid, 1 invalid signature or bad input, 2 usage/setup.

use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  \
         receipt-public-key                          # print key_id/public key of RECEIPT_SIGNING_KEY\n  \
         receipt-public-key --verify --payload FILE --signature FILE [--public-key KEY | --public-key-file FILE]\n\n\
         KEY forms: 64 hex characters or base64 of the 32-byte public key."
    );
    ExitCode::from(2)
}

fn read_file(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map(|text| text.trim().to_string())
        .map_err(|error| format!("cannot read {path}: {error}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return usage();
    }

    if args.first().map(String::as_str) == Some("--verify") {
        let mut payload = None;
        let mut signature = None;
        let mut public_key = None;
        let mut index = 1;
        while index < args.len() {
            let flag = args[index].as_str();
            let value = args.get(index + 1);
            match (flag, value) {
                ("--payload", Some(value)) => payload = Some(value.clone()),
                ("--signature", Some(value)) => signature = Some(value.clone()),
                ("--public-key", Some(value)) => public_key = Some(value.clone()),
                ("--public-key-file", Some(value)) => {
                    public_key = Some(value.clone());
                }
                _ => return usage(),
            }
            index += 2;
        }
        let (Some(payload), Some(signature)) = (payload, signature) else {
            return usage();
        };
        let payload = match read_file(&payload) {
            Ok(text) => text,
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::from(2);
            }
        };
        // A signature file may legitimately have trailing whitespace/newlines
        // (editors add them); the decoder trims.
        let signature = match read_file(&signature) {
            Ok(text) => text,
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::from(2);
            }
        };
        let raw_key = match public_key {
            Some(path_or_key) => {
                if std::path::Path::new(&path_or_key).is_file() {
                    match read_file(&path_or_key) {
                        Ok(text) => text,
                        Err(error) => {
                            eprintln!("{error}");
                            return ExitCode::from(2);
                        }
                    }
                } else {
                    path_or_key
                }
            }
            None => {
                eprintln!(
                    "no public key given: pass --public-key <base64|hex> or --public-key-file <path>, \
                     or publish it from the deployment (GET /v1/routing/receipts/public-key)"
                );
                return ExitCode::from(2);
            }
        };
        let key = match mail_common::routing_receipt::parse_public_key(&raw_key) {
            Ok(key) => key,
            Err(error) => {
                eprintln!("public key: {error}");
                return ExitCode::from(2);
            }
        };
        match mail_common::routing_receipt::verify_payload(&payload, &signature, &key) {
            Ok(()) => {
                println!(
                    "VALID — signature verifies over {} payload byte(s) under key_id {}",
                    payload.len(),
                    mail_common::routing_receipt::key_id_for(&key)
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                println!(
                    "INVALID — {error} (key_id {})",
                    mail_common::routing_receipt::key_id_for(&key)
                );
                ExitCode::from(1)
            }
        }
    } else {
        // Publish the public half of the configured signing seed.
        match mail_common::routing_receipt::RoutingReceiptSigner::from_env() {
            Ok(Some(signer)) => {
                println!("scheme:            ed25519");
                println!("key_id:            {}", signer.key_id());
                println!("public_key_base64: {}", signer.public_key_base64());
                println!("public_key_hex:    {}", signer.public_key_hex());
                println!(
                    "\nSet RECEIPT_PUBLIC_KEY to either form on the api-server \
                     (verify: GET /v1/routing/receipts/public-key)."
                );
                ExitCode::SUCCESS
            }
            Ok(None) => {
                eprintln!(
                    "{} is unset — nothing to publish. Set a 32-byte Ed25519 seed \
                     (`openssl rand -hex 32`).",
                    mail_common::routing_receipt::RECEIPT_SIGNING_KEY_ENV
                );
                ExitCode::from(2)
            }
            Err(error) => {
                eprintln!("{}", error);
                ExitCode::from(2)
            }
        }
    }
}
