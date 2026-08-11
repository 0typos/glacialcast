//! Offline native relay credential authority commands.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use glacialcast_protocol::{
    credential::{
        CertificateAuthorityPublic, CredentialRequest, NativeCredential,
        create_certificate_authority, load_certificate_authority,
    },
    private_state::{create_private, read_private},
};
use std::path::{Path, PathBuf};

const MAX_MATERIAL_BYTES: usize = 4 * 1024 * 1024;
const DAY_MS: i64 = 24 * 60 * 60 * 1_000;

#[derive(Debug, Parser)]
#[command(version, about = "Manage an offline GlacialCast credential authority")]
struct PkiArgs {
    #[command(subcommand)]
    command: PkiCommand,
}

#[derive(Debug, Subcommand)]
enum PkiCommand {
    /// Create a new private authority and export its public key.
    CreateCa {
        #[arg(long)]
        authority: PathBuf,
        #[arg(long)]
        public: PathBuf,
    },
    /// Issue a role credential from a signed request.
    Issue {
        #[arg(long)]
        authority: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 365)]
        days: u32,
    },
    /// Create a signed revocation list from credential files.
    Revoke {
        #[arg(long)]
        authority: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 30)]
        days: u32,
        #[arg(required = true)]
        credentials: Vec<PathBuf>,
    },
    /// Print the authority identifier and public signing key.
    Show {
        #[arg(long)]
        public: PathBuf,
    },
}

/// Runs an explicitly selected offline PKI operation.
///
/// # Errors
///
/// Returns an error for unsafe files, invalid signed material, overwrite
/// attempts, or invalid validity bounds.
pub fn run() -> Result<()> {
    let mut arguments: Vec<_> = std::env::args_os().collect();
    if arguments.get(1).and_then(|value| value.to_str()) == Some("pki") {
        arguments.remove(1);
    }
    let args = PkiArgs::parse_from(arguments);
    match args.command {
        PkiCommand::CreateCa { authority, public } => {
            let public_key = create_certificate_authority(&authority)?;
            create_private(&public, &public_key.encode()?)?;
            println!("created authority {}", encode_hex(&public_key.id()?));
        }
        PkiCommand::Issue {
            authority,
            request,
            output,
            days,
        } => {
            let authority = load_certificate_authority(&authority)?;
            let request = CredentialRequest::decode(&read_private(&request, MAX_MATERIAL_BYTES)?)?;
            let now = glacialcast_protocol::now_ms();
            request.verify(now, duration_ms(days)?)?;
            let credential = authority.issue(
                &request,
                now,
                now.checked_add(duration_ms(days)?)
                    .context("credential expiry overflows")?,
                duration_ms(days)?,
            )?;
            create_private(&output, &credential.encode()?)?;
            println!("issued {}", encode_hex(&credential.body.serial));
        }
        PkiCommand::Revoke {
            authority,
            output,
            days,
            credentials,
        } => {
            let authority = load_certificate_authority(&authority)?;
            let mut serials = Vec::with_capacity(credentials.len());
            for path in credentials {
                serials.push(
                    NativeCredential::decode(&read_private(&path, MAX_MATERIAL_BYTES)?)?
                        .body
                        .serial,
                );
            }
            let now = glacialcast_protocol::now_ms();
            let list = authority.sign_revocations(
                now,
                now.checked_add(duration_ms(days)?)
                    .context("revocation expiry overflows")?,
                serials,
            )?;
            create_private(&output, &list.encode()?)?;
            println!("wrote {} revocation(s)", list.body.serials.len());
        }
        PkiCommand::Show { public } => {
            let authority = load_public(&public)?;
            println!("authority {}", encode_hex(&authority.id()?));
            println!("signing-key {}", encode_hex(&authority.signing_key));
        }
    }
    Ok(())
}

fn load_public(path: &Path) -> Result<CertificateAuthorityPublic> {
    Ok(CertificateAuthorityPublic::decode(&read_private(
        path,
        MAX_MATERIAL_BYTES,
    )?)?)
}

fn duration_ms(days: u32) -> Result<i64> {
    i64::from(days)
        .checked_mul(DAY_MS)
        .filter(|duration| *duration > 0)
        .context("validity days must be positive and bounded")
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validity_days_reject_zero_and_convert_without_overflow() {
        assert!(duration_ms(0).is_err());
        assert_eq!(duration_ms(1).unwrap(), DAY_MS);
    }
}
