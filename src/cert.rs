use anyhow::Result;
use clap::Subcommand;
use std::fs;
use std::path::PathBuf;
use x509_parser::prelude::*;

use crate::crypto::{
    generate_ca_certificate, generate_client_certificate, generate_server_certificate,
    verify_certificate_chain, verify_certificate_hostname,
};

#[derive(Debug, Clone, Subcommand)]
pub enum CertCommand {
    /// Generate a CA certificate
    Ca {
        /// Common name for the CA
        #[arg(long)]
        common_name: String,

        /// Validity period in days
        #[arg(long, default_value = "3650")]
        validity_days: u32,

        /// Output certificate to file
        #[arg(long)]
        out_cert: Option<PathBuf>,

        /// Output private key to file
        #[arg(long)]
        out_key: Option<PathBuf>,
    },

    /// Generate a server certificate
    Server {
        /// Common name for the server
        #[arg(long)]
        common_name: String,

        /// DNS names for Subject Alternative Names
        #[arg(long, value_delimiter = ',')]
        dns_names: Vec<String>,

        /// IP addresses for Subject Alternative Names
        #[arg(long, value_delimiter = ',')]
        ip_addresses: Vec<String>,

        /// CA certificate path
        #[arg(long)]
        ca_cert: PathBuf,

        /// CA private key path
        #[arg(long)]
        ca_key: PathBuf,

        /// Validity period in days
        #[arg(long, default_value = "365")]
        validity_days: u32,

        /// Output certificate to file
        #[arg(long)]
        out_cert: Option<PathBuf>,

        /// Output private key to file
        #[arg(long)]
        out_key: Option<PathBuf>,
    },

    /// Generate a client certificate
    Client {
        /// Common name for the client
        #[arg(long)]
        common_name: String,

        /// CA certificate path
        #[arg(long)]
        ca_cert: PathBuf,

        /// CA private key path
        #[arg(long)]
        ca_key: PathBuf,

        /// Validity period in days
        #[arg(long, default_value = "365")]
        validity_days: u32,

        /// Output certificate to file
        #[arg(long)]
        out_cert: Option<PathBuf>,

        /// Output private key to file
        #[arg(long)]
        out_key: Option<PathBuf>,
    },

    /// Show certificate details
    Show {
        /// Certificate file to examine
        #[arg(long)]
        cert: PathBuf,
    },

    /// Verify a certificate against a CA
    Verify {
        /// Certificate to verify
        #[arg(long)]
        cert: PathBuf,

        /// CA certificate
        #[arg(long)]
        ca_cert: PathBuf,

        /// Expected hostname (optional)
        #[arg(long)]
        hostname: Option<String>,
    },
}

/// Execute a certificate command
pub fn execute_cert_command(cmd: CertCommand) -> Result<()> {
    match cmd {
        CertCommand::Ca {
            common_name,
            validity_days,
            out_cert,
            out_key,
        } => {
            // Generate CA certificate
            let bundle = generate_ca_certificate(&common_name, validity_days)?;

            // Write certificate
            let cert_path = out_cert.ok_or_else(|| {
                anyhow::anyhow!("--out-cert is required; refusing to print certificate to stdout")
            })?;
            fs::write(&cert_path, &bundle.certificate_pem)?;
            eprintln!("CA certificate written to: {}", cert_path.display());

            // Write private key
            let key_path = out_key.ok_or_else(|| {
                anyhow::anyhow!("--out-key is required; refusing to print private key to stdout")
            })?;
            // Set restrictive permissions (600) on Unix systems
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::write(&key_path, bundle.private_key_pem.expose_secret())?;
                let metadata = fs::metadata(&key_path)?;
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o600);
                fs::set_permissions(&key_path, permissions)?;
            }
            #[cfg(not(unix))]
            {
                fs::write(&key_path, bundle.private_key_pem.expose_secret())?;
            }
            eprintln!("CA private key written to: {}", key_path.display());

            eprintln!("CA certificate generated successfully");
        }

        CertCommand::Server {
            common_name,
            dns_names,
            ip_addresses,
            ca_cert,
            ca_key,
            validity_days,
            out_cert,
            out_key,
        } => {
            // Read CA cert and key
            let ca_cert_pem = fs::read_to_string(&ca_cert)?;
            let ca_key_pem = fs::read_to_string(&ca_key)?;

            // Generate server certificate
            let bundle = generate_server_certificate(
                &ca_cert_pem,
                &ca_key_pem,
                &common_name,
                dns_names,
                ip_addresses,
                validity_days,
            )?;

            // Write certificate
            let cert_path = out_cert.ok_or_else(|| {
                anyhow::anyhow!("--out-cert is required; refusing to print certificate to stdout")
            })?;
            fs::write(&cert_path, &bundle.certificate_pem)?;
            eprintln!("Server certificate written to: {}", cert_path.display());

            // Write private key
            let key_path = out_key.ok_or_else(|| {
                anyhow::anyhow!("--out-key is required; refusing to print private key to stdout")
            })?;
            // Set restrictive permissions (600) on Unix systems
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::write(&key_path, bundle.private_key_pem.expose_secret())?;
                let metadata = fs::metadata(&key_path)?;
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o600);
                fs::set_permissions(&key_path, permissions)?;
            }
            #[cfg(not(unix))]
            {
                fs::write(&key_path, bundle.private_key_pem.expose_secret())?;
            }
            eprintln!("Server private key written to: {}", key_path.display());

            eprintln!("Server certificate generated successfully");
        }

        CertCommand::Client {
            common_name,
            ca_cert,
            ca_key,
            validity_days,
            out_cert,
            out_key,
        } => {
            // Read CA cert and key
            let ca_cert_pem = fs::read_to_string(&ca_cert)?;
            let ca_key_pem = fs::read_to_string(&ca_key)?;

            // Generate client certificate
            let bundle = generate_client_certificate(
                &ca_cert_pem,
                &ca_key_pem,
                &common_name,
                validity_days,
            )?;

            // Write certificate
            let cert_path = out_cert.ok_or_else(|| {
                anyhow::anyhow!("--out-cert is required; refusing to print certificate to stdout")
            })?;
            fs::write(&cert_path, &bundle.certificate_pem)?;
            eprintln!("Client certificate written to: {}", cert_path.display());

            // Write private key
            let key_path = out_key.ok_or_else(|| {
                anyhow::anyhow!("--out-key is required; refusing to print private key to stdout")
            })?;
            // Set restrictive permissions (600) on Unix systems
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::write(&key_path, bundle.private_key_pem.expose_secret())?;
                let metadata = fs::metadata(&key_path)?;
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o600);
                fs::set_permissions(&key_path, permissions)?;
            }
            #[cfg(not(unix))]
            {
                fs::write(&key_path, bundle.private_key_pem.expose_secret())?;
            }
            eprintln!("Client private key written to: {}", key_path.display());

            eprintln!("Client certificate generated successfully");
        }

        CertCommand::Show { cert } => {
            // Load certificate
            let cert_pem = fs::read_to_string(&cert)?;
            let cert_der = pem_rfc7468::decode_vec(cert_pem.as_bytes())?.1;

            // Parse certificate
            let (_, certificate) = X509Certificate::from_der(&cert_der)?;

            // Print formatted details
            println!("Certificate Details:");
            println!("===================");
            println!();
            println!("Subject: {}", certificate.subject());
            println!("Issuer: {}", certificate.issuer());
            println!();
            println!("Serial Number: {}", certificate.serial.to_str_radix(16));
            println!();
            println!("Validity:");
            println!("  Not Before: {}", certificate.validity().not_before);
            println!("  Not After:  {}", certificate.validity().not_after);
            println!();

            // Print key usage
            if let Ok(Some(key_usage_ext)) = certificate.key_usage() {
                let ku = &key_usage_ext.value;
                println!("Key Usage:");
                if ku.digital_signature() {
                    println!("  - Digital Signature");
                }
                if ku.key_encipherment() {
                    println!("  - Key Encipherment");
                }
                if ku.key_cert_sign() {
                    println!("  - Certificate Sign");
                }
                if ku.crl_sign() {
                    println!("  - CRL Sign");
                }
                println!();
            }

            // Print extended key usage
            if let Ok(Some(eku_ext)) = certificate.extended_key_usage() {
                let eku = &eku_ext.value;
                println!("Extended Key Usage:");
                if eku.server_auth {
                    println!("  - TLS Web Server Authentication");
                }
                if eku.client_auth {
                    println!("  - TLS Web Client Authentication");
                }
                println!();
            }

            // Print subject alternative names
            if let Ok(Some(san_ext)) = certificate.subject_alternative_name() {
                let san = &san_ext.value;
                println!("Subject Alternative Names:");
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(dns) => println!("  DNS: {}", dns),
                        GeneralName::IPAddress(ip) => {
                            let ip_str = match ip.len() {
                                4 => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                                16 => std::net::Ipv6Addr::from([
                                    ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8],
                                    ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15],
                                ])
                                .to_string(),
                                _ => "Invalid IP".to_string(),
                            };
                            println!("  IP Address: {}", ip_str);
                        }
                        _ => {}
                    }
                }
                println!();
            }

            // Print CA status
            println!("Is CA: {}", certificate.is_ca());
            println!();

            // Print signature algorithm
            println!(
                "Signature Algorithm: {}",
                certificate.signature_algorithm.algorithm
            );
        }

        CertCommand::Verify {
            cert,
            ca_cert,
            hostname,
        } => {
            // Load certificate and CA
            let cert_pem = fs::read_to_string(&cert)?;
            let cert_der = pem_rfc7468::decode_vec(cert_pem.as_bytes())?.1;

            let ca_cert_pem = fs::read_to_string(&ca_cert)?;
            let ca_cert_der = pem_rfc7468::decode_vec(ca_cert_pem.as_bytes())?.1;

            // Verify certificate chain
            match verify_certificate_chain(&cert_der, &ca_cert_der) {
                Ok(()) => {
                    println!("Certificate chain verification: PASSED");
                }
                Err(e) => {
                    println!("Certificate chain verification: FAILED");
                    println!("Error: {}", e);
                    return Err(e.into());
                }
            }

            // Verify hostname if provided
            if let Some(hostname) = hostname {
                match verify_certificate_hostname(&cert_der, &hostname) {
                    Ok(()) => {
                        println!("Hostname verification for '{}': PASSED", hostname);
                    }
                    Err(e) => {
                        println!("Hostname verification for '{}': FAILED", hostname);
                        println!("Error: {}", e);
                        return Err(e.into());
                    }
                }
            }

            println!();
            println!("All verifications passed successfully");
        }
    }

    Ok(())
}
