use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FileAccessError {
    #[error("Certificate file not found: {path}\n\nCheck that the file exists and the path in config.toml is correct.")]
    FileNotFound { path: PathBuf },

    #[error("Certificate file access denied\n\nDiagnostics:\n{diagnostics}\n\nSuggested Fix:\n{fix_suggestion}")]
    PermissionDenied {
        diagnostics: String,
        fix_suggestion: String,
    },

    #[error("Failed to read file metadata: {0}")]
    MetadataError(#[from] std::io::Error),
}

/// Cache for container detection result
static CONTAINER_DETECTION: OnceLock<bool> = OnceLock::new();

/// Detects if running inside a Docker container
pub fn is_running_in_container() -> bool {
    *CONTAINER_DETECTION.get_or_init(|| {
        // Check 1: Look for /.dockerenv file
        if std::path::Path::new("/.dockerenv").exists() {
            return true;
        }

        // Check 2: Examine /proc/1/cgroup for container indicators
        #[cfg(target_os = "linux")]
        {
            if let Ok(content) = std::fs::read_to_string("/proc/1/cgroup") {
                if content.contains("/docker/")
                    || content.contains("/lxc/")
                    || content.contains("/kubepods/")
                {
                    return true;
                }
            }

            // Check 3: Look for container-specific environment variables
            if std::env::var("KUBERNETES_SERVICE_HOST").is_ok()
                || std::env::var("DOCKER_CONTAINER").is_ok()
            {
                return true;
            }
        }

        false
    })
}

/// Validates that certificate files are accessible before attempting to read them
pub fn validate_file_access(
    cert_path: &Path,
    key_path: &Path,
    file_type: &str,
) -> Result<(), FileAccessError> {
    // Validate certificate file
    validate_single_file(cert_path, file_type, false)?;

    // Validate key file (private key)
    validate_single_file(key_path, file_type, true)?;

    Ok(())
}

/// Validates access to a single certificate or key file
fn validate_single_file(
    file_path: &Path,
    file_type: &str,
    is_private_key: bool,
) -> Result<(), FileAccessError> {
    // Check if file exists
    if !file_path.exists() {
        return Err(FileAccessError::FileNotFound {
            path: file_path.to_path_buf(),
        });
    }

    // Try to read file metadata
    let metadata = match std::fs::metadata(file_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            // Permission denied on metadata read - gather diagnostics
            let diagnostics = build_diagnostics(file_path, None, None, is_private_key);
            let fix_suggestion = generate_fix_suggestion(
                get_current_uid(),
                None,
                None,
                is_running_in_container(),
                file_path,
                file_type,
                is_private_key,
            );

            return Err(FileAccessError::PermissionDenied {
                diagnostics,
                fix_suggestion,
            });
        }
        Err(e) => return Err(FileAccessError::MetadataError(e)),
    };

    // Get file ownership and permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let file_owner_uid = metadata.uid();
        let file_mode = metadata.mode();
        let current_uid = get_current_uid();

        // Check if we can actually read the file
        match std::fs::File::open(file_path) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                let diagnostics = build_diagnostics(
                    file_path,
                    Some(file_owner_uid),
                    Some(file_mode),
                    is_private_key,
                );
                let fix_suggestion = generate_fix_suggestion(
                    current_uid,
                    Some(file_owner_uid),
                    Some(file_mode),
                    is_running_in_container(),
                    file_path,
                    file_type,
                    is_private_key,
                );

                Err(FileAccessError::PermissionDenied {
                    diagnostics,
                    fix_suggestion,
                })
            }
            Err(e) => Err(FileAccessError::MetadataError(e)),
        }
    }

    #[cfg(not(unix))]
    {
        // On non-Unix systems, just try to open the file
        match std::fs::File::open(file_path) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                let diagnostics = build_diagnostics(file_path, None, None, is_private_key);
                let fix_suggestion = generate_fix_suggestion(
                    0, // N/A on Windows
                    None,
                    None,
                    false, // Container detection less relevant on Windows
                    file_path,
                    file_type,
                    is_private_key,
                );

                Err(FileAccessError::PermissionDenied {
                    diagnostics,
                    fix_suggestion,
                })
            }
            Err(e) => Err(FileAccessError::MetadataError(e)),
        }
    }
}

/// Builds diagnostic information about the permission issue
fn build_diagnostics(
    file_path: &Path,
    file_owner_uid: Option<u32>,
    file_mode: Option<u32>,
    is_private_key: bool,
) -> String {
    let mut diag = String::new();

    diag.push_str(&format!("- File path: {}\n", file_path.display()));
    diag.push_str(&format!(
        "- File type: {}\n",
        if is_private_key {
            "Private Key"
        } else {
            "Certificate"
        }
    ));
    diag.push_str(&format!(
        "- Running in container: {}\n",
        if is_running_in_container() {
            "Yes"
        } else {
            "No"
        }
    ));

    #[cfg(unix)]
    {
        let current_uid = get_current_uid();
        let current_user = get_current_username();

        diag.push_str(&format!(
            "- Current UID: {} ({})\n",
            current_uid, current_user
        ));

        if let Some(uid) = file_owner_uid {
            diag.push_str(&format!("- File owner UID: {}\n", uid));
        }

        if let Some(mode) = file_mode {
            let perm_bits = mode & 0o777;
            diag.push_str(&format!("- File permissions: {:04o} (", perm_bits));

            // Format human-readable permissions
            let owner_read = if perm_bits & 0o400 != 0 { 'r' } else { '-' };
            let owner_write = if perm_bits & 0o200 != 0 { 'w' } else { '-' };
            let owner_exec = if perm_bits & 0o100 != 0 { 'x' } else { '-' };
            let group_read = if perm_bits & 0o040 != 0 { 'r' } else { '-' };
            let group_write = if perm_bits & 0o020 != 0 { 'w' } else { '-' };
            let group_exec = if perm_bits & 0o010 != 0 { 'x' } else { '-' };
            let other_read = if perm_bits & 0o004 != 0 { 'r' } else { '-' };
            let other_write = if perm_bits & 0o002 != 0 { 'w' } else { '-' };
            let other_exec = if perm_bits & 0o001 != 0 { 'x' } else { '-' };

            diag.push_str(&format!(
                "{}{}{}{}{}{}{}{}{}))",
                owner_read,
                owner_write,
                owner_exec,
                group_read,
                group_write,
                group_exec,
                other_read,
                other_write,
                other_exec
            ));
        }
    }

    #[cfg(not(unix))]
    {
        diag.push_str("- Platform: Windows (limited diagnostic information available)");
    }

    diag
}

/// Generates context-aware fix suggestions based on the detected scenario
fn generate_fix_suggestion(
    current_uid: u32,
    file_owner_uid: Option<u32>,
    file_mode: Option<u32>,
    in_container: bool,
    file_path: &Path,
    file_type: &str,
    is_private_key: bool,
) -> String {
    let mut suggestion = String::new();

    #[cfg(unix)]
    {
        // Scenario 1: Running in container with wrong ownership
        if in_container {
            if let Some(owner_uid) = file_owner_uid {
                if owner_uid != current_uid {
                    suggestion.push_str(&format!(
                        "The {} file is owned by UID {}, but the container runs as UID {}.\n\n",
                        if is_private_key {
                            "private key"
                        } else {
                            "certificate"
                        },
                        owner_uid,
                        current_uid
                    ));

                    suggestion.push_str("Option 1: Fix ownership on the Docker host\n");
                    suggestion.push_str(&format!(
                        "  sudo chown -R {}:{} {}\n\n",
                        current_uid,
                        current_uid,
                        file_path
                            .parent()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| file_path.display().to_string())
                    ));

                    suggestion.push_str("Option 2: Regenerate certificates inside the container\n");
                    suggestion.push_str(&format!(
                        "  docker exec <container-name> utun cert {} --common-name <hostname> -o {}\n\n",
                        file_type,
                        file_path.parent()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "/certs".to_string())
                    ));

                    suggestion.push_str("Option 3: Use a bind mount with proper ownership\n");
                    suggestion.push_str(
                        "  Create certificates with the container user's UID before mounting\n",
                    );

                    return suggestion;
                }
            }
        }

        // Scenario 2: Wrong permissions (too permissive or too restrictive)
        if let Some(mode) = file_mode {
            let perm_bits = mode & 0o777;

            if is_private_key {
                // Private key should be 0600
                if perm_bits != 0o600 {
                    if perm_bits & 0o077 != 0 {
                        suggestion.push_str("Private key file has insecure permissions (readable by group or others).\n\n");
                    } else {
                        suggestion.push_str(
                            "Private key file permissions are too restrictive or incorrect.\n\n",
                        );
                    }

                    suggestion.push_str("Fix with:\n");
                    if in_container {
                        suggestion.push_str(&format!(
                            "  docker exec <container-name> chmod 0600 {}\n",
                            file_path.display()
                        ));
                    } else {
                        suggestion.push_str(&format!("  chmod 0600 {}\n", file_path.display()));
                    }

                    return suggestion;
                }
            }
        }

        // Scenario 3: Ownership mismatch (non-container)
        if !in_container {
            if let Some(owner_uid) = file_owner_uid {
                if owner_uid != current_uid {
                    suggestion.push_str(&format!(
                        "The {} file is owned by UID {}, but the current process runs as UID {}.\n\n",
                        if is_private_key { "private key" } else { "certificate" },
                        owner_uid,
                        current_uid
                    ));

                    suggestion.push_str("Fix with:\n");
                    suggestion.push_str(&format!(
                        "  sudo chown {} {}\n",
                        current_uid,
                        file_path.display()
                    ));

                    if is_private_key {
                        suggestion.push_str(&format!("  chmod 0600 {}\n", file_path.display()));
                    }

                    return suggestion;
                }
            }
        }

        // Scenario 4: Generic permission issue
        suggestion.push_str("The file cannot be read due to permission restrictions.\n\n");

        if in_container {
            suggestion.push_str("Verify:\n");
            suggestion.push_str(&format!(
                "1. File ownership matches container UID ({})\n",
                current_uid
            ));
            if is_private_key {
                suggestion.push_str("2. Private key has 0600 permissions\n");
            } else {
                suggestion.push_str("2. Certificate file is readable\n");
            }
            suggestion
                .push_str("3. Volume mounts are configured correctly in docker-compose.yml\n");
        } else {
            suggestion.push_str("Check:\n");
            suggestion.push_str(&format!(
                "1. File ownership: ls -l {}\n",
                file_path.display()
            ));
            suggestion.push_str(&format!(
                "2. Current user: id (should show UID {})\n",
                current_uid
            ));
            if is_private_key {
                suggestion.push_str(&format!(
                    "3. Fix permissions: chmod 0600 {}\n",
                    file_path.display()
                ));
            }
        }
    }

    #[cfg(not(unix))]
    {
        suggestion.push_str("The file cannot be accessed due to permission restrictions.\n\n");
        suggestion.push_str("On Windows:\n");
        suggestion.push_str("1. Right-click the file and select Properties\n");
        suggestion.push_str("2. Go to the Security tab\n");
        suggestion.push_str("3. Ensure your user account has Read permissions\n");
        if is_private_key {
            suggestion.push_str(
                "4. For private keys, ensure only your user has access (remove other users)\n",
            );
        }
    }

    suggestion
}

/// Gets the current process UID
#[cfg(unix)]
fn get_current_uid() -> u32 {
    // Safety: getuid() is always safe to call
    unsafe { libc::getuid() }
}

#[cfg(not(unix))]
fn get_current_uid() -> u32 {
    0 // N/A on Windows
}

/// Gets the current username
#[cfg(unix)]
fn get_current_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_detection() {
        // Just ensure it doesn't panic
        let _ = is_running_in_container();
    }

    #[test]
    fn test_diagnostics_building() {
        let path = Path::new("/test/cert.pem");
        let diag = build_diagnostics(path, Some(1000), Some(0o600), false);
        assert!(diag.contains("/test/cert.pem"));
        assert!(diag.contains("Certificate"));
    }

    #[test]
    fn test_fix_suggestion_container_ownership() {
        let path = Path::new("/certs/server.key");
        let suggestion = generate_fix_suggestion(
            1000,       // current UID
            Some(1003), // file owner UID
            Some(0o600),
            true, // in container
            path,
            "server",
            true, // is private key
        );
        assert!(suggestion.contains("owned by UID 1003"));
        assert!(suggestion.contains("container runs as UID 1000"));
        assert!(suggestion.contains("chown"));
    }

    #[test]
    fn test_fix_suggestion_insecure_permissions() {
        let path = Path::new("/certs/server.key");
        let suggestion = generate_fix_suggestion(
            1000,
            Some(1000),  // same owner
            Some(0o644), // insecure permissions
            false,
            path,
            "server",
            true,
        );
        assert!(suggestion.contains("insecure permissions"));
        assert!(suggestion.contains("chmod 0600"));
    }
}
