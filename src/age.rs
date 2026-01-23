//! Uses the age crate to encrypt, decrypt and rekey files

use std::{
    collections::HashSet,
    convert::Into,
    fs,
    io::{self, BufReader, Read},
    path::Path,
};

use age::{
    armor::{ArmoredReader, ArmoredWriter, Format},
    cli_common::{
        file_io::{InputReader, OutputFormat, OutputWriter},
        StdinGuard,
    },
    decryptor::RecipientsDecryptor,
};

use base64::{
    prelude::{BASE64_STANDARD, BASE64_STANDARD_NO_PAD},
    Engine,
};
use color_eyre::{
    eyre::{eyre, Result, WrapErr},
    Help,
};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

// [Copied from str4d/rage age-core/src/format.rs]
// https://github.com/str4d/rage/blob/c266bfa44c829621e2db647ced820fca357b032f/age-core/src/format.rs#L11
const STANZA_PREFIX: &str = "-> ";

// [Copied from str4d/rage age/src/format.rs]
// https://github.com/str4d/rage/blob/c266bfa44c829621e2db647ced820fca357b032f/age/src/format.rs#L20
const MAC_PREFIX: &str = "---";

// [Copied from str4d/rage age/src/ssh.rs]
// https://github.com/str4d/rage/blob/c266bfa44c829621e2db647ced820fca357b032f/age/src/ssh.rs#L26-L27
const SSH_ED25519_TAG: &str = "ssh-ed25519";
const SSH_RSA_TAG: &str = "ssh-rsa";

/// Extracts SSH recipient fingerprints from an age file.
/// Returns Err if any non-SSH recipient type is found.
pub(crate) fn recipient_fingerprints<P: AsRef<Path>>(path: P) -> Result<HashSet<String>> {
    let path_str = path.as_ref().to_str().map(String::from);
    let input_reader = InputReader::new(path_str)?;
    let mut reader = ArmoredReader::new(input_reader);
    let mut data = Vec::new();
    reader.read_to_end(&mut data).wrap_err("Failed to read age file")?;

    // Find MAC line (header ends there, ciphertext after is binary)
    let mac_prefix = MAC_PREFIX.as_bytes();
    let header_end = data
        .windows(mac_prefix.len())
        .position(|w| w == mac_prefix)
        .unwrap_or(data.len());
    let header = String::from_utf8(data[..header_end].to_vec()).wrap_err("Invalid UTF-8 in header")?;

    let mut fingerprints = HashSet::new();
    for line in header.lines() {
        let Some(stanza) = line.strip_prefix(STANZA_PREFIX) else {
            continue;
        };
        let parts: Vec<&str> = stanza.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let (tag, encoded_tag) = (parts[0], parts[1]);
        match tag {
            SSH_ED25519_TAG | SSH_RSA_TAG => {
                fingerprints.insert(format!("{tag}:{encoded_tag}"));
            }
            // Ignore grease stanzas (tags ending in "-grease", added by age for forward compatibility)
            t if t.ends_with("-grease") => {}
            _ => return Err(eyre!("Cannot verify non-SSH recipient type: {}", tag)),
        }
    }
    Ok(fingerprints)
}

/// Computes the fingerprint for an SSH public key string.
///
/// Takes a full pubkey like "ssh-ed25519 AAAA... comment" and returns "{tag}:{encoded_tag}"
/// where encoded_tag is base64_no_pad(sha256(ssh_key)[0..4]).
///
/// [Copied from str4d/rage encoded_tag computation (not public API)](
/// https://github.com/str4d/rage/blob/c266bfa44c829621e2db647ced820fca357b032f/age/src/ssh/recipient.rs#L195
pub(crate) fn fingerprint_from_pubkey(pubkey: &str) -> Result<String> {
    // Validate it's a valid SSH key (uses public age API)
    pubkey
        .parse::<age::ssh::Recipient>()
        .map_err(|_| eyre!("Cannot verify non-SSH key"))?;
    // Parse: "{tag} {base64_ssh_key} [comment]"
    let parts: Vec<&str> = pubkey.trim().split_whitespace().collect();
    let tag = parts[0];
    let ssh_key = BASE64_STANDARD.decode(parts[1]).wrap_err("Invalid base64 in SSH key")?;
    // Compute encoded_tag: base64_no_pad(sha256(ssh_key)[0..4])
    let encoded_tag = BASE64_STANDARD_NO_PAD.encode(&Sha256::digest(&ssh_key)[..4]);
    Ok(format!("{tag}:{encoded_tag}"))
}

fn get_age_decryptor<P: AsRef<Path>>(
    path: P,
) -> Result<RecipientsDecryptor<ArmoredReader<BufReader<InputReader>>>> {
    let s = path.as_ref().to_str().map(std::string::ToString::to_string);
    let input_reader = InputReader::new(s)?;
    let decryptor = age::Decryptor::new(ArmoredReader::new(input_reader))?;

    match decryptor {
        age::Decryptor::Passphrase(_) => {
            Err(eyre!(String::from("Agenix does not support passphrases")))
        }
        age::Decryptor::Recipients(decryptor) => Ok(decryptor),
    }
}

/// Parses a recipient from a string.
/// [Copied from str4d/rage (ASL-2.0)](
/// https://github.com/str4d/rage/blob/85c0788dc511f1410b4c1811be6b8904d91f85db/rage/src/bin/rage/main.rs)
fn parse_recipient(
    s: &str,
    recipients: &mut Vec<Box<dyn age::Recipient + Send>>,
    plugin_recipients: &mut Vec<age::plugin::Recipient>,
) -> Result<()> {
    if let Ok(pk) = s.parse::<age::x25519::Recipient>() {
        recipients.push(Box::new(pk));
        Ok(())
    } else if let Some(pk) = { s.parse::<age::ssh::Recipient>().ok().map(Box::new) } {
        recipients.push(pk);
        Ok(())
    } else if let Ok(pk) = s.parse::<age::plugin::Recipient>() {
        plugin_recipients.push(pk);
        Ok(())
    } else {
        Err(eyre!("Invalid recipient: {}", s))
            .with_suggestion(|| "Make sure you use an ssh-ed25519, ssh-rsa or an X25519 public key, alternatively install an age plugin which supports your key")
    }
}

/// Returns the file paths to `$HOME/.ssh/{id_rsa,id_ed25519}` if each exists
fn get_default_identity_paths() -> Result<Vec<String>> {
    let home_path = home::home_dir().ok_or_else(|| eyre!("Could not determine home directory"))?;
    let ssh_dir = home_path.join(".ssh");

    let id_rsa = ssh_dir.join("id_rsa");
    let id_ed25519 = ssh_dir.join("id_ed25519");

    let filtered_paths = [id_rsa, id_ed25519]
        .iter()
        .filter(|x| x.exists())
        .filter_map(|x| x.to_str())
        .map(std::string::ToString::to_string)
        .collect();

    Ok(filtered_paths)
}

/// Searches plugins and transforms `age::plugin::Recipient` to `age::Recipients`
fn merge_plugin_recipients_and_recipients(
    recipients: &mut Vec<Box<dyn age::Recipient + Send>>,
    plugin_recipients: &[age::plugin::Recipient],
) -> Result<()> {
    // Get names of all required plugins from the recipients
    let mut plugin_names = plugin_recipients
        .iter()
        .map(age::plugin::Recipient::plugin)
        .collect::<Vec<_>>();
    plugin_names.sort_unstable();
    plugin_names.dedup();

    // Add to recipients
    for plugin_name in plugin_names {
        recipients.push(Box::new(age::plugin::RecipientPluginV1::new(
            plugin_name,
            plugin_recipients,
            // Rage allows for symmetric encryption, but this is not actually something which fits
            // into ragenix's design
            &Vec::<age::plugin::Identity>::new(),
            age::cli_common::UiCallbacks,
        )?));
    }
    Ok(())
}

/// Get all the identities from the given paths and the default locations.
///
/// Default locations are `$HOME/.ssh/id_rsa` and `$HOME/.ssh/id_ed25519`.
pub(crate) fn get_identities(identity_paths: &[String]) -> Result<Vec<Box<dyn age::Identity>>> {
    let mut identities: Vec<String> = identity_paths.to_vec();
    let mut default_identities = get_default_identity_paths()?;

    identities.append(&mut default_identities);

    if identities.is_empty() {
        Err(eyre!("No usable identity or identities"))
    } else {
        // Error out if an identity is tried to be read from stdin
        let mut stdin_guard = StdinGuard::new(true);
        Ok(age::cli_common::read_identities(
            identities,
            None,
            &mut stdin_guard,
        )?)
    }
}

/// Decrypt an age-encrypted file to a plaintext file.
///
/// The output file is created with a mode of `0o600`.
pub(crate) fn decrypt<P: AsRef<Path>>(
    input_file: P,
    output_file: P,
    identities: &[Box<dyn age::Identity>],
) -> Result<()> {
    let output_file_mode: u32 = 0o600;
    let decryptor = get_age_decryptor(input_file)?;
    decryptor
        .decrypt(identities.iter().map(|i| i.as_ref() as &dyn age::Identity))
        .map_err(Into::into)
        .and_then(|mut plaintext_reader| {
            let output = output_file
                .as_ref()
                .to_str()
                .map(std::string::ToString::to_string);
            let mut ciphertext_writer =
                OutputWriter::new(output, true, OutputFormat::Unknown, output_file_mode, false)?;
            io::copy(&mut plaintext_reader, &mut ciphertext_writer)?;
            Ok(())
        })
}

/// Encrypt a plaintext file to an age-encrypted file.
///
/// The output file is created with a mode of `0o644`.
pub(crate) fn encrypt<P: AsRef<Path>>(
    input_file: P,
    output_file: P,
    public_keys: &[String],
) -> Result<()> {
    let output_file_mode: u32 = 0o644;
    let mut input = InputReader::new(input_file.as_ref().to_str().map(str::to_string))?;

    // Create an output to the user-requested location.
    let output = OutputWriter::new(
        output_file.as_ref().to_str().map(str::to_string),
        true,
        OutputFormat::Text,
        output_file_mode,
        false,
    )?;

    let mut recipients: Vec<Box<dyn age::Recipient + Send>> = vec![];
    let mut plugin_recipients: Vec<age::plugin::Recipient> = vec![];

    for pubkey in public_keys {
        parse_recipient(pubkey, &mut recipients, &mut plugin_recipients)?;
    }

    merge_plugin_recipients_and_recipients(&mut recipients, &plugin_recipients)?;

    let encryptor =
        age::Encryptor::with_recipients(recipients).ok_or(eyre!("Missing recipients"))?;

    let mut output = encryptor
        .wrap_output(
            ArmoredWriter::wrap_output(output, Format::AsciiArmor)
                .wrap_err("Failed to wrap output with age::ArmoredWriter")?,
        )
        .map_err(|err| eyre!(err))?;

    io::copy(&mut input, &mut output)?;
    output.finish().and_then(ArmoredWriter::finish)?;

    Ok(())
}

/// Re-encrypt a file in memory using the given public keys.
///
/// Decrypts the file and stream-encrypts the contents into a temporary
/// file. Afterward, the temporary file replaces the file at the input path.
///
/// Plaintext is never written to persistent storage but only processed in memory.
pub(crate) fn rekey<P: AsRef<Path>>(
    file: P,
    identities: &[Box<dyn age::Identity>],
    public_keys: &[String],
) -> Result<()> {
    let mut recipients: Vec<Box<dyn age::Recipient + Send>> = vec![];
    let mut plugin_recipients: Vec<age::plugin::Recipient> = vec![];

    for pubkey in public_keys {
        parse_recipient(pubkey, &mut recipients, &mut plugin_recipients)?;
    }
    let decryptor = get_age_decryptor(&file)?;
    decryptor
        .decrypt(identities.iter().map(|i| i.as_ref() as &dyn age::Identity))
        .map_err(Into::into)
        .and_then(|mut plaintext_reader| {
            // Create a temporary file to write the re-encrypted data to
            let outfile = NamedTempFile::new()?;

            // Merge plugin recipients
            merge_plugin_recipients_and_recipients(&mut recipients, &plugin_recipients)?;

            // Create an encryptor for the (new) recipients to encrypt the file for
            let encryptor =
                age::Encryptor::with_recipients(recipients).ok_or(eyre!("Missing recipients"))?;
            let mut ciphertext_writer = encryptor
                .wrap_output(
                    ArmoredWriter::wrap_output(&outfile, Format::AsciiArmor)
                        .wrap_err("Failed to wrap output with age::ArmoredWriter")?,
                )
                .map_err(|err| eyre!(err))?;

            // Do the re-encryption
            io::copy(&mut plaintext_reader, &mut ciphertext_writer)?;
            ciphertext_writer.finish().and_then(ArmoredWriter::finish)?;

            // Re-encrpytion is done, now replace the original file
            fs::copy(outfile, file)?;

            Ok(())
        })
}
