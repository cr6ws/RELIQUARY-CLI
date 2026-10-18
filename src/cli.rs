use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Personal encrypted file vault.
///
/// Hide files so they vanish from their original location, then release them
/// back when you need them. Everything inside the vault is encrypted with a
/// key derived from your master password.
#[derive(Parser, Debug)]
#[command(
    name = "vault",
    version,
    about,
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    /// Path to the vault directory. Defaults to ~/.vault
    #[arg(long, global = true, env = "VAULT_DIR")]
    pub vault: Option<PathBuf>,

    /// Unlock with the recovery key instead of the master password.
    ///
    /// Accepts the 64-character hex string printed by `vault init`.
    #[arg(long, global = true, conflicts_with = "password_file")]
    pub recovery: Option<String>,

    /// Read the master password from this file instead of prompting.
    ///
    /// Intended for scripting. The file should contain only the password, no
    /// trailing newline required. Reading from a file is inherently less safe
    /// than an interactive prompt — anything that can read the file can read
    /// the password — so prefer the prompt for interactive use.
    #[arg(long, global = true, env = "VAULT_PASSWORD_FILE")]
    pub password_file: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a new vault and set the master password.
    Init(InitArgs),

    /// Encrypt files and move them into the vault.
    Hide(HideArgs),

    /// List everything currently in the vault.
    List(ListArgs),

    /// Show full metadata for one vault entry.
    Show(ShowArgs),

    /// Decrypt an entry and return it to its original location.
    Release(ReleaseArgs),

    /// Permanently destroy an entry without restoring it.
    Forget(ForgetArgs),

    /// Best-effort cleanup of Windows traces left behind by hidden files.
    Scrub(ScrubArgs),
}

#[derive(clap::Args, Debug)]
pub struct InitArgs {
    /// Print the recovery key as machine-readable hex instead of a phrase.
    #[arg(long)]
    pub raw: bool,
}

#[derive(clap::Args, Debug)]
pub struct HideArgs {
    /// Files or directories to hide. Directories are walked recursively.
    #[arg(required = true, value_name = "PATH")]
    pub paths: Vec<PathBuf>,

    /// Keep the original file instead of moving it into the vault.
    ///
    /// Use this when you want a copy hidden rather than the original removed.
    #[arg(long)]
    pub copy: bool,
}

#[derive(clap::Args, Debug)]
pub struct ListArgs {
    /// Show original paths instead of just names.
    #[arg(long)]
    pub paths: bool,

    /// Emit one entry per line with a fixed delimiter, for scripting.
    #[arg(long)]
    pub plain: bool,
}

#[derive(clap::Args, Debug)]
pub struct ShowArgs {
    /// Entry ID (a `vault list` ID, or any unambiguous prefix).
    pub id: String,
}

#[derive(clap::Args, Debug)]
pub struct ReleaseArgs {
    /// Entry ID to release.
    pub id: String,

    /// Restore to this path instead of the original location.
    #[arg(long, short = 't')]
    pub to: Option<PathBuf>,

    /// Overwrite the destination if it already exists.
    #[arg(long)]
    pub force: bool,

    /// Keep the encrypted copy in the vault after restoring.
    #[arg(long)]
    pub keep: bool,
}

#[derive(clap::Args, Debug)]
pub struct ForgetArgs {
    /// Entry ID to destroy.
    pub id: String,

    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

#[derive(clap::Args, Debug)]
pub struct ScrubArgs {
    /// Also purge Explorer thumbnail caches.
    #[arg(long)]
    pub previews: bool,

    /// Also purge Recent Documents entries.
    #[arg(long)]
    pub recent: bool,

    /// Run without confirmation prompts.
    #[arg(long)]
    pub yes: bool,
}
