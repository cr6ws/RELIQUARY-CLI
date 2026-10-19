pub mod archive;
mod cli;
mod commands;
mod crypto;
mod menu;
mod object;
mod session;
mod util;
mod win;

use std::path::PathBuf;

use anyhow::Result;
use clap::{CommandFactory, Parser};

use cli::{Cli, Command};
use session::Credential;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Cli {
        vault: vault_dir,
        recovery,
        password_file,
        command,
    } = cli;

    let cred = Credential::new(recovery, password_file);

    // The menu takes ownership of the credential so one unlock can serve a
    // whole session of arrow-key selections; every other path only borrows it
    // for the length of a single command, exactly as before.
    let result = match command {
        None | Some(Command::Menu) => menu_or_help(vault_dir, cred),
        Some(Command::Init(a)) => commands::init::run(a, vault_dir, &cred),
        Some(Command::Hide(a)) => commands::hide::run(a, vault_dir, &cred),
        Some(Command::List(a)) => commands::list::run(a, vault_dir, &cred),
        Some(Command::Show(a)) => commands::show::run(a, vault_dir, &cred),
        Some(Command::Release(a)) => commands::release::run(a, vault_dir, &cred),
        Some(Command::Forget(a)) => commands::forget::run(a, vault_dir, &cred),
        Some(Command::Scrub(a)) => commands::scrub::run(a, vault_dir),
    };

    if let Err(e) = result {
        // anyhow's chain gives us the context we layered on at each step,
        // which is what makes a failure in a 10-step pipeline diagnosable.
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }

    Ok(())
}

/// Launch the menu, or explain why we cannot.
///
/// A pipe, a scheduled task and a CI runner all reach this branch with no way
/// to answer a keypress. Pointing them at `--help` beats blocking forever on
/// input that is never coming.
fn menu_or_help(vault_dir: Option<PathBuf>, cred: Credential) -> Result<()> {
    if menu::interactive() {
        return menu::run(vault_dir, cred);
    }

    eprintln!("error: no command given, and stdin is not an interactive terminal");
    eprintln!();
    let _ = Cli::command().print_help();
    std::process::exit(2);
}

pub fn run_command(
    command: Command,
    vault_dir: Option<PathBuf>,
    recovery: Option<String>,
    password_file: Option<PathBuf>,
) -> Result<()> {
    let cred = Credential::new(recovery, password_file);
    match command {
        Command::Menu => menu_or_help(vault_dir, cred),
        Command::Init(a) => commands::init::run(a, vault_dir, &cred),
        Command::Hide(a) => commands::hide::run(a, vault_dir, &cred),
        Command::List(a) => commands::list::run(a, vault_dir, &cred),
        Command::Show(a) => commands::show::run(a, vault_dir, &cred),
        Command::Release(a) => commands::release::run(a, vault_dir, &cred),
        Command::Forget(a) => commands::forget::run(a, vault_dir, &cred),
        Command::Scrub(a) => commands::scrub::run(a, vault_dir),
    }
}
