mod cli;
mod commands;
mod crypto;
mod object;
mod session;
mod util;
mod win;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Command};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Cli {
        vault: vault_dir,
        recovery,
        password_file,
        command,
    } = cli;

    // Each command takes ownership of its args and of the optional recovery
    // key, so nothing borrowed outlives the blocking I/O it may perform.
    let result = match command {
        Command::Init(a) => commands::init::run(a, vault_dir, password_file),
        Command::Hide(a) => commands::hide::run(a, vault_dir, recovery, password_file),
        Command::List(a) => commands::list::run(a, vault_dir, recovery, password_file),
        Command::Show(a) => commands::show::run(a, vault_dir, recovery, password_file),
        Command::Release(a) => commands::release::run(a, vault_dir, recovery, password_file),
        Command::Forget(a) => commands::forget::run(a, vault_dir, recovery, password_file),
        Command::Scrub(a) => commands::scrub::run(a, vault_dir),
    };

    if let Err(e) = result {
        // anyhow's chain gives us the context we layered on at each step,
        // which is what makes a failure in a 10-step pipeline diagnosable.
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }

    Ok(())
}
