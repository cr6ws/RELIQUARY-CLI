use anyhow::{Context, Result};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{self, Clear, ClearType},
};
use std::io::{self, Write};
use std::path::PathBuf;

use crate::cli::{
    Command, ForgetArgs, HideArgs, InitArgs, ListArgs, ReleaseArgs, ScrubArgs, ShowArgs,
};
use crate::crypto::vault::VaultDir;

const ITEMS: [&str; 7] = [
    "Initialize reliquary",
    "Hide files",
    "List reliquary",
    "Show entry",
    "Release entry",
    "Forget entry",
    "Scrub traces",
];

pub fn run(
    vault_dir: Option<PathBuf>,
    recovery: Option<String>,
    password_file: Option<PathBuf>,
) -> Result<()> {
    let vault_exists = VaultDir::resolve(vault_dir.clone())?.exists();
    let mut selected = if vault_exists { 2 } else { 0 };
    terminal::enable_raw_mode()?;
    loop {
        draw(selected, vault_exists)?;
        if let Event::Key(key) = event::read().context("could not read keyboard input")? {
            match key.code {
                KeyCode::Up => selected = selected.checked_sub(1).unwrap_or(ITEMS.len() - 1),
                KeyCode::Down => selected = (selected + 1) % ITEMS.len(),
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Enter => {
                    terminal::disable_raw_mode()?;
                    execute!(io::stdout(), cursor::Show)?;
                    let result = dispatch(
                        selected,
                        vault_exists,
                        vault_dir.clone(),
                        recovery.clone(),
                        password_file.clone(),
                    );
                    if let Err(error) = result {
                        eprintln!("\nerror: {error:#}");
                    }
                    pause()?;
                    terminal::enable_raw_mode()?;
                }
                _ => {}
            }
        }
    }

    terminal::disable_raw_mode()?;
    execute!(io::stdout(), cursor::Show, ResetColor)?;
    println!();
    Ok(())
}

fn draw(selected: usize, vault_exists: bool) -> Result<()> {
    let mut out = io::stdout();
    execute!(
        out,
        cursor::Hide,
        Clear(ClearType::All),
        cursor::MoveTo(0, 0),
        SetForegroundColor(Color::Cyan),
        Print(
            r#"
██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
██║   ██║███████║██║   ██║██║     ██║
╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║
 ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║
  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝
"#
        ),
        SetForegroundColor(Color::DarkGrey),
        Print("\n  encrypted file reliquary  /  interactive console\n\n"),
        SetForegroundColor(Color::White)
    )?;

    for (index, item) in ITEMS.iter().enumerate() {
        let label = if index == 0 && vault_exists {
            "Initialize reliquary (already exists)"
        } else {
            item
        };
        if index == selected {
            execute!(
                out,
                SetForegroundColor(Color::Black),
                crossterm::style::SetBackgroundColor(Color::Cyan),
                Print(format!("  > {label:<32} ")),
                ResetColor,
                Print("\n")
            )?;
        } else {
            execute!(
                out,
                SetForegroundColor(Color::DarkGrey),
                Print(format!("    {label}\n"))
            )?;
        }
    }

    execute!(
        out,
        SetForegroundColor(Color::DarkGrey),
        Print("\n  ↑/↓ navigate   enter select   q quit\n"),
        ResetColor
    )?;
    out.flush()?;
    Ok(())
}

fn dispatch(
    selected: usize,
    vault_exists: bool,
    vault_dir: Option<PathBuf>,
    recovery: Option<String>,
    password_file: Option<PathBuf>,
) -> Result<()> {
    if selected == 0 && vault_exists {
        println!("\n  A reliquary already exists. Choose another operation.");
        return Ok(());
    }

    let command = match selected {
        0 => Command::Init(InitArgs { raw: false }),
        1 => Command::Hide(HideArgs {
            paths: vec![PathBuf::from(prompt("File or directory path")?)],
            copy: false,
        }),
        2 => Command::List(ListArgs {
            paths: true,
            plain: false,
        }),
        3 => Command::Show(ShowArgs {
            id: prompt("Entry ID or prefix")?,
        }),
        4 => Command::Release(ReleaseArgs {
            id: prompt("Entry ID or prefix")?,
            to: None,
            force: false,
            keep: false,
        }),
        5 => Command::Forget(ForgetArgs {
            id: prompt("Entry ID or prefix")?,
            yes: false,
        }),
        6 => Command::Scrub(ScrubArgs {
            previews: true,
            recent: true,
            yes: false,
        }),
        _ => unreachable!(),
    };

    crate::run_command(command, vault_dir, recovery, password_file)
}

fn prompt(label: &str) -> Result<String> {
    print!("\n  {label}: ");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_string())
}

fn pause() -> Result<()> {
    print!("\n  press enter to return to the menu...");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(())
}
