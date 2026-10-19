//! The interactive menu — the face of `vault` when it is run with no
//! subcommand.
//!
//! Design note: this is a *panel*, not a list. The wordmark is a chiselled
//! brass plate and the selected row is a struck gold bar, because the thing
//! being operated is a door. Colour is truecolor throughout, but every paint
//! call degrades to plain text when the console cannot render escapes, so the
//! menu stays usable rather than becoming a wall of `ESC[38;2;...m`.
//!
//! Every line is padded to exactly [`LINE_W`] visible characters. That is what
//! makes repaints safe: each frame is emitted from the home position as one
//! buffered write, so a shorter line always overwrites a longer one and rows
//! never drift between frames.

use std::path::PathBuf;

use anyhow::Result;
use zeroize::Zeroizing;

use crate::cli::{ForgetArgs, HideArgs, InitArgs, ListArgs, ReleaseArgs, ScrubArgs, ShowArgs};
use crate::commands;
use crate::crypto::vault::VaultDir;
use crate::session::{Credential, AUTH_FAILED};
use crate::util;
use crate::win::console::{self, Console, Key, Rgb};

// ── palette ─────────────────────────────────────────────────────────────
//
// Warm brass against a cold ink ground. Nothing here is a web-framework
// default; the gradients below are hand-tuned to read as metal rather than
// as a sunset.

const BRASS: [Rgb; 6] = [
    (255, 237, 190), // highlight edge
    (250, 214, 138),
    (243, 186, 84), // the working gold
    (228, 157, 60),
    (205, 127, 44),
    (174, 99, 33), // shadow edge
];

const GOLD: Rgb = (243, 186, 84);
const INK_ON_GOLD: Rgb = (17, 15, 10);
const CREAM: Rgb = (233, 227, 214);
const STEEL: Rgb = (124, 135, 151);
const DIM: Rgb = (84, 93, 107);
const CRIMSON: Rgb = (229, 72, 77);

/// Width of the panel interior. The banner is 44 columns and centres in it.
const INNER_W: usize = 56;
/// Total width of every line the menu draws, including menu borders.
const LINE_W: usize = INNER_W + 2;

const SUBTITLE: &str = "── E N C R Y P T E D   F I L E   V A U L T ──";
// `⏎` (U+23CE) lives in Miscellaneous Technical, which Consolas does not
// cover — it would land as a tofu box on the default conhost font. `Enter`
// reads better anyway.
const HINTS: &str = "   ↑↓ move   Enter run   1-8 jump   q quit";

// ── the wordmark ────────────────────────────────────────────────────────
//
// Eight columns per letter, six rows tall, joined by a single space: 44
// columns total. Built from letters rather than pasted as one block so the
// row count and the gradient are guaranteed to agree.

const LETTER_V: [&str; 6] = [
    "██    ██",
    "██    ██",
    " ██  ██ ",
    "  ████  ",
    "   ██   ",
    "   ██   ",
];
const LETTER_A: [&str; 6] = [
    "   ██   ",
    "  ████  ",
    " ██  ██ ",
    "████████",
    "██    ██",
    "██    ██",
];
const LETTER_U: [&str; 6] = [
    "██    ██",
    "██    ██",
    "██    ██",
    "██    ██",
    " ██  ██ ",
    "  ████  ",
];
const LETTER_L: [&str; 6] = [
    "██      ",
    "██      ",
    "██      ",
    "██      ",
    "██      ",
    "████████",
];
const LETTER_T: [&str; 6] = [
    "████████",
    "   ██   ",
    "   ██   ",
    "   ██   ",
    "   ██   ",
    "   ██   ",
];

fn banner() -> [String; 6] {
    std::array::from_fn(|row| {
        [LETTER_V, LETTER_A, LETTER_U, LETTER_L, LETTER_T]
            .map(|letter| letter[row])
            .join(" ")
    })
}

// ── the command list ────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Hide,
    List,
    Show,
    Release,
    Forget,
    Scrub,
    Init,
    Quit,
}

struct Item {
    action: Action,
    key: char,
    label: &'static str,
    desc: &'static str,
    /// Gated on a vault existing. `init` obviously is not, and `scrub` deals
    /// with Windows traces outside the vault, so it is not either.
    needs_vault: bool,
}

const ITEMS: [Item; 8] = [
    Item {
        action: Action::Hide,
        key: '1',
        label: "HIDE",
        desc: "encrypt files and move them in",
        needs_vault: true,
    },
    Item {
        action: Action::List,
        key: '2',
        label: "LIST",
        desc: "show everything in the vault",
        needs_vault: true,
    },
    Item {
        action: Action::Show,
        key: '3',
        label: "SHOW",
        desc: "inspect one entry's metadata",
        needs_vault: true,
    },
    Item {
        action: Action::Release,
        key: '4',
        label: "RELEASE",
        desc: "return a file to its original path",
        needs_vault: true,
    },
    Item {
        action: Action::Forget,
        key: '5',
        label: "FORGET",
        desc: "destroy an entry, no restoring",
        needs_vault: true,
    },
    Item {
        action: Action::Scrub,
        key: '6',
        label: "SCRUB",
        desc: "purge Windows traces and thumbnails",
        needs_vault: false,
    },
    Item {
        action: Action::Init,
        key: '7',
        label: "INIT",
        desc: "create a new vault",
        needs_vault: false,
    },
    Item {
        action: Action::Quit,
        key: '8',
        label: "QUIT",
        desc: "leave (the password is wiped)",
        needs_vault: false,
    },
];

// ── layout helpers ──────────────────────────────────────────────────────

/// Pad or cut `text` to exactly `width` visible characters.
fn fit(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        text.chars().take(width).collect()
    } else {
        let mut out = text.to_string();
        out.push_str(&" ".repeat(width - len));
        out
    }
}

/// Like [`fit`], but when it has to cut it keeps the tail — a path is more
/// recognisable by its last few components than by its first.
fn fit_left(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len <= width {
        return fit(text, width);
    }
    let mut out = String::from("…");
    out.extend(text.chars().skip(len - width + 1));
    out
}

fn centered(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        return fit(text, width);
    }
    let left = (width - len) / 2;
    format!(
        "{}{}{}",
        " ".repeat(left),
        text,
        " ".repeat(width - len - left)
    )
}

// ── session state ───────────────────────────────────────────────────────

struct State {
    vault_dir: Option<PathBuf>,
    base: Credential,
    /// The password, once obtained. Held so a session of arrow-key selections
    /// costs one prompt instead of one per command; `Zeroizing` wipes it when
    /// the menu exits.
    cached: Option<Zeroizing<String>>,
}

impl State {
    fn vault_exists(&self) -> bool {
        VaultDir::resolve(self.vault_dir.clone())
            .map(|dir| dir.exists())
            .unwrap_or(false)
    }

    /// Count `.enc` objects without unlocking — listing the directory needs no
    /// key, which is what lets the status line stay live.
    fn entry_count(&self) -> Option<usize> {
        let dir = VaultDir::resolve(self.vault_dir.clone()).ok()?;
        if !dir.exists() {
            return None;
        }
        let read = std::fs::read_dir(dir.objects_dir()).ok()?;
        Some(
            read.filter_map(|entry| entry.ok())
                .filter(|entry| {
                    entry.path().extension().and_then(|ext| ext.to_str()) == Some("enc")
                })
                .count(),
        )
    }

    /// Indices of the rows the cursor may rest on right now.
    fn selectable(&self) -> Vec<usize> {
        let vault = self.vault_exists();
        ITEMS
            .iter()
            .enumerate()
            .filter(|(_, item)| !item.needs_vault || vault)
            .map(|(index, _)| index)
            .collect()
    }

    /// The credential a normal vault command should run with.
    fn credential(&self) -> Credential {
        match &self.base {
            Credential::Prompt => match &self.cached {
                Some(password) => Credential::Password(password.clone()),
                None => Credential::Prompt,
            },
            other => other.clone(),
        }
    }

    /// The credential `init` should run with: always the one the user asked
    /// for on the command line, never a cached password from an earlier
    /// command, because init sets a *new* password that must be typed twice.
    fn fresh_credential(&self) -> Credential {
        self.base.clone()
    }

    /// Obtain a password before a command that needs one, caching it so the
    /// next selection does not ask again.
    fn prepare(&mut self) -> Result<()> {
        if !self.base.needs_prompt() || self.cached.is_some() {
            return Ok(());
        }
        match util::prompt_password() {
            Ok(password) => {
                self.cached = Some(password);
                Ok(())
            }
            Err(e) => Err(e.context("could not read the vault password")),
        }
    }

    /// Throw the cached password away if it just failed to open the vault, so
    /// the next selection prompts instead of repeating the same failure.
    fn invalidate_if_stale(&mut self, message: &str) {
        if message.contains(AUTH_FAILED) {
            self.cached = None;
        }
    }
}

// ── drawing ─────────────────────────────────────────────────────────────

fn frame(inner: &str) -> String {
    format!("│{inner}│")
}

fn title_line(inner: &str) -> String {
    format!(" {inner} ")
}

fn item_line(con: &Console, item: &Item, selected: bool, enabled: bool) -> String {
    // 3 gutter + marker + space, then 1 digit + 2, then 8 label + 1 = 17,
    // leaving INNER_W - 17 = 39 for the description.
    //
    // Widths are measured in chars, not bytes: the `▸` marker is three bytes
    // of UTF-8, and deriving the remaining space from `.len()` makes exactly
    // the selected row two columns short of its neighbours — which is enough
    // to shift every frame line under it.
    let head = format!("   {} ", if selected { "▸" } else { " " });
    let num = format!("{}  ", item.key);
    let label = format!("{:<8} ", item.label);
    let desc = fit(
        item.desc,
        INNER_W - head.chars().count() - num.chars().count() - label.chars().count(),
    );

    let inner = if selected {
        con.paint(INK_ON_GOLD, GOLD, &format!("{head}{num}{label}{desc}"))
    } else if !enabled {
        con.fg(DIM, &format!("{head}{num}{label}{desc}"))
    } else {
        format!(
            "{}{}{}{}",
            con.fg(DIM, &head),
            con.fg(DIM, &num),
            con.fg(CREAM, &label),
            con.fg(DIM, &desc),
        )
    };
    frame(&inner)
}

fn status_line(state: &State) -> String {
    let root = VaultDir::resolve(state.vault_dir.clone())
        .map(|dir| dir.root.display().to_string())
        .unwrap_or_else(|_| "(invalid vault path)".to_string());

    match state.entry_count() {
        Some(n) => {
            let unit = if n == 1 { "entry" } else { "entries" };
            format!("   vault  {root}   ·   {n} {unit}")
        }
        None => format!("   vault  {root}   ·   no vault yet"),
    }
}

/// Build one complete frame. Every returned string is exactly [`LINE_W`]
/// visible characters wide.
fn render(con: &Console, state: &State, slot: usize) -> Vec<String> {
    let selectable = state.selectable();
    let vault = state.vault_exists();
    let mut lines = Vec::with_capacity(22);

    lines.push(" ".repeat(LINE_W));

    for (row, text) in banner().into_iter().enumerate() {
        // 6 + 44 + 6 centres the wordmark in the 56-column interior.
        let padded = format!("      {text}      ");
        lines.push(title_line(&con.fg(BRASS[row], &fit(&padded, INNER_W))));
    }

    lines.push(title_line(&con.fg(STEEL, &centered(SUBTITLE, INNER_W))));
    lines.push(" ".repeat(LINE_W));
    lines.push(format!("╭{}╮", "─".repeat(INNER_W)));

    for (index, item) in ITEMS.iter().enumerate() {
        let selected = selectable.get(slot).copied() == Some(index);
        let enabled = !item.needs_vault || vault;
        lines.push(item_line(con, item, selected, enabled));
    }

    lines.push(format!("╰{}╯", "─".repeat(INNER_W)));
    lines.push(" ".repeat(LINE_W));
    lines.push(con.fg(DIM, &fit(HINTS, LINE_W)));
    lines.push(con.fg(STEEL, &fit_left(&status_line(state), LINE_W)));
    lines
}

/// Query the real terminal size and return the 1-based `(col, row)` cursor
/// position that places the top-left corner of the panel in the centre of the
/// screen. Falls back to `(1, 1)` when the size cannot be determined (e.g.
/// during unit tests or on a headless console where `Console::size()` returns
/// `None`).
///
/// The panel is `LINE_W` columns wide and `frame_height` rows tall. Offsets
/// are clamped to 1 so the panel never tries to start before the first column
/// or before the first row.
fn center_offsets(con: &Console, frame_height: usize) -> (usize, usize) {
    match con.size() {
        Some((term_cols, term_rows)) => {
            let col = ((term_cols as usize).saturating_sub(LINE_W) / 2 + 1).max(1);
            let row = ((term_rows as usize).saturating_sub(frame_height) / 2 + 1).max(1);
            (col, row)
        }
        None => (1, 1),
    }
}

/// Emit a frame as a single write so the screen updates in one operation
/// rather than flickering line by line.
fn paint(con: &Console, lines: &[String], wipe: bool) {
    let mut buf = String::new();
    if con.color() {
        if wipe {
            buf.push_str("\x1b[2J");
        }
        let (col, row) = center_offsets(con, lines.len());
        for (i, line) in lines.iter().enumerate() {
            // Move to the exact position for each line, then erase to end-of-line
            // so leftover characters from a wider previous frame cannot bleed.
            buf.push_str(&format!("\x1b[{};{}H", row + i, col));
            buf.push_str(line);
            buf.push_str("\x1b[K");
        }
        // Erase everything below the last panel row.
        buf.push_str(&format!("\x1b[{};{}H", row + lines.len(), 1));
        buf.push_str("\x1b[J");
    } else {
        if wipe {
            // Without escapes there is no home position, so a stale frame cannot
            // be overwritten in place and has to be scrolled away instead.
            buf.push_str(&"\n".repeat(40));
        }
        for line in lines {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    con.write(&buf);
}

/// First frame: the wordmark strikes itself onto the screen one row at a time,
/// then the rest of the panel lands at once. Runs exactly once per session.
fn reveal(con: &Console, lines: &[String]) {
    con.clear();
    let (col, row) = center_offsets(con, lines.len());
    for (index, line) in lines.iter().enumerate() {
        if con.color() {
            con.write(&format!("\x1b[{};{}H", row + index, col));
        }
        con.write(line);
        if con.color() {
            con.write("\x1b[K");
        }
        con.write("\n");
        if (1..=6).contains(&index) {
            std::thread::sleep(std::time::Duration::from_millis(45));
        }
    }
    if con.color() {
        con.write(&format!("\x1b[{};{}H", row + lines.len(), 1));
        con.write("\x1b[J");
    }
}

// ── command dispatch ────────────────────────────────────────────────────

fn ask(prompt: &str) -> String {
    print!("  {prompt}: ");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return String::new();
    }
    line.trim().to_string()
}

/// Print the listing, then ask which entry to act on.
///
/// This costs a second unlock — the listing is its own command — and it is
/// worth it: without it the user would have to leave the menu, run `list`,
/// memorise an ID and come back. A blank answer cancels.
fn pick_id(state: &State) -> Result<Option<String>> {
    let cred = state.credential();
    commands::list::run(
        ListArgs {
            paths: true,
            plain: false,
        },
        state.vault_dir.clone(),
        &cred,
    )?;

    println!();
    let id = ask("entry ID");
    Ok(if id.is_empty() { None } else { Some(id) })
}

fn header(con: &Console, item: &Item) {
    println!(
        " {}  {}",
        con.fg(GOLD, item.label),
        con.fg(STEEL, item.desc)
    );
    println!(
        "  {}",
        con.fg(
            DIM,
            &"─".repeat(LINE_W.saturating_sub(item.label.len() + 4))
        )
    );
    println!();
}

/// Gather whatever the chosen command needs, then run it.
fn execute(state: &mut State, item: &Item) -> Result<()> {
    if item.needs_vault {
        state.prepare()?;
    }
    let dir = state.vault_dir.clone();

    match item.action {
        // Handled by the caller — reaching it would mean the loop failed to
        // break out on QUIT.
        Action::Quit => Ok(()),

        Action::Init => {
            commands::init::run(InitArgs { raw: false }, dir, &state.fresh_credential())
        }

        Action::List => commands::list::run(
            ListArgs {
                paths: true,
                plain: false,
            },
            dir,
            &state.credential(),
        ),

        Action::Hide => {
            let line = ask("path(s) to hide, separated by ;");
            let paths: Vec<PathBuf> = line
                .split(';')
                .map(util::clean_path)
                .filter(|path| !path.as_os_str().is_empty())
                .collect();
            if paths.is_empty() {
                println!("cancelled");
                return Ok(());
            }
            let copy = util::confirm("keep the original file as a copy")?;
            commands::hide::run(HideArgs { paths, copy }, dir, &state.credential())
        }

        Action::Show => {
            let Some(id) = pick_id(state)? else {
                println!("cancelled");
                return Ok(());
            };
            commands::show::run(ShowArgs { id }, dir, &state.credential())
        }

        Action::Release => {
            let Some(id) = pick_id(state)? else {
                println!("cancelled");
                return Ok(());
            };
            let to = ask("restore to (blank = original location)");
            let to = if to.trim().is_empty() {
                None
            } else {
                Some(util::clean_path(&to))
            };
            let force = util::confirm("overwrite the destination if it exists")?;
            let keep = util::confirm("keep the encrypted copy in the vault")?;
            commands::release::run(
                ReleaseArgs {
                    id,
                    to,
                    force,
                    keep,
                },
                dir,
                &state.credential(),
            )
        }

        Action::Forget => {
            let Some(id) = pick_id(state)? else {
                println!("cancelled");
                return Ok(());
            };
            // The command asks for final confirmation itself.
            commands::forget::run(ForgetArgs { id, yes: false }, dir, &state.credential())
        }

        Action::Scrub => {
            let previews = util::confirm("purge Explorer thumbnail caches")?;
            let recent = util::confirm("purge Recent Documents and Prefetch")?;
            if !previews && !recent {
                println!("nothing selected");
                return Ok(());
            }
            commands::scrub::run(
                ScrubArgs {
                    previews,
                    recent,
                    yes: false,
                },
                dir,
            )
        }
    }
}

/// Run one command below the panel, then hold for a keypress and repaint.
fn run_action(con: &Console, state: &mut State, item: &Item) {
    con.show_cursor();
    con.clear();
    header(con, item);

    match execute(state, item) {
        Ok(()) => {}
        Err(e) => {
            let message = format!("{e:#}");
            state.invalidate_if_stale(&message);
            println!();
            eprintln!("  {} {message}", con.fg(CRIMSON, "error:"));
        }
    }

    println!();
    println!("  {}", con.fg(DIM, "press any key to return to the menu"));
    let _ = con.read_key();
    con.hide_cursor();
    con.clear();
}

// ── the loop ────────────────────────────────────────────────────────────

/// Is stdin/stdout a console a menu can be driven from?
///
/// Re-exported so `main` does not have to reach past this module into the
/// Win32 layer.
pub fn interactive() -> bool {
    console::interactive()
}

/// Draw the panel and loop until the user quits. Only ever reached when both
/// ends are a real terminal — `main` sends pipes and scheduled tasks to
/// `--help` instead.
pub fn run(vault_dir: Option<PathBuf>, base: Credential) -> Result<()> {
    let con = Console::new();
    let mut state = State {
        vault_dir,
        base,
        cached: None,
    };
    let mut slot = 0usize;
    let mut opening = true;

    con.hide_cursor();

    loop {
        let selectable = state.selectable();
        if selectable.is_empty() {
            break;
        }
        slot = slot.min(selectable.len() - 1);

        let frame_lines = render(&con, &state, slot);
        if opening {
            reveal(&con, &frame_lines);
            opening = false;
        } else {
            paint(&con, &frame_lines, false);
        }

        match con.read_key()? {
            Key::Esc | Key::Char('q') | Key::Char('Q') => break,
            Key::Char(' ') | Key::Enter => {
                let index = match selectable.get(slot) {
                    Some(i) => *i,
                    None => break,
                };
                match ITEMS[index].action {
                    Action::Quit => break,
                    _ => run_action(&con, &mut state, &ITEMS[index]),
                }
            }
            Key::Up | Key::Char('k') => slot = slot.saturating_sub(1),
            Key::Down | Key::Char('j') => slot = (slot + 1) % selectable.len(),
            Key::Home | Key::PageUp => slot = 0,
            Key::End | Key::PageDown => slot = selectable.len() - 1,
            // Digits jump the cursor without running anything — one keypress
            // straight into FORGET would be a trap.
            Key::Char(c) if c.is_ascii_digit() => {
                if let Some(found) = selectable.iter().position(|&i| ITEMS[i].key == c) {
                    slot = found;
                }
            }
            _ => {}
        }
    }

    // Nothing is held past here: `state` goes out of scope with the cached
    // password in it and `Zeroizing` wipes it, while `con` restores the
    // cursor and colour state on drop.
    con.show_cursor();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Width in *visible* characters: CSI sequences such as `ESC[38;2;1;2;3m`
    /// carry no width, and a frame whose rows disagree by even one column
    /// will tear the moment two different rows are painted in sequence.
    fn visible_width(line: &str) -> usize {
        let mut width = 0;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                // ESC, then a CSI intro byte, then the parameter run.
                if chars.peek() == Some(&'[') {
                    chars.next();
                    while let Some(&next) = chars.peek() {
                        chars.next();
                        if ('\x40'..='\x7e').contains(&next) {
                            break;
                        }
                    }
                }
                continue;
            }
            width += 1;
        }
        width
    }

    fn state() -> State {
        State {
            vault_dir: None,
            base: Credential::Prompt,
            cached: None,
        }
    }

    fn frame_for(slot: usize) -> Vec<String> {
        render(&Console::new(), &state(), slot)
    }

    #[test]
    fn every_row_of_every_frame_is_exactly_line_w_wide() {
        for slot in 0..ITEMS.len() {
            for (index, line) in frame_for(slot).iter().enumerate() {
                assert_eq!(
                    visible_width(line),
                    LINE_W,
                    "frame line {index} with selection slot {slot}"
                );
            }
        }
    }

    #[test]
    fn the_frame_is_twenty_two_rows() {
        assert_eq!(frame_for(0).len(), 22);
    }

    /// The marked row must be `10 + selectable[slot]` — this pins both the
    /// layout index of the command block and the mapping from cursor slot to
    /// item, so a row drifting by one cannot go unnoticed.
    #[test]
    fn the_selection_marks_the_row_its_slot_names() {
        let con = Console::new();
        let state = state();
        let selectable = state.selectable();

        for slot in 0..selectable.len() {
            let lines = render(&con, &state, slot);
            let marked = lines
                .iter()
                .enumerate()
                .filter(|(_, line)| line.contains('▸'))
                .map(|(index, _)| index)
                .collect::<Vec<_>>();

            assert_eq!(
                marked,
                vec![10 + selectable[slot]],
                "cursor slot {slot} of {selectable:?}"
            );
        }
    }

    #[test]
    fn the_wordmark_is_five_letters_six_rows_and_44_columns() {
        let rows = banner();
        assert_eq!(rows.len(), 6);
        for (index, row) in rows.iter().enumerate() {
            assert_eq!(row.chars().count(), 44, "banner row {index} of {row:?}");
        }
    }

    /// Renders a frame verbatim so the layout can be read by eye under
    /// `cargo test menu -- --nocapture`.
    #[test]
    fn print_a_frame() {
        let lines = frame_for(0);
        for line in lines {
            println!("{line}");
        }
    }
}
