//! Windows console plumbing for the interactive menu.
//!
//! Hand-rolled against `kernel32` instead of pulling in `crossterm`, for the
//! same reason `secure_delete` is hand-rolled: on a security tool one fewer
//! dependency is one fewer supply-chain surface, and the surface this feature
//! needs is five functions and one input record.
//!
//! Three things here are easy to get wrong, and they are why this file exists:
//!
//! * Windows only understands ANSI escapes after
//!   `ENABLE_VIRTUAL_TERMINAL_PROCESSING` is set on the output handle. It is
//!   off by default in conhost, where colours would otherwise print as raw
//!   `ESC[38;2;...m` garbage.
//! * Raw mode is scoped to a single `read_key` call rather than held for the
//!   life of the menu. It enters on the way in and leaves on the way out, so a
//!   command can never run — or be left running after a panic — with line
//!   input and echo switched off: both `rpassword` and `stdin().read_line`
//!   would misbehave there. Ctrl+C can still strand the console in raw mode,
//!   which is what the Ctrl handler below is for; a shell that has lost echo
//!   and line editing is the single most annoying failure a console program
//!   can cause.
//! * The cursor *is* hidden during repaints, and that state does outlive the
//!   process — so a Ctrl handler puts it back before the default handler
//!   terminates us. `SetConsoleCtrlHandler` runs on a thread Windows creates
//!   for it, hence the raw `WriteFile` rather than `std::io::stdout`, which
//!   could deadlock against a lock held by the thread being torn down.

use anyhow::Result;
use std::ffi::c_void;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

/// 24-bit colour. Windows Terminal and conhost on Windows 10+ take truecolor
/// directly, so there is no palette juggling to do.
pub type Rgb = (u8, u8, u8);

const STD_INPUT_HANDLE: u32 = (-10i32) as u32;
const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32;

const ENABLE_PROCESSED_OUTPUT: u32 = 0x0001;
const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

const KEY_EVENT: u16 = 0x0001;

const VK_RETURN: u16 = 0x0D;
const VK_ESCAPE: u16 = 0x1B;
const VK_PRIOR: u16 = 0x21;
const VK_NEXT: u16 = 0x22;
const VK_END: u16 = 0x23;
const VK_HOME: u16 = 0x24;
const VK_UP: u16 = 0x26;
const VK_DOWN: u16 = 0x28;

/// Win32 `KEY_EVENT_RECORD`.
///
/// Laid out by hand rather than via a bindings crate; the assertions below
/// fail the build if the offsets ever drift, because decoding a key event at
/// the wrong offset would silently turn garbage into keystrokes.
#[repr(C)]
#[derive(Clone, Copy)]
struct KeyEventRecord {
    key_down: i32,
    repeat_count: u16,
    virtual_key_code: u16,
    virtual_scan_code: u16,
    unicode_char: u16,
    control_key_state: u32,
}

/// Win32 `INPUT_RECORD`: a `WORD` tag, 2 bytes of alignment padding, then a
/// 16-byte union. Only the key arm is ever read.
#[repr(C)]
#[derive(Clone, Copy)]
struct InputRecord {
    event_type: u16,
    _pad: u16,
    key: KeyEventRecord,
}

const _: () = assert!(std::mem::size_of::<KeyEventRecord>() == 16);
const _: () = assert!(std::mem::size_of::<InputRecord>() == 20);

#[allow(non_snake_case)]
#[link(name = "kernel32")]
extern "system" {
    fn GetStdHandle(std_handle: u32) -> isize;
    fn GetConsoleMode(console: isize, mode: *mut u32) -> i32;
    fn SetConsoleMode(console: isize, mode: u32) -> i32;
    fn ReadConsoleInputW(
        console: isize,
        record: *mut InputRecord,
        length: u32,
        read: *mut u32,
    ) -> i32;
    fn SetConsoleCtrlHandler(handler: Option<extern "system" fn(u32) -> i32>, add: i32) -> i32;
    fn WriteFile(
        file: isize,
        buf: *const u8,
        len: u32,
        written: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn GetConsoleScreenBufferInfo(console: isize, info: *mut ConsoleScreenBufferInfo) -> i32;
}

/// Win32 `COORD`: a column/row pair.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Coord {
    x: i16,
    y: i16,
}

/// Win32 `SMALL_RECT`: the visible window region within the screen buffer.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SmallRect {
    left: i16,
    top: i16,
    right: i16,
    bottom: i16,
}

/// Win32 `CONSOLE_SCREEN_BUFFER_INFO`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ConsoleScreenBufferInfo {
    size: Coord,
    cursor_position: Coord,
    attributes: u16,
    window: SmallRect,
    maximum_window_size: Coord,
}

/// A keypress the menu cares about. Everything else is dropped on the floor —
/// the menu has no text entry of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Home,
    End,
    PageUp,
    PageDown,
    Enter,
    Esc,
    Char(char),
    Other,
}

// Shared with the Ctrl handler, which lives on a thread Windows creates for
// it and therefore cannot borrow `&Console`.
static OUTPUT_HANDLE: AtomicIsize = AtomicIsize::new(0);
static VT_ENABLED: AtomicBool = AtomicBool::new(false);
static CURSOR_HIDDEN: AtomicBool = AtomicBool::new(false);

/// True when both ends are a real console, i.e. a menu can be driven at all.
///
/// `vault` invoked from a pipe or a scheduled task gets pointed back at the
/// plain CLI instead of blocking forever on a keypress nobody will send.
pub fn interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

pub struct Console {
    input: isize,
    color: bool,
}

impl Console {
    /// Claim the console for the menu: turn on ANSI processing and arm the
    /// Ctrl handler that undoes whatever we changed.
    pub fn new() -> Self {
        unsafe {
            let output = GetStdHandle(STD_OUTPUT_HANDLE);
            let input = GetStdHandle(STD_INPUT_HANDLE);

            let mut mode = 0u32;
            let color = GetConsoleMode(output, &mut mode) != 0
                && SetConsoleMode(
                    output,
                    mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
                ) != 0;

            OUTPUT_HANDLE.store(output, Ordering::SeqCst);
            VT_ENABLED.store(color, Ordering::SeqCst);
            // Failure is not fatal: it only costs us a cursor that stays
            // hidden if the user hits Ctrl+C, which is cosmetic.
            SetConsoleCtrlHandler(Some(restore_console), 1);

            Self { input, color }
        }
    }

    pub fn color(&self) -> bool {
        self.color
    }

    /// Return the current terminal dimensions as `(columns, rows)`.
    ///
    /// Uses the *visible window* rectangle from `CONSOLE_SCREEN_BUFFER_INFO`
    /// rather than the full screen-buffer size, so it reflects what the user
    /// actually sees even when the buffer is taller than the window. Returns
    /// `None` when the handle is not a real console (e.g. during unit tests
    /// that instantiate `Console::new()` over a pipe).
    pub fn size(&self) -> Option<(u16, u16)> {
        unsafe {
            let output = OUTPUT_HANDLE.load(Ordering::SeqCst);
            if output == 0 {
                return None;
            }
            let mut info = ConsoleScreenBufferInfo::default();
            if GetConsoleScreenBufferInfo(output, &mut info) == 0 {
                return None;
            }
            let cols = (info.window.right - info.window.left + 1).max(1) as u16;
            let rows = (info.window.bottom - info.window.top + 1).max(1) as u16;
            Some((cols, rows))
        }
    }

    /// Block until the next keypress.
    ///
    /// Key-up events and non-key records are filtered out so that holding an
    /// arrow key does not double-fire, and control characters never surface as
    /// `Char` — Ctrl+C reaches us as a signal instead, which is what lets the
    /// user escape the menu at all.
    pub fn read_key(&self) -> Result<Key> {
        loop {
            let mut record = unsafe { std::mem::zeroed::<InputRecord>() };
            let mut read = 0u32;
            let ok = unsafe { ReadConsoleInputW(self.input, &mut record, 1, &mut read) };
            if ok == 0 {
                anyhow::bail!("could not read console input");
            }
            if read == 0 || record.event_type != KEY_EVENT || record.key.key_down == 0 {
                continue;
            }
            return Ok(match record.key.virtual_key_code {
                VK_UP => Key::Up,
                VK_DOWN => Key::Down,
                VK_HOME => Key::Home,
                VK_END => Key::End,
                VK_PRIOR => Key::PageUp,
                VK_NEXT => Key::PageDown,
                VK_RETURN => Key::Enter,
                VK_ESCAPE => Key::Esc,
                _ => match char::from_u32(record.key.unicode_char as u32) {
                    Some(c) if !c.is_control() => Key::Char(c),
                    _ => Key::Other,
                },
            });
        }
    }

    /// Foreground colour around `text`, or the plain text when the console
    /// cannot render escapes.
    pub fn fg(&self, color: Rgb, text: &str) -> String {
        if self.color {
            format!(
                "\x1b[38;2;{};{};{}m{text}\x1b[0m",
                color.0, color.1, color.2
            )
        } else {
            text.to_string()
        }
    }

    /// Foreground and background together — one reset, so a selection bar can
    /// span a whole line without the colour dropping out midway.
    pub fn paint(&self, fg: Rgb, bg: Rgb, text: &str) -> String {
        if self.color {
            format!(
                "\x1b[38;2;{};{};{}m\x1b[48;2;{};{};{}m{text}\x1b[0m",
                fg.0, fg.1, fg.2, bg.0, bg.1, bg.2
            )
        } else {
            text.to_string()
        }
    }

    pub fn hide_cursor(&self) {
        if self.color && !CURSOR_HIDDEN.swap(true, Ordering::SeqCst) {
            self.write("\x1b[?25l");
        }
    }

    pub fn show_cursor(&self) {
        if self.color && CURSOR_HIDDEN.swap(false, Ordering::SeqCst) {
            self.write("\x1b[?25h");
        }
    }

    /// Blank the screen and park the cursor top-left.
    pub fn clear(&self) {
        if self.color {
            self.write("\x1b[2J\x1b[H");
        } else {
            // Without escapes there is no way to home the cursor, so push the
            // old content off the top instead.
            self.write(&"\n".repeat(40));
        }
    }

    pub fn write(&self, text: &str) {
        let mut out = std::io::stdout();
        let _ = out.write_all(text.as_bytes());
        let _ = out.flush();
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        self.show_cursor();
        if self.color {
            self.write("\x1b[0m");
        }
    }
}

/// Put the console back before we die.
///
/// Returning `FALSE` hands the event to the default handler, which terminates
/// the process — our only job is to make sure the shell the user returns to
/// still has a visible cursor. Runs on Windows' own Ctrl-handler thread, so it
/// touches nothing that could be locked by the thread going away.
extern "system" fn restore_console(event: u32) -> i32 {
    // 0 = Ctrl+C, 1 = Ctrl+Break, 2 = console close, 3 = logoff, 4 = shutdown.
    if event > 4 {
        return 0;
    }
    if CURSOR_HIDDEN.swap(false, Ordering::SeqCst) && VT_ENABLED.load(Ordering::SeqCst) {
        let output = OUTPUT_HANDLE.load(Ordering::SeqCst);
        if output != 0 {
            unsafe {
                let mut written = 0u32;
                WriteFile(
                    output,
                    b"\x1b[?25h".as_ptr(),
                    6,
                    &mut written,
                    std::ptr::null_mut(),
                );
            }
        }
    }
    0
}
