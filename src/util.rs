use anyhow::{Context, Result};
use zeroize::Zeroizing;

/// Prompt for the vault password on the terminal.
///
/// Kept in one place so every command behaves identically and no command
/// accidentally falls back to an echo-enabled read.
pub fn prompt_password() -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        rpassword::prompt_password("Vault password: ").context("could not read password")?,
    ))
}

/// Ask a yes/no question on stdin. Defaults to no on EOF or garbage, so an
/// accidental Enter never confirms a destructive operation.
pub fn confirm(question: &str) -> Result<bool> {
    use std::io::Write;

    print!("{question} [y/N] ");
    std::io::stdout().flush().ok();

    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok();
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
}

pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", UNITS[i])
}

/// Format a Unix timestamp as a local-ish date string.
///
/// Deliberately avoids pulling in chrono: a vault listing doesn't need
/// timezone-correct formatting, and one fewer dependency is one fewer
/// supply-chain surface for a security tool.
pub fn format_timestamp(unix: i64) -> String {
    if unix <= 0 {
        return "unknown".to_string();
    }
    let (y, mo, d, h, mi) = civil_from_unix(unix);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}")
}

/// Convert Unix seconds to UTC calendar fields.
///
/// Howard Hinnant's `civil_from_days` algorithm — exact for the whole
/// supported range and free of the off-by-one errors that hand-rolled
/// date math tends to attract.
fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };

    (y, m, d, (rem / 3600) as u32, ((rem % 3600) / 60) as u32)
}
