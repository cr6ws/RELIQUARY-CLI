use anyhow::Result;
use std::path::PathBuf;

use crate::cli::ListArgs;
use crate::object::Object;
use crate::session::Session;

pub fn run(
    args: ListArgs,
    vault_dir: Option<PathBuf>,
    recovery: Option<String>,
    password_file: Option<PathBuf>,
) -> Result<()> {
    let dir = Session::locate(vault_dir)?;
    let session = Session::unlock(dir, recovery.as_deref(), password_file.as_deref())?;

    let objects = session.objects()?;
    if objects.is_empty() {
        println!("vault is empty");
        return Ok(());
    }

    let mut entries = Vec::with_capacity(objects.len());
    for obj in &objects {
        match Object::read_meta(session.keys(), obj) {
            Ok(meta) => entries.push((obj.clone(), meta)),
            Err(e) => eprintln!("warning: {} could not be read: {e}", obj.display()),
        }
    }

    if entries.is_empty() {
        println!("vault is empty");
        return Ok(());
    }

    // Most recently hidden first — that's usually what you're looking for.
    entries.sort_by_key(|(_, m)| std::cmp::Reverse(m.hidden_at));

    if args.plain {
        for (obj, meta) in &entries {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                id_of(obj),
                meta.size,
                meta.hidden_at,
                meta.orig_name.escape_debug(),
                meta.orig_path.display().to_string().escape_debug(),
            );
        }
        return Ok(());
    }

    let name_w = entries
        .iter()
        .map(|(_, m)| m.orig_name.chars().count())
        .max()
        .unwrap_or(4)
        .clamp(4, 48);

    println!(
        "{:<10}  {:<name_w$}  {:>10}  {:<12}",
        "ID",
        "NAME",
        "SIZE",
        "HIDDEN",
        name_w = name_w
    );
    println!(
        "{:<10}  {:<name_w$}  {:>10}  {:<12}",
        "-".repeat(10),
        "-".repeat(name_w),
        "-".repeat(10),
        "-".repeat(12),
        name_w = name_w
    );

    for (obj, meta) in &entries {
        let name = truncate(&meta.orig_name, name_w);
        println!(
            "{:<10}  {:<name_w$}  {:>10}  {:<12}",
            id_of(obj),
            name,
            human_size(meta.size),
            format_age(meta.hidden_at),
            name_w = name_w
        );
    }

    println!();
    println!(
        "{} entries, {} total",
        entries.len(),
        human_size(entries.iter().map(|(_, m)| m.size).sum())
    );
    if args.paths {
        println!();
        for (obj, meta) in &entries {
            println!("{}  {}", id_of(obj), meta.orig_path.display());
        }
    }

    Ok(())
}

pub fn id_of(obj: &std::path::Path) -> String {
    obj.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

pub fn human_size(bytes: u64) -> String {
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

fn format_age(unix: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let delta = (now - unix).max(0);

    match delta {
        0..=59 => "just now".to_string(),
        60..=3599 => format!("{}m ago", delta / 60),
        3600..=86399 => format!("{}h ago", delta / 3600),
        86400..=2_591_999 => format!("{}d ago", delta / 86400),
        _ => format!("{}mo ago", delta / 2_592_000),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut = s.chars().take(max.saturating_sub(1)).collect::<String>();
    format!("{cut}…")
}
