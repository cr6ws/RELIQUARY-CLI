use anyhow::Result;
use std::path::PathBuf;

use crate::cli::ListArgs;
use crate::object::Object;
use crate::session::{Credential, Session};

pub fn run(args: ListArgs, vault_dir: Option<PathBuf>, cred: &Credential) -> Result<()> {
    let dir = Session::locate(vault_dir)?;
    let session = Session::unlock(dir, cred)?;

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

    let folder_groups = crate::session::discover_folders(&entries);

    if args.plain {
        // Keep the existing five-column machine-readable shape, but include
        // synthetic folder targets before their individual file objects.
        // This makes a folder ID usable by scripts as well as the human table.
        for folder in &folder_groups {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                folder.id,
                folder.total_size,
                folder.latest_hidden_at,
                format!("{}/", folder.name).escape_debug(),
                format!(
                    "{}\\ (folder, {} files)",
                    folder.path.display(),
                    folder.objects.len()
                )
                .escape_debug(),
            );
        }
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

    struct ListItem {
        id: String,
        name: String,
        size: u64,
        hidden_at: i64,
        path_str: String,
        is_dir: bool,
    }

    let mut items = Vec::new();

    for fg in &folder_groups {
        items.push(ListItem {
            id: fg.id.clone(),
            name: format!("{}/", fg.name),
            size: fg.total_size,
            hidden_at: fg.latest_hidden_at,
            path_str: format!(
                "{}\\ (folder, {} files)",
                fg.path.display(),
                fg.objects.len()
            ),
            is_dir: true,
        });
    }

    for (obj, meta) in &entries {
        let is_dir = meta.ext == "dir";
        let display_name = if is_dir {
            format!("{}/", meta.orig_name)
        } else {
            meta.orig_name.clone()
        };
        let path_str = if is_dir {
            format!("{}\\ (folder archive)", meta.orig_path.display())
        } else {
            meta.orig_path.display().to_string()
        };
        items.push(ListItem {
            id: id_of(obj),
            name: display_name,
            size: meta.size,
            hidden_at: meta.hidden_at,
            path_str,
            is_dir,
        });
    }

    items.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| b.hidden_at.cmp(&a.hidden_at))
    });

    let name_w = items
        .iter()
        .map(|item| item.name.chars().count())
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

    for item in &items {
        let name = truncate(&item.name, name_w);
        println!(
            "{:<10}  {:<name_w$}  {:>10}  {:<12}",
            item.id,
            name,
            human_size(item.size),
            format_age(item.hidden_at),
            name_w = name_w
        );
    }

    println!();
    let file_count = entries.iter().filter(|(_, m)| m.ext != "dir").count();
    let folder_count = items.iter().filter(|item| item.is_dir).count();
    let total_bytes: u64 = entries.iter().map(|(_, m)| m.size).sum();

    if folder_count > 0 {
        println!(
            "{} items ({} folder{}, {} file{}), {} total",
            items.len(),
            folder_count,
            if folder_count == 1 { "" } else { "s" },
            file_count,
            if file_count == 1 { "" } else { "s" },
            human_size(total_bytes)
        );
    } else {
        println!(
            "{} entries, {} total",
            entries.len(),
            human_size(total_bytes)
        );
    }

    if args.paths {
        println!();
        for folder in &folder_groups {
            println!(
                "{}  {}/  {} files",
                folder.id,
                folder.path.display(),
                folder.objects.len()
            );
        }
        for item in &items {
            if !item.is_dir {
                println!("{}  {}", item.id, item.path_str);
            }
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
