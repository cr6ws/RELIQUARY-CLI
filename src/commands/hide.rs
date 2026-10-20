use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

use crate::cli::HideArgs;
use crate::object::{Meta, Object};
use crate::session::{Credential, Session};
use crate::util;
use crate::win;

pub fn run(args: HideArgs, vault_dir: Option<PathBuf>, cred: &Credential) -> Result<()> {
    let dir = Session::locate(vault_dir)?;
    let session = Session::unlock(dir, cred)?;

    // Expand every argument into a concrete list of files, walking any
    // directories recursively. Globs are resolved here too, because the
    // shell does not expand them on Windows the way it does on Unix.
    //
    // Strip surrounding double/single quotes before resolving: Windows
    // "Copy as path" always wraps paths in quotes, and the OS rejects `"`
    let mut ok = 0usize;
    let mut failed = 0usize;

    for input in &args.paths {
        let clean = util::clean_path(&input.to_string_lossy());
        if clean.is_dir() {
            match hide_folder(&session, &clean, args.copy) {
                Ok((name, id)) => {
                    println!("hid folder {}/ ({id})", name);
                    ok += 1;
                }
                Err(e) => {
                    eprintln!("FAIL {}: {e}", clean.display());
                    failed += 1;
                }
            }
        } else {
            let mut files = Vec::new();
            if let Err(e) = collect_files(&clean, &mut files) {
                eprintln!("FAIL {}: {e}", clean.display());
                failed += 1;
                continue;
            }
            if files.is_empty() {
                eprintln!("FAIL {}: no files matched pattern", clean.display());
                failed += 1;
                continue;
            }
            for file in &files {
                match hide_one(&session, file, args.copy) {
                    Ok(name) => {
                        println!("hid  {}", name);
                        ok += 1;
                    }
                    Err(e) => {
                        eprintln!("FAIL {}: {e}", file.display());
                        failed += 1;
                    }
                }
            }
        }
    }

    if ok == 0 && failed == 0 {
        bail!("no files matched the given paths");
    }

    println!();
    println!(
        "{} hidden, {} failed, {} total in reliquary",
        ok,
        failed,
        session.objects()?.len()
    );

    if failed > 0 {
        bail!("{failed} item(s) could not be hidden");
    }
    Ok(())
}

fn hide_folder(session: &Session, src: &Path, keep_original: bool) -> Result<(String, String)> {
    let canon = src
        .canonicalize()
        .with_context(|| format!("could not resolve {}", src.display()))?;
    let meta_src =
        std::fs::metadata(&canon).with_context(|| format!("could not read {}", canon.display()))?;
    let folder_name = canon
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "folder".to_string());

    let temp_archive_path = std::env::temp_dir().join(format!(
        "vlt_dir_{}_{}.tmp",
        std::process::id(),
        crate::crypto::keys::random_hex_id()
    ));

    let archive_size = {
        let mut temp_file = std::fs::File::create(&temp_archive_path).with_context(|| {
            format!(
                "could not create temp archive {}",
                temp_archive_path.display()
            )
        })?;
        crate::archive::pack(&canon, &mut temp_file)?
    };

    let meta = Meta {
        orig_name: folder_name.clone(),
        orig_path: canon.clone(),
        size: archive_size,
        mtime: mtime_of(&meta_src),
        hidden_at: now_unix(),
        ext: "dir".to_string(),
    };

    let obj_id = crate::crypto::keys::random_hex_id();
    let obj_path = session.dir.objects_dir().join(format!("{obj_id}.enc"));

    let write_res = Object::write(session.keys(), &meta, &temp_archive_path, &obj_path);
    let _ = std::fs::remove_file(&temp_archive_path);

    if let Err(e) = write_res {
        let _ = std::fs::remove_file(&obj_path);
        return Err(e.context(format!("could not encrypt folder {}", src.display())));
    }

    if !keep_original {
        // Securely delete all files in the directory tree, then clean up empty directories
        for entry in walkdir::WalkDir::new(&canon)
            .contents_first(true)
            .into_iter()
            .flatten()
        {
            let p = entry.path();
            if p.is_file() {
                let _ = win::secure_delete::delete(p);
            }
        }
        clean_empty_dirs(&canon);
    }

    Ok((folder_name, obj_id))
}

fn hide_one(session: &Session, src: &Path, keep_original: bool) -> Result<String> {
    let meta_src =
        std::fs::metadata(src).with_context(|| format!("could not read {}", src.display()))?;

    if meta_src.is_dir() {
        bail!(
            "{} is a directory (it should have been expanded)",
            src.display()
        );
    }

    // Canonicalize so the stored path is absolute and free of `..` segments.
    // This matters because `release` will write back to exactly this path.
    let canon = src
        .canonicalize()
        .with_context(|| format!("could not resolve {}", src.display()))?;

    let size = meta_src.len();
    let mtime = mtime_of(&meta_src);
    let name = canon
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unnamed".to_string());
    let ext = canon
        .extension()
        .map(|e| e.to_string_lossy().into_owned())
        .unwrap_or_default();

    let meta = Meta {
        orig_name: name.clone(),
        orig_path: canon.clone(),
        size,
        mtime,
        hidden_at: now_unix(),
        ext,
    };

    // Object filename is derived from the content-independent random nonce,
    // so two identical files produce two distinct vault entries.
    let obj_name = format!("{}.enc", crate::crypto::keys::random_hex_id());
    let obj_path = session.dir.objects_dir().join(&obj_name);

    Object::write(session.keys(), &meta, src, &obj_path).with_context(|| {
        // Don't leave a half-written object behind on failure.
        let _ = std::fs::remove_file(&obj_path);
        format!("could not encrypt {}", src.display())
    })?;

    // Only remove the source after the encrypted copy is safely on disk.
    if !keep_original {
        win::secure_delete::delete(src)
            .with_context(|| format!("encrypted OK, but could not remove {}", src.display()))?;
    }

    Ok(name)
}

/// Recursively remove empty directories bottom-up starting from the leaves.
///
/// Only removes directories that contain no files and no subdirectories.
/// If any file remains (e.g. failed to encrypt or write-protected), the
/// directory is preserved.
fn clean_empty_dirs(root: &Path) {
    if !root.is_dir() {
        return;
    }
    let walker = walkdir::WalkDir::new(root)
        .contents_first(true)
        .follow_links(false);
    for entry in walker.into_iter().flatten() {
        if entry.file_type().is_dir() {
            let _ = std::fs::remove_dir(entry.path());
        }
    }
}

fn collect_files(input: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let s = input.to_string_lossy();

    // Glob patterns: only treated as such if they actually contain wildcards,
    // so a literal path containing `[` still works.
    if s.contains('*') || s.contains('?') || s.contains('[') {
        let entries = glob::glob(&s).with_context(|| format!("invalid pattern `{s}`"))?;
        let mut any = false;
        for entry in entries {
            let entry = entry.with_context(|| format!("error in pattern `{s}`"))?;
            any = true;
            collect_files(&entry, out)?;
        }
        if !any {
            bail!("pattern `{s}` matched nothing");
        }
        return Ok(());
    }

    let meta =
        std::fs::metadata(input).with_context(|| format!("cannot access {}", input.display()))?;

    if meta.is_dir() {
        // The user passed a folder path directly — walk every file inside it.
        for entry in walkdir::WalkDir::new(input).follow_links(false) {
            let entry = entry.with_context(|| format!("error walking {}", input.display()))?;
            if entry.file_type().is_file() {
                out.push(entry.path().to_path_buf());
            }
        }
    } else {
        out.push(input.to_path_buf());
    }
    Ok(())
}

fn mtime_of(meta: &std::fs::Metadata) -> (i64, u32) {
    use std::time::UNIX_EPOCH;
    match meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
    {
        Some(d) => (d.as_secs() as i64, d.subsec_nanos()),
        None => (0, 0),
    }
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
