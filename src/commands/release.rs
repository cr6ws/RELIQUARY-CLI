use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::cli::ReleaseArgs;
use crate::commands::list::id_of;
use crate::object::{Meta, Object};
use crate::session::{Credential, Session, Target};

pub fn run(args: ReleaseArgs, vault_dir: Option<PathBuf>, cred: &Credential) -> Result<()> {
    let dir = Session::locate(vault_dir)?;
    let session = Session::unlock(dir, cred)?;

    let target = session.resolve_target(&args.id)?;

    match target {
        Target::Object(obj) => {
            let id = id_of(&obj);
            let meta = Object::read_meta(session.keys(), &obj)
                .context("could not decrypt this entry — wrong password or corrupt object")?;

            let dest = match &args.to {
                Some(p) => crate::util::clean_path(&p.to_string_lossy()),
                None => meta.orig_path.clone(),
            };

            if meta.ext == "dir" {
                println!("releasing folder {id}  {}/", meta.orig_name);
                println!("  to {}", dest.display());

                if dest.exists() && !args.force {
                    bail!(
                        "{} already exists\npass --force to overwrite it",
                        dest.display()
                    );
                }

                let temp_archive_path = std::env::temp_dir().join(format!(
                    "vlt_rel_{}_{}.tmp",
                    std::process::id(),
                    crate::crypto::keys::random_hex_id()
                ));

                let restored = {
                    let mut out = std::fs::File::create(&temp_archive_path).with_context(|| {
                        format!("could not create temp file {}", temp_archive_path.display())
                    })?;
                    let result = Object::extract_to(session.keys(), &obj, &mut out).and_then(|m| {
                        out.flush()?;
                        Ok(m)
                    });
                    match result {
                        Ok(m) => m,
                        Err(e) => {
                            let _ = std::fs::remove_file(&temp_archive_path);
                            return Err(e.context(format!(
                                "decryption failed — {} was NOT written, the vault copy is untouched",
                                dest.display()
                            )));
                        }
                    }
                };

                if restored.size != meta.size {
                    let _ = std::fs::remove_file(&temp_archive_path);
                    bail!("restored size does not match the vault record — aborting");
                }

                let mut in_file = std::fs::File::open(&temp_archive_path).with_context(|| {
                    format!(
                        "could not open temp archive {}",
                        temp_archive_path.display()
                    )
                })?;
                let file_count = crate::archive::unpack(&mut in_file, &dest)
                    .with_context(|| format!("could not unpack folder to {}", dest.display()))?;
                drop(in_file);
                let _ = std::fs::remove_file(&temp_archive_path);

                if !args.keep {
                    std::fs::remove_file(&obj).with_context(|| {
                        format!("restored OK, but could not remove {}", obj.display())
                    })?;
                    println!(
                        "released folder {} ({} files) to {}",
                        meta.orig_name,
                        file_count,
                        dest.display()
                    );
                } else {
                    println!(
                        "released folder {} ({} files) to {} (vault copy kept)",
                        meta.orig_name,
                        file_count,
                        dest.display()
                    );
                }
            } else {
                release_single_file(session.keys(), &obj, &meta, &dest, args.force, args.keep)?;
            }
        }
        Target::Folder(folder) => {
            println!(
                "releasing folder {} ({} files)",
                folder.name,
                folder.objects.len()
            );
            let dest_root = match &args.to {
                Some(p) => crate::util::clean_path(&p.to_string_lossy()),
                None => folder.path.clone(),
            };
            println!("  to {}", dest_root.display());

            let mut ok = 0usize;
            for (obj, meta) in &folder.objects {
                let file_dest = if args.to.is_some() {
                    let rel = meta
                        .orig_path
                        .strip_prefix(&folder.path)
                        .unwrap_or(Path::new(&meta.orig_name));
                    dest_root.join(rel)
                } else {
                    meta.orig_path.clone()
                };

                match release_single_file(
                    session.keys(),
                    obj,
                    meta,
                    &file_dest,
                    args.force,
                    args.keep,
                ) {
                    Ok(()) => ok += 1,
                    Err(e) => eprintln!("FAIL {}: {e}", meta.orig_name),
                }
            }

            println!(
                "released folder {} ({} of {} files restored) to {}",
                folder.name,
                ok,
                folder.objects.len(),
                dest_root.display()
            );
        }
    }

    Ok(())
}

fn release_single_file(
    keys: &crate::crypto::keys::VaultKeys,
    obj: &Path,
    meta: &Meta,
    dest: &Path,
    force: bool,
    keep: bool,
) -> Result<()> {
    let id = id_of(obj);
    println!("releasing {id}  {}", meta.orig_name);
    println!("  to {}", dest.display());

    if dest.exists() && !force {
        bail!(
            "{} already exists\npass --force to overwrite it",
            dest.display()
        );
    }

    let tmp = temp_sibling(dest)?;

    let restored = {
        let mut out = std::fs::File::create(&tmp)
            .with_context(|| format!("could not create {}", tmp.display()))?;
        let result = Object::extract_to(keys, obj, &mut out).and_then(|m| {
            out.flush()?;
            Ok(m)
        });

        match result {
            Ok(m) => m,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(e.context(format!(
                    "decryption failed — {} was NOT written, the vault copy is untouched",
                    dest.display()
                )));
            }
        }
    };

    if restored.size != meta.size {
        let _ = std::fs::remove_file(&tmp);
        bail!("restored size does not match the vault record — aborting");
    }

    std::fs::rename(&tmp, dest).with_context(|| {
        let _ = std::fs::remove_file(&tmp);
        format!(
            "could not move restored file into place at {}",
            dest.display()
        )
    })?;

    if restored.mtime.0 > 0 {
        let (secs, nanos) = restored.mtime;
        let ft = filetime::FileTime::from_unix_time(secs, nanos);
        let _ = filetime::set_file_mtime(dest, ft);
    }

    if !keep {
        std::fs::remove_file(obj)
            .with_context(|| format!("restored OK, but could not remove {}", obj.display()))?;
        println!("released  {}", dest.display());
    } else {
        println!("released  {} (vault copy kept)", dest.display());
    }

    Ok(())
}

/// A unique temporary path in the same directory as `dest`.
///
/// Same directory on purpose: the final rename must stay within one
/// filesystem, otherwise it degrades to a copy and loses its atomicity.
fn temp_sibling(dest: &Path) -> Result<PathBuf> {
    let parent = match dest.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };

    if !parent.exists() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("could not create directory {}", parent.display()))?;
    }

    let base = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());

    for _ in 0..16 {
        let nonce = crate::crypto::keys::random_bytes::<6>();
        let candidate = parent.join(format!(".{}.{}.vaulttmp", base, hex::encode(nonce)));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }

    bail!(
        "could not allocate a temporary file next to {}",
        dest.display()
    )
}
