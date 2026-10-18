use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::cli::ReleaseArgs;
use crate::commands::list::id_of;
use crate::object::Object;
use crate::session::Session;

pub fn run(
    args: ReleaseArgs,
    vault_dir: Option<PathBuf>,
    recovery: Option<String>,
    password_file: Option<PathBuf>,
) -> Result<()> {
    let dir = Session::locate(vault_dir)?;
    let session = Session::unlock(dir, recovery.as_deref(), password_file.as_deref())?;

    let obj = session.resolve_id(&args.id)?;
    let id = id_of(&obj);

    // Peek at the metadata first so we can show the user where the file is
    // going before we write a single byte.
    let meta = Object::read_meta(session.keys(), &obj)
        .context("could not decrypt this entry — wrong password or corrupt object")?;

    let dest = match &args.to {
        Some(p) => p.clone(),
        None => meta.orig_path.clone(),
    };

    println!("releasing {id}  {}", meta.orig_name);
    println!("  to {}", dest.display());

    if dest.exists() && !args.force {
        bail!(
            "{} already exists\npass --force to overwrite it",
            dest.display()
        );
    }

    // Never write the decrypted bytes directly to the final path. If
    // decryption fails partway through we would leave a half-written file
    // that could silently replace the user's data, so we write to a
    // sibling temp file and only rename once every chunk authenticated.
    let tmp = temp_sibling(&dest)?;

    let restored = {
        let mut out = std::fs::File::create(&tmp)
            .with_context(|| format!("could not create {}", tmp.display()))?;
        let result = Object::extract_to(session.keys(), &obj, &mut out).and_then(|m| {
            out.flush()?;
            Ok(m)
        });

        match result {
            Ok(m) => m,
            Err(e) => {
                // Clean up the partial temp file; never leave debris that
                // might be mistaken for the real thing.
                let _ = std::fs::remove_file(&tmp);
                return Err(e.context(format!(
                    "decryption failed — {} was NOT written, the vault copy is untouched",
                    dest.display()
                )));
            }
        }
    };

    // Confirm the restored bytes match what was hidden. A mismatch here
    // means either silent corruption or tampering — refuse to install it.
    if restored.size != meta.size {
        let _ = std::fs::remove_file(&tmp);
        bail!("restored size does not match the vault record — aborting");
    }

    std::fs::rename(&tmp, &dest).with_context(|| {
        let _ = std::fs::remove_file(&tmp);
        format!(
            "could not move restored file into place at {}",
            dest.display()
        )
    })?;

    // Put the original modification time back so the file doesn't look
    // freshly created.
    if restored.mtime.0 > 0 {
        let (secs, nanos) = restored.mtime;
        let ft = filetime::FileTime::from_unix_time(secs, nanos);
        let _ = filetime::set_file_mtime(&dest, ft);
    }

    if !args.keep {
        std::fs::remove_file(&obj)
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
