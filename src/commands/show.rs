use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::cli::ShowArgs;
use crate::commands::list::id_of;
use crate::object::Object;
use crate::session::Session;
use crate::util::{format_size, format_timestamp};

pub fn run(
    args: ShowArgs,
    vault_dir: Option<PathBuf>,
    recovery: Option<String>,
    password_file: Option<PathBuf>,
) -> Result<()> {
    let dir = Session::locate(vault_dir)?;
    let session = Session::unlock(dir, recovery.as_deref(), password_file.as_deref())?;

    let obj = session.resolve_id(&args.id)?;
    let meta = Object::read_meta(session.keys(), &obj).context("could not decrypt this entry")?;

    let on_disk = std::fs::metadata(&obj).map(|m| m.len()).unwrap_or(0);

    println!("ID            {}", id_of(&obj));
    println!("Name          {}", meta.orig_name);
    println!("Original path {}", meta.orig_path.display());
    println!(
        "Size          {} ({} bytes)",
        format_size(meta.size),
        meta.size
    );
    println!("Vault object  {} ({})", obj.display(), format_size(on_disk));
    println!(
        "Extension     {}",
        if meta.ext.is_empty() {
            "—".into()
        } else {
            meta.ext.clone()
        }
    );
    println!("Hidden at     {}", format_timestamp(meta.hidden_at));
    println!("Modified at   {}", format_timestamp(meta.mtime.0));

    Ok(())
}
