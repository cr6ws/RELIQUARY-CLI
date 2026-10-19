use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::cli::ShowArgs;
use crate::commands::list::id_of;
use crate::object::Object;
use crate::session::{Credential, Session, Target};
use crate::util::{format_size, format_timestamp};

pub fn run(args: ShowArgs, vault_dir: Option<PathBuf>, cred: &Credential) -> Result<()> {
    let dir = Session::locate(vault_dir)?;
    let session = Session::unlock(dir, cred)?;

    let target = session.resolve_target(&args.id)?;

    match target {
        Target::Object(obj) => {
            let meta =
                Object::read_meta(session.keys(), &obj).context("could not decrypt this entry")?;
            let on_disk = std::fs::metadata(&obj).map(|m| m.len()).unwrap_or(0);

            if meta.ext == "dir" {
                println!("ID            {}", id_of(&obj));
                println!("Type          Folder archive");
                println!("Name          {}/", meta.orig_name);
                println!("Original path {}", meta.orig_path.display());
                println!(
                    "Size          {} ({} bytes)",
                    format_size(meta.size),
                    meta.size
                );
                println!("Vault object  {} ({})", obj.display(), format_size(on_disk));
                println!("Hidden at     {}", format_timestamp(meta.hidden_at));
                println!("Modified at   {}", format_timestamp(meta.mtime.0));
            } else {
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
            }
        }
        Target::Folder(folder) => {
            println!("ID            {}", folder.id);
            println!("Type          Folder ({} files)", folder.objects.len());
            println!("Name          {}/", folder.name);
            println!("Original path {}", folder.path.display());
            println!(
                "Total size    {} ({} bytes)",
                format_size(folder.total_size),
                folder.total_size
            );
            println!(
                "Hidden at     {}",
                format_timestamp(folder.latest_hidden_at)
            );
            println!();
            println!("Files inside:");
            for (obj, m) in &folder.objects {
                let rel = m
                    .orig_path
                    .strip_prefix(&folder.path)
                    .unwrap_or(Path::new(&m.orig_name));
                println!(
                    "  {:<10}  {:<32}  {:>10}",
                    id_of(obj),
                    rel.display(),
                    format_size(m.size)
                );
            }
        }
    }

    Ok(())
}
