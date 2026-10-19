use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::cli::ForgetArgs;
use crate::commands::list::id_of;
use crate::object::Object;
use crate::session::{Credential, Session, Target};
use crate::util::confirm;
use crate::win;

pub fn run(args: ForgetArgs, vault_dir: Option<PathBuf>, cred: &Credential) -> Result<()> {
    let dir = Session::locate(vault_dir)?;
    let session = Session::unlock(dir, cred)?;

    let target = session.resolve_target(&args.id)?;

    match target {
        Target::Object(obj) => {
            let meta =
                Object::read_meta(session.keys(), &obj).context("could not decrypt this entry")?;
            let id = id_of(&obj);

            if !args.yes {
                let is_dir = meta.ext == "dir";
                println!(
                    "About to permanently destroy{}:",
                    if is_dir { " folder" } else { "" }
                );
                println!("  ID    {}", id);
                println!(
                    "  name  {}{}",
                    meta.orig_name,
                    if is_dir { "/" } else { "" }
                );
                println!("  path  {}", meta.orig_path.display());
                println!("  size  {}", crate::util::format_size(meta.size));
                println!();
                if !confirm("There is no undo. Destroy it?")? {
                    println!("cancelled");
                    return Ok(());
                }
            }

            win::secure_delete::delete(&obj)
                .with_context(|| format!("could not destroy {}", obj.display()))?;

            println!("forgot {}", id);
        }
        Target::Folder(folder) => {
            if !args.yes {
                println!("About to permanently destroy folder:");
                println!("  ID    {}", folder.id);
                println!("  name  {}/", folder.name);
                println!("  path  {}", folder.path.display());
                println!(
                    "  size  {} ({} files)",
                    crate::util::format_size(folder.total_size),
                    folder.objects.len()
                );
                println!();
                if !confirm("There is no undo. Destroy it?")? {
                    println!("cancelled");
                    return Ok(());
                }
            }

            for (obj, _) in &folder.objects {
                let _ = win::secure_delete::delete(obj);
            }

            println!(
                "forgot folder {} ({} files destroyed)",
                folder.name,
                folder.objects.len()
            );
        }
    }

    Ok(())
}
