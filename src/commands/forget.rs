use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::cli::ForgetArgs;
use crate::commands::list::id_of;
use crate::object::Object;
use crate::session::Session;
use crate::util::confirm;
use crate::win;

pub fn run(
    args: ForgetArgs,
    vault_dir: Option<PathBuf>,
    recovery: Option<String>,
    password_file: Option<PathBuf>,
) -> Result<()> {
    let dir = Session::locate(vault_dir)?;
    let session = Session::unlock(dir, recovery.as_deref(), password_file.as_deref())?;

    let obj = session.resolve_id(&args.id)?;
    let meta = Object::read_meta(session.keys(), &obj).context("could not decrypt this entry")?;

    let id = id_of(&obj);

    if !args.yes {
        println!("About to permanently destroy:");
        println!("  ID    {}", id);
        println!("  name  {}", meta.orig_name);
        println!("  path  {}", meta.orig_path.display());
        println!("  size  {}", crate::util::format_size(meta.size));
        println!();
        if !confirm("There is no undo. Destroy it?")? {
            println!("cancelled");
            return Ok(());
        }
    }

    // Overwrite before unlinking. The object is already encrypted, so this
    // is defense in depth rather than a hard guarantee — see the note on
    // `win::secure_delete` about what overwrite can and cannot promise on
    // modern storage.
    win::secure_delete::delete(&obj)
        .with_context(|| format!("could not destroy {}", obj.display()))?;

    println!("forgot {}", id);
    Ok(())
}
