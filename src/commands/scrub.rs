use anyhow::{bail, Context, Result};
use std::path::PathBuf;

use crate::cli::ScrubArgs;
use crate::util::confirm;
use crate::win::traces::{scrub, ScrubTargets};

pub fn run(args: ScrubArgs, _vault_dir: Option<PathBuf>) -> Result<()> {
    if !args.previews && !args.recent {
        // Doing nothing silently would be worse than asking.
        println!("nothing selected — pass --previews, --recent, or both");
        println!();
        println!("  --previews   purge Explorer thumbnail and icon caches");
        println!("  --recent     purge Recent Documents and Prefetch entries");
        return Ok(());
    }

    println!("This will clear Windows artifacts OUTSIDE the reliquary.");
    println!("It cannot be undone, and it may affect other applications.");
    println!();

    if !args.yes && !confirm("Continue?")? {
        println!("cancelled");
        return Ok(());
    }

    let targets = ScrubTargets {
        previews: args.previews,
        recent: args.recent,
    };

    let reports = scrub(targets);

    let mut any_error = false;
    for r in &reports {
        print!("{} ({}): ", r.label, r.path_display());
        match &r.error {
            Some(e) => {
                any_error = true;
                println!("could not read — {e}");
            }
            None => {
                if r.removed == 0 && r.skipped == 0 {
                    println!("nothing to clean");
                } else {
                    println!("{} removed, {} skipped", r.removed, r.skipped);
                    if r.skipped > 0 {
                        println!(
                            "    (skipped files are usually locked by a running program — \
                             close Explorer windows and retry)"
                        );
                    }
                }
            }
        }
    }

    println!();
    println!("Done. Note: this reduces traces but cannot guarantee their removal.");
    println!("Windows keeps records (USN journal, $MFT) that no userland tool can reach.");

    if any_error {
        bail!("some locations could not be cleaned");
    }
    Ok(())
}

/// Print where Windows keeps its preview caches, for the curious.
#[allow(dead_code)]
pub fn show_cache_locations() -> Result<()> {
    let loc = crate::win::traces::describe_cache_location()
        .context("could not determine cache location")?;
    println!("{}", loc.display());
    Ok(())
}
