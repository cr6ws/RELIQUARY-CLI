use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Overwrite a file with random data, then unlink it.
///
/// # What this can and cannot promise
///
/// On an HDD this is effective: one pass of random data destroys the
/// previous contents at the physical level.
///
/// On an SSD or NVMe drive it is **best-effort only**. The drive's
/// controller remaps blocks internally, and TRIM means the overwrite may
/// never reach the physical cells that held the original data. Nothing
/// userspace can do changes that. We overwrite anyway because it costs
/// little and helps on HDDs and on SSDs that honour TRIM promptly, but
/// we do not claim it guarantees erasure.
///
/// Filesystem-level metadata (directory entries, $MFT records) is not
/// addressed here either.
pub fn delete(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("{} does not exist", path.display());
    }

    let len = std::fs::metadata(path)
        .with_context(|| format!("could not stat {}", path.display()))?
        .len();

    // Clear the read-only attribute if set, otherwise the overwrite fails.
    clear_readonly(path)?;

    if len > 0 {
        overwrite_random(path, len)?;
    }

    // Rename before unlinking. This destroys the association between the
    // original filename and the (now overwritten) data, so a directory
    // recovery tool fishing the entry back out gets an opaque name.
    let scratch = scratch_name(path);
    std::fs::rename(path, &scratch)
        .with_context(|| format!("could not rename {} before deletion", path.display()))?;

    std::fs::remove_file(&scratch)
        .with_context(|| format!("could not delete {}", scratch.display()))?;

    Ok(())
}

fn clear_readonly(path: &Path) -> Result<()> {
    let mut perms = std::fs::metadata(path)
        .with_context(|| format!("could not stat {}", path.display()))?
        .permissions();

    if perms.readonly() {
        // `set_readonly(false)` clears FILE_ATTRIBUTE_READONLY, which is what
        // actually blocks the overwrite below. Scoped to Windows deliberately:
        // on Unix the same call would make the file world-writable, which is
        // the opposite of what a vault should do to a file it is about to
        // destroy. On Unix the process's own write permission is enough.
        #[cfg(windows)]
        {
            // False positive: this block only compiles on Windows, so the
            // Unix world-writable behavior clippy warns about cannot occur.
            #[allow(clippy::permissions_set_readonly_false)]
            {
                perms.set_readonly(false);
            }
            std::fs::set_permissions(path, perms)
                .with_context(|| format!("could not clear read-only on {}", path.display()))?;
        }
        #[cfg(not(windows))]
        {
            let _ = &perms;
        }
    }
    Ok(())
}

fn overwrite_random(path: &Path, len: u64) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .read(true)
        .open(path)
        .with_context(|| format!("could not open {} for overwrite", path.display()))?;

    // One pass of random data. Random rather than zeros so the result is
    // indistinguishable from "never written" rather than "deliberately wiped".
    let mut buf = vec![0u8; 64 * 1024];
    let mut remaining = len;

    while remaining > 0 {
        let take = std::cmp::min(remaining, buf.len() as u64) as usize;
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf[..take]);
        f.write_all(&buf[..take])
            .with_context(|| format!("could not overwrite {}", path.display()))?;
        remaining -= take as u64;
    }

    f.flush()?;
    // Force the overwrite out of the OS cache before we unlink, so a power
    // cut immediately after `delete` doesn't resurrect the original data.
    f.sync_all()
        .with_context(|| format!("could not flush {} to disk", path.display()))?;

    // Wipe our own buffer too.
    use zeroize::Zeroize;
    buf.zeroize();

    Ok(())
}

fn scratch_name(path: &Path) -> std::path::PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let nonce = crate::crypto::keys::random_bytes::<8>();
    let hidden = format!(
        ".{}.{}.deleted",
        crate::crypto::keys::random_hex_id(),
        hex::encode(nonce)
    );
    parent.join(hidden)
}

/// Zero a file in place without deleting it. Used by `scrub` for caches we
/// can't safely unlink but can still blank.
#[allow(dead_code)]
pub fn zero_in_place(path: &Path) -> Result<()> {
    let mut f: File = OpenOptions::new()
        .write(true)
        .read(true)
        .open(path)
        .with_context(|| format!("could not open {}", path.display()))?;

    let len = f.metadata().context("could not stat")?.len();
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&vec![0u8; len as usize])?;
    f.flush()?;
    f.sync_all()?;
    Ok(())
}

/// Read and discard a file's contents. Used to detect whether a path is
/// readable before we attempt to scrub it.
#[allow(dead_code)]
pub fn probe_readable(path: &Path) -> Result<()> {
    let mut f = File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    let mut sink = Vec::new();
    f.read_to_end(&mut sink)?;
    Ok(())
}
