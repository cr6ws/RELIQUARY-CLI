use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Which categories of Windows trace to purge.
#[derive(Clone, Copy, Debug)]
pub struct ScrubTargets {
    pub previews: bool,
    pub recent: bool,
}

/// A location we attempted to clean, and what happened.
pub struct ScrubReport {
    pub label: &'static str,
    /// Where this report looked. Surfaced in `scrub` output so the user can
    /// verify the right location was touched, and so a silent no-op on a
    /// missing directory is visible rather than hidden.
    pub path: PathBuf,
    pub removed: usize,
    pub skipped: usize,
    pub error: Option<String>,
}

impl ScrubReport {
    /// Location for display, shortened from the left if very long.
    pub fn path_display(&self) -> String {
        let s = self.path.display().to_string();
        if s.len() > 57 {
            format!("...{}", &s[s.len() - 54..])
        } else {
            s
        }
    }
}

/// Purge Windows artifacts that can outlive a hidden file.
///
/// # Why this exists
///
/// When Explorer renders a folder it writes a thumbnail into a shared cache
/// keyed by path. If you hide `photo.jpg`, the file is gone but a 96x96
/// rendering of it can persist in `thumbcache_*.db` indefinitely. Recent
/// Documents and Prefetch leave similar residue.
///
/// # Honest limitations
///
/// This is best-effort, not a guarantee:
///
/// * Explorer holds `thumbcache_*.db` open with an exclusive lock. We cannot
///   delete it while Explorer is running, and we do not kill the process —
///   that would be a hostile thing for a vault to do to your desktop.
/// * The cache files are not the only copy. Volumes keep a USN journal that
///   records filenames independently of anything we can reach from here.
/// * Prefetch is admin-only. We try, and report a skip if we lack rights.
///
/// So: `scrub` meaningfully reduces casual exposure. It does not make a
/// forensic analyst's job impossible, and we would rather say that plainly
/// than let you believe otherwise.
pub fn scrub(targets: ScrubTargets) -> Vec<ScrubReport> {
    let mut reports = Vec::new();

    if targets.previews {
        if let Some(dir) = explorer_cache_dir() {
            reports.push(scrub_thumbnail_cache(&dir));
        } else {
            reports.push(ScrubReport {
                label: "thumbnail cache",
                path: PathBuf::from("(not found)"),
                removed: 0,
                skipped: 0,
                error: Some("could not locate LOCALAPPDATA".into()),
            });
        }
    }

    if targets.recent {
        if let Some(dir) = recent_dir() {
            reports.push(scrub_recent(&dir));
        }
        if let Some(dir) = prefetch_dir() {
            reports.push(scrub_prefetch(&dir));
        }
    }

    reports
}

fn explorer_cache_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|p| p.join("Microsoft").join("Windows").join("Explorer"))
}

fn recent_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .map(|p| p.join("Microsoft").join("Windows").join("Recent"))
}

fn prefetch_dir() -> Option<PathBuf> {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|p| p.join("Prefetch"))
}

fn scrub_thumbnail_cache(dir: &Path) -> ScrubReport {
    let mut report = ScrubReport {
        label: "thumbnail cache",
        path: dir.to_path_buf(),
        removed: 0,
        skipped: 0,
        error: None,
    };

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            report.error = Some(e.to_string());
            return report;
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        if !(name.starts_with("thumbcache_") || name.starts_with("iconcache_")) {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => report.removed += 1,
            // Almost always ERROR_SHARING_VIOLATION — Explorer has it open.
            Err(_) => report.skipped += 1,
        }
    }

    report
}

fn scrub_recent(dir: &Path) -> ScrubReport {
    let mut report = ScrubReport {
        label: "recent documents",
        path: dir.to_path_buf(),
        removed: 0,
        skipped: 0,
        error: None,
    };

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            report.error = Some(e.to_string());
            return report;
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        // Only the shortcut files. Deleting arbitrary contents of the user's
        // Recent folder would be overreach.
        if name.ends_with(".lnk") {
            match std::fs::remove_file(entry.path()) {
                Ok(()) => report.removed += 1,
                Err(_) => report.skipped += 1,
            }
        }
    }

    report
}

fn scrub_prefetch(dir: &Path) -> ScrubReport {
    let mut report = ScrubReport {
        label: "prefetch",
        path: dir.to_path_buf(),
        removed: 0,
        skipped: 0,
        error: None,
    };

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            report.error = Some(e.to_string());
            return report;
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        if name.ends_with(".pf") {
            match std::fs::remove_file(entry.path()) {
                Ok(()) => report.removed += 1,
                // Requires elevation; expected to fail for a non-admin shell.
                Err(_) => report.skipped += 1,
            }
        }
    }

    report
}

/// Where Explorer writes its icon and thumbnail caches. Exposed so `scrub`
/// can report the location even when it couldn't clean it.
pub fn describe_cache_location() -> Result<PathBuf> {
    explorer_cache_dir().context("LOCALAPPDATA is not set")
}
