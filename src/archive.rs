use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

const VDIR_MAGIC: &[u8; 4] = b"VDIR";
const VDIR_VERSION: u8 = 1;

const TAG_FILE: u8 = 1;
const TAG_DIR: u8 = 2;

/// Archive a directory tree into a single output byte stream.
///
/// Preserves relative directory structure, file contents, empty subdirectories,
/// and file modification timestamps.
pub fn pack(root: &Path, out: &mut dyn Write) -> Result<u64> {
    let mut writer = BufWriter::new(out);
    writer.write_all(VDIR_MAGIC)?;
    writer.write_all(&[VDIR_VERSION])?;
    let mut total_bytes = 5u64;

    let walker = walkdir::WalkDir::new(root)
        .min_depth(1)
        .follow_links(false)
        .sort_by_file_name();

    for entry in walker {
        let entry = entry.with_context(|| format!("error walking {}", root.display()))?;
        let entry_path = entry.path();
        let rel_path = entry_path.strip_prefix(root).with_context(|| {
            format!(
                "could not determine relative path for {}",
                entry_path.display()
            )
        })?;
        let rel_str = rel_path.to_string_lossy().replace('\\', "/");
        let rel_bytes = rel_str.as_bytes();
        if rel_bytes.len() > u16::MAX as usize {
            bail!("relative path too long: {rel_str}");
        }

        let meta = entry
            .metadata()
            .with_context(|| format!("could not stat {}", entry_path.display()))?;
        let (mtime_secs, mtime_nanos) = mtime_of(&meta);

        if entry.file_type().is_dir() {
            writer.write_all(&[TAG_DIR])?;
            writer.write_all(&(rel_bytes.len() as u16).to_le_bytes())?;
            writer.write_all(rel_bytes)?;
            writer.write_all(&mtime_secs.to_le_bytes())?;
            writer.write_all(&mtime_nanos.to_le_bytes())?;
            total_bytes += 1 + 2 + rel_bytes.len() as u64 + 8 + 4;
        } else if entry.file_type().is_file() {
            let file_len = meta.len();
            writer.write_all(&[TAG_FILE])?;
            writer.write_all(&(rel_bytes.len() as u16).to_le_bytes())?;
            writer.write_all(rel_bytes)?;
            writer.write_all(&mtime_secs.to_le_bytes())?;
            writer.write_all(&mtime_nanos.to_le_bytes())?;
            writer.write_all(&file_len.to_le_bytes())?;
            total_bytes += 1 + 2 + rel_bytes.len() as u64 + 8 + 4 + 8 + file_len;

            let mut f = File::open(entry_path)
                .with_context(|| format!("could not open {}", entry_path.display()))?;
            std::io::copy(&mut f, &mut writer)
                .with_context(|| format!("could not read {}", entry_path.display()))?;
        }
    }

    writer.flush()?;
    Ok(total_bytes)
}

/// Unpack an archive stream into `dest_root`.
///
/// Creates all subdirectories, writes file contents, and restores timestamps.
pub fn unpack(reader: &mut dyn Read, dest_root: &Path) -> Result<usize> {
    let mut reader = BufReader::new(reader);

    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .context("archive is empty or truncated")?;
    if &magic != VDIR_MAGIC {
        bail!("not a valid vault directory archive (bad magic)");
    }

    let mut version = [0u8; 1];
    reader
        .read_exact(&mut version)
        .context("truncated archive header")?;
    if version[0] != VDIR_VERSION {
        bail!("unsupported archive version: {}", version[0]);
    }

    std::fs::create_dir_all(dest_root)
        .with_context(|| format!("could not create directory {}", dest_root.display()))?;

    let mut dirs_to_timestamp: Vec<(PathBuf, i64, u32)> = Vec::new();
    let mut file_count = 0usize;

    loop {
        let mut tag = [0u8; 1];
        match reader.read_exact(&mut tag) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).context("error reading archive entry tag"),
        }

        let mut len_buf = [0u8; 2];
        reader
            .read_exact(&mut len_buf)
            .context("truncated entry path length")?;
        let path_len = u16::from_le_bytes(len_buf) as usize;

        let mut path_bytes = vec![0u8; path_len];
        reader
            .read_exact(&mut path_bytes)
            .context("truncated entry path")?;
        let rel_str = String::from_utf8(path_bytes).context("invalid UTF-8 in entry path")?;

        let mut mtime_secs_buf = [0u8; 8];
        reader
            .read_exact(&mut mtime_secs_buf)
            .context("truncated entry mtime")?;
        let mtime_secs = i64::from_le_bytes(mtime_secs_buf);

        let mut mtime_nanos_buf = [0u8; 4];
        reader
            .read_exact(&mut mtime_nanos_buf)
            .context("truncated entry mtime nanos")?;
        let mtime_nanos = u32::from_le_bytes(mtime_nanos_buf);

        let target = dest_root.join(&rel_str);

        match tag[0] {
            TAG_DIR => {
                std::fs::create_dir_all(&target)
                    .with_context(|| format!("could not create directory {}", target.display()))?;
                dirs_to_timestamp.push((target, mtime_secs, mtime_nanos));
            }
            TAG_FILE => {
                let mut file_len_buf = [0u8; 8];
                reader
                    .read_exact(&mut file_len_buf)
                    .context("truncated file length")?;
                let file_len = u64::from_le_bytes(file_len_buf);

                if let Some(parent) = target.parent() {
                    if !parent.exists() {
                        std::fs::create_dir_all(parent).with_context(|| {
                            format!("could not create parent directory {}", parent.display())
                        })?;
                    }
                }

                let mut out_file = File::create(&target)
                    .with_context(|| format!("could not create file {}", target.display()))?;
                let mut limited = (&mut reader).take(file_len);
                let copied = std::io::copy(&mut limited, &mut out_file)
                    .with_context(|| format!("could not write file {}", target.display()))?;
                if copied != file_len {
                    bail!(
                        "truncated file data for {}: expected {file_len} bytes, got {copied}",
                        target.display()
                    );
                }
                out_file.flush()?;
                drop(out_file);

                let ft = filetime::FileTime::from_unix_time(mtime_secs, mtime_nanos);
                let _ = filetime::set_file_times(&target, ft, ft);
                file_count += 1;
            }
            other => bail!("corrupted archive: unknown entry tag {other}"),
        }
    }

    // Restore directory timestamps bottom-up so modifying children does not overwrite them.
    dirs_to_timestamp.sort_by_key(|(p, _, _)| std::cmp::Reverse(p.as_os_str().len()));
    for (dir_path, secs, nanos) in dirs_to_timestamp {
        let ft = filetime::FileTime::from_unix_time(secs, nanos);
        let _ = filetime::set_file_times(&dir_path, ft, ft);
    }

    Ok(file_count)
}

/// Peek at the entries in an archive without extracting files to disk.
/// Returns `Vec<(relative_path, size_in_bytes, is_directory)>`.
pub fn list_entries(reader: &mut dyn Read) -> Result<Vec<(String, u64, bool)>> {
    let mut reader = BufReader::new(reader);

    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .context("archive is empty or truncated")?;
    if &magic != VDIR_MAGIC {
        bail!("not a valid vault directory archive (bad magic)");
    }

    let mut version = [0u8; 1];
    reader
        .read_exact(&mut version)
        .context("truncated archive header")?;
    if version[0] != VDIR_VERSION {
        bail!("unsupported archive version: {}", version[0]);
    }

    let mut entries = Vec::new();

    loop {
        let mut tag = [0u8; 1];
        match reader.read_exact(&mut tag) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).context("error reading entry tag"),
        }

        let mut len_buf = [0u8; 2];
        reader
            .read_exact(&mut len_buf)
            .context("truncated path length")?;
        let path_len = u16::from_le_bytes(len_buf) as usize;

        let mut path_bytes = vec![0u8; path_len];
        reader
            .read_exact(&mut path_bytes)
            .context("truncated path")?;
        let rel_str = String::from_utf8(path_bytes).context("invalid UTF-8 in path")?;

        let mut mtime_buf = [0u8; 12];
        reader
            .read_exact(&mut mtime_buf)
            .context("truncated mtime")?;

        match tag[0] {
            TAG_DIR => {
                entries.push((rel_str, 0u64, true));
            }
            TAG_FILE => {
                let mut file_len_buf = [0u8; 8];
                reader
                    .read_exact(&mut file_len_buf)
                    .context("truncated file length")?;
                let file_len = u64::from_le_bytes(file_len_buf);
                entries.push((rel_str, file_len, false));
                std::io::copy(&mut (&mut reader).take(file_len), &mut std::io::sink())?;
            }
            other => bail!("unknown entry tag {other}"),
        }
    }

    Ok(entries)
}

fn mtime_of(meta: &std::fs::Metadata) -> (i64, u32) {
    match meta.modified() {
        Ok(t) => match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
            Err(e) => (
                -(e.duration().as_secs() as i64),
                e.duration().subsec_nanos(),
            ),
        },
        Err(_) => (0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_archive_empty_and_files() {
        let tmp = std::env::temp_dir().join(format!("vdir_test_{}", std::process::id()));
        let src = tmp.join("src");
        let dst = tmp.join("dst");

        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(src.join("sub/empty")).unwrap();
        std::fs::write(src.join("hello.txt"), b"Hello World").unwrap();
        std::fs::write(src.join("sub/nested.bin"), vec![42u8; 1024]).unwrap();

        let mut buf = Vec::new();
        let bytes_written = pack(&src, &mut buf).unwrap();
        assert!(bytes_written > 0);

        let entries = list_entries(&mut &buf[..]).unwrap();
        assert_eq!(entries.len(), 4); // sub, sub/empty, hello.txt, sub/nested.bin

        let count = unpack(&mut &buf[..], &dst).unwrap();
        assert_eq!(count, 2); // 2 files

        assert_eq!(
            std::fs::read(dst.join("hello.txt")).unwrap(),
            b"Hello World"
        );
        assert_eq!(
            std::fs::read(dst.join("sub/nested.bin")).unwrap(),
            vec![42u8; 1024]
        );
        assert!(dst.join("sub/empty").is_dir());

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
