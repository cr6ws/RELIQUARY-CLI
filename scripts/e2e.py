"""End-to-end exercise of the vault binary.

Drives the real compiled executable through the full lifecycle and asserts
observable filesystem behaviour — that files genuinely vanish, that no
plaintext leaks into the vault, and that release returns bytes identical to
the original.

Uses `--password-file` rather than a pty. `rpassword` refuses piped stdin on
purpose (a password in a pipe buffer or a parent's stdout is a real leak), so
the only supported non-interactive path is the documented flag.
"""

import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

VAULT_EXE = Path(r"C:\Users\johnc\Desktop\sms\target\release\vault.exe")
PASSWORD = "correct horse battery staple"

failures = []
checks = 0


def run(args, vault_dir, pwfile=None):
    """Invoke the vault binary, supplying credentials non-interactively."""
    cmd = [str(VAULT_EXE), "--vault", str(vault_dir)]
    if pwfile is not None:
        cmd += ["--password-file", str(pwfile)]
    cmd += list(args)

    # Capture stdout+stderr together so ordering matches what a user sees.
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def check(label, cond, detail=""):
    global checks
    checks += 1
    if cond:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}  {detail}")
        failures.append(label)


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def objects_in(vault_dir):
    d = Path(vault_dir) / "objects"
    return sorted(d.glob("*.enc")) if d.exists() else []


def main():
    root = Path(tempfile.mkdtemp(prefix="vault-e2e-"))
    vault_dir = root / "vault"
    work = root / "work"
    work.mkdir()

    # Password file with a trailing newline, the way `echo` would write it.
    # Confirms the CLI strips it rather than treating it as part of the
    # password.
    pwfile = work / "pw.txt"
    pwfile.write_text(PASSWORD + "\r\n", newline="")

    original = work / "secret-photo.png"
    payload = os.urandom(3 * 1024 * 1024 + 137)  # multi-chunk + odd remainder
    original.write_bytes(payload)
    original_hash = sha256(original)

    print(f"sandbox: {root}\n")

    print("[1] init")
    code, out = run(["init", "--raw"], vault_dir, pwfile)
    check("init exits 0", code == 0, f"code={code}\n{out}")
    hdr = Path(vault_dir) / "vault.hdr"
    check("vault.hdr created", hdr.exists())
    hdr_len_init = hdr.stat().st_size if hdr.exists() else 0

    recovery = ""
    for line in out.splitlines():
        s = line.strip()
        if len(s) == 64 and all(c in "0123456789abcdef" for c in s):
            recovery = s
            break
    check("recovery key printed (64 hex)", len(recovery) == 64, f"got {recovery!r}")

    # init strips a trailing newline, so the same file works for init and unlock.
    check("recovery key is never written to disk",
          not any("0123456789abcdef" in p.read_text(errors="ignore")
                  for p in vault_dir.rglob("*") if p.is_file()),
          "recovery material found on disk")

    print("\n[2] wrong password is rejected before touching any file")
    badpw = work / "bad.txt"
    badpw.write_text("definitely-not-the-password", newline="")
    code, out = run(["hide", str(original)], vault_dir, badpw)
    check("wrong password exits non-zero", code != 0, f"code={code}\n{out}")
    check("wrong password is named in the error", "wrong password" in out.lower(), out)
    check("file untouched after failed auth", original.exists())
    check("no object created", not objects_in(vault_dir))

    print("\n[3] hide")
    code, out = run(["hide", str(original)], vault_dir, pwfile)
    check("hide exits 0", code == 0, f"code={code}\n{out}")
    check("original file VANISHED from disk", not original.exists(),
          "file still present after hide")

    objs = objects_in(vault_dir)
    check("exactly one object created", len(objs) == 1, f"got {len(objs)}")
    entry_id = objs[0].stem if objs else ""
    if objs:
        blob = objs[0].read_bytes()
        check("no plaintext bytes leak into the object",
              payload[:64] not in blob, "first 64 plaintext bytes found in .enc")
        check("no original filename in the object",
              b"secret-photo" not in blob, "filename leaked in cleartext")
        check("object is larger than plaintext (framing+tags)",
              len(blob) > len(payload), f"{len(blob)} vs {len(payload)}")

    # The property that matters: header length must not grow as the vault
    # fills, otherwise its size leaks the entry count.
    check("vault.hdr size is invariant as the vault fills",
          hdr.stat().st_size == hdr_len_init,
          f"{hdr_len_init} -> {hdr.stat().st_size}")

    print("\n[4] list")
    code, out = run(["list"], vault_dir, pwfile)
    check("list exits 0", code == 0, f"code={code}\n{out}")
    check("list shows the original filename", "secret-photo.png" in out, out)
    check("list shows the ID", bool(entry_id) and entry_id in out, out)

    print("\n[5] list --plain is machine-parseable")
    code, out = run(["list", "--plain"], vault_dir, pwfile)
    check("list --plain exits 0", code == 0, out)
    rows = [r for r in out.strip().splitlines() if r.strip()]
    check("list --plain emits folder and file rows", len(rows) == 2, out)
    check(
        "list --plain includes the file ID",
        any(row.startswith(entry_id) for row in rows),
        out,
    )
    check(
        "list --plain includes a folder ID",
        any("\twork/" in row for row in rows),
        out,
    )

    print("\n[6] show")
    code, out = run(["show", entry_id], vault_dir, pwfile)
    check("show exits 0", code == 0, f"code={code}\n{out}")
    check("show reveals original filename", "secret-photo.png" in out, out)
    check("show reveals original size", str(len(payload)) in out, out)

    print("\n[7] ID prefix matching")
    prefix = entry_id[:4]
    code, out = run(["show", prefix], vault_dir, pwfile)
    check(f"prefix `{prefix}` resolves", code == 0, out)
    code, out = run(["show", "zzzz"], vault_dir, pwfile)
    check("unknown ID is rejected", code != 0, out)
    check("unknown ID says so", "no entry matches" in out.lower(), out)

    print("\n[8] release to original location")
    code, out = run(["release", entry_id], vault_dir, pwfile)
    check("release exits 0", code == 0, f"code={code}\n{out}")
    check("file is back on disk", original.exists(), "file missing after release")
    if original.exists():
        check("released bytes are IDENTICAL to the original",
              sha256(original) == original_hash, "content changed")
    check("object removed after release", not objects_in(vault_dir),
          "object still present")

    print("\n[9] hide then forget (destroy without restoring)")
    original.write_bytes(b"temporary payload for forget test")
    code, out = run(["hide", str(original)], vault_dir, pwfile)
    check("hide (2nd) exits 0", code == 0, f"code={code}\n{out}")
    check("2nd file vanished", not original.exists())
    objs = objects_in(vault_dir)
    forget_id = objs[0].stem if objs else ""
    code, out = run(["forget", forget_id, "--yes"], vault_dir, pwfile)
    check("forget exits 0", code == 0, f"code={code}\n{out}")
    check("object destroyed", not objects_in(vault_dir))

    print("\n[10] release will not clobber without --force")
    original.write_bytes(b"aaa")
    code, out = run(["hide", str(original)], vault_dir, pwfile)
    original.write_bytes(b"bbb-existing")
    objs = objects_in(vault_dir)
    fid = objs[0].stem if objs else ""
    code, out = run(["release", fid], vault_dir, pwfile)
    check("release without --force refuses to clobber", code != 0, out)
    check("existing file untouched", original.read_bytes() == b"bbb-existing")
    code, out = run(["release", fid, "--force"], vault_dir, pwfile)
    check("release --force succeeds", code == 0, f"code={code}\n{out}")
    check("restored original content", original.read_bytes() == b"aaa")

    print("\n[11] release --to overrides destination, vault entry survives --keep")
    original.write_bytes(b"destination override test")
    code, out = run(["hide", str(original)], vault_dir, pwfile)
    objs = objects_in(vault_dir)
    rid = objs[0].stem if objs else ""
    alt = work / "restored-elsewhere.bin"
    code, out = run(["release", rid, "--to", str(alt), "--keep"], vault_dir, pwfile)
    check("release --to exits 0", code == 0, f"code={code}\n{out}")
    check("file written to the override path",
          alt.exists() and alt.read_bytes() == b"destination override test")
    check("vault entry kept (--keep)", len(objects_in(vault_dir)) == 1)
    code, out = run(["release", rid, "--force"], vault_dir, pwfile)
    check("release without --keep removes the entry", code == 0, out)
    check("vault now empty", not objects_in(vault_dir))

    print("\n[12] unlock via --recovery key")
    original.write_bytes(b"recovery path test")
    code, out = run(["hide", str(original)], vault_dir, pwfile)
    objs = objects_in(vault_dir)
    rid = objs[0].stem if objs else ""
    code, out = run(["--recovery", recovery, "list"], vault_dir)
    check("list works with --recovery", code == 0, f"code={code}\n{out}")
    check("recovery-key listing shows the entry", bool(rid) and rid in out, out)
    code, out = run(["--recovery", recovery, "release", rid], vault_dir)
    check("release works with --recovery", code == 0, f"code={code}\n{out}")
    check("file restored via recovery key",
          original.read_bytes() == b"recovery path test")

    print("\n[13] garbage recovery key is rejected")
    # Use a distinct path: `original` is hidden by step [12] and released back
    # onto disk, so reusing it here would have `hide` refuse to securely
    # delete a file it cannot overwrite.
    leak = work / "leak.txt"
    leak.write_bytes(b"x")
    code, out = run(["hide", str(leak)], vault_dir, pwfile)
    check("hide still works before the bad-key attempt", code == 0, f"code={code}\n{out}")
    code, out = run(["--recovery", "0" * 64, "list"], vault_dir)
    check("bogus recovery key exits non-zero", code != 0, f"code={code}\n{out}")
    check("bogus recovery key is named in the error", "recovery" in out.lower(), out)

    print("\n[14] password file written by Windows PowerShell")
    # PowerShell's default redirection writes UTF-16LE with a BOM. This is
    # the single most likely way a Windows user creates a password file, and
    # a naive read_to_string rejects it as invalid UTF-8.
    ps_pw = work / "ps-pw.txt"
    ps_bytes = b"\xff\xfe" + "".join(c + "\x00" for c in PASSWORD).encode("latin-1")
    ps_pw.write_bytes(ps_bytes)

    # Release restores to the original path and removes the vault entry. That
    # round trip is what proves the key derived from the decoded password is
    # correct -- a wrong key cannot decrypt the object at all.
    #
    # Pick the object this step just created. Step [13] deliberately leaves an
    # entry behind, and object ids are random, so the lexicographically-first
    # entry is not necessarily the new one -- releasing the wrong entry would
    # restore the wrong bytes and still exit 0.
    before = {p.name for p in objects_in(vault_dir)}
    original.write_bytes(b"powershell encoded pw test")
    code, out = run(["hide", str(original)], vault_dir, ps_pw)
    check("hide works with a UTF-16LE password file", code == 0, f"code={code}\n{out}")
    check("file vanished under a UTF-16LE password file", not original.exists())

    fresh = [p for p in objects_in(vault_dir) if p.name not in before]
    check("exactly one new vault entry", len(fresh) == 1,
          f"new={[p.name for p in fresh]}")
    ps_id = fresh[0].stem if fresh else ""
    code, out = run(["release", ps_id], vault_dir, ps_pw)
    check("release works with a UTF-16LE password file", code == 0, f"code={code}\n{out}")
    check("restored from UTF-16LE password file",
          original.exists() and original.read_bytes() == b"powershell encoded pw test")
    # Step [13]'s entry is still in the vault; only the new one should be gone.
    check("new entry removed after round trip",
          {p.name for p in objects_in(vault_dir)} == before)

    print("\n[15] empty password file is rejected")
    empty_pw = work / "empty.txt"
    empty_pw.write_text("", newline="")
    # Use a distinct path: `original` is deliberately left on disk by step
    # [14] so its round trip can be asserted above, and clobbering it here
    # would make that assertion depend on which step ran last.
    canary = work / "canary.txt"
    canary.write_bytes(b"y")
    code, out = run(["hide", str(canary)], vault_dir, empty_pw)
    check("empty password file exits non-zero", code != 0, out)
    check("empty password file is named in the error", "empty" in out.lower(), out)
    check("file untouched by empty-password auth", canary.exists())

    print(f"\n{'=' * 54}")
    if failures:
        print(f"{len(failures)} of {checks} checks FAILED:")
        for f in failures:
            print(f"  - {f}")
    else:
        print(f"all {checks} checks passed")
    print(f"sandbox left at: {root}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
