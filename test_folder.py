import subprocess, tempfile, shutil, os
from pathlib import Path

exe = Path('target/release/vault.exe').resolve()
tmp = Path(tempfile.mkdtemp(prefix='test_folder_'))
vault_dir = tmp / 'vault'
pwfile = tmp / 'pw.txt'
pwfile.write_text('SecretPassword123!', encoding='utf-8')

# 1. init
subprocess.run([str(exe), '--vault', str(vault_dir), '--password-file', str(pwfile), 'init', '--raw'], check=True)

# 2. create folder with nested files
test_folder = tmp / 'my_backup'
test_folder.mkdir()
(test_folder / 'file1.txt').write_text('content 1')
(test_folder / 'sub').mkdir()
(test_folder / 'sub' / 'file2.txt').write_text('content 2 in sub')

print('Created test files:')
assert (test_folder / 'file1.txt').exists()
assert (test_folder / 'sub' / 'file2.txt').exists()

# 3. hide folder
res = subprocess.run([str(exe), '--vault', str(vault_dir), '--password-file', str(pwfile), 'hide', str(test_folder)], capture_output=True, text=True, check=True)
print('Hide output:\n' + res.stdout)
assert not test_folder.exists(), 'Folder should have vanished!'

# 4. list
res = subprocess.run([str(exe), '--vault', str(vault_dir), '--password-file', str(pwfile), 'list'], capture_output=True, text=True, check=True)
print('List output:\n' + res.stdout)
assert 'my_backup/' in res.stdout, 'my_backup/ should be in list!'

# extract folder ID
lines = [l for l in res.stdout.splitlines() if 'my_backup/' in l]
folder_id = lines[0].split()[0]
print('Folder ID is:', folder_id)

# 5. show folder
res = subprocess.run([str(exe), '--vault', str(vault_dir), '--password-file', str(pwfile), 'show', folder_id], capture_output=True, text=True, check=True)
print('Show output:\n' + res.stdout)
assert 'Folder' in res.stdout

# 6. release folder
res = subprocess.run([str(exe), '--vault', str(vault_dir), '--password-file', str(pwfile), 'release', folder_id], capture_output=True, text=True, check=True)
print('Release output:\n' + res.stdout)
assert test_folder.exists(), 'Folder should be restored!'
assert (test_folder / 'file1.txt').read_text() == 'content 1'
assert (test_folder / 'sub' / 'file2.txt').read_text() == 'content 2 in sub'
print('RELEASE VERIFIED! ALL NESTED FILES RESTORED!')

# Clean up
shutil.rmtree(tmp)
print('ALL TEST STEPS PASSED SUCCESSFULLY!')
