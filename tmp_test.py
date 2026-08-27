import tempfile, os, subprocess
code = 'class X { void f() { Runtime.getRuntime().exec("make"); } }'
path = os.path.join(tempfile.gettempdir(), 'TestTokens.java')
with open(path, 'w') as f: f.write(code)
result = subprocess.run(
    ['dotnet', 'run', '--no-build', '--project', 'src/QualityGuard.Cli', '--', '--path', path, '--all-rules'],
    capture_output=True, text=True, timeout=30,
    cwd=r'C:\Sorgenti\Personal\QualityGuard'
)
for line in result.stdout.split('\n'):
    if 'SEC-' in line or 'ISSUE' in line:
        print(line)
os.unlink(path)
