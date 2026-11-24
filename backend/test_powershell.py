
import subprocess

script = r"""
$ErrorActionPreference = 'Stop'

$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624, 4625
} -MaxEvents 10

ConvertTo-Json -InputObject @($events) -Depth 4 -Compress
"""

result = subprocess.run(
    [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        script,
    ],
    capture_output=True,
    text=True,
    timeout=30,
    check=False,
)

print("Return code:", result.returncode)
print("STDOUT:", result.stdout[:1000])
print("STDERR:", result.stderr[:1000])
