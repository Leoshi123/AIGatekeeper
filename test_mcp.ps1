$ErrorActionPreference = 'Stop'
$p = Start-Process -FilePath 'python' -ArgumentList '-m','src.mcp_server' -WorkingDirectory 'C:\Users\leosh\OneDrive\Documents\AIGatekeeper' -PassThru -NoNewWindow
Start-Sleep -Seconds 3
if ($p.HasExited) {
    Write-Host "Process exited with code: $($p.ExitCode)"
} else {
    Write-Host "Process is running with PID: $($p.Id)"
    Stop-Process $p.Id -Force
}
