$ErrorActionPreference = 'Stop'
$python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
$server = Join-Path $PSScriptRoot 'server.py'
if (-not (Test-Path -LiteralPath $python)) { throw 'Create .venv and install requirements.lock.txt first.' }
if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'config.json'))) { throw 'Run setup_receiver.py first.' }
if (Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue) {
    throw 'Port 8765 is already occupied. No duplicate receiver was started.'
}
$receiverProcess = Start-Process -FilePath $python -ArgumentList ('"' + $server + '"') -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $PSScriptRoot 'receiver.out.log') -RedirectStandardError (Join-Path $PSScriptRoot 'receiver.err.log')
Write-Output "Receiver launched as PID $($receiverProcess.Id). Check receiver.err.log if connection fails."
