param(
    [Parameter(Mandatory=$true)][string]$Runtime,
    [Parameter(Mandatory=$true)][string]$PythonExe
)
$ErrorActionPreference = 'Stop'
$runtimePath = [IO.Path]::GetFullPath($Runtime)
$pythonwPath = Join-Path (Split-Path -Parent $PythonExe) 'pythonw.exe'
$managerPath = Join-Path $PSScriptRoot 'ssh_manager.py'
if (-not (Test-Path -LiteralPath $pythonwPath) -or -not (Test-Path -LiteralPath $managerPath)) {
    throw 'Python or manager script is missing.'
}
$configPath = Join-Path $runtimePath 'config.json'
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$taskName = $config.task_name
if ($taskName -notmatch '^PersistentSSH-[a-f0-9]{20}$') { throw 'Invalid task name in profile' }
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$arguments = '"' + $managerPath + '" --runtime "' + $runtimePath + '" _serve'
$action = New-ScheduledTaskAction -Execute $pythonwPath -Argument $arguments -WorkingDirectory $PSScriptRoot
$principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Actions.Execute -ne $pythonwPath -or $existing.Actions.Arguments -ne $arguments) {
        throw 'A task with this name already points elsewhere. Inspect it before replacing it.'
    }
} else {
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Description 'Persistent SSH: on-demand local connection broker. No automatic login; serves the current user through an authenticated local pipe.' | Out-Null
}
Start-ScheduledTask -TaskName $taskName
Write-Output $taskName
