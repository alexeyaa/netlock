# --- NetLock: install.ps1 ---
$ErrorActionPreference = "Stop"

# Админ-права
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Write-Error "Запусти PowerShell от имени администратора."
  exit 1
}

$Base = "C:\ProgramData\NetLock"
New-Item -ItemType Directory -Path $Base -Force | Out-Null

$LockScript     = Join-Path $Base "lock.ps1"
$UnlockScript   = Join-Path $Base "unlock.ps1"
$ApplyScript    = Join-Path $Base "apply-mode.ps1"
$PrelockWfw     = Join-Path $Base "prelock.wfw"
$ModeFile       = Join-Path $Base "mode.txt"

$TaskLockXml        = Join-Path $Base "task_lock.xml"
$TaskUnlockXml      = Join-Path $Base "task_unlock.xml"
$TaskRemoteConnXml  = Join-Path $Base "task_remote_connect.xml"
$TaskRemoteDiscXml  = Join-Path $Base "task_remote_disconnect.xml"
$TaskStartupXml     = Join-Path $Base "task_startup.xml"

# -------- lock.ps1 (разрешено только RDP + Mullvad), идемпотентный --------
@'
$ErrorActionPreference = "Stop"
$Base     = "C:\ProgramData\NetLock"
$Pre      = Join-Path $Base "prelock.wfw"
$ModeFile = Join-Path $Base "mode.txt"

# Если уже "locked" — выходим
if (Test-Path $ModeFile) {
  $cur = (Get-Content $ModeFile -ErrorAction SilentlyContinue) -join ''
  if ($cur -eq 'locked') { exit 0 }
}

# Сохраним текущую конфигурацию фаервола (один раз)
if (-not (Test-Path $Pre)) {
  netsh advfirewall export "$Pre" | Out-Null
}

# Включим группу RDP и дублирующее правило
netsh advfirewall firewall set rule group="Remote Desktop" new enable=Yes | Out-Null
netsh advfirewall firewall delete rule name="NetLock Allow RDP Inbound" | Out-Null
netsh advfirewall firewall add rule name="NetLock Allow RDP Inbound" dir=in action=allow protocol=TCP localport=3389 profile=any | Out-Null

# Найдём Mullvad/туннельные процессы
$pf = ${env:ProgramFiles}
$pf86 = ${env:ProgramFiles(x86)}
$SearchRoots = @(); if ($pf){$SearchRoots+=$pf}; if($pf86){$SearchRoots+=$pf86}
$names = @("mullvad.exe","mullvad-daemon.exe","openvpn.exe","wg.exe","wireguard.exe")
$Candidates = @()
foreach ($root in $SearchRoots) {
  $names | ForEach-Object {
    Get-ChildItem -Path $root -Recurse -Filter $_ -ErrorAction SilentlyContinue |
      ForEach-Object { $Candidates += $_.FullName }
  }
}
$Candidates = $Candidates | Select-Object -Unique

# Пересоздадим наши allow-правила
foreach ($rn in @(
  "NetLock Allow Mullvad Outbound",
  "NetLock Allow WireGuard Outbound",
  "NetLock Allow OpenVPN Outbound",
  "NetLock Allow OpenVPN Outbound (TCP)")
) { netsh advfirewall firewall delete rule name="$rn" | Out-Null }

foreach ($app in $Candidates) {
  netsh advfirewall firewall add rule name="NetLock Allow Mullvad Outbound" dir=out action=allow program="$app" enable=yes profile=any | Out-Null
}

# Частые порты туннелей
netsh advfirewall firewall add rule name="NetLock Allow WireGuard Outbound" dir=out action=allow protocol=UDP remoteport=51820 profile=any | Out-Null
netsh advfirewall firewall add rule name="NetLock Allow OpenVPN Outbound" dir=out action=allow protocol=UDP remoteport=1194 profile=any | Out-Null
netsh advfirewall firewall add rule name="NetLock Allow OpenVPN Outbound (TCP)" dir=out action=allow protocol=TCP remoteport=1194,443 profile=any | Out-Null

# Политики: всё блокируем
netsh advfirewall set domainprofile  firewallpolicy blockinbound,blockoutbound | Out-Null
netsh advfirewall set privateprofile firewallpolicy blockinbound,blockoutbound | Out-Null
netsh advfirewall set publicprofile  firewallpolicy blockinbound,blockoutbound | Out-Null

# Отметим состояние
Set-Content -Path $ModeFile -Value 'locked' -Encoding ASCII
'@ | Set-Content -Path $LockScript -Encoding UTF8

# -------- unlock.ps1 (восстановление), идемпотентный --------
@"
`$ErrorActionPreference = "Stop"
`$Base     = "C:\ProgramData\NetLock"
`$Pre      = Join-Path `$Base "prelock.wfw"
`$ModeFile = Join-Path `$Base "mode.txt"

# Если уже "unlocked" — выходим
if (Test-Path `$ModeFile) {
  `$cur = (Get-Content `$ModeFile -ErrorAction SilentlyContinue) -join ''
  if (`$cur -eq 'unlocked') { exit 0 }
}

if (Test-Path `$Pre) {
  netsh advfirewall import "`$Pre" | Out-Null
  Remove-Item -Path "`$Pre" -Force -ErrorAction SilentlyContinue
} else {
  netsh advfirewall set domainprofile  firewallpolicy blockinbound,allowoutbound | Out-Null
  netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound | Out-Null
  netsh advfirewall set publicprofile  firewallpolicy blockinbound,allowoutbound | Out-Null
}

Set-Content -Path "`$ModeFile" -Value 'unlocked' -Encoding ASCII
"@ | Set-Content -Path $UnlockScript -Encoding UTF8

# -------- apply-mode.ps1 (мьютекс + дебаунс + лог) --------
@'
$ErrorActionPreference = "Stop"

$Base    = "C:\ProgramData\NetLock"
$Lock    = Join-Path $Base "lock.ps1"
$Unlock  = Join-Path $Base "unlock.ps1"
$LogPath = Join-Path $Base "netlock.log"

function Log([string]$m) { "$(Get-Date -Format o) $m" | Add-Content -Path $LogPath -ErrorAction SilentlyContinue }

function Test-WorkstationLocked {
  try {
    $sig = @"
using System;
using System.Runtime.InteropServices;
public class L {
  [DllImport("user32.dll")] public static extern bool OpenInputDesktop(uint dwFlags, bool fInherit, uint dwDesiredAccess);
  [DllImport("user32.dll")] public static extern IntPtr OpenDesktop(string lpszDesktop, uint dwFlags, bool fInherit, uint dwDesiredAccess);
  [DllImport("user32.dll")] public static extern bool SwitchDesktop(IntPtr hDesktop);
}
"@
    Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue | Out-Null
    $h = [L]::OpenDesktop("Default",0,$false,0x100)
    if ($h -ne [IntPtr]::Zero) { return -not [L]::SwitchDesktop($h) } else { return $false }
  } catch { return $false }
}

function Test-ActiveRdpSession {
  $rdpActive = $false
  try {
    $out = (qwinsta.exe) 2>$null
    if ($out) { $rdpActive = ($out | Select-String -SimpleMatch "rdp-tcp") -and ($out | Select-String -SimpleMatch "Active") }
  } catch { }
  if (-not $rdpActive) {
    try {
      $out = (quser.exe) 2>$null
      if ($out) { $rdpActive = ($out | Select-String -SimpleMatch "rdp-tcp") -and ($out | Select-String -SimpleMatch "Active") }
    } catch { }
  }
  return [bool]$rdpActive
}

# Глобальный мьютекс (межпроцессный, межсессионный)
$mutex = New-Object System.Threading.Mutex($false, "Global\NetLockMutex")
$got = $mutex.WaitOne(20000)  # 20 секунд таймаут, чтобы не зависнуть
if (-not $got) { Log "mutex timeout"; exit 0 }

try {
  # Небольшой дебаунс, чтобы схлопнуть быстрые флуктуации
  Start-Sleep -Milliseconds 800

  $locked = Test-WorkstationLocked
  $rdp    = Test-ActiveRdpSession

  # логику держим "последнее слово за текущим снимком"
  $doUnlock = (-not $locked) -or $rdp
  $action = if ($doUnlock) { "unlock" } else { "lock" }
  Log "state: locked=$locked rdp=$rdp -> $action"

  if ($doUnlock) {
    powershell -NoProfile -ExecutionPolicy Bypass -File $Unlock | Out-Null
  } else {
    powershell -NoProfile -ExecutionPolicy Bypass -File $Lock   | Out-Null
  }
}
finally {
  $mutex.ReleaseMutex() | Out-Null
}
'@ | Set-Content -Path $ApplyScript -Encoding UTF8

# -------- Задачи Планировщика --------
$author  = "$env:UserName"
$UserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

function New-TaskXml {
param([string]$stateChange,[string]$desc)
@"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>$author</Author><Description>$desc</Description></RegistrationInfo>
  <Triggers>
    <SessionStateChangeTrigger><Enabled>true</Enabled><StateChange>$stateChange</StateChange></SessionStateChangeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$UserSid</UserId>
      <RunLevel>HighestAvailable</RunLevel>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>
    <ExecutionTimeLimit>PT2M</ExecutionTimeLimit>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -File "$ApplyScript"</Arguments>
      <WorkingDirectory>$Base</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@
}

# XML для логон-триггера (упростим старт)
@"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>$author</Author><Description>NetLock: apply at logon</Description></RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><Delay>PT10S</Delay></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$UserSid</UserId>
      <RunLevel>HighestAvailable</RunLevel>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>
    <ExecutionTimeLimit>PT2M</ExecutionTimeLimit>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -File "$ApplyScript"</Arguments>
      <WorkingDirectory>$Base</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@ | Set-Content -Path $TaskStartupXml -Encoding Unicode

# Чистим возможные старые задачи (тихо)
function Remove-TaskIfExists {
  param([string]$Name)
  cmd /c "schtasks /Query /TN ""$Name"" >NUL 2>&1"
  if ($LASTEXITCODE -eq 0) {
    cmd /c "schtasks /Delete /TN ""$Name"" /F >NUL 2>&1"
  }
}
Remove-TaskIfExists "NetLock\OnLock_Apply"
Remove-TaskIfExists "NetLock\OnUnlock_Apply"
Remove-TaskIfExists "NetLock\OnRemoteConnect_Apply"
Remove-TaskIfExists "NetLock\OnRemoteDisconnect_Apply"
Remove-TaskIfExists "NetLock\AtStartup_Apply"

# Генерим XML задач
(New-TaskXml -stateChange "SessionLock"       -desc "NetLock: apply on lock")              | Set-Content -Path $TaskLockXml -Encoding Unicode
(New-TaskXml -stateChange "SessionUnlock"     -desc "NetLock: apply on unlock")            | Set-Content -Path $TaskUnlockXml -Encoding Unicode
(New-TaskXml -stateChange "RemoteConnect"     -desc "NetLock: apply on remote connect")    | Set-Content -Path $TaskRemoteConnXml -Encoding Unicode
(New-TaskXml -stateChange "RemoteDisconnect"  -desc "NetLock: apply on remote disconnect") | Set-Content -Path $TaskRemoteDiscXml -Encoding Unicode

# Регистрируем/обновляем задачи
schtasks /Create /TN "NetLock\OnLock_Apply"             /XML "$TaskLockXml"        /F | Out-Null
schtasks /Create /TN "NetLock\OnUnlock_Apply"           /XML "$TaskUnlockXml"      /F | Out-Null
schtasks /Create /TN "NetLock\OnRemoteConnect_Apply"    /XML "$TaskRemoteConnXml"  /F | Out-Null
schtasks /Create /TN "NetLock\OnRemoteDisconnect_Apply" /XML "$TaskRemoteDiscXml"  /F | Out-Null
schtasks /Create /TN "NetLock\AtStartup_Apply"          /XML "$TaskStartupXml"     /F | Out-Null

Write-Host "NetLock установлен. Контроллер: $ApplyScript"
Write-Host "Задачи: OnLock/OnUnlock/RemoteConnect/RemoteDisconnect/AtStartup"
Write-Host "Готово. Заблокируй экран (Win+L) для проверки."
