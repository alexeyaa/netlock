<#
 NetLock Unified Script
 Usage:
   .\netlock.ps1 install     - create/update scheduled tasks and default config
   .\netlock.ps1 uninstall   - remove scheduled tasks (optionally keep data)
   .\netlock.ps1 lock        - apply locked firewall state (JSON driven)
   .\netlock.ps1 unlock      - restore previous firewall state / allow outbound
   .\netlock.ps1 apply       - controller: auto decide lock/unlock (mutexed)
   .\netlock.ps1 help        - show this help

 All state + config lives in C:\ProgramData\NetLock\data
 JSON rules file: netlock-rules.json
#>
param(
  [Parameter(Position=0)][ValidateSet('install','uninstall','lock','unlock','apply','help','update')]
  [string]$Action = 'help',
  [switch]$Force,
  [switch]$Purge # for uninstall: also remove data files
)
$ErrorActionPreference = 'Stop'

function Write-Info($m){ Write-Host "[NetLock] $m" }
function Write-Warn($m){ Write-Warning "[NetLock] $m" }
function Write-Err($m){ Write-Error "[NetLock] $m" }

function Test-Admin {
  if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    throw 'Требуются права администратора.'
  }
}

function Get-Paths {
  $base = 'C:\ProgramData\NetLock'
  $data = Join-Path $base 'data'
  return [pscustomobject]@{
    Base=$base
    Data=$data
    Pre = Join-Path $data 'prelock.wfw'
    ModeFile = Join-Path $data 'mode.txt'
    Log = Join-Path $data 'netlock.log'
    Rules = Join-Path $data 'netlock-rules.json'
    LegacyPrograms = Join-Path $data 'allow-programs.json'
    TaskLock = Join-Path $data 'task_lock.xml'
    TaskUnlock = Join-Path $data 'task_unlock.xml'
    TaskRemoteConnect = Join-Path $data 'task_remote_connect.xml'
    TaskRemoteDisconnect = Join-Path $data 'task_remote_disconnect.xml'
    TaskStartup = Join-Path $data 'task_startup.xml'
  }
}

# --- Logging with rotation ---
$Global:NetLock_LogMaxBytes = 200KB
$Global:NetLock_LogKeep = 5
function Write-Log {
  param([string]$Message,[string]$Level='INFO',[switch]$NoConsole)
  $paths = Get-Paths
  if (-not (Test-Path $paths.Data)) { New-Item -ItemType Directory -Path $paths.Data -Force | Out-Null }
  $file = $paths.Log
  # rotation
  try {
    if (Test-Path $file) {
      $len = (Get-Item $file).Length
      if ($len -ge $Global:NetLock_LogMaxBytes) {
        for ($i=$Global:NetLock_LogKeep-1; $i -ge 1; $i--) {
          $src = "$file.$i"
          $dst = "$file." + ($i+1)
          if (Test-Path $src) { Move-Item -Path $src -Destination $dst -Force -ErrorAction SilentlyContinue }
        }
        Move-Item -Path $file -Destination "$file.1" -Force -ErrorAction SilentlyContinue
      }
    }
  } catch {}
  $line = "$(Get-Date -Format o) [$Level] $Message"
  try { Add-Content -Path $file -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
  if (-not $NoConsole) { Write-Host "[NetLock] $Message" }
}

function New-DefaultRulesConfig {
  $default = @{
    version = 1
    rules = @(
      @{ type='port'; name='RDP Inbound'; enabled=$true; direction='in'; action='allow'; protocol='TCP'; localPorts='3389'; profile='any' },
      @{ type='programSearch'; name='Mullvad/ WireGuard / OpenVPN Processes'; enabled=$true; direction='out'; action='allow'; filenames=@('mullvad.exe','mullvad-daemon.exe','openvpn.exe','wg.exe','wireguard.exe'); searchRootsEnv=@('ProgramFiles','ProgramFiles(x86)'); profile='any' },
      @{ type='port'; name='WireGuard UDP'; enabled=$true; direction='out'; action='allow'; protocol='UDP'; remotePorts='51820'; profile='any' },
      @{ type='port'; name='OpenVPN UDP'; enabled=$true; direction='out'; action='allow'; protocol='UDP'; remotePorts='1194'; profile='any' },
      @{ type='port'; name='OpenVPN TCP'; enabled=$true; direction='out'; action='allow'; protocol='TCP'; remotePorts='1194,443'; profile='any' },
      @{ type='program'; name='Resilio Sync'; enabled=$true; direction='out'; action='allow'; program='C:\\Users\\alexey\\AppData\\Roaming\\Resilio Sync\\Resilio Sync.exe'; profile='any' },
      @{ type='program'; name='Kopia'; enabled=$true; direction='out'; action='allow'; program='C:\\Program Files\\KopiaUI\\resources\\server\\kopia.exe'; profile='any' }
    )
    policy = @{ setBlockAll = $true }
  }
  return ($default | ConvertTo-Json -Depth 8)
}

function Get-NetLockConfig($paths) {
  if (-not (Test-Path $paths.Data)) { New-Item -ItemType Directory -Path $paths.Data -Force | Out-Null }
  if (-not (Test-Path $paths.Rules)) {
    $cfg = New-DefaultRulesConfig
    # migrate legacy simple list
    if (Test-Path $paths.LegacyPrograms) {
      try {
        $legacy = Get-Content -Raw -Path $paths.LegacyPrograms | ConvertFrom-Json -ErrorAction Stop
        if ($legacy.programs) {
          $json = $cfg | ConvertFrom-Json
          foreach ($p in ($legacy.programs | Where-Object { $_ })) {
            $json.rules += @{ type='program'; name=(Split-Path $p -Leaf); enabled=$true; direction='out'; action='allow'; program=$p; profile='any' }
          }
          $cfg = ($json | ConvertTo-Json -Depth 8)
        }
      } catch { }
    }
    Set-Content -Path $paths.Rules -Value $cfg -Encoding UTF8 -ErrorAction SilentlyContinue
  }
  try { return Get-Content -Raw -Path $paths.Rules | ConvertFrom-Json -ErrorAction Stop } catch { return (New-DefaultRulesConfig | ConvertFrom-Json) }
}

function Invoke-Lock($paths,[switch]$FullCleanup) {
  Test-Admin
  $ModeFile = $paths.ModeFile
  if (Test-Path $ModeFile) {
    try { if ((Get-Content $ModeFile -ErrorAction SilentlyContinue) -eq 'locked') { return } } catch {}
  }
  $Config = Get-NetLockConfig $paths
  $Rules = @(); if ($Config.rules){ $Rules = $Config.rules }
  if (-not (Test-Path $paths.Pre)) { netsh advfirewall export "$($paths.Pre)" | Out-Null }
  netsh advfirewall firewall set rule group="Remote Desktop" new enable=Yes | Out-Null

  if ($FullCleanup) {
    # Удаляем ВСЕ старые правила NetLock* перед пересозданием
    try {
      $existing = (netsh advfirewall firewall show rule name=all) 2>$null
      if ($existing) {
        $toDelete = @()
        foreach ($line in $existing) { if ($line -match '^Rule Name:\s*(.+)$') { $rn = $Matches[1].Trim(); if ($rn -like 'NetLock *') { $toDelete += $rn } } }
        $toDelete = $toDelete | Select-Object -Unique
        foreach ($d in $toDelete) { netsh advfirewall firewall delete rule name="$d" | Out-Null }
        Write-Log ("Full cleanup removed {0} rule(s)" -f $toDelete.Count) 'CLEAN'
      }
    } catch { }
  }
  $planned = New-Object System.Collections.Generic.HashSet[string]
  $expanded = @()
  foreach ($r in $Rules) {
    if (-not $r) { continue }
    $enabled = $true; if ($r.PSObject.Properties.Name -contains 'enabled'){ $enabled = [bool]$r.enabled }
    $type = $r.type; if (-not $type) { continue }
    switch ($type) {
      'program' {
        if ($r.program -and (Test-Path $r.program)) {
          $ruleName = 'NetLock ' + $r.name
          $expanded += [pscustomobject]@{ name=$ruleName; enabled=$enabled; dir=$r.direction; action=$r.action; program=$r.program; profile=$r.profile }
          $planned.Add($ruleName) | Out-Null
        }
      }
      'programSearch' {
        $filenames = @(); if ($r.filenames){ $filenames = @($r.filenames) }
        if ($filenames.Count -eq 0){ continue }
        $roots=@()
        if ($r.searchRootsEnv){ foreach($envName in $r.searchRootsEnv){ $val=[Environment]::GetEnvironmentVariable($envName); if($val){ $roots+=$val } } }
        if ($r.searchRoots){ $roots += @($r.searchRoots) }
        $found=@()
        foreach($root in $roots | Where-Object { $_ -and (Test-Path $_) }){
          foreach($fn in $filenames){ try { Get-ChildItem -Path $root -Recurse -Filter $fn -ErrorAction SilentlyContinue | ForEach-Object { $found += $_.FullName } } catch {} }
        }
        $found = $found | Select-Object -Unique
        foreach($f in $found){
          $ruleName = 'NetLock ' + $r.name + ': ' + (Split-Path $f -Leaf)
          $expanded += [pscustomobject]@{ name=$ruleName; enabled=$enabled; dir=$r.direction; action=$r.action; program=$f; profile=$r.profile }
          $planned.Add($ruleName) | Out-Null
        }
      }
      'port' {
        $ruleName = 'NetLock ' + $r.name
        $expanded += [pscustomobject]@{ name=$ruleName; enabled=$enabled; dir=$r.direction; action=$r.action; protocol=$r.protocol; localPorts=$r.localPorts; remotePorts=$r.remotePorts; profile=$r.profile }
        $planned.Add($ruleName) | Out-Null
      }
    }
  }
  foreach($n in $planned){ netsh advfirewall firewall delete rule name="$n" | Out-Null }
  foreach($er in $expanded){
    if (-not $er.enabled){ continue }
     $cmd = ('netsh advfirewall firewall add rule name="{0}" dir={1} action={2} profile={3} enable=yes' -f $er.name,$er.dir,$er.action,$er.profile)
     if ($er.program){ $cmd += ' program="' + $er.program + '"' }
     if ($er.protocol){ $cmd += ' protocol=' + $er.protocol }
     if ($er.localPorts){ $cmd += ' localport=' + $er.localPorts }
     if ($er.remotePorts){ $cmd += ' remoteport=' + $er.remotePorts }
     Invoke-Expression $cmd | Out-Null
  }
  if ($Config.policy -and $Config.policy.setBlockAll){
    netsh advfirewall set domainprofile  firewallpolicy blockinbound,blockoutbound | Out-Null
    netsh advfirewall set privateprofile firewallpolicy blockinbound,blockoutbound | Out-Null
    netsh advfirewall set publicprofile  firewallpolicy blockinbound,blockoutbound | Out-Null
  }
  Set-Content -Path $ModeFile -Value 'locked' -Encoding ASCII
  Write-Log ('Applied locked state' + ($(if($FullCleanup){' (full cleanup)'}))) 'STATE'
}

function Invoke-Unlock($paths){
  Test-Admin
  $ModeFile = $paths.ModeFile
  if (Test-Path $ModeFile){ try { if ((Get-Content $ModeFile -ErrorAction SilentlyContinue) -eq 'unlocked'){ return } } catch {} }
  if (Test-Path $paths.Pre){
    netsh advfirewall import "$($paths.Pre)" | Out-Null
    Remove-Item -Path $paths.Pre -Force -ErrorAction SilentlyContinue
  } else {
    netsh advfirewall set domainprofile  firewallpolicy blockinbound,allowoutbound | Out-Null
    netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound | Out-Null
    netsh advfirewall set publicprofile  firewallpolicy blockinbound,allowoutbound | Out-Null
  }
  Set-Content -Path $ModeFile -Value 'unlocked' -Encoding ASCII
  Write-Log 'Restored (unlocked) state.' 'STATE'
}

function Test-WorkstationLocked {
  try {
    $sig = @'
using System;using System.Runtime.InteropServices;public class L { [DllImport("user32.dll")] public static extern bool OpenInputDesktop(uint a,bool b,uint c); [DllImport("user32.dll")] public static extern IntPtr OpenDesktop(string d,uint e,bool f,uint g); [DllImport("user32.dll")] public static extern bool SwitchDesktop(IntPtr h); }
'@
    Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue | Out-Null
    $h = [L]::OpenDesktop('Default',0,$false,0x100)
    if ($h -ne [IntPtr]::Zero){ return -not [L]::SwitchDesktop($h) } else { return $false }
  } catch { return $false }
}
function Test-ActiveRdpSession {
  $rdpActive = $false
  try { $o = (qwinsta.exe) 2>$null; if($o){ $rdpActive = ($o | Select-String -SimpleMatch 'rdp-tcp') -and ($o | Select-String -SimpleMatch 'Active') } } catch {}
  if (-not $rdpActive){ try { $o=(quser.exe) 2>$null; if($o){ $rdpActive = ($o | Select-String -SimpleMatch 'rdp-tcp') -and ($o | Select-String -SimpleMatch 'Active') } } catch {} }
  return [bool]$rdpActive
}

function Invoke-Apply($paths){
  Test-Admin
  if (-not (Test-Path $paths.Data)){ New-Item -ItemType Directory -Path $paths.Data -Force | Out-Null }
  $mutex = New-Object System.Threading.Mutex($false,'Global\NetLockMutex')
  $got = $mutex.WaitOne(20000)
  if (-not $got){ Write-Log 'mutex timeout' 'WARN'; return }
  try {
    Start-Sleep -Milliseconds 800
    $locked = Test-WorkstationLocked
    $rdp = Test-ActiveRdpSession
    $doUnlock = (-not $locked) -or $rdp
    $action = if ($doUnlock){ 'unlock' } else { 'lock' }
    Write-Log "state: locked=$locked rdp=$rdp -> $action" 'APPLY'
    if ($doUnlock){ Invoke-Unlock $paths } else { Invoke-Lock $paths }
  } finally { $mutex.ReleaseMutex() | Out-Null }
}

function New-TaskXml($paths,$stateChange,$desc){
  $author = $env:UserName
  $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $applyPath = $MyInvocation.MyCommand.Path
  @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>$author</Author><Description>$desc</Description></RegistrationInfo>
  <Triggers><SessionStateChangeTrigger><Enabled>true</Enabled><StateChange>$stateChange</StateChange></SessionStateChangeTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>$sid</UserId><RunLevel>HighestAvailable</RunLevel><LogonType>InteractiveToken</LogonType></Principal></Principals>
  <Settings><MultipleInstancesPolicy>Queue</MultipleInstancesPolicy><ExecutionTimeLimit>PT2M</ExecutionTimeLimit><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>powershell.exe</Command><Arguments>-NoProfile -ExecutionPolicy Bypass -File "$applyPath" apply</Arguments><WorkingDirectory>$($paths.Base)</WorkingDirectory></Exec></Actions>
</Task>
"@
}
function New-StartupTaskXml($paths){
  $author = $env:UserName
  $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $applyPath = $MyInvocation.MyCommand.Path
  @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>$author</Author><Description>NetLock: apply at logon</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><Delay>PT10S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>$sid</UserId><RunLevel>HighestAvailable</RunLevel><LogonType>InteractiveToken</LogonType></Principal></Principals>
  <Settings><MultipleInstancesPolicy>Queue</MultipleInstancesPolicy><ExecutionTimeLimit>PT2M</ExecutionTimeLimit><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>powershell.exe</Command><Arguments>-NoProfile -ExecutionPolicy Bypass -File "$applyPath" apply</Arguments><WorkingDirectory>$($paths.Base)</WorkingDirectory></Exec></Actions>
</Task>
"@
}

function Remove-TaskIfExists($name){ cmd /c "schtasks /Query /TN `"$name`" >NUL 2>&1"; if ($LASTEXITCODE -eq 0){ cmd /c "schtasks /Delete /TN `"$name`" /F >NUL 2>&1" }
}

function Install-NetLock($paths){
  Test-Admin
  if (-not (Test-Path $paths.Base)){ New-Item -ItemType Directory -Path $paths.Base -Force | Out-Null }
  if (-not (Test-Path $paths.Data)){ New-Item -ItemType Directory -Path $paths.Data -Force | Out-Null }
  Get-NetLockConfig $paths | Out-Null
  foreach($t in 'NetLock\\OnLock_Apply','NetLock\\OnUnlock_Apply','NetLock\\OnRemoteConnect_Apply','NetLock\\OnRemoteDisconnect_Apply','NetLock\\AtStartup_Apply'){ Remove-TaskIfExists $t }
  (New-TaskXml $paths 'SessionLock' 'NetLock: apply on lock')              | Set-Content -Path $paths.TaskLock -Encoding Unicode
  (New-TaskXml $paths 'SessionUnlock' 'NetLock: apply on unlock')          | Set-Content -Path $paths.TaskUnlock -Encoding Unicode
  (New-TaskXml $paths 'RemoteConnect' 'NetLock: apply on remote connect')  | Set-Content -Path $paths.TaskRemoteConnect -Encoding Unicode
  (New-TaskXml $paths 'RemoteDisconnect' 'NetLock: apply on remote disconnect') | Set-Content -Path $paths.TaskRemoteDisconnect -Encoding Unicode
  (New-StartupTaskXml $paths) | Set-Content -Path $paths.TaskStartup -Encoding Unicode
  schtasks /Create /TN "NetLock\OnLock_Apply"             /XML "$($paths.TaskLock)" /F | Out-Null
  schtasks /Create /TN "NetLock\OnUnlock_Apply"           /XML "$($paths.TaskUnlock)" /F | Out-Null
  schtasks /Create /TN "NetLock\OnRemoteConnect_Apply"    /XML "$($paths.TaskRemoteConnect)" /F | Out-Null
  schtasks /Create /TN "NetLock\OnRemoteDisconnect_Apply" /XML "$($paths.TaskRemoteDisconnect)" /F | Out-Null
  schtasks /Create /TN "NetLock\AtStartup_Apply"          /XML "$($paths.TaskStartup)" /F | Out-Null
  Write-Log 'Installed scheduled tasks. Use "apply" or lock session (Win+L) to test.' 'INFO'
}

function Uninstall-NetLock($paths){
  Test-Admin
  foreach($t in 'NetLock\\OnLock_Apply','NetLock\\OnUnlock_Apply','NetLock\\OnRemoteConnect_Apply','NetLock\\OnRemoteDisconnect_Apply','NetLock\\AtStartup_Apply'){ Remove-TaskIfExists $t }
  Write-Log 'Scheduled tasks removed.' 'INFO'
  if ($Purge){
    Remove-Item -Path $paths.Data -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log 'Data directory purged.' 'INFO'
  }
}

function Show-Help {
@'
NetLock unified tool
Actions:
  install    - создать/обновить задачи и конфиг
  uninstall  - удалить задачи (используйте -Purge чтобы удалить данные)
  lock       - применить ограниченный профиль
  unlock     - снять ограничения
  apply      - контроллер (авто выбор lock/unlock)
  help       - эта справка
  update     - валидация/перечистка: удалить все правила NetLock* и применить заново

Config: C:\ProgramData\NetLock\data\netlock-rules.json
Правила: поля type=program|programSearch|port, enabled, direction (in|out), action (allow|block), profile (any|domain|private|public).
Отключение правила: "enabled": false.
'@
}

$paths = Get-Paths
switch ($Action) {
  'help'      { Show-Help }
  'install'   { Install-NetLock $paths }
  'uninstall' { Uninstall-NetLock $paths }
  'lock'      { Invoke-Lock $paths }
  'unlock'    { Invoke-Unlock $paths }
  'apply'     { Invoke-Apply $paths }
  'update'    { Invoke-Lock $paths -FullCleanup }
}
