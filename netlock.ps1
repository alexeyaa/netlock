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
  [Parameter(Position=0)][ValidateSet('install','uninstall','lock','unlock','apply','help','update','validate')]
  [string]$Action = 'help',
  [switch]$Force,
  [switch]$Purge # for uninstall: also remove data files
)
$ErrorActionPreference = 'Stop'

# --- Auto elevation for actions that modify firewall ---
function Test-IsAdmin {
  try { return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator') } catch { return $false }
}
$elevNeededActions = @('install','uninstall','lock','unlock','apply','update')
if ($elevNeededActions -contains $Action) {
  if (-not (Test-IsAdmin)) {
    Write-Host '[NetLock] Авто-повышение привилегий (UAC)...'
    $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"$PSCommandPath",$Action)
    if ($Force) { $argList += '-Force' }
    if ($Purge) { $argList += '-Purge' }
    try {
      Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs | Out-Null
      # Лог запишется в дочернем процессе; текущий просто завершится.
      return
    } catch {
      Write-Host '[NetLock] Не удалось повысить привилегии: ' + $_.Exception.Message
      throw 'Требуются права администратора.'
    }
  }
}

function Write-Info($m){ Write-Host "[NetLock] $m" }
function Write-Warn($m){ Write-Warning "[NetLock] $m" }
function Write-Err($m){ Write-Error "[NetLock] $m" }

<#
.SYNOPSIS
  Проверяет запуск от имени администратора.
.DESCRIPTION
  Бросает исключение, если текущий процесс PowerShell не имеет административных привилегий.
.OUTPUTS
  None. Exception при отсутствии прав.
#>
function Test-Admin {
  if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    throw 'Требуются права администратора.'
  }
}

<#
.SYNOPSIS
  Возвращает объект со всеми путями NetLock.
.DESCRIPTION
  Центральная точка формирования путей к базе, данным, логам, конфигу и XML задач.
.OUTPUTS
  PSCustomObject с именованными свойствами.
#>
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
<#
.SYNOPSIS
  Пишет строку в лог с ротацией.
.DESCRIPTION
  Добавляет строку в netlock.log (UTF8). При превышении размера (NetLock_LogMaxBytes) выполняет каскадную ротацию до NetLock_LogKeep файлов.
.PARAMETER Message
  Текст сообщения.
.PARAMETER Level
  Метка уровня (INFO|STATE|APPLY|CLEAN|WARN ...).
.PARAMETER NoConsole
  Подавляет вывод в консоль.
.NOTES
  Потокобезопасность минимальная; допускается одновременный доступ с редким конфликтом.
#>
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

# Detect availability of modern NetSecurity firewall cmdlets
$Global:NetLock_UseNetSecurity = $false
try {
  if (Get-Command -Name New-NetFirewallRule -ErrorAction Stop) { $Global:NetLock_UseNetSecurity = $true }
} catch { $Global:NetLock_UseNetSecurity = $false }
if ($Global:NetLock_UseNetSecurity) { try { Import-Module NetSecurity -ErrorAction SilentlyContinue } catch {} }

# --- Global validation & sanitation helpers ---
function Test-NLDirection($v){ if ($v -and ($v -in @('in','out'))) { return $v } $null }
function Test-NLAction($v){ if ($v -and ($v -in @('allow','block'))) { return $v } $null }
function Test-NLProtocol($v){ if (-not $v){ return $null }; $n=$v.ToUpperInvariant(); if ($n -in @('TCP','UDP','ANY','ICMPV4','ICMPV6','GRE','ESP')){ return $n }; $null }
function Test-NLProfile($v){ if ($v -and ($v -in @('any','domain','private','public'))) { return $v } $null }
function Test-NLPorts($v){ if (-not $v){ return $null }; if ($v -match '^[0-9, \-]+$'){ return $v }; $null }
function Normalize-NLPorts($v){
  if (-not $v){ return $null }
  $parts = $v -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  # remove duplicates, validate numeric or range
  $clean = New-Object System.Collections.Generic.List[string]
  foreach($p in $parts){
    if ($p -match '^[0-9]+(-[0-9]+)?$'){
      if (-not $clean.Contains($p)) { $clean.Add($p) }
    } else {
      # skip silently; could log in validate path
    }
  }
  if ($clean.Count -eq 0){ return $null }
  return ($clean -join ',')
}
function ConvertTo-NLName($v){ if (-not $v){ return 'NetLockRule' }; $s=$v.Trim(); if ($s.Length -gt 60){ $s=$s.Substring(0,60) }; ($s -replace '["`|>;<]','_') }
function ConvertTo-NLPath($p){ if (-not $p){ return $null }; $s=$p.Trim(); if ($s.Length -gt 260){ $s=$s.Substring(0,260) }; ($s -replace '["`|>;<]','') }

# programSearch caching (TTL)
$Global:NetLock_SearchCacheTTLSeconds = 600
function Get-NLSearchCache($paths){ $f = Join-Path $paths.Data 'programSearch-cache.json'; if (Test-Path $f){ try { return (Get-Content -Raw -Path $f | ConvertFrom-Json -ErrorAction Stop) } catch {} }; return @{ entries = @{} } }
function Save-NLSearchCache($paths,$cache){ try { ($cache | ConvertTo-Json -Depth 6) | Set-Content -Path (Join-Path $paths.Data 'programSearch-cache.json') -Encoding UTF8 -ErrorAction SilentlyContinue } catch {} }
function Get-NLSearchKey($filenames,$roots){ ($filenames | Sort-Object) -join ';' + '|' + (($roots | Sort-Object) -join ';') }
function Resolve-NLProgramSearch($paths,$filenames,$roots,[switch]$NoUpdate){
  $cache = Get-NLSearchCache $paths; $now=Get-Date; $key=Get-NLSearchKey $filenames $roots; $ttl=$Global:NetLock_SearchCacheTTLSeconds; $entries=$cache.entries
  if ($entries.ContainsKey($key)) { $entry=$entries[$key]; try { $ts=[DateTime]$entry.timestamp } catch { $ts=$null }; if ($ts -and ($now - $ts).TotalSeconds -lt $ttl){ return @($entry.paths) } }
  $found=@(); foreach($root in $roots | Where-Object { $_ -and (Test-Path $_) }){ foreach($fn in $filenames){ try { Get-ChildItem -Path $root -Recurse -Filter $fn -ErrorAction SilentlyContinue | ForEach-Object { $found += $_.FullName } } catch {} } }
  $found = $found | Select-Object -Unique
  if (-not $NoUpdate){ $entries[$key] = @{ timestamp = $now; paths = $found }; Save-NLSearchCache $paths $cache }
  return $found
}

function New-DefaultRulesConfig {
<#
.SYNOPSIS
  Формирует JSON с набором правил по умолчанию.
.DESCRIPTION
  Создаёт предопределённый объект (version, rules, policy) и возвращает сериализованный JSON.
.OUTPUTS
  String (JSON).
.NOTES
  Используется при первой установке, либо при восстановлении после ошибок чтения.
#>
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
<#
.SYNOPSIS
  Загружает (или создаёт) конфигурацию NetLock.
.DESCRIPTION
  Если файл отсутствует — генерирует дефолт. Выполняет миграцию legacy allow-programs.json, добавляя их как program правила.
.PARAMETER paths
  Объект путей из Get-Paths.
.OUTPUTS
  PSCustomObject десериализованный из JSON.
.NOTES
  При ошибке парсинга возвращает дефолтный объект (не бросает исключение).
#>
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
<#
.SYNOPSIS
  Применяет ограниченный (locked) режим NetLock.
.DESCRIPTION
  Экспортирует текущие правила (один раз), опционально удаляет старые NetLock* правила, строит набор новых по JSON конфигурации, валидирует и применяет их.
.PARAMETER paths
  Объект путей (Get-Paths).
.PARAMETER FullCleanup
  Удалить все NetLock* правила перед созданием (используется action update).
.OUTPUTS
  Логи через Write-Log; возвращаемых значений нет.
.NOTES
  Учитывает кеш programSearch. Пишет статистику: added / skipped / expanded.
#>
  Test-Admin
  $ModeFile = $paths.ModeFile
  if (Test-Path $ModeFile) {
    try { if ((Get-Content $ModeFile -ErrorAction SilentlyContinue) -eq 'locked') { return } } catch {}
  }
  $Config = Get-NetLockConfig $paths
  $Rules = @(); if ($Config.rules){ $Rules = $Config.rules }
  if (-not (Test-Path $paths.Pre)) { netsh advfirewall export "$($paths.Pre)" | Out-Null }
  if ($Global:NetLock_UseNetSecurity) {
    try { Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | Out-Null } catch { netsh advfirewall firewall set rule group="Remote Desktop" new enable=Yes | Out-Null }
  } else {
    netsh advfirewall firewall set rule group="Remote Desktop" new enable=Yes | Out-Null
  }

  if ($FullCleanup) {
    # Удаляем ВСЕ старые правила NetLock* перед пересозданием
    try {
      if ($Global:NetLock_UseNetSecurity) {
        $toDelete = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'NetLock *' }
        $count = 0
        if ($toDelete) { foreach($r in $toDelete){ try { $r | Remove-NetFirewallRule -ErrorAction SilentlyContinue; $count++ } catch {} } }
        Write-Log ("Full cleanup removed {0} rule(s)" -f $count) 'CLEAN'
      } else {
        $existing = (netsh advfirewall firewall show rule name=all) 2>$null
        if ($existing) {
          $toDelete = @()
          foreach ($line in $existing) { if ($line -match '^Rule Name:\s*(.+)$') { $rn = $Matches[1].Trim(); if ($rn -like 'NetLock *') { $toDelete += $rn } } }
   $planned = New-Object System.Collections.Generic.HashSet[string]
   $expanded = @()
   $added = 0; $skipped = 0
          Write-Log ("Full cleanup removed {0} rule(s)" -f $toDelete.Count) 'CLEAN'
        }
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
  foreach($n in $planned){
    if ($Global:NetLock_UseNetSecurity) {
      try { Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue } catch {}
    } else {
      netsh advfirewall firewall delete rule name="$n" | Out-Null
    }
  }
  foreach($er in $expanded){
    if (-not $er.enabled){ continue }
    $dir = Test-NLDirection $er.dir; if (-not $dir){ Write-Log "skip rule '$($er.name)' invalid direction" 'WARN'; continue }
    $act = Test-NLAction $er.action; if (-not $act){ Write-Log "skip rule '$($er.name)' invalid action" 'WARN'; continue }
    $prof = Test-NLProfile $er.profile; if (-not $prof){ $prof='any' }
    $proto = $null; if ($er.protocol){ $proto = Test-NLProtocol $er.protocol }
  $lports = $null; if ($er.localPorts){ $lports = Test-NLPorts $er.localPorts; if ($lports){ $lports = Normalize-NLPorts $lports } }
  $rports = $null; if ($er.remotePorts){ $rports = Test-NLPorts $er.remotePorts; if ($rports){ $rports = Normalize-NLPorts $rports } }
    $rname = ConvertTo-NLName $er.name
    $programPath = $null; if ($er.program){ $programPath = ConvertTo-NLPath $er.program; if ($programPath -and -not (Test-Path $programPath)){ Write-Log "skip rule '$rname' program not found" 'WARN'; continue } }
    if ($Global:NetLock_UseNetSecurity) {
      $dirMapped = if ($dir -eq 'in'){ 'Inbound' } else { 'Outbound' }
      $actMapped = if ($act -eq 'allow'){ 'Allow' } else { 'Block' }
      $profMapped = if ($prof -eq 'any'){ 'Any' } else { $prof.Substring(0,1).ToUpper() + $prof.Substring(1) }
      $params = @{ DisplayName=$rname; Direction=$dirMapped; Action=$actMapped; Enabled='True'; Profile=$profMapped }
      if ($programPath){ $params.Program = $programPath }
      if ($proto){ $params.Protocol = $proto }
      if ($lports){ $params.LocalPort = $lports }
      if ($rports){ $params.RemotePort = $rports }
      try {
        New-NetFirewallRule @params -ErrorAction Stop | Out-Null
      } catch {
        $dbg = ($params.GetEnumerator() | ForEach-Object { $_.Key+'='+$_.Value }) -join ';'
        $msg = $_.Exception.Message
        Write-Log "failed to add rule '$rname' via cmdlet: $msg params=[$dbg]" 'WARN'
        # Fallback: if это ошибка портов и есть список через запятую -> попробовать разбить на отдельные
        if ($msg -match 'port is invalid' -and $params.ContainsKey('RemotePort') -and ($params.RemotePort -is [string]) -and ($params.RemotePort -like '*,*')) {
          $splitPorts = $params.RemotePort -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[0-9]+$' }
          if ($splitPorts.Count -gt 1) {
            Write-Log "attempting split fallback for '$rname' into $($splitPorts.Count) single-port rules" 'INFO'
            $i=0
            foreach($sp in $splitPorts){
              $i++
              $p2 = @{}
              foreach($k in $params.Keys){ if ($k -ne 'RemotePort' -and $k -ne 'DisplayName'){ $p2[$k] = $params[$k] } }
              $suffix = if ($splitPorts.Count -gt 1) { " ($sp)" } else { '' }
              $rn2 = $rname + $suffix
              $p2['DisplayName'] = $rn2
              $p2['RemotePort'] = $sp
              try { New-NetFirewallRule @p2 -ErrorAction Stop | Out-Null; Write-Log "fallback added '$rn2'" 'APPLY' } catch { Write-Log "fallback failed '$rn2': $($_.Exception.Message)" 'WARN' }
            }
          }
        }
      }
    } else {
      $ruleArgs = @('advfirewall','firewall','add','rule',"name=$rname","dir=$dir","action=$act","profile=$prof","enable=yes")
      if ($programPath){ $ruleArgs += "program=$programPath" }
      if ($proto){ $ruleArgs += "protocol=$proto" }
      if ($lports){ $ruleArgs += "localport=$lports" }
      if ($rports){ $ruleArgs += "remoteport=$rports" }
      & netsh @ruleArgs | Out-Null
    }
  }
  if ($Config.policy -and $Config.policy.setBlockAll){
    if ($Global:NetLock_UseNetSecurity) {
      try { Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Block -ErrorAction Stop | Out-Null } catch { netsh advfirewall set domainprofile  firewallpolicy blockinbound,blockoutbound | Out-Null; netsh advfirewall set privateprofile firewallpolicy blockinbound,blockoutbound | Out-Null; netsh advfirewall set publicprofile  firewallpolicy blockinbound,blockoutbound | Out-Null }
    } else {
      netsh advfirewall set domainprofile  firewallpolicy blockinbound,blockoutbound | Out-Null
      netsh advfirewall set privateprofile firewallpolicy blockinbound,blockoutbound | Out-Null
      netsh advfirewall set publicprofile  firewallpolicy blockinbound,blockoutbound | Out-Null
    }
  }
  Set-Content -Path $ModeFile -Value 'locked' -Encoding ASCII
  Write-Log ('Applied locked state' + ($(if($FullCleanup){' (full cleanup)'}))) 'STATE'
}

function Invoke-Unlock($paths){
<#
.SYNOPSIS
  Восстанавливает нормальный (unlocked) режим.
.DESCRIPTION
  Импортирует сохранённый экспорт prelock.wfw если он существует, иначе задаёт политики firewall allow outbound. Удаляет prelock.wfw.
.PARAMETER paths
  Объект путей.
.OUTPUTS
  None.
#>
  Test-Admin
  $ModeFile = $paths.ModeFile
  if (Test-Path $ModeFile){ try { if ((Get-Content $ModeFile -ErrorAction SilentlyContinue) -eq 'unlocked'){ return } } catch {} }
  if (Test-Path $paths.Pre){
    netsh advfirewall import "$($paths.Pre)" | Out-Null
    Remove-Item -Path $paths.Pre -Force -ErrorAction SilentlyContinue
  } else {
    if ($Global:NetLock_UseNetSecurity) {
      try { Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop | Out-Null } catch { netsh advfirewall set domainprofile  firewallpolicy blockinbound,allowoutbound | Out-Null; netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound | Out-Null; netsh advfirewall set publicprofile  firewallpolicy blockinbound,allowoutbound | Out-Null }
    } else {
      netsh advfirewall set domainprofile  firewallpolicy blockinbound,allowoutbound | Out-Null
      netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound | Out-Null
      netsh advfirewall set publicprofile  firewallpolicy blockinbound,allowoutbound | Out-Null
    }
  }
  Set-Content -Path $ModeFile -Value 'unlocked' -Encoding ASCII
  Write-Log 'Restored (unlocked) state.' 'STATE'
}

function Invoke-Validate($paths){
<#
.SYNOPSIS
  Сухая проверка конфигурации.
.DESCRIPTION
  Расширяет programSearch с использованием кеша (без обновления), валидирует поля и выводит сводку без изменений в системе.
.PARAMETER paths
  Объект путей.
.OUTPUTS
  Печатает сводку в stdout.
#>
  Test-Admin
  $Config = Get-NetLockConfig $paths
  $Rules = @(); if ($Config.rules){ $Rules = $Config.rules }
  $expanded=@()
  $added=0; $skipped=0
  foreach($r in $Rules){
    if (-not $r){ continue }
    $enabled=$true; if ($r.PSObject.Properties.Name -contains 'enabled'){ $enabled=[bool]$r.enabled }
    $type=$r.type; if (-not $type){ $skipped++; continue }
    switch($type){
      'program' {
        if ($r.program -and (Test-Path $r.program)){
          $expanded += [pscustomobject]@{ name='NetLock '+$r.name; enabled=$enabled; dir=$r.direction; action=$r.action; program=$r.program; profile=$r.profile }
        } else { $skipped++ }
      }
      'programSearch' {
        $filenames=@(); if ($r.filenames){ $filenames=@($r.filenames) }
        if ($filenames.Count -eq 0){ $skipped++; continue }
        $roots=@(); if ($r.searchRootsEnv){ foreach($envName in $r.searchRootsEnv){ $val=[Environment]::GetEnvironmentVariable($envName); if($val){ $roots+=$val } } }
        if ($r.searchRoots){ $roots += @($r.searchRoots) }
        $found = Resolve-NLProgramSearch -paths $paths -filenames $filenames -roots $roots -NoUpdate
        foreach($f in $found){ $expanded += [pscustomobject]@{ name='NetLock '+$r.name+': '+(Split-Path $f -Leaf); enabled=$enabled; dir=$r.direction; action=$r.action; program=$f; profile=$r.profile } }
      }
      'port' {
        $expanded += [pscustomobject]@{ name='NetLock '+$r.name; enabled=$enabled; dir=$r.direction; action=$r.action; protocol=$r.protocol; localPorts=$r.localPorts; remotePorts=$r.remotePorts; profile=$r.profile }
      }
      default { $skipped++ }
    }
  }
  foreach($er in $expanded){
    if (-not $er.enabled){ continue }
    $dir = Test-NLDirection $er.dir; if (-not $dir){ $skipped++; continue }
    $act = Test-NLAction $er.action; if (-not $act){ $skipped++; continue }
    $prof = Test-NLProfile $er.profile; if (-not $prof){ $prof='any' }
    if ($er.protocol){ if (-not (Test-NLProtocol $er.protocol)){ $skipped++; continue } }
    if ($er.localPorts){ if (-not (Test-NLPorts $er.localPorts)){ $skipped++; continue } }
    if ($er.remotePorts){ if (-not (Test-NLPorts $er.remotePorts)){ $skipped++; continue } }
    if ($er.program){ $pp=ConvertTo-NLPath $er.program; if ($pp -and -not (Test-Path $pp)){ $skipped++; continue } }
    $added++
  }
  $disabled = ($expanded | Where-Object { -not $_.enabled }).Count
  $summary = "VALIDATE: expanded=$($expanded.Count) would-add=$added skipped=$skipped disabled=$disabled"
  Write-Host $summary
  if ($expanded.Count -gt 0){
    Write-Host 'First rules:'
    $expanded | Select-Object -First 10 | ForEach-Object { Write-Host '  ' $_.name }
  }
  Write-Host 'No changes applied.'
}

function Test-WorkstationLocked {
<#
.SYNOPSIS
  Определяет, заблокирован ли интерактивный рабочий стол.
.DESCRIPTION
  Использует P/Invoke user32 (OpenDesktop + SwitchDesktop) для проверки возможности переключения.
.RETURNS
  [bool] True если рабочая станция заблокирована.
#>
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
<#
.SYNOPSIS
  Проверяет активную RDP сессию.
.DESCRIPTION
  Парсит вывод qwinsta/quser для поиска строк rdp-tcp с состоянием Active.
.RETURNS
  [bool] True если есть активная RDP сессия.
#>
  $rdpActive = $false
  try { $o = (qwinsta.exe) 2>$null; if($o){ $rdpActive = ($o | Select-String -SimpleMatch 'rdp-tcp') -and ($o | Select-String -SimpleMatch 'Active') } } catch {}
  if (-not $rdpActive){ try { $o=(quser.exe) 2>$null; if($o){ $rdpActive = ($o | Select-String -SimpleMatch 'rdp-tcp') -and ($o | Select-String -SimpleMatch 'Active') } } catch {} }
  return [bool]$rdpActive
}

function Invoke-Apply($paths){
<#
.SYNOPSIS
  Автоматический контроллер режима.
.DESCRIPTION
  Захватывает глобальный мьютекс, определяет состояние (lock/unlock) по факту блокировки станции и RDP активности, вызывает соответствующую функцию.
.PARAMETER paths
  Объект путей.
.NOTES
  Имеет встроенную задержку 800ms для «стабилизации» состояния после события.
#>
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
<#
.SYNOPSIS
  Генерирует XML задачи планировщика для события смены сеанса.
.PARAMETER paths
  Объект путей.
.PARAMETER stateChange
  SessionLock | SessionUnlock | RemoteConnect | RemoteDisconnect.
.PARAMETER desc
  Описание в XML.
.RETURNS
  String (XML содержимое).
#>
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
<#
.SYNOPSIS
  Генерирует XML задачи на запуск при входе пользователя.
.PARAMETER paths
  Объект путей.
.RETURNS
  String (XML).
#>
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
<#
.SYNOPSIS
  Удаляет задачу планировщика, если существует.
.PARAMETER name
  Полное имя задачи (включая путь).
#>
}

function Install-NetLock($paths){
<#
.SYNOPSIS
  Создаёт или обновляет задачи планировщика и базовую конфигурацию.
.DESCRIPTION
  Генерирует XML, регистрирует задачи (lock/unlock/remote connect/disconnect/startup), гарантирует наличие JSON конфигурации.
.PARAMETER paths
  Объект путей.
#>
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
<#
.SYNOPSIS
  Удаляет задачи планировщика NetLock.
.DESCRIPTION
  Снимает все задачи NetLock и опционально (ключ -Purge) удаляет директорию data.
.PARAMETER paths
  Объект путей.
#>
  Test-Admin
  foreach($t in 'NetLock\\OnLock_Apply','NetLock\\OnUnlock_Apply','NetLock\\OnRemoteConnect_Apply','NetLock\\OnRemoteDisconnect_Apply','NetLock\\AtStartup_Apply'){ Remove-TaskIfExists $t }
  Write-Log 'Scheduled tasks removed.' 'INFO'
  if ($Purge){
    Remove-Item -Path $paths.Data -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log 'Data directory purged.' 'INFO'
  }
}

function Show-Help {
<#
.SYNOPSIS
  Выводит краткую справку по действиям.
.DESCRIPTION
  Текстовое описание поддерживаемых action и структуры конфига.
#>
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
  validate   - сухая проверка правил и расширения programSearch без изменения firewall

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
  'validate'  { Invoke-Validate $paths }
}
