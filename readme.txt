== Установка

Открой PowerShell от имени администратора.

Скопируй текст выше в C:\ProgramData\NetLock\install.ps1.

Выполни:

Set-ExecutionPolicy Bypass -Scope Process -Force
powershell -File C:\ProgramData\NetLock\install.ps1


Проверка:

Нажми Win+L (сеанс заблокируется).

С другой машины подключись RDP на этот хост — подключение должно проходить.

На заблокированной машине интернет для приложений должен быть «глухой», кроме Mullvad (если он активен).

Разблокируй сеанс — интернет вернётся.

Если ты авторизован внутри RDP-сессии, интернет будет включён (даже при заблокированном локальном экране).

Нестандартный порт RDP? После установки отредактируй C:\ProgramData\NetLock\lock.ps1 и поменяй localport=3389 на свой. Затем заблокируй/разблокируй экран или запусти C:\ProgramData\NetLock\apply-mode.ps1.

даление (чистый откат)

В PowerShell от администратора выполни:

# 1) Удалить задачи
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

# 2) Откатить фаервол к дефолтной политике (In=Block, Out=Allow)
netsh advfirewall set domainprofile  firewallpolicy blockinbound,allowoutbound
netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound
netsh advfirewall set publicprofile  firewallpolicy blockinbound,allowoutbound

# 3) (Опционально) удалить созданные правила нашего набора
foreach ($rn in @(
  "NetLock Allow RDP Inbound",
  "NetLock Allow Mullvad Outbound",
  "NetLock Allow WireGuard Outbound",
  "NetLock Allow OpenVPN Outbound",
  "NetLock Allow OpenVPN Outbound (TCP)")
) { netsh advfirewall firewall delete rule name="$rn" }

# 4) Удалить папку и файлы
Remove-Item -Path "C:\ProgramData\NetLock" -Recurse -Force -ErrorAction SilentlyContinue


Готово. Если нужны правки под твой порт RDP или конкретные пути Mullvad — скажи, сразу подгоню скрипт.