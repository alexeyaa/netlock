NetLock Unified Script Usage (RU)
=================================

Используется один файл: netlock.ps1

Действия:
  install    - установить/обновить задачи планировщика и создать конфиг
  uninstall  - удалить задачи (опция -Purge удалит каталог data полностью)
  lock       - применить ограниченный режим (перекрывает outbound, разрешает только правила из JSON)
  unlock     - восстановить предыдущее состояние фаервола (или разрешить outbound по умолчанию)
  apply      - контроллер: автоматически вызывает lock/unlock на основе состояния рабочего стола и RDP
  update     - удалить ВСЕ старые правила NetLock* и применить текущие из JSON
  help       - показать справку

Примеры запуска (из административного PowerShell):
  powershell -NoProfile -ExecutionPolicy Bypass -File .\netlock.ps1 install
  powershell -NoProfile -ExecutionPolicy Bypass -File .\netlock.ps1 lock
  powershell -NoProfile -ExecutionPolicy Bypass -File .\netlock.ps1 unlock
  powershell -NoProfile -ExecutionPolicy Bypass -File .\netlock.ps1 apply
  powershell -NoProfile -ExecutionPolicy Bypass -File .\netlock.ps1 update

Файлы и структура:
  C:\ProgramData\NetLock\netlock.ps1              - основной скрипт
  C:\ProgramData\NetLock\data\netlock-rules.json  - конфигурация правил
  C:\ProgramData\NetLock\data\prelock.wfw         - сохранённый экспорт правил (для возврата при unlock)
  C:\ProgramData\NetLock\data\mode.txt             - текущее состояние (locked/unlocked)
  C:\ProgramData\NetLock\data\netlock.log          - лог (ротация: ~200KB, до 5 файлов netlock.log.N)

JSON схема (минимально):
{
  "version": 1,
  "rules": [
    { "type": "port", "name": "RDP Inbound", "enabled": true, "direction": "in", "action": "allow", "protocol": "TCP", "localPorts": "3389", "profile": "any" },
    { "type": "program", "name": "Resilio Sync", "enabled": true, "direction": "out", "action": "allow", "program": "C:\\Users\\...\\Resilio Sync.exe", "profile": "any" },
    { "type": "programSearch", "name": "VPN Processes", "enabled": true, "direction": "out", "action": "allow", "filenames": ["openvpn.exe"], "searchRootsEnv": ["ProgramFiles","ProgramFiles(x86)"], "profile": "any" }
  ],
  "policy": { "setBlockAll": true }
}

Поля:
  type: program | programSearch | port
  enabled: true/false (если false — правило не создаётся)
  direction: in | out
  action: allow | block (обычно allow)
  profile: any | domain | private | public
  program: путь к exe (для type=program)
  filenames: массив имён exe для поиска (для type=programSearch)
  searchRootsEnv: массив имён переменных окружения (ProgramFiles, ProgramFiles(x86), и т.п.)
  localPorts / remotePorts / protocol: для портовых правил

Отключение правила: поменять enabled на false и выполнить lock снова.

Uninstall:
  .\netlock.ps1 uninstall -Purge   # также удалит каталог data

Безопасность:
  Перед первым lock сохраняется экспорт (prelock.wfw). При unlock импортируется назад и файл удаляется.

Логирование:
  Автоматическая ротация при ~200KB: текущий файл переименовывается в netlock.log.1, далее каскадом до .5.
  Метки уровней: [INFO], [STATE], [APPLY], [CLEAN], [WARN].

Мьютекс:
  Используется Global\NetLockMutex для избежания гонок при apply.

Изменение правил:
  1. Отредактировать netlock-rules.json.
  2. Запустить: .\netlock.ps1 lock (или дождаться события блокировки экрана, если контроллер включён).