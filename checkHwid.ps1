# Требуются права Администратора для чтения всех серийников и веток реестра
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Clear-Host

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "     АУДИТ ВИРТУАЛЬНОЙ МАШИНЫ (HWID & VM DETECTION)       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Сигнатуры виртуализации, которые ищут игры и античиты
$vmKeywords = @("VMware", "VBOX", "Virtual", "QEMU", "KVM", "Xen", "Hyper-V", "Bochs", "Parallels", "Red Hat", "VirtIO", "Msft", "00000000", "To be filled", "System Product Name", "Default string")
$vmMacPrefixes = @("00:05:69", "00:0C:29", "00:1C:14", "00:50:56", "08:00:27", "52:54:00", "00:15:5D", "00:16:3E")

function Test-Suspicious ($text) {
    if ([string]::IsNullOrWhiteSpace($text)) { return $true }
    foreach ($kw in $vmKeywords) {
        if ($text -match "(?i)$kw") { return $true }
    }
    return $false
}

function Write-Check ($label, $value) {
    $isSuspicious = Test-Suspicious $value
    if ($isSuspicious) {
        Write-Host ("  [!] {0,-28}: " -f $label) -NoNewline -ForegroundColor Red
        Write-Host "$value" -ForegroundColor Red
    } else {
        Write-Host ("  [+] {0,-28}: " -f $label) -NoNewline -ForegroundColor Green
        Write-Host "$value" -ForegroundColor White
    }
}

# 1. ИМЯ ПК И СИСТЕМА
Write-Host "`n[1] СИСТЕМА И ИМЯ ПК" -ForegroundColor Yellow
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem$csp = Get-CimInstance Win32_ComputerSystemProduct

Write-Check "Имя ПК (Hostname)" $env:COMPUTERNAME
Write-Check "Имя пользователя" $env:USERNAME
Write-Check "Производитель ПК" $cs.Manufacturer
Write-Check "Модель ПК" $cs.Model
Write-Check "UUID системы (SMBIOS)" $csp.UUID
Write-Check "Серийный номер ОС" $os.SerialNumber

# Проверка стандартного сгенерированного имени Windows (DESKTOP-XXXXXXX / WIN-XXXXXXX)
if ($env:COMPUTERNAME -match "^(DESKTOP\vert{}WIN\vert{}LAPTOP)-[A-Z0-9]{7,}$") {
    Write-Host "  [*] Заметка: Имя ПК имеет стандартный шаблон установки Windows (рекомендуется кастомизировать под обычный домашний ПК)." -ForegroundColor DarkYellow
}

# 2. МАТЕРИНСКАЯ ПЛАТА И BIOS
Write-Host "`n[2] МАТЕРИНСКАЯ ПЛАТА И BIOS" -ForegroundColor Yellow
$bios = Get-CimInstance Win32_BIOS
$bb = Get-CimInstance Win32_BaseBoard

Write-Check "Производитель BIOS" $bios.Manufacturer
Write-Check "Версия BIOS" $bios.SMBIOSBIOSVersion
Write-Check "Серийный номер BIOS" $bios.SerialNumber
Write-Check "Производитель мат. платы" $bb.Manufacturer
Write-Check "Модель мат. платы" $bb.Product
Write-Check "Серийный номер мат. платы" $bb.SerialNumber

# 3. ПРОЦЕССОР И ФЛАГ ГИПЕРВИЗОРА
Write-Host "`n[3] ПРОЦЕССОР (CPU)" -ForegroundColor Yellow
$cpu = Get-CimInstance Win32_Processor
foreach ($p in$cpu) {
    Write-Check "Название CPU" $p.Name
    Write-Check "Processor ID" $p.ProcessorId
}
if ($cs.HypervisorPresent) {
    Write-Host "  [!] Флаг HypervisorPresent    : TRUE (КРИТИЧНО! Система открыто сообщает, что работает под гипервизором)" -ForegroundColor Red
} else {
    Write-Host "  [+] Флаг HypervisorPresent    : FALSE (Отлично, флаг гипервизора скрыт)" -ForegroundColor Green
}

# 4. ВИДЕОКАРТА (GPU) И МОНИТОР
Write-Host "`n[4] ВИДЕОКАРТА И МОНИТОР" -ForegroundColor Yellow
$gpus = Get-CimInstance Win32_VideoController
foreach ($gpu in $gpus) {
    Write-Check "Видеоадаптер" $gpu.Name
    Write-Check "PNP Device ID" $gpu.PNPDeviceID
    Write-Check "Видеопроцессор" $gpu.VideoProcessor
}
$monitors = Get-CimInstance Win32_DesktopMonitor
foreach ($m in $monitors) {
    Write-Check "Монитор" "$($m.Name) ($($m.PNPDeviceID))"
}

# 5. НАКОПИТЕЛИ (HDD / SSD / DVD)
Write-Host "`n[5] ДИСКИ И CD/DVD ПРИВОДЫ" -ForegroundColor Yellow
$disks = Get-CimInstance Win32_DiskDrive
foreach ($d in$disks) {
    Write-Check "Диск (Модель)" $d.Model
    Write-Check "Диск (Серийный номер)" ($d.SerialNumber.Trim())
    Write-Check "Диск (PNP Device ID)" $d.PNPDeviceID
}

$cdroms = Get-CimInstance Win32_CDROMDrive
if ($cdroms) {
    foreach ($cd in$cdroms) {
        Write-Check "CD/DVD Привод" $cd.Name
        Write-Check "CD/DVD PNP ID" $cd.PNPDeviceID
    }
} else {
    Write-Host "  [+] CD/DVD Приводы            : Отсутствуют (рекомендуется для маскировки)" -ForegroundColor Green
}

# 6. ОПЕРАТИВНАЯ ПАМЯТЬ (RAM)
Write-Host "`n[6] ОПЕРАТИВНАЯ ПАМЯТЬ (RAM)" -ForegroundColor Yellow
$ram = Get-CimInstance Win32_PhysicalMemory
foreach ($r in $ram) {
    Write-Check "Планка RAM (Производитель)" $r.Manufacturer
    Write-Check "Планка RAM (PartNumber)" $r.PartNumber
    Write-Check "Планка RAM (Серийник)" $r.SerialNumber
}

# 7. СЕТЕВЫЕ АДАПТЕРЫ И MAC-АДРЕСА
Write-Host "`n[7] СЕТЬ И MAC-АДРЕСА" -ForegroundColor Yellow
$nics = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq$true }
foreach ($nic in$nics) {
    Write-Check "Сетевой адаптер" $nic.Description
    $mac =$nic.MACAddress
    $macPrefix = if ($mac.Length -ge 8) {$mac.Substring(0, 8).ToUpper() } else { "" }
    if ($vmMacPrefixes -contains$macPrefix) {
        Write-Host ("  [!] {0,-28}: {1} (Палится OUI-префикс виртуальной машины!)" -f "MAC-адрес", $mac) -ForegroundColor Red
    } else {
        Write-Host ("  [+] {0,-28}: {1}" -f "MAC-адрес", $mac) -ForegroundColor Green
    }
}

# 8. ГЛУБОКАЯ ПРОВЕРКА РЕЕСТРА И УНИКАЛЬНЫХ ГУИДОВ
Write-Host "`n[8] КЛЮЧЕВЫЕ ЗАПИСИ РЕЕСТРА (ANTI-CHEAT & FINGERPRINTS)" -ForegroundColor Yellow

$regChecks = @(
    @{ Name = "MachineGuid (Cryptography)"; Path = "HKLM:\SOFTWARE\Microsoft\Cryptography"; Key = "MachineGuid" },
    @{ Name = "HwProfileGuid (Hardware)"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001"; Key = "HwProfileGuid" },
    @{ Name = "SusClientId (Windows Update)"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate"; Key = "SusClientId" },
    @{ Name = "SystemBIOSVersion"; Path = "HKLM:\HARDWARE\Description\System"; Key = "SystemBIOSVersion" },
    @{ Name = "VideoBIOSVersion"; Path = "HKLM:\HARDWARE\Description\System"; Key = "VideoBIOSVersion" },
    @{ Name = "BIOS Vendor (Реестр)"; Path = "HKLM:\HARDWARE\Description\System\BIOS"; Key = "BIOSVendor" },
    @{ Name = "SystemManufacturer (Реестр)"; Path = "HKLM:\HARDWARE\Description\System\BIOS"; Key = "SystemManufacturer" },
    @{ Name = "SystemProductName (Реестр)"; Path = "HKLM:\HARDWARE\Description\System\BIOS"; Key = "SystemProductName" }
)

foreach ($rc in $regChecks) {
    if (Test-Path $rc.Path) {
        $val = (Get-ItemProperty -Path $rc.Path -Name $rc.Key -ErrorAction SilentlyContinue).$($rc.Key)
        if ($val -is [array]) { $val = $val -join " | " }
        Write-Check $rc.Name $val
    }
}

# Проверка SCSI дерева в реестре (игры часто читают именно его напрямую в обход WMI)
$scsiPaths = Get-ChildItem "HKLM:\HARDWARE\DEVICEMAP\Scsi" -Recurse -ErrorAction SilentlyContinue
foreach ($sp in $scsiPaths) {
    $ident = (Get-ItemProperty -Path $sp.PSPath -Name "Identifier" -ErrorAction SilentlyContinue).Identifier
    $serial = (Get-ItemProperty -Path $sp.PSPath -Name "SerialNumber" -ErrorAction SilentlyContinue).SerialNumber
    if ($ident) {
        Write-Check "SCSI Реестр ($($sp.PSChildName))" "$ident (SN: $serial)"
    }
}

# 9. ТАБЛИЦЫ ACPI (OEM ID)
Write-Host "`n[9] ТАБЛИЦЫ ACPI (ВЕТКИ РЕЕСТРА)" -ForegroundColor Yellow
$acpiTables = @("DSDT", "FADT", "RSDT", "SSDT")
foreach ($tab in $acpiTables) {$path = "HKLM:\HARDWARE\ACPI\$tab"
    if (Test-Path $path) {
        $subkeys = Get-ChildItem$path -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName
        foreach ($sk in$subkeys) {
            Write-Check "ACPI таблица $tab" $sk
        }
    }
}

# 10. ДАТЧИКИ ТЕМПЕРАТУРЫ, СЛУЖБЫ, ПРОЦЕССЫ И ФАЙЛЫ ГОСТЕВЫХ ДОПОЛНЕНИЙ
Write-Host "`n[10] КОСВЕННЫЕ ПРИЗНАКИ (ДАТЧИКИ, ДРАЙВЕРЫ, ПРОЦЕССЫ)" -ForegroundColor Yellow

# Проверка термальных зон (в ВМ они обычно пустые)
$thermal = Get-CimInstance -Namespace "root/wmi" -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue
if ($thermal) {
    Write-Host "  [+] Датчики температуры ACPI  : Присутствуют" -ForegroundColor Green
} else {
    Write-Host "  [!] Датчики температуры ACPI  : ОТСУТСТВУЮТ (Частый признак ВМ)" -ForegroundColor Red
}

# Поиск драйверов и служб ВМ
$vmServices = Get-Service | Where-Object { $_.Name -match "(?i)(vmtools|vbox|vmmouse|vmhgfs|vmci|vioscsi|viostor|balloon|qemu|spice)" -or $_.DisplayName -match "(?i)(VMware|VirtualBox|QEMU|VirtIO)" }
if ($vmServices) {
    foreach ($srv in $vmServices) {
        Write-Host "  [!] Обнаружена служба ВМ      : $($srv.Name) ($($srv.DisplayName))" -ForegroundColor Red
    }
} else {
    Write-Host "  [+] Службы гостевых дополнений: Не обнаружены" -ForegroundColor Green
}

# Поиск процессов ВМ
$vmProcs = Get-Process | Where-Object { $_.ProcessName -match "(?i)(vmtoolsd|vmwaretray|vmwareuser|vboxservice|vboxtray|qemu-ga|vdagent)" }
if ($vmProcs) {
    foreach ($pr in $vmProcs) {
        Write-Host "  [!] Обнаружен процесс ВМ      : $($pr.ProcessName).exe" -ForegroundColor Red
    }
} else {
    Write-Host "  [+] Процессы гостевых утилит  : Не обнаружены" -ForegroundColor Green
}

# Поиск файлов драйверов в System32\drivers
$vmDrivers = @("vmmouse.sys", "vmhgfs.sys", "vmci.sys", "vmmemctl.sys", "vboxguest.sys", "vboxmouse.sys", "vboxsf.sys", "vboxvideo.sys", "vioscsi.sys", "viostor.sys", "netkvm.sys", "balloon.sys")
$foundDrivers = @()
foreach ($drv in $vmDrivers) {
    if (Test-Path "$env:SystemRoot\System32\drivers\$drv") {
        $foundDrivers += $drv
    }
}
if ($foundDrivers.Count -gt 0) {
    Write-Host "  [!] Файлы драйверов ВМ в Sys32: $($foundDrivers -join ', ')" -ForegroundColor Red
} else {
    Write-Host "  [+] Файлы драйверов ВМ в Sys32: Чисто" -ForegroundColor Green
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Проверка завершена. Красные пункты [!] требуют спуфинга. " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan