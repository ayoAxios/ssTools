Write-Host ""
Write-Host @"
   _____         .__                 _________                  .__               _________ .__                   __                 
  /  _  \ ___  __|__| ____  ______  /   _____/ ______________  _|__| ____  ____   \_   ___ \|  |__   ____   ____ |  | __ ___________ 
 /  /_\  \\  \/  /  |/  _ \/  ___/  \_____  \_/ __ \_  __ \  \/ /  |/ ___\/ __ \  /    \  \/|  |  \_/ __ \_/ ___\|  |/ // __ \_  __ \
/    |    \>    <|  (  <_> )___ \   /        \  ___/|  | \/\   /|  \  \__\  ___/  \     \___|   Y  \  ___/\  \___|    <\  ___/|  | \/
\____|__  /__/\_ \__|\____/____  > /_______  /\___  >__|    \_/ |__|\___  >___  >  \______  /___|  /\___  >\___  >__|_ \\___  >__|   
        \/      \/             \/          \/     \/                    \/    \/          \/     \/     \/     \/     \/    \/       
                                                                                                                                                                                                                              
"@ -ForegroundColor Magenta



$isAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host ""
    Write-Host "                     ADMIN PRIVILEGES REQUIRED" -ForegroundColor Red
    Write-Host "                     Please run this script AS AN ADMIN." -ForegroundColor Red
   
    exit
}
Write-Host "made by _.ayo?" -ForegroundColor White

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host ("║ {0,-70} ║" -f "Service + Essential Log checker") -ForegroundColor Magenta
Write-Host "╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""


try {
    $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $uptime = (Get-Date) - $bootTime
    Write-Host "┌─ SYSTEM BOOT INFO ────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host ("  Last Boot : {0}" -f $bootTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor White
    Write-Host ("  Uptime    : {0} days, {1:D2}:{2:D2}:{3:D2}" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds) -ForegroundColor Green
    Write-Host "└───────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
} catch {
    Write-Host "Unable to retrieve boot time information" -ForegroundColor Red
}

$drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -ne 5 }
if ($drives) {
    Write-Host ""
    Write-Host "┌─ CONNECTED DRIVES ─────────────────────────────────────────────────┐" -ForegroundColor Cyan

    foreach ($drive in $drives) {
        $fs = $drive.FileSystem -as [string]
        if (-not $fs) { $fs = "N/A" }

        if ($drive.FreeSpace -and $drive.Size -and $drive.Size -gt 0) {
            $freeStr = "{0:N0} bytes free" -f $drive.FreeSpace
        } else {
            $freeStr = "N/A"
        }

        Write-Host ("  {0,-4}  FileSystem: {1,-8}  FreeSpace: {2}" -f $drive.DeviceID, $fs, $freeStr) -ForegroundColor Green
    }

    Write-Host "└────────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "┌─ SERVICE STATUS ─────────────────────────────────────────────────────────┐" -ForegroundColor Cyan

$services = @(
    @{Name = "SysMain"; DisplayName = "SysMain"},
    @{Name = "PcaSvc"; DisplayName = "Program Compatibility Assistant Service"},
    @{Name = "DPS"; DisplayName = "Diagnostic Policy Service"},
    @{Name = "EventLog"; DisplayName = "Windows Event Log"},
    @{Name = "Schedule"; DisplayName = "Task Scheduler"},
    @{Name = "Bam"; DisplayName = "Background Activity Moderator"},
    @{Name = "Dusmsvc"; DisplayName = "Data Usage"},
    @{Name = "Appinfo"; DisplayName = "Application Information"},
    @{Name = "CDPSvc"; DisplayName = "Connected Devices Platform Service"},
    @{Name = "DcomLaunch"; DisplayName = "DCOM Server Process Launcher"},
    @{Name = "PlugPlay"; DisplayName = "Plug and Play"},
    @{Name = "wsearch"; DisplayName = "Windows Search"}
)

foreach ($svc in $services) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($service) {
        $displayName = $service.DisplayName
        if ($displayName.Length -gt 38) {
            $displayName = $displayName.Substring(0, 35) + "..."
        }

        if ($service.Status -eq "Running") {
            Write-Host -NoNewline ("  {0,-12} {1,-40}" -f $svc.Name, $displayName) -ForegroundColor Green
            if ($svc.Name -eq "Bam") {
                Write-Host (" | {0}" -f "Enabled") -ForegroundColor Yellow
            } else {
                try {
                    $process = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" | Select-Object ProcessId
                    if ($process.ProcessId -gt 0) {
                        $proc = Get-Process -Id $process.ProcessId -ErrorAction SilentlyContinue
                        if ($proc) {
                            Write-Host (" | started: {0}" -f $proc.StartTime.ToString("HH:mm:ss")) -ForegroundColor Yellow
                        } else {
                            Write-Host " | started: N/A" -ForegroundColor Yellow
                        }
                    } else {
                        Write-Host " | started: N/A" -ForegroundColor Yellow
                    }
                } catch {
                    Write-Host " | started: N/A" -ForegroundColor Yellow
                }
            }
        } else {
            Write-Host ("  {0,-12} {1,-40} {2}" -f $svc.Name, $displayName, $service.Status) -ForegroundColor Red
        }
    } else {
        Write-Host ("  {0,-12} {1,-40} {2}" -f $svc.Name, "Not Found", "Stopped") -ForegroundColor Yellow
    }
}
Write-Host "└──────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

Write-Host ""
Write-Host "┌─ REGISTRY CHECKS ─────────────────────────────────────────────────┐" -ForegroundColor Cyan

$settings = @(
    @{ Name = "CMD"; Path = "HKCU:\Software\Policies\Microsoft\Windows\System"; Key = "DisableCMD"; Warning = "Disabled"; Safe = "Available" },
    @{ Name = "PowerShell Logging"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Key = "EnableScriptBlockLogging"; Warning = "Disabled"; Safe = "Enabled" },
    @{ Name = "Activities Cache"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Key = "EnableActivityFeed"; Warning = "Disabled"; Safe = "Enabled" },
    @{ Name = "Prefetch Enabled"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Key = "EnablePrefetcher"; Warning = "Disabled"; Safe = "Enabled" }
)

foreach ($s in $settings) {
    $status = Get-ItemProperty -Path $s.Path -Name $s.Key -ErrorAction SilentlyContinue
    Write-Host "  " -NoNewline
    if ($status -and $status.$($s.Key) -eq 0) {
        Write-Host ("{0}: " -f $s.Name) -NoNewline -ForegroundColor White
        Write-Host $($s.Warning) -ForegroundColor Red
    } else {
        Write-Host ("{0}: " -f $s.Name) -NoNewline -ForegroundColor White
        Write-Host $($s.Safe) -ForegroundColor Green
    }
}
Write-Host "└───────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

function Check-EventLog {
    param ($logName, $eventID, $message)
    $event = Get-WinEvent -LogName $logName -FilterXPath "*[System[EventID=$eventID]]" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($event) {
        Write-Host "  $message at: " -NoNewline -ForegroundColor White
        Write-Host $event.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow
    } else {
        Write-Host "  $message - No records found" -ForegroundColor Green
    }
}

function Check-RecentEventLog {
    param ($logName, $eventIDs, $message)
    $event = Get-WinEvent -LogName $logName -FilterXPath "*[System[EventID=$($eventIDs -join ' or EventID=')]]" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($event) {
        Write-Host "  $message (ID: $($event.Id)) at: " -NoNewline -ForegroundColor White
        Write-Host $event.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow
    } else {
        Write-Host "  $message - No records found" -ForegroundColor Green
    }
}

function Check-DeviceDeleted {
    try {
        $event = Get-WinEvent -LogName "Microsoft-Windows-Kernel-PnP/Configuration" -FilterXPath "*[System[EventID=400]]" -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($event) {
            Write-Host "  Device configuration changed at: " -NoNewline -ForegroundColor White
            Write-Host $event.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow
            return
        }
    } catch {}

    try {
        $event = Get-WinEvent -FilterHashtable @{LogName="System"; ID=225} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($event) {
            Write-Host "  Device removed at: " -NoNewline -ForegroundColor White
            Write-Host $event.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow
            return
        }
    } catch {}

    try {
        $events = Get-WinEvent -LogName "System" | Where-Object {$_.Id -eq 225 -or $_.Id -eq 400} | Sort-Object TimeCreated -Descending | Select-Object -First 1
        if ($events) {
            Write-Host "  Last device change at: " -NoNewline -ForegroundColor White
            Write-Host $events.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow
            return
        }
    } catch {}

    Write-Host "  Device changes - No records found" -ForegroundColor Green
}

Write-Host ""
Write-Host "┌─ EVENT LOGS ──────────────────────────────────────────────────────┐" -ForegroundColor Cyan

Check-EventLog "Application" 3079 "Checking for USN Journal Deletion"
Check-RecentEventLog "System" @(104, 1102) "Suspicous Event Logs "
Check-EventLog "System" 1074 "Last PC Shutdown"
Check-EventLog "Security" 4616 "System time changed"
Check-EventLog "System" 6005 "Event Log Service started"
Check-DeviceDeleted
Write-Host "└───────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

$prefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchPath) {
    Write-Host ""
    Write-Host "┌─ PREFETCH INTEGRITY ─────────────────────────────────────────────┐" -ForegroundColor Cyan

    $files = Get-ChildItem -Path $prefetchPath -Filter *.pf -Force -ErrorAction SilentlyContinue
    if (-not $files) {
        Write-Host "  No prefetch files found. Please check the folder." -ForegroundColor Yellow
    } else {
        $hashTable = @{}
        $suspiciousFiles = @{}
        $totalFiles = $files.Count

        $hiddenFiles = @()
        $readOnlyFiles = @()
        $hiddenAndReadOnlyFiles = @()
        $invalidSignatureFiles = @()
        $errorFiles = @()

        foreach ($file in $files) {
            try {
                $isHidden = $file.Attributes -band [System.IO.FileAttributes]::Hidden
                $isReadOnly = $file.Attributes -band [System.IO.FileAttributes]::ReadOnly

                if ($isHidden -and $isReadOnly) {
                    $hiddenAndReadOnlyFiles += $file
                    if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                        $suspiciousFiles[$file.Name] = "Hidden and Read-only"
                    }
                } elseif ($isHidden) {
                    $hiddenFiles += $file
                    if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                        $suspiciousFiles[$file.Name] = "Hidden file"
                    }
                } elseif ($isReadOnly) {
                    $readOnlyFiles += $file
                    if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                        $suspiciousFiles[$file.Name] = "Read-only file"
                    }
                }

                $stream = [System.IO.File]::OpenRead($file.FullName)
                $reader = New-Object System.IO.BinaryReader($stream)
                $signature = [System.Text.Encoding]::ASCII.GetString($reader.ReadBytes(3))
                $reader.Close()
                $stream.Close()

                if ($signature -ne "MAM") {
                    $invalidSignatureFiles += $file
                    if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                        $suspiciousFiles[$file.Name] = "Invalid signature: $signature"
                    } else {
                        $suspiciousFiles[$file.Name] += ", Invalid signature: $signature"
                    }
                }

                $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                if ($hash) {
                    if ($hashTable.ContainsKey($hash.Hash)) {
                        $hashTable[$hash.Hash].Add($file.Name)
                    } else {
                        $hashTable[$hash.Hash] = [System.Collections.Generic.List[string]]::new()
                        $hashTable[$hash.Hash].Add($file.Name)
                    }
                }
            } catch {
                $errorFiles += $file
                if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                    $suspiciousFiles[$file.Name] = "Error analyzing file: $($_.Exception.Message)"
                }
            }
        }

        if ($hiddenAndReadOnlyFiles.Count -gt 0) {
            Write-Host ("  Hidden & Read-only Files: {0} found" -f $hiddenAndReadOnlyFiles.Count) -ForegroundColor Yellow
            foreach ($file in $hiddenAndReadOnlyFiles) {
                Write-Host ("    {0}" -f $file.Name) -ForegroundColor White
            }
        }

        if ($hiddenFiles.Count -gt 0) {
            Write-Host ("  Hidden Files: {0} found" -f $hiddenFiles.Count) -ForegroundColor Yellow
            foreach ($file in $hiddenFiles) {
                Write-Host ("    {0}" -f $file.Name) -ForegroundColor White
            }
        } else {
            Write-Host "  Hidden Files: None" -ForegroundColor Green
        }

        if ($readOnlyFiles.Count -gt 0) {
            Write-Host ("  Read-Only Files: {0}" -f $readOnlyFiles.Count) -ForegroundColor Yellow
            foreach ($file in $readOnlyFiles) {
                Write-Host ("    {0}" -f $file.Name) -ForegroundColor White
            }
        } else {
            Write-Host "  Read-Only Files: None" -ForegroundColor Green
        }

        if ($invalidSignatureFiles.Count -gt 0) {
            Write-Host ("  Invalid Signatures: {0}" -f $invalidSignatureFiles.Count) -ForegroundColor Yellow
            foreach ($file in $invalidSignatureFiles) {
                Write-Host ("    {0}" -f $file.Name) -ForegroundColor White
            }
        } else {
            Write-Host "  File Signatures: All good" -ForegroundColor Green
        }

        $repeatedHashes = $hashTable.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
        if ($repeatedHashes) {
            Write-Host ("  Duplicate Files: {0} sets found" -f $repeatedHashes.Count) -ForegroundColor Yellow
            foreach ($entry in $repeatedHashes) {
                foreach ($file in $entry.Value) {
                    if (-not $suspiciousFiles.ContainsKey($file)) {
                        $suspiciousFiles[$file] = "Duplicate file"
                    }
                }
                Write-Host ("    Duplicate set: {0}" -f ($entry.Value -join ", ")) -ForegroundColor White
            }
        } else {
            Write-Host "  Duplicates: None" -ForegroundColor Green
        }

        if ($suspiciousFiles.Count -gt 0) {
            Write-Host ""
            Write-Host ("  SUSPICIOUS FILES FOUND: {0}/{1}" -f $suspiciousFiles.Count, $totalFiles) -ForegroundColor Yellow
            foreach ($entry in $suspiciousFiles.GetEnumerator() | Sort-Object Key) {
                Write-Host ("    {0} : {1}" -f $entry.Key, $entry.Value) -ForegroundColor White
            }
        } else {
            Write-Host ""
            Write-Host ("  Prefetch integrity: Clean ({0} files checked)" -f $totalFiles) -ForegroundColor Green
        }
    }
} else {
    Write-Host ""
    Write-Host "  Prefetch folder not found at: $prefetchPath" -ForegroundColor Red
}
Write-Host "└───────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

try {
    $recycleBinPath = "$env:SystemDrive" + '\$Recycle.Bin'
    Write-Host ""
    Write-Host "┌─ RECYCLE BIN ────────────────────────────────────────────────────┐" -ForegroundColor Cyan

    if (Test-Path $recycleBinPath) {
        $recycleBinFolder = Get-Item -LiteralPath $recycleBinPath -Force
        $userFolders = Get-ChildItem -LiteralPath $recycleBinPath -Directory -Force -ErrorAction SilentlyContinue

        if ($userFolders) {
            $allDeletedItems = @()
            $latestModTime = $recycleBinFolder.LastWriteTime

            foreach ($userFolder in $userFolders) {
                if ($userFolder.LastWriteTime -gt $latestModTime) {
                    $latestModTime = $userFolder.LastWriteTime
                }

                $userItems = Get-ChildItem -LiteralPath $userFolder.FullName -File -Force -ErrorAction SilentlyContinue
                if ($userItems) {
                    $allDeletedItems += $userItems

                    $latestFile = $userItems | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($latestFile -and $latestFile.LastWriteTime -gt $latestModTime) {
                        $latestModTime = $latestFile.LastWriteTime
                    }
                }
            }

            Write-Host ("  Last Modified : {0}" -f $latestModTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor Yellow

            if ($allDeletedItems.Count -gt 0) {
                Write-Host ("  Total Items   : {0}" -f $allDeletedItems.Count) -ForegroundColor Yellow

                $latestItem = $allDeletedItems | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                Write-Host ("  Latest Item   : {0}" -f $latestItem.Name) -ForegroundColor Gray
            } else {
                Write-Host ("  Status        : Folders present but empty") -ForegroundColor Green
            }
        } else {
            Write-Host ("  Status        : Empty") -ForegroundColor Green
            Write-Host ("  Last Modified : {0}" -f $recycleBinFolder.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor Green
        }

        $clearEvent = Get-WinEvent -FilterHashtable @{LogName="System"; Id=10006} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($clearEvent) {
            Write-Host ("  Last Cleared (Event) : {0}" -f $clearEvent.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor Red
        }
    } else {
        Write-Host ("  Recycle Bin not found at: {0}" -f $recycleBinPath) -ForegroundColor Yellow
        Write-Host "  Note: Recycle Bin may be empty or on a different drive" -ForegroundColor Gray
    }
} catch {
    Write-Host "  Recycle Bin: Unable to access" -ForegroundColor Red
    Write-Host ("  Error: {0}" -f $($_.Exception.Message)) -ForegroundColor 'DarkRed'
}
Write-Host "└───────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

    
 $consoleHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"

Write-Host "┌─ Console Host History ──────────────────────────────────────────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan

try {
    if (Test-Path $consoleHistoryPath) {
        $historyFile = Get-Item -Path $consoleHistoryPath -Force
        Write-Host "    Last Modified: " -NoNewline -ForegroundColor White
        Write-Host $historyFile.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") -ForegroundColor Yellow

        $attributes = $historyFile.Attributes
        if ($attributes -ne "Archive") {
            Write-Host "    Attributes: " -NoNewline -ForegroundColor White
            Write-Host $attributes -ForegroundColor Yellow
        } else {
            Write-Host "    Attributes: Normal" -ForegroundColor Green
        }

        $fileSize = $historyFile.Length
        Write-Host "    File Size: " -NoNewline -ForegroundColor White
        Write-Host "$([math]::Round($fileSize/1024, 2)) KB" -ForegroundColor Yellow

    } else {
        Write-Host "    File not found: $consoleHistoryPath" -ForegroundColor Yellow
        Write-Host "    Note: PowerShell history may be disabled or never used" -ForegroundColor Gray
    }
} catch {
    Write-Host "  Error accessing system information: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan



Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host ("║ {0,-70} ║" -f "Check Complete") -ForegroundColor Magenta
Write-Host ("║ {0,-70} ║" -f "Thanks for using") -ForegroundColor Magenta
Write-Host "╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
