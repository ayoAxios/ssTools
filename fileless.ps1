# ==============================================
# 🔍 PowerShell Fileless Command Scanner v10
#   - Focuses on actual commands and script blocks
#   - Clean CSV output for Timeline Explorer
#   - Only Event IDs 600, 400, 403 from PowerShell logs
#   - Proper CSV formatting without comma issues
# ==============================================

Clear-Host

$path = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
$csvPath = "C:\fileless.csv"

# Suspicious patterns (case-insensitive)
$patterns = @(
    'iex',
    'iwr',
    'irm',
    'Invoke-Expression',
    'Invoke-WebRequest',
    'Invoke-RestMethod',
    'New-Object',
    'DownloadFile',
    'DownloadString',
    'certutil',
    'curl',
    'wget',
    'bitsadmin',
    '-EncodedCommand',
    'http://',
    'https://',
    'rundll32'
)

$results = @()
$minLen = 8

Write-Host "🔍 PowerShell Fileless Command Scanner" -ForegroundColor Cyan
Write-Host "=============================================="

# Scan command history file
if (Test-Path $path) {
    Write-Host "`n[+] Scanning PowerShell command history..." -ForegroundColor Green
    $allLines = Get-Content -Path $path

    for ($i = 0; $i -lt $allLines.Count; $i++) {
        $line = $allLines[$i].Trim()
        if ($line.Length -lt $minLen) { continue }

        $foundFlags = @()
        foreach ($pattern in $patterns) {
            if ($line -match ("(?i)" + [regex]::Escape($pattern))) {
                $foundFlags += $pattern
            }
        }

        if ($foundFlags.Count -gt 0) {
            $results += [PSCustomObject]@{
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Source = "PSHistory"
                Command = $line
                Flags = ($foundFlags -join " | ")  # Use pipe instead of comma for CSV
                FlagCount = $foundFlags.Count
                Severity = if ($foundFlags.Count -ge 3) { "High" } elseif ($foundFlags.Count -eq 2) { "Medium" } else { "Low" }
            }
        }
    }
    Write-Host "[✔] History scan complete: $($results.Count) findings" -ForegroundColor Green
}

# Scan PowerShell Event Logs for Event IDs 600, 400, 403 only
Write-Host "`n[+] Scanning PowerShell Event Logs (IDs: 600, 400, 403)..." -ForegroundColor Green

function Extract-CommandFromEvent {
    param($Event)
    
    $command = $null
    
    # Try to extract from HostApplication field in the message
    if ($Event.Message -match "HostApplication=([^\r\n#]+)") {
        $command = $matches[1].Trim()
        # Remove any trailing # characters
        $command = $command -replace '#$', ''
    }
    
    # If that didn't work, try parsing the XML for HostApplication
    if (-not $command -or $command.Length -lt 5) {
        try {
            $eventXml = [xml]$Event.ToXml()
            $hostApp = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq "HostApplication" }
            if ($hostApp -and $hostApp.'#text') {
                $command = $hostApp.'#text'.Trim()
                # Remove any trailing # characters
                $command = $command -replace '#$', ''
            }
        } catch {
            # XML parsing failed, fall back to property scanning
            if ($Event.Properties -and $Event.Properties.Count -gt 0) {
                for ($i = 0; $i -lt $Event.Properties.Count; $i++) {
                    $propValue = $Event.Properties[$i].Value
                    if ($propValue -and $propValue.ToString() -match "powershell") {
                        $command = $propValue.ToString().Trim()
                        $command = $command -replace '#$', ''
                        break
                    }
                }
            }
        }
    }
    
    return $command
}

function Test-SuspiciousPatterns {
    param($Command)
    
    $foundFlags = @()
    
    if (-not $Command) { return $foundFlags }
    
    foreach ($pattern in $patterns) {
        # Use simple case-insensitive matching instead of complex regex
        if ($Command -like "*$pattern*") {
            $foundFlags += $pattern
        }
    }
    
    return $foundFlags
}

try {
    $eventLogs = @('Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell')
    $relevantEvents = @()
    
    foreach ($logName in $eventLogs) {
        try {
            Write-Host "  Checking: $logName" -ForegroundColor Gray
            # Get more events to ensure we catch everything
            $events = Get-WinEvent -LogName $logName -MaxEvents 5000 -ErrorAction SilentlyContinue | 
                     Where-Object { $_.Id -in @(600, 400, 403) }
            
            if ($events) {
                Write-Host "  [✔] Found $($events.Count) events (IDs: 600,400,403)" -ForegroundColor Green
                $relevantEvents += $events
            }
        } catch {
            Write-Host "  [⚠] Cannot access: $logName" -ForegroundColor Yellow
        }
    }

    if ($relevantEvents.Count -gt 0) {
        $eventFindings = 0
        Write-Host "  Processing $($relevantEvents.Count) events..." -ForegroundColor Gray
        
        foreach ($event in $relevantEvents) {
            $command = Extract-CommandFromEvent -Event $event
            
            if ($command -and $command.Length -ge $minLen) {
                $foundFlags = Test-SuspiciousPatterns -Command $command

                if ($foundFlags.Count -gt 0) {
                    $results += [PSCustomObject]@{
                        Timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                        Source = "EventLog-$($event.Id)"
                        Command = $command
                        Flags = ($foundFlags -join " | ")  # Use pipe instead of comma for CSV
                        FlagCount = $foundFlags.Count
                        Severity = if ($foundFlags.Count -ge 3) { "High" } elseif ($foundFlags.Count -eq 2) { "Medium" } else { "Low" }
                    }
                    $eventFindings++
                    
                    # Show progress for large datasets
                    if ($eventFindings % 10 -eq 0) {
                        Write-Host "  Processed $eventFindings findings..." -ForegroundColor Gray
                    }
                }
            }
        }
        Write-Host "[✔] Event log scan complete: $eventFindings findings from events" -ForegroundColor Green
    } else {
        Write-Host "[ℹ] No Event ID 600, 400, or 403 events found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[❌] Error accessing event logs: $_" -ForegroundColor Red
}

# Display results in console
if ($results.Count -eq 0) {
    Write-Host "`n[✔] No suspicious commands found." -ForegroundColor Green
    # Create empty CSV with headers
    [PSCustomObject]@{
        Timestamp = "N/A"
        Source = "No findings"
        Command = "No suspicious commands detected"
        Flags = "None"
        FlagCount = 0
        Severity = "None"
    } | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "[📄] Empty report exported to: $csvPath" -ForegroundColor Cyan
    return
}

Write-Host "`n[📋] SCAN RESULTS (Console View):" -ForegroundColor Cyan
Write-Host "=============================================="

foreach ($result in $results) {
    $color = switch ($result.Severity) {
        "High" { "Red" }
        "Medium" { "Yellow" }
        "Low" { "Green" }
    }
    
    Write-Host "`n🕒 $($result.Timestamp)" -ForegroundColor White
    Write-Host "📁 Source: $($result.Source)" -ForegroundColor Gray
    Write-Host "⚡ Command: $($result.Command)" -ForegroundColor $color
    Write-Host "🚩 Flags: $($result.Flags)" -ForegroundColor Cyan
    Write-Host "📊 Severity: $($result.Severity) ($($result.FlagCount) flags)" -ForegroundColor DarkGray
}

# Export clean CSV for Timeline Explorer
Write-Host "`n[📄] Exporting to CSV for Timeline Explorer..." -ForegroundColor Cyan
try {
    $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[✔] Successfully exported $($results.Count) records to: $csvPath" -ForegroundColor Green
    
    # Show CSV preview
    Write-Host "`n[📊] CSV Preview:" -ForegroundColor Cyan
    $results | Select-Object Timestamp, Source, Severity, FlagCount, Command, Flags | Format-Table -AutoSize
    
} catch {
    Write-Host "[❌] Error exporting to CSV: $_" -ForegroundColor Red
}

Write-Host "`n=============================================="
Write-Host "[🎯] Ready for Timeline Explorer import!" -ForegroundColor Green
Write-Host "[📁] File: $csvPath" -ForegroundColor Cyan
Write-Host "[📊] Total findings: $($results.Count)" -ForegroundColor White