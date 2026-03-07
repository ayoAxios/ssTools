$Host.UI.RawUI.WindowTitle = "FiveM PC Check - Suspicious Activity Scanner"
$Host.UI.RawUI.BackgroundColor = "Black"
Clear-Host

# ---- Helpers ------------------------------------------------

function Write-Header {
    param($text)
    Write-Host ""
    Write-Host "  ════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "   $text" -ForegroundColor Cyan
    Write-Host "  ════════════════════════════════════════════════" -ForegroundColor DarkCyan
}

function Write-Flag {
    param($label, $value, $reason)
    Write-Host "  [!] " -ForegroundColor Red -NoNewline
    Write-Host "$label" -ForegroundColor Yellow -NoNewline
    Write-Host " → $value" -ForegroundColor White
    if ($reason) {
        Write-Host "      Reason: $reason" -ForegroundColor DarkYellow
    }
}

function Write-Clean {
    param($text)
    Write-Host "  [✓] $text" -ForegroundColor DarkGreen
}

function Write-Info {
    param($text)
    Write-Host "  [~] $text" -ForegroundColor DarkGray
}

$suspiciousCount = 0
$findings = [System.Collections.ArrayList]::new()

function Add-Finding {
    param($category, $detail, $reason)
    $null = $findings.Add([PSCustomObject]@{ Category=$category; Detail=$detail; Reason=$reason })
    $script:suspiciousCount++
}

# Known VPS/Datacenter ASN keywords
$vpsKeywords = @("vultr","digitalocean","linode","hetzner","ovh","contabo","aws","amazon","azure","google cloud",
                  "cloudflare","leaseweb","choopa","frantech","server","datacenter","vps","hosting","dedicated")

# Known cheat / pipe / remote tools
$suspiciousProcessNames = @("plink","putty","ncat","nc","netcat","socat","chisel","frp","frpc","frps",
                             "proxifier","proxycap","stunnel","iodine","ssf","ligolo","rpivot",
                             "meterpreter","payload","inject","loader","hook","trainer","cheatengine",
                             "cheat engine","processhacker","processhacker2","ph2","ph64")

$suspiciousPaths = @("\\temp\\","\\tmp\\","\\appdata\\local\\temp\\","\\appdata\\roaming\\temp\\",
                      "\\downloads\\","\\public\\","\\users\\public\\")

$suspiciousPipes = @("cheat","gta","fivem","hack","inject","pipe","cmd","shell","ghost","loader",
                      "remote","vps","tunnel","bypass","spoof")

# ============================================================
Write-Host ""
Write-Host "            catching cursed bypass.lol" -ForegroundColor White
Write-Host ""
Write-Host "  Starting scan for pipes n shiii  ..." -ForegroundColor DarkGray
Start-Sleep -Milliseconds 500

# ============================================================
# CHECK 1: Running Processes
# ============================================================
Write-Header "CHECK 1: Running Processes"

$processes = Get-Process | Select-Object Name, Id, Path, CPU, @{N='StartTime';E={try{$_.StartTime}catch{'N/A'}}}

$foundSuspiciousProc = $false
foreach ($proc in $processes) {
    $name = $proc.Name.ToLower()
    foreach ($sus in $suspiciousProcessNames) {
        if ($name -like "*$sus*") {
            Write-Flag "Suspicious Process" "$($proc.Name) (PID: $($proc.Id))" "Known cheat/pipe/remote tool name match: '$sus'"
            Add-Finding "Process" "$($proc.Name) PID:$($proc.Id)" "Matches known cheat/remote tool: $sus"
            $foundSuspiciousProc = $true
        }
    }
    # Check if running from suspicious path
    if ($proc.Path) {
        $pathLower = $proc.Path.ToLower()
        foreach ($susPath in $suspiciousPaths) {
            if ($pathLower -like "*$susPath*") {
                Write-Flag "Process in Suspicious Path" "$($proc.Name) → $($proc.Path)" "Executables running from Temp/Public folders is unusual"
                Add-Finding "Process Path" "$($proc.Name) at $($proc.Path)" "Running from suspicious directory"
                $foundSuspiciousProc = $true
            }
        }
    }
}

if (-not $foundSuspiciousProc) { Write-Clean "No obviously suspicious processes found" }

# ============================================================
# CHECK 2: Process Tree (Parent-Child)
# ============================================================
Write-Header "CHECK 2: Process Parent-Child Relationships"

try {
    $wmiProcs = Get-WmiObject Win32_Process | Select-Object Name, ProcessId, ParentProcessId, CommandLine
    $procDict = @{}
    foreach ($p in $wmiProcs) { $procDict[$p.ProcessId] = $p.Name }

    $foundSuspiciousTree = $false
    foreach ($proc in $wmiProcs) {
        $cmdLine = $proc.CommandLine
        if (-not $cmdLine) { continue }
        $cmdLower = $cmdLine.ToLower()

        # cmd.exe or powershell with pipe/ssh in args
        if (($proc.Name -like "cmd.exe" -or $proc.Name -like "powershell*") -and
            ($cmdLower -match "ssh|plink|pipe|netcat|ncat|socat|\|")) {
            $parentName = $procDict[$proc.ParentProcessId]
            Write-Flag "Pipe/SSH in Shell Args" "$($proc.Name) (PID $($proc.ProcessId))" "Parent: $parentName | CMD: $cmdLine"
            Add-Finding "Process Tree" $proc.Name "Shell with SSH/pipe arguments: $cmdLine"
            $foundSuspiciousTree = $true
        }

        # cmd.exe spawned by something other than explorer or ConHost
        if ($proc.Name -eq "cmd.exe") {
            $parentName = $procDict[$proc.ParentProcessId]
            if ($parentName -and $parentName -notmatch "explorer|cmd|powershell|conhost|WindowsTerminal|pwsh") {
                Write-Flag "Unusual CMD Parent" "cmd.exe spawned by: $parentName (PID $($proc.ParentProcessId))" "CMD should normally be opened by explorer or a terminal"
                Add-Finding "Process Tree" "cmd.exe" "Spawned by unusual parent: $parentName"
                $foundSuspiciousTree = $true
            }
        }
    }
    if (-not $foundSuspiciousTree) { Write-Clean "Process tree looks normal" }
} catch {
    Write-Info "Could not query WMI process tree (run as Admin for full results)"
}

# ============================================================
# CHECK 3: Active Network Connections
# ============================================================
Write-Header "CHECK 3: Active Network Connections"

try {
    $netstatOutput = netstat -ano 2>$null
    $establishedLines = $netstatOutput | Select-String "ESTABLISHED"

    $wmiProcs2 = Get-WmiObject Win32_Process | Select-Object ProcessId, Name, CommandLine
    $pidToProc = @{}
    foreach ($p in $wmiProcs2) { $pidToProc[[string]$p.ProcessId] = $p }

    $foundSuspiciousNet = $false

    foreach ($line in $establishedLines) {
        $parts = $line.ToString().Trim() -split '\s+'
        if ($parts.Count -lt 5) { continue }

        $remoteAddr = $parts[2]
        $pid = $parts[4]
        $procInfo = $pidToProc[$pid]
        $procName = if ($procInfo) { $procInfo.Name } else { "Unknown(PID:$pid)" }

        # Skip localhost
        if ($remoteAddr -match "^127\.|^\[::1\]|^0\.0\.0\.0") { continue }

        # Extract IP
        $remoteIP = $remoteAddr -replace ':\d+$', '' -replace '^\[', '' -replace '\]', ''

        # Flag if cmd.exe or powershell owns a connection
        if ($procName -match "cmd\.exe|powershell") {
            Write-Flag "Shell Owns Network Connection" "$procName (PID $pid) → $remoteAddr" "cmd/powershell should NEVER own an established connection — strong pipe indicator"
            Add-Finding "Network" "$procName → $remoteAddr" "Shell process with active connection"
            $foundSuspiciousNet = $true
        }

        # Flag common SSH/tunnel ports
        $remotePort = ($remoteAddr -split ':')[-1]
        if ($remotePort -in @("22","4444","1337","8888","9999","31337","6666","6667","1080","3128")) {
            Write-Flag "Suspicious Port Connection" "$procName (PID $pid) → $remoteAddr (Port $remotePort)" "Port commonly used for SSH tunnels, shells, or SOCKS proxies"
            Add-Finding "Network" "$procName → $remoteAddr" "Suspicious port: $remotePort"
            $foundSuspiciousNet = $true
        }
    }

    if (-not $foundSuspiciousNet) { Write-Clean "No obviously suspicious connections found" }
    Write-Info "Tip: Cross-reference IPs above at ipinfo.io to check if they belong to VPS providers"

} catch {
    Write-Info "Could not fully parse network connections"
}

# ============================================================
# CHECK 4: Named Pipes
# ============================================================
Write-Header "CHECK 4: Named Pipes (Pipe Cheat Smoking Gun)"

try {
    $pipes = [System.IO.Directory]::GetFiles("\\\\.\\pipe\\")
    $legitPipes = @("lsass","srvsvc","wkssvc","ntsvcs","svcctl","eventlog","spoolss","browser",
                     "epmapper","LSM_API_service","atsvc","trkwks","winreg","InitShutdown",
                     "Ctx_WinStation","TermSrv","W32TIME","netlogon","protected_storage")

    $foundSuspiciousPipe = $false
    foreach ($pipe in $pipes) {
        $pipeName = $pipe.Replace("\\.\\pipe\\","").Replace("\\.\pipe\","").ToLower()
        $isLegit = $false
        foreach ($legit in $legitPipes) {
            if ($pipeName -like "*$legit*") { $isLegit = $true; break }
        }
        # Check against suspicious keywords
        foreach ($sus in $suspiciousPipes) {
            if ($pipeName -like "*$sus*") {
                Write-Flag "Suspicious Named Pipe" "\\.\pipe\$pipeName" "Pipe name matches known cheat/remote keywords"
                Add-Finding "Named Pipe" "\\.\pipe\$pipeName" "Suspicious pipe name"
                $foundSuspiciousPipe = $true
            }
        }
        # Flag non-legit short/random-looking pipes
        if (-not $isLegit -and $pipeName.Length -gt 0) {
            if ($pipeName -match "^[a-z0-9]{8,}$" -and $pipeName -notmatch "chrome|firefox|discord|steam|epic") {
                Write-Flag "Unknown/Random Named Pipe" "\\.\pipe\$pipeName" "Random-looking pipe name — may be a cheat communication channel"
                Add-Finding "Named Pipe" "\\.\pipe\$pipeName" "Random/unknown pipe name"
                $foundSuspiciousPipe = $true
            }
        }
    }
    if (-not $foundSuspiciousPipe) { Write-Clean "No suspicious named pipes detected" }
} catch {
    Write-Info "Could not enumerate named pipes (run as Administrator)"
}

# ============================================================
# CHECK 5: CMD & PowerShell History
# ============================================================
Write-Header "CHECK 5: Shell Command History"

# PowerShell history
$psHistoryPath = (Get-PSReadlineOption -ErrorAction SilentlyContinue).HistorySavePath
if ($psHistoryPath -and (Test-Path $psHistoryPath)) {
    $psHistory = Get-Content $psHistoryPath -ErrorAction SilentlyContinue | Select-Object -Last 100
    $foundHistory = $false
    foreach ($line in $psHistory) {
        $lineLower = $line.ToLower()
        if ($lineLower -match "ssh|plink|netcat|ncat|socat|pipe|tunnel|vps|frp|chisel|inject|loader") {
            Write-Flag "Suspicious PS History" $line "PowerShell history contains remote/pipe keywords"
            Add-Finding "PS History" $line "Suspicious command in history"
            $foundHistory = $true
        }
    }
    if (-not $foundHistory) { Write-Clean "PowerShell history looks clean" }
} else {
    Write-Info "No PowerShell history file found"
}

# ============================================================
# CHECK 6: Startup Entries
# ============================================================
Write-Header "CHECK 6: Startup / Autorun Entries"

$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$knownLegitStartup = @("onedrive","teams","discord","steam","nvidia","amd","realtek","intel","
                         logitech","razer","corsair","spotify","dropbox","googledrive","zoom",
                         "windowsdefender","securityhealth","backgroundtaskhost")

$foundStartup = $false
foreach ($regPath in $regPaths) {
    try {
        $entries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
        if ($entries) {
            $entries.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                $entryName = $_.Name.ToLower()
                $entryVal  = $_.Value.ToLower()
                $isKnown = $false
                foreach ($legit in $knownLegitStartup) {
                    if ($entryName -like "*$legit*" -or $entryVal -like "*$legit*") { $isKnown = $true; break }
                }
                if (-not $isKnown) {
                    # Check if value path is suspicious
                    $isSuspiciousPath = $false
                    foreach ($susPath in $suspiciousPaths) {
                        if ($entryVal -like "*$susPath*") { $isSuspiciousPath = $true; break }
                    }
                    if ($isSuspiciousPath -or $entryVal -match "ssh|plink|pipe|tunnel|inject|loader") {
                        Write-Flag "Suspicious Startup Entry" "$($_.Name) = $($_.Value)" "Autorun from suspicious path or with suspicious keywords"
                        Add-Finding "Startup" "$($_.Name) = $($_.Value)" "Suspicious autorun entry"
                        $foundStartup = $true
                    } else {
                        Write-Info "Unknown startup (verify manually): $($_.Name) = $($_.Value)"
                    }
                }
            }
        }
    } catch {}
}
if (-not $foundStartup) { Write-Clean "No clearly suspicious startup entries" }

# ============================================================
# CHECK 7: DNS Cache (VPS Connections)
# ============================================================
Write-Header "CHECK 7: DNS Cache (Recent Connections)"

try {
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
    $foundDNS = $false
    foreach ($entry in $dnsCache) {
        $name = $entry.Entry.ToLower()
        foreach ($kw in $vpsKeywords) {
            if ($name -like "*$kw*") {
                Write-Flag "VPS/Datacenter DNS Entry" $entry.Entry "Resolved hostname suggests VPS/datacenter connection"
                Add-Finding "DNS Cache" $entry.Entry "VPS-related hostname in DNS cache"
                $foundDNS = $true
                break
            }
        }
    }
    if (-not $foundDNS) { Write-Clean "No obvious VPS/datacenter hostnames in DNS cache" }
} catch {
    Write-Info "Could not read DNS cache"
}

# ============================================================
# CHECK 8: Recent Files in Suspicious Locations
# ============================================================
Write-Header "CHECK 8: Recent Executables in Temp/AppData"

$checkFolders = @(
    $env:TEMP,
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp",
    "$env:USERPROFILE\Downloads"
)

$foundRecentExe = $false
$cutoff = (Get-Date).AddDays(-7)

foreach ($folder in $checkFolders) {
    if (Test-Path $folder) {
        $recentExes = Get-ChildItem $folder -Filter "*.exe" -ErrorAction SilentlyContinue |
                      Where-Object { $_.LastWriteTime -gt $cutoff } |
                      Sort-Object LastWriteTime -Descending

        foreach ($exe in $recentExes) {
            Write-Flag "Recent EXE in $folder" $exe.Name "Modified: $($exe.LastWriteTime) | Path: $($exe.FullName)"
            Add-Finding "Recent Files" $exe.FullName "Recent executable in suspicious location"
            $foundRecentExe = $true
        }

        # Also check .bat, .ps1, .py
        $recentScripts = Get-ChildItem $folder -Include "*.bat","*.ps1","*.py","*.vbs" -ErrorAction SilentlyContinue |
                         Where-Object { $_.LastWriteTime -gt $cutoff } |
                         Sort-Object LastWriteTime -Descending

        foreach ($script in $recentScripts) {
            Write-Flag "Recent Script in $folder" $script.Name "Modified: $($script.LastWriteTime) | Path: $($script.FullName)"
            Add-Finding "Recent Files" $script.FullName "Recent script in suspicious location"
            $foundRecentExe = $true
        }
    }
}
if (-not $foundRecentExe) { Write-Clean "No recent suspicious executables found in temp locations" }

# ============================================================
# CHECK 9: FiveM Plugins & Files
# ============================================================
Write-Header "CHECK 9: FiveM Integrity"

$fivemPlugins = "$env:LOCALAPPDATA\FiveM\FiveM.app\plugins"
$fivemCitizen = "$env:LOCALAPPDATA\FiveM\FiveM.app\citizen"

if (Test-Path $fivemPlugins) {
    $plugins = Get-ChildItem $fivemPlugins -ErrorAction SilentlyContinue
    if ($plugins) {
        foreach ($plugin in $plugins) {
            Write-Flag "FiveM Plugin Found" $plugin.Name "Non-default plugins can inject code into FiveM — verify legitimacy"
            Add-Finding "FiveM" $plugin.FullName "Plugin in FiveM plugins folder"
        }
    } else {
        Write-Clean "FiveM plugins folder is empty"
    }
} else {
    Write-Info "FiveM plugins folder not found (FiveM may not be installed)"
}

# Check for modified citizen files recently
if (Test-Path $fivemCitizen) {
    $recentCitizen = Get-ChildItem $fivemCitizen -Recurse -ErrorAction SilentlyContinue |
                     Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-3) -and -not $_.PSIsContainer } |
                     Sort-Object LastWriteTime -Descending | Select-Object -First 10
    if ($recentCitizen) {
        Write-Host ""
        Write-Info "Recently modified FiveM citizen files (last 3 days):"
        foreach ($f in $recentCitizen) {
            Write-Flag "Modified Citizen File" $f.Name "$($f.LastWriteTime) | $($f.FullName)"
            Add-Finding "FiveM" $f.FullName "Recently modified citizen file"
        }
    } else {
        Write-Clean "No recently modified FiveM citizen files"
    }
}

# ============================================================
# CHECK 10: Prefetch (Recently Run Programs)
# ============================================================
Write-Header "CHECK 10: Recently Executed Programs (Prefetch)"

$prefetchPath = "C:\Windows\Prefetch"
if (Test-Path $prefetchPath) {
    try {
        $recentPrefetch = Get-ChildItem $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue |
                          Sort-Object LastWriteTime -Descending | Select-Object -First 50

        $foundPrefetch = $false
        foreach ($pf in $recentPrefetch) {
            $pfName = $pf.Name.ToLower()
            foreach ($sus in ($suspiciousProcessNames + @("ssh","tunnel","pipe","inject","frp","chisel"))) {
                if ($pfName -like "*$sus*") {
                    Write-Flag "Suspicious Prefetch Entry" $pf.Name "Last run: $($pf.LastWriteTime) — matches known cheat/remote tool"
                    Add-Finding "Prefetch" $pf.Name "Prefetch entry for suspicious program: $sus"
                    $foundPrefetch = $true
                }
            }
        }
        if (-not $foundPrefetch) { Write-Clean "No suspicious entries in prefetch" }
    } catch {
        Write-Info "Could not read Prefetch (run as Administrator)"
    }
} else {
    Write-Info "Prefetch folder not accessible"
}

# ============================================================
# SUMMARY REPORT
# ============================================================
Write-Host ""
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor $(if($suspiciousCount -gt 5){"Red"}elseif($suspiciousCount -gt 0){"Yellow"}else{"Green"})
Write-Host "  ║           SCAN COMPLETE - SUMMARY REPORT          ║" -ForegroundColor $(if($suspiciousCount -gt 5){"Red"}elseif($suspiciousCount -gt 0){"Yellow"}else{"Green"})
Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor $(if($suspiciousCount -gt 5){"Red"}elseif($suspiciousCount -gt 0){"Yellow"}else{"Green"})
Write-Host ""

if ($suspiciousCount -eq 0) {
    Write-Host "  ✓ RESULT: CLEAN — No suspicious indicators found" -ForegroundColor Green
    Write-Host "    This does not guarantee the player is clean." -ForegroundColor DarkGray
    Write-Host "    A sophisticated cheater may have cleaned up before the check." -ForegroundColor DarkGray
} else {
    $color = if ($suspiciousCount -gt 5) { "Red" } else { "Yellow" }
    Write-Host "  ⚠ RESULT: $suspiciousCount SUSPICIOUS INDICATOR(S) FOUND" -ForegroundColor $color
    Write-Host ""
    Write-Host "  ┌─ FINDINGS ──────────────────────────────────────" -ForegroundColor DarkGray

    $groupedFindings = $findings | Group-Object Category
    foreach ($group in $groupedFindings) {
        Write-Host "  │" -ForegroundColor DarkGray
        Write-Host "  │  [$($group.Name)]" -ForegroundColor Yellow
        foreach ($item in $group.Group) {
            Write-Host "  │   • $($item.Detail)" -ForegroundColor White
            Write-Host "  │     → $($item.Reason)" -ForegroundColor DarkYellow
        }
    }
    Write-Host "  └─────────────────────────────────────────────────" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  Scan finished: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "  Save this window as a screenshot for your ban evidence." -ForegroundColor DarkGray
Write-Host ""

# Keep window open
Write-Host "  Press any key to exit..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
