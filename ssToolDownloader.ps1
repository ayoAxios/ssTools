# ============================================================
# Tool Downloader - Parallel Downloads via Runspaces
# Run as Administrator!
# ============================================================

# Check for Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges. Please run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

# ============================================================
# Add Windows Defender Exclusion for C: drive
# ============================================================
Write-Host "Configuring Windows Defender exclusion for C: drive..." -ForegroundColor Cyan

try {
    # Check if C: drive is already excluded
    $existingExclusions = Get-MpPreference -ErrorAction Stop | Select-Object -ExpandProperty ExclusionPath
    if ($existingExclusions -contains "C:\") {
        Write-Host "C: drive is already excluded from Windows Defender scanning." -ForegroundColor Green
    } else {
        Add-MpPreference -ExclusionPath "C:\" -ErrorAction Stop
        Write-Host "Added C: drive to Windows Defender exclusions." -ForegroundColor Green
    }
} catch {
    Write-Host "Failed to add Defender exclusion: $_" -ForegroundColor Red
    Write-Host "Script will continue, but some tools may be blocked by Defender." -ForegroundColor Yellow
}

# ============================================================
# Base folder setup
# ============================================================
$baseFolder = "C:\ss1"

if (-not (Test-Path $baseFolder)) {
    New-Item -ItemType Directory -Path $baseFolder -Force | Out-Null
    Write-Host "Created base folder: $baseFolder" -ForegroundColor Cyan
}

# ============================================================
# Tool Definitions
# ============================================================

$tools = @(
    @{ Name = "everything";       Url = "https://www.voidtools.com/Everything-1.4.1.1032.x86-Setup.exe";                                                           FileName = "Everything-Setup.exe";              Zip = $false; Run = $false }
    @{ Name = "amcache parser";   Url = "https://github.com/Orbdiff/AmcacheParser/releases/download/v1.0/AmcacheParser.exe";                                       FileName = "AmcacheParser.exe";                 Zip = $false; Run = $false }
    @{ Name = "prefetch parser";  Url = "https://github.com/Orbdiff/PrefetchView/releases/download/v1.6.5/pv++.exe";                                              FileName = "pv++.exe";                          Zip = $false; Run = $false }
    @{ Name = "winprefetchview";  Url = "https://www.nirsoft.net/utils/winprefetchview-x64.zip";                                                                    FileName = "winprefetchview-x64.zip";           Zip = $true;  Run = $false }
    @{ Name = "bamparser";        Url = "https://github.com/Orbdiff/BAMReveal/releases/download/v1.2.5/BAMReveal.exe";                                             FileName = "BAMReveal.exe";                     Zip = $false; Run = $false }
    @{ Name = "journal trace";    Url = "https://github.com/spokwn/JournalTrace/releases/download/1.2/JournalTraceNormal.exe";                                     FileName = "JournalTraceNormal.exe";            Zip = $false; Run = $false }
    @{ Name = "system informer";  Url = "https://github.com/winsiderss/si-builds/releases/download/4.0.26048.2459/systeminformer-build-canary-setup.exe";          FileName = "systeminformer-setup.exe";          Zip = $false; Run = $false }
    @{ Name = "velociraptor";     Url = "https://github.com/Velocidex/velociraptor/releases/download/v0.75/velociraptor-v0.75.6-windows-386.exe";                  FileName = "velociraptor.exe";                  Zip = $false; Run = $false }
    @{ Name = "paths parser";     Url = "https://github.com/spokwn/PathsParser/releases/download/v1.2/PathsParser.exe";                                           FileName = "PathsParser.exe";                   Zip = $false; Run = $false }
    @{ Name = "task parser";      Url = "https://github.com/ItzIceHere/RedLotus-Task-Sentinel/releases/download/RL/RedLotusTaskSentinel.exe";                      FileName = "RedLotusTaskSentinel.exe";          Zip = $false; Run = $false }
    @{ Name = "hardlink finder";  Url = "https://github.com/praiselily/HardlinkFinder/releases/download/Tools/hardlink.exe";                                       FileName = "hardlink.exe";                      Zip = $false; Run = $false }
    @{ Name = "ps hunter";        Url = "https://github.com/praiselily/PSHunter/releases/download/Built/PSHunter.exe";                                             FileName = "PSHunter.exe";                      Zip = $false; Run = $false }
    @{ Name = "lastactivityview"; Url = "https://www.nirsoft.net/utils/lastactivityview.zip";                                                                        FileName = "lastactivityview.zip";              Zip = $true;  Run = $false }
    @{ Name = "registry explorer"; Url = "https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip";                                                      FileName = "RegistryExplorer.zip";              Zip = $true;  Run = $false }
    @{ Name = "INDXRipper";        Url = "https://github.com/harelsegev/INDXRipper/releases/download/v20231117/INDXRipper-20231117-py3.12-amd64.zip";              FileName = "INDXRipper.zip";                    Zip = $true;  Run = $true;
       RunCmd = { param($folder)
           $exe = Get-ChildItem $folder -Recurse -Filter "INDXRipper.exe" | Select-Object -First 1 -ExpandProperty FullName
           if ($exe) { & $exe "C:" --deleted-dirs (Join-Path $folder "output.csv") }
       }
    }
    @{ Name = "shimcache";         Url = "https://download.ericzimmermanstools.com/net9/AppCompatCacheParser.zip";                                                    FileName = "AppCompatCacheParser.zip";          Zip = $true;  Run = $true;
       RunCmd = { param($folder)
           $exe = Get-ChildItem $folder -Recurse -Filter "AppCompatCacheParser.exe" | Select-Object -First 1 -ExpandProperty FullName
           if ($exe) {
               Push-Location $folder
               & $exe --csv .
               Pop-Location
           }
       }
    }
    @{ Name = "srum";              Url = "https://download.ericzimmermanstools.com/net9/SrumECmd.zip";                                                                FileName = "SrumECmd.zip";                      Zip = $true;  Run = $true;
       RunCmd = { param($folder)
           $exe = Get-ChildItem $folder -Recurse -Filter "SrumECmd.exe" | Select-Object -First 1 -ExpandProperty FullName
           if ($exe) {
               Push-Location $folder
               & $exe -f "C:\Windows\System32\sru\SRUDB.dat" --csv .
               Pop-Location
           }
       }
    }
    @{ Name = "dotnet-aspnetcore-runtime"; Url = "https://builds.dotnet.microsoft.com/dotnet/aspnetcore/Runtime/9.0.14/aspnetcore-runtime-9.0.14-win-x64.exe"; FileName = "aspnetcore-runtime-9.0.14-win-x64.exe"; Zip = $false; Run = $true;
       RunCmd = { param($folder)
           $exe = Join-Path $folder "aspnetcore-runtime-9.0.14-win-x64.exe"
           if (Test-Path $exe) {
               $installed = dotnet --list-runtimes 2>$null | Where-Object { $_ -match "Microsoft\.AspNetCore\.App 9\.0\.14" }
               if ($installed) {
                   Write-Host "  ASP.NET Core Runtime 9.0.14 already installed, skipping." -ForegroundColor Green
               } else {
                   Write-Host "  Installing ASP.NET Core Runtime 9.0.14..." -ForegroundColor Yellow
                   Start-Process -FilePath $exe -ArgumentList "/install /quiet /norestart" -Wait
                   Write-Host "  ASP.NET Core Runtime 9.0.14 installed." -ForegroundColor Green
               }
           }
       }
    }
    @{ Name = "timeline explorer"; Url = "https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip";                                                        FileName = "TimelineExplorer.zip";              Zip = $true;  Run = $false }
    @{ Name = "hayabusa";         Url = "https://github.com/Yamato-Security/hayabusa/releases/download/v3.8.1/hayabusa-3.8.1-win-x64-live-response.zip";             FileName = "hayabusa-3.8.1-win-x64-live-response.zip"; Zip = $true; Run = $true;
       RunCmd = { param($folder)
           $exe = Get-ChildItem $folder -Recurse -Filter "hayabusa-3.8.1-win-x64.exe" | Select-Object -First 1 -ExpandProperty FullName
           if ($exe) {
               Push-Location $folder
               & $exe csv-timeline --output CSVoutput.csv -d C:\Windows\System32\winevt\Logs --HTML-report HTMLOutput.html --ISO-8601 --yes
               Pop-Location
           }
       }
    }
    @{ Name = "mftecmd";          Url = "https://download.ericzimmermanstools.com/net9/MFTECmd.zip";                                                               FileName = "MFTECmd.zip";                       Zip = $true;  Run = $true;
       RunCmd = { param($folder)
           $exe = Get-ChildItem $folder -Recurse -Filter "MFTECmd.exe" | Select-Object -First 1 -ExpandProperty FullName
           if ($exe) {
               Push-Location $folder
               & $exe -f "C:\`$MFT" --csv .
               Pop-Location
           }
       }
    }
)

# ============================================================
# Parallel Download Scriptblock
# ============================================================

$downloadScript = {
    param($tool, $baseFolder)

    $toolFolder  = Join-Path $baseFolder $tool.Name
    $destination = Join-Path $toolFolder $tool.FileName

    if (-not (Test-Path $toolFolder)) {
        New-Item -ItemType Directory -Path $toolFolder -Force | Out-Null
    }

    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($tool.Url, $destination)
        return @{ Success = $true; Name = $tool.Name; Message = "[OK] $($tool.Name)" }
    } catch {
        return @{ Success = $false; Name = $tool.Name; Message = "[FAIL] $($tool.Name): $_" }
    }
}

# ============================================================
# Launch all downloads in parallel using Runspaces
# ============================================================

Write-Host "Starting parallel downloads..." -ForegroundColor Cyan

$runspacePool = [runspacefactory]::CreateRunspacePool(1, 8)
$runspacePool.Open()

$jobs = @()
$results = @()

foreach ($tool in $tools) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $runspacePool
    $ps.AddScript($downloadScript).AddArgument($tool).AddArgument($baseFolder) | Out-Null
    $jobs += @{ PS = $ps; Handle = $ps.BeginInvoke(); Tool = $tool }
}

foreach ($job in $jobs) {
    $result = $job.PS.EndInvoke($job.Handle)
    $results += $result
    $color = if ($result.Success) { "Green" } else { "Red" }
    Write-Host $result.Message -ForegroundColor $color
    $job.PS.Dispose()
}

$runspacePool.Close()
$runspacePool.Dispose()

$successfulTools = $results | Where-Object { $_.Success } | ForEach-Object { $_.Name }

Write-Host "`nAll downloads complete. Processing zips and running tools..." -ForegroundColor Cyan

# ============================================================
# Post-download: Run non-zip executables
# ============================================================

foreach ($tool in $tools | Where-Object { $_.Zip -eq $false -and $_.Run -eq $true }) {
    if ($tool.Name -notin $successfulTools) {
        Write-Host "Skipping $($tool.Name) – download failed." -ForegroundColor Red
        continue
    }
    $toolFolder = Join-Path $baseFolder $tool.Name
    Write-Host "Running $($tool.Name)..." -ForegroundColor Yellow
    try {
        & $tool.RunCmd $toolFolder
        Write-Host "  $($tool.Name) complete." -ForegroundColor Green
    } catch {
        Write-Host "  FAILED to run $($tool.Name): $_" -ForegroundColor Red
    }
}

# ============================================================
# Post-download: Extract zips and run tools
# ============================================================

foreach ($tool in $tools | Where-Object { $_.Zip -eq $true }) {
    if ($tool.Name -notin $successfulTools) {
        Write-Host "Skipping $($tool.Name) – download failed." -ForegroundColor Red
        continue
    }
    $toolFolder  = Join-Path $baseFolder $tool.Name
    $zipPath     = Join-Path $toolFolder $tool.FileName

    if (Test-Path $zipPath) {
        Write-Host "Extracting $($tool.Name)..." -ForegroundColor Yellow
        try {
            Expand-Archive -Path $zipPath -DestinationPath $toolFolder -Force
            Remove-Item $zipPath -Force
            Write-Host "  Extracted: $toolFolder" -ForegroundColor Green
        } catch {
            Write-Host "  FAILED to extract $($tool.Name): $_" -ForegroundColor Red
            continue
        }
    } else {
        Write-Host "ZIP file missing for $($tool.Name) – skipping." -ForegroundColor Red
        continue
    }

    if ($tool.Run -and $tool.RunCmd) {
        Write-Host "  Running $($tool.Name)..." -ForegroundColor Yellow
        try {
            & $tool.RunCmd $toolFolder
            Write-Host "  $($tool.Name) complete." -ForegroundColor Green
        } catch {
            Write-Host "  FAILED to run $($tool.Name): $_" -ForegroundColor Red
        }
    }
}

Write-Host "`nAll done! Tools saved to: $baseFolder" -ForegroundColor Cyan
