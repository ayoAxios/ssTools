[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$servicesPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
$services = Get-ChildItem -Path $servicesPath
$userName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$timeThreshold = (Get-Date).AddMinutes(-60)
Write-Host "made by _.ayo" -ForegroundColor DarkGray
$knownMappings = @{
    "AarSvc" = "AarSvc.dll"; "AppHostSvc" = "apphostsvc.dll"; "AppIDSvc" = "appidsvc.dll"; "AppMgmt" = "appmgmts.dll";
    "AppReadiness" = "AppReadiness.dll"; "AppXSvc" = "appxdeploymentserver.dll"; "AudioEndpointBuilder" = "AudioEndpointBuilder.dll";
    "Audiosrv" = "Audiosrv.dll"; "autotimesvc" = "autotimesvc.dll"; "AxInstSV" = "AxInstSV.dll";
    "BcastDVRUserService" = "BcastDVRUserService.dll"; "BDESVC" = "bdesvc.dll"; "BFE" = "bfe.dll"; "BITS" = "qmgr.dll";
    "BluetoothUserService" = "Microsoft.Bluetooth.UserService.dll"; "BrokerInfrastructure" = "psmsrv.dll";
    "BTAGService" = "BTAGService.dll"; "BthAvctpSvc" = "BthAvctpSvc.dll"; "bthserv" = "bthserv.dll";
    "camsvc" = "CapabilityAccessManager.dll"; "CaptureService" = "CaptureService.dll"; "cbdhsvc" = "cbdhsvc.dll";
    "CDPSvc" = "CDPSvc.dll"; "CDPUserSvc" = "CDPUserSvc.dll"; "CertPropSvc" = "certprop.dll"; "ClipSVC" = "ClipSVC.dll";
    "ConsentUxUserSvc" = "ConsentUxClient.dll"; "CoreMessagingRegistrar" = "coremessaging.dll"; "CscService" = "cscsvc.dll";
    "DcomLaunch" = "rpcss.dll"; "dcsvc" = "dcsvc.dll"; "defragsvc" = "defragsvc.dll";
    "DeviceAssociationBrokerSvc" = "deviceaccess.dll"; "DeviceAssociationService" = "das.dll"; "DeviceInstall" = "umpnpmgr.dll";
    "DevicePickerUserSvc" = "Windows.Devices.Picker.dll"; "DevicesFlowUserSvc" = "DevicesFlowBroker.dll";
    "DevQueryBroker" = "DevQueryBroker.dll"; "diagsvc" = "DiagSvc.dll"; "DiagTrack" = "diagtrack.dll";
    "DispBrokerDesktopSvc" = "DispBroker.Desktop.dll"; "DisplayEnhancementService" = "Microsoft.Graphics.Display.DisplayEnhancementService.dll";
    "DmEnrollmentSvc" = "Windows.Internal.Management.dll"; "dmwappushservice" = "dmwappushsvc.dll"; "Dnscache" = "dnsrslvr.dll";
    "DsmSvc" = "DeviceSetupManager.dll"; "DsSvc" = "DsSvc.dll"; "DusmSvc" = "dusmsvc.dll"; "Eaphost" = "eapsvc.dll";
    "EFS" = "efssvc.dll"; "embeddedmode" = "embeddedmodesvc.dll"; "EntAppSvc" = "EnterpriseAppMgmtSvc.dll";
    "EventLog" = "wevtsvc.dll"; "EventSystem" = "es.dll"; "FontCache" = "FntCache.dll"; "FrameServer" = "FrameServer.dll";
    "gpsvc" = "gpsvc.dll"; "GraphicsPerfSvc" = "GraphicsPerfSvc.dll"; "HomeGroupListener" = "ListSvc.dll";
    "HomeGroupProvider" = "provsvc.dll"; "HvHost" = "hvhostsvc.dll"; "icssvc" = "tetheringservice.dll"; "IKEEXT" = "ikeext.dll";
    "InstallService" = "InstallService.dll"; "iphlpsvc" = "iphlpsvc.dll"; "KeyIso" = "keyiso.dll"; "KtmRm" = "msdtckrm.dll";
    "LanmanServer" = "srvsvc.dll"; "LanmanWorkstation" = "wkssvc.dll"; "lfsvc" = "lfsvc.dll"; "LicenseManager" = "LicenseManagerSvc.dll";
    "lmhosts" = "lmhsvc.dll"; "LSM" = "lsm.dll"; "LxpSvc" = "LanguageOverlayServer.dll"; "MapsBroker" = "moshost.dll";
    "McpManagementService" = "McpManagementService.dll"; "MessagingService" = "MessagingService.dll"; "mpssvc" = "mpssvc.dll";
    "MSiSCSI" = "iscsiexe.dll"; "NaturalAuthentication" = "NaturalAuth.dll"; "NcdAutoSetup" = "NcdAutoSetup.dll";
    "Netlogon" = "netlogon.dll"; "netprofm" = "netprofmsvc.dll"; "NetSetupSvc" = "NetSetupSvc.dll"; "NgcCtnrSvc" = "NgcCtnrSvc.dll";
    "NgcSvc" = "ngcsvc.dll"; "NlaSvc" = "netprofmsvc.dll"; "OneSyncSvc" = "APHostService.dll"; "p2pimsvc" = "pnrpsvc.dll";
    "PcaSvc" = "pcasvc.dll"; "PhoneSvc" = "PhoneService.dll"; "PimIndexMaintenanceSvc" = "PimIndexMaintenance.dll";
    "PlugPlay" = "umpnpmgr.dll"; "PolicyAgent" = "ipsecsvc.dll"; "Power" = "umpo.dll"; "PrintNotify" = "PrintConfig.dll";
    "PrintWorkflowUserSvc" = "PrintWorkflowService.dll"; "ProfSvc" = "profsvc.dll"; "PushToInstall" = "PushToInstall.dll";
    "RasAuto" = "rasauto.dll"; "RasMan" = "rasmans.dll"; "RemoteAccess" = "mprdim.dll"; "RemoteRegistry" = "regsvc.dll";
    "RetailDemo" = "RDXService.dll"; "RmSvc" = "RMapi.dll"; "RpcEptMapper" = "RpcEpMap.dll"; "RpcSs" = "rpcss.dll";
    "SCardSvr" = "SCardSvr.dll"; "ScDeviceEnum" = "ScDeviceEnum.dll"; "Schedule" = "schedsvc.dll"; "SCPolicySvc" = "certprop.dll";
    "SEMgrSvc" = "SEMgrSvc.dll"; "SensorService" = "SensorService.dll"; "SensrSvc" = "sensrsvc.dll"; "SessionEnv" = "sessenv.dll";
    "SharedAccess" = "ipnathlp.dll"; "SharedRealitySvc" = "SharedRealitySvc.dll"; "ShellHWDetection" = "shsvcs.dll";
    "shpamsvc" = "Windows.SharedPC.AccountManager.dll"; "smphost" = "smphost.dll"; "SmsRouter" = "SmsRouterSvc.dll";
    "SSDPSRV" = "ssdpsrv.dll"; "StateRepository" = "windows.staterepository.dll"; "stisvc" = "wiaservc.dll";
    "StorSvc" = "storsvc.dll"; "swprv" = "swprv.dll"; "SysMain" = "sysmain.dll"; "TabletInputService" = "TabSvc.dll";
    "TapiSrv" = "tapisrv.dll"; "TermService" = "termsrv.dll"; "Themes" = "themeservice.dll"; "TimeBrokerSvc" = "TimeBrokerServer.dll";
    "TokenBroker" = "TokenBroker.dll"; "TroubleshootingSvc" = "MitigationClient.dll"; "tzautoupdate" = "tzautoupdate.dll";
    "UdkUserSvc" = "windowsudkservices.shellcommon.dll"; "UmRdpService" = "umrdp.dll"; "UnistoreSvc" = "unistore.dll";
    "upnphost" = "upnphost.dll"; "UserDataSvc" = "userdataservice.dll"; "UserManager" = "usermgr.dll"; "UsoSvc" = "usosvc.dll";
    "VacSvc" = "vac.dll"; "VaultSvc" = "vaultsvc.dll"; "vmicguestinterface" = "icsvc.dll"; "vmicheartbeat" = "icsvc.dll";
    "vmickvpexchange" = "icsvc.dll"; "vmicrdv" = "icsvcext.dll"; "vmicshutdown" = "icsvc.dll"; "vmictimesync" = "icsvc.dll";
    "vmicvmsession" = "icsvc.dll"; "vmicvss" = "icsvcvss.dll"; "W32Time" = "w32time.dll"; "WaaSMedicSvc" = "WaaSMedicSvc.dll";
    "WalletService" = "WalletService.dll"; "WarpJITSvc" = "Windows.WARP.JITService.dll"; "WbioSrvc" = "wbiosrvc.dll";
    "Wcmsvc" = "wcmsvc.dll"; "WebClient" = "webclnt.dll"; "Wecsvc" = "wecsvc.dll"; "wercplsupport" = "wercplsupport.dll";
    "WerSvc" = "WerSvc.dll"; "WFDSConMgrSvc" = "wfdsconmgrsvc.dll"; "WiaRpc" = "wiarpc.dll"; "WinHttpAutoProxySvc" = "winhttp.dll";
    "Winmgmt" = "WMIsvc.dll"; "WinRM" = "WsmSvc.dll"; "wisvc" = "flightsettings.dll"; "WlanSvc" = "wlansvc.dll";
    "wlidsvc" = "wlidsvc.dll"; "WManSvc" = "Windows.Management.Service.dll"; "workfolderssvc" = "workfolderssvc.dll";
    "WpcMonSvc" = "WpcDesktopMonSvc.dll"; "WPDBusEnum" = "wpdbusenum.dll"; "WpnService" = "WpnService.dll";
    "WpnUserService" = "WpnUserService.dll"; "wscsvc" = "wscsvc.dll"; "wuauserv" = "wuaueng.dll"; "WwanSvc" = "wwansvc.dll";
    "XblAuthManager" = "XblAuthManager.dll"; "XblGameSave" = "XblGameSave.dll"; "XboxGipSvc" = "XboxGipSvc.dll"
}

$contatoreAnomalie = 0
$anomalieLista = [System.Collections.Generic.List[PSCustomObject]]::new()
$modificheRecenti = [System.Collections.Generic.List[string]]::new()
$csvData = [System.Collections.Generic.List[PSCustomObject]]::new()
$recentlyModifiedSet = [System.Collections.Generic.HashSet[string]]::new()

$outputDir = "C:\ss1"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

function Get-ExecutablePathFromImagePath {
    param([string]$imagePath)
    if (-not $imagePath) { return $null }
    $expanded = [System.Environment]::ExpandEnvironmentVariables($imagePath)
    if ($expanded -match '^"([^"]+)"') {
        return $matches[1]
    }
    $firstToken = ($expanded -split '\s+')[0]
    if ($firstToken) {
        return $firstToken
    }
    return $null
}

function Resolve-FullPath {
    param([string]$Path)
    if (-not $Path) { return $null }
    $expanded = [System.Environment]::ExpandEnvironmentVariables($Path)
    if ($expanded -match '^"([^"]+)"') {
        $expanded = $matches[1]
    }
    if ($expanded -match '^\\SystemRoot\\') {
        $expanded = $expanded -replace '^\\SystemRoot\\', "$env:SystemRoot\"
    }
    if ($expanded -match '^System32\\') {
        $expanded = "$env:SystemRoot\$expanded"
    }
    if ($expanded -match '^system32\\') {
        $expanded = "$env:SystemRoot\$expanded"
    }
    if ($expanded -match '^\\\\.\\') {
        return $expanded
    }
    try {
        $fullPath = [System.IO.Path]::GetFullPath($expanded)
        return $fullPath
    } catch {
        return $expanded
    }
}

function Get-FilePathOnly {
    param([string]$Path)
    if (-not $Path) { return $null }
    $expanded = [System.Environment]::ExpandEnvironmentVariables($Path)
    if ($expanded -match '^"([^"]+)"') {
        $expanded = $matches[1]
    }
    if ($expanded -match '^\\SystemRoot\\') {
        $expanded = $expanded -replace '^\\SystemRoot\\', "$env:SystemRoot\"
    }
    if ($expanded -match '^System32\\') {
        $expanded = "$env:SystemRoot\$expanded"
    }
    if ($expanded -match '^system32\\') {
        $expanded = "$env:SystemRoot\$expanded"
    }
    if ($expanded -match '^\\\\.\\') {
        return $expanded
    }
    $firstToken = ($expanded -split '\s+')[0]
    if ($firstToken) {
        try {
            $fullPath = [System.IO.Path]::GetFullPath($firstToken)
            return $fullPath
        } catch {
            return $firstToken
        }
    }
    try {
        $fullPath = [System.IO.Path]::GetFullPath($expanded)
        return $fullPath
    } catch {
        return $expanded
    }
}

function Test-FileAnomalies {
    param(
        [string]$FilePath,
        [string]$ServiceName,
        [bool]$CheckMapping = $false
    )
    $anomalies = @()
    if (-not (Test-Path $FilePath)) {
        return $anomalies
    }
    $fileItem = Get-Item -Path $FilePath -ErrorAction SilentlyContinue
    if (-not $fileItem) {
        return $anomalies
    }

    $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
    if (-not $sig) {
        $anomalies += "SIGNATURE NOT VERIFIABLE"
    } elseif ($sig.Status -eq "NotSigned") {
        $anomalies += "DLL NOT SIGNED"
    } elseif ($sig.Status -ne "Valid") {
        $anomalies += "INVALID SIGNATURE: $($sig.Status)"
    }

    if ($CheckMapping -and $knownMappings.ContainsKey($ServiceName)) {
        $expected = $knownMappings[$ServiceName]
        if ($fileItem.Name.ToLower() -ne $expected.ToLower()) {
            $anomalies += "DLL REPLACED (expected: $expected)"
        }
    } elseif ($CheckMapping -and -not $knownMappings.ContainsKey($ServiceName)) {
        if ($fileItem.Name -notmatch "\.dll$") {
            $anomalies += "ANOMALOUS EXTENSION: $($fileItem.Name)"
        }
    }
    return $anomalies
}

function Test-ImagePathAnomalies {
    param(
        [string]$ImagePath,
        [string]$ServiceName
    )
    $anomalies = @()
    if (-not $ImagePath) { return $anomalies }
    $expandedPath = [System.Environment]::ExpandEnvironmentVariables($ImagePath)
    $lowerPath = $expandedPath.ToLower()
    
    $commandInterpreters = @(
        @{Pattern = "cmd\.exe\s+/c"; Name = "CMD.EXE /c"},
        @{Pattern = "cmd\.exe\s+/k"; Name = "CMD.EXE /k"},
        @{Pattern = "powershell\.exe\s+-"; Name = "PowerShell -"},
        @{Pattern = "pwsh\.exe\s+-"; Name = "PowerShell Core -"},
        @{Pattern = "wscript\.exe"; Name = "WScript"},
        @{Pattern = "cscript\.exe"; Name = "CScript"},
        @{Pattern = "mshta\.exe"; Name = "MSHTA"},
        @{Pattern = "rundll32\.exe"; Name = "Rundll32"},
        @{Pattern = "regsvr32\.exe"; Name = "RegSvr32"},
        @{Pattern = "cdb\.exe"; Name = "CDB Debugger"},
        @{Pattern = "wmic\.exe"; Name = "WMIC"},
        @{Pattern = "bash\.exe"; Name = "Bash/WSL"},
        @{Pattern = "wsl\.exe"; Name = "WSL"}
    )
    
    foreach ($interpreter in $commandInterpreters) {
        if ($lowerPath -match $interpreter.Pattern) {
            $cmdContext = ""
            if ($lowerPath -match "($($interpreter.Pattern)).*") {
                $cmdContext = $matches[0]
                if ($cmdContext.Length -gt 100) { $cmdContext = $cmdContext.Substring(0, 100) + "..." }
            }
            $anomalies += "COMMAND INTERPRETER ABUSE: $($interpreter.Name) detected in ImagePath"
            $anomalies += "  Context: $cmdContext"
        }
    }
    
    if ($lowerPath -match "\\\\.\\pipe\\") {
        $pipeName = ""
        if ($lowerPath -match "\\\\.\\pipe\\([^\s]+)") {
            $pipeName = $matches[1]
        }
        $anomalies += "NAMED PIPE USAGE: ImagePath references named pipe"
        if ($pipeName) { $anomalies += "  Pipe: \\.\pipe\$pipeName" }
    }
    
    if ($lowerPath -match '^[^"]*.+\s+.+\.exe') {
        $isQuoted = $false
        if ($ImagePath -match '^".*"') {
            $isQuoted = $true
        }
        if (-not $isQuoted) {
            $anomalies += "UNQUOTED PATH WITH SPACES: Path contains spaces but is not properly quoted"
            $anomalies += "  Path: $ImagePath"
        }
    }
    
    if ($lowerPath -match "\|" -and $lowerPath -notmatch "svchost\.exe" -and $lowerPath -notmatch "\\windows\\" -and $lowerPath -notmatch "program files") {
        $anomalies += "SUSPICIOUS OPERATOR: Pipe operator (|) in command line"
    }
    
    if ($lowerPath -match "&" -and $lowerPath -notmatch "svchost\.exe" -and $lowerPath -notmatch "\\windows\\" -and $lowerPath -notmatch "program files") {
        $anomalies += "SUSPICIOUS OPERATOR: Command chaining (&) in command line"
    }
    
    if ($lowerPath -match "&&" -and $lowerPath -notmatch "svchost\.exe" -and $lowerPath -notmatch "\\windows\\") {
        $anomalies += "SUSPICIOUS OPERATOR: Conditional chaining (&&) in command line"
    }
    
    if ($lowerPath -match "\|\|" -and $lowerPath -notmatch "svchost\.exe" -and $lowerPath -notmatch "\\windows\\") {
        $anomalies += "SUSPICIOUS OPERATOR: Conditional chaining (||) in command line"
    }
    
    if ($lowerPath -match ";" -and $lowerPath -notmatch "svchost\.exe" -and $lowerPath -notmatch "\\windows\\") {
        $anomalies += "SUSPICIOUS OPERATOR: Command separator (;) in command line"
    }
    
    if ($lowerPath -match ">" -and $lowerPath -notmatch "svchost\.exe" -and $lowerPath -notmatch "\\windows\\" -and $lowerPath -notmatch "program files") {
        $anomalies += "SUSPICIOUS OPERATOR: Output redirection (>) in command line"
    }
    
    if ($lowerPath -match "<" -and $lowerPath -notmatch "svchost\.exe" -and $lowerPath -notmatch "\\windows\\") {
        $anomalies += "SUSPICIOUS OPERATOR: Input redirection (<) in command line"
    }
    
    if ($lowerPath -match "%[^%]+%") {
        $envVars = [regex]::Matches($lowerPath, "%([^%]+)%")
        foreach ($envVar in $envVars) {
            $varName = $envVar.Groups[1].Value
            $legitimateVars = @("systemroot", "windir", "programfiles", "programfiles(x86)", "commonprogramfiles", "allusersprofile")
            if ($varName -notin $legitimateVars) {
                $anomalies += "SUSPICIOUS ENVIRONMENT VARIABLE: %$varName% in ImagePath"
            }
        }
    }
    
    if ($lowerPath -match "-enc(odedcommand)?\s+" -or $lowerPath -match "-e\s+[a-z0-9+/=]{20,}") {
        $anomalies += "ENCODED COMMAND: Base64 encoded command detected in ImagePath"
    }
    
    if ($expandedPath.Length -gt 500) {
        $anomalies += "SUSPICIOUSLY LONG COMMAND: ImagePath length > 500 characters"
    }
    
    if ($lowerPath -match "-windowstyle\s+hidden" -or $lowerPath -match "-w\s+hidden") {
        $anomalies += "HIDDEN WINDOW: Script/command attempts to run with hidden window"
    }
    
    $networkCommands = @("net use", "net share", "net view", "netstat", "nslookup", "ping", "tracert", "pathping", "telnet", "ssh")
    foreach ($cmd in $networkCommands) {
        if ($lowerPath -match $cmd -and $lowerPath -notmatch "svchost\.exe" -and $lowerPath -notmatch "\\windows\\" -and $lowerPath -notmatch "ndkping\.sys") {
            $anomalies += "NETWORK COMMAND: '$cmd' executed in service context"
            break
        }
    }
    
    return $anomalies | Select-Object -Unique
}

function Add-Anomaly {
    param(
        [string]$ServiceName,
        [string]$FilePath,
        [string[]]$Issues,
        [bool]$IsRecentlyModified = $false
    )
    if ($Issues.Count -eq 0) { return }

    $alwaysShow = @("DLL REPLACED", "INVALID SIGNATURE", "DLL NOT SIGNED", "ANOMALOUS EXTENSION", "WEAK REGISTRY PERMISSIONS", "COMMAND INTERPRETER ABUSE", "NAMED PIPE USAGE", "UNQUOTED PATH", "ENCODED COMMAND", "SUSPICIOUS OPERATOR", "HIDDEN WINDOW", "NETWORK COMMAND", "SUSPICIOUS ENVIRONMENT VARIABLE", "SUSPICIOUSLY LONG COMMAND")
    $filteredIssues = @()
    foreach ($issue in $Issues) {
        $isAlways = $false
        foreach ($crit in $alwaysShow) {
            if ($issue -match $crit) { $isAlways = $true; break }
        }
        if ($isAlways) {
            $filteredIssues += $issue
        } elseif ($IsRecentlyModified) {
            $filteredIssues += $issue
        }
    }
    if ($filteredIssues.Count -eq 0) { return }

    $global:contatoreAnomalie++
    $modTime = if (Test-Path $FilePath) { (Get-Item $FilePath).LastWriteTime.ToString("HH:mm:ss dd/MM/yyyy") } else { "N/A (file not found)" }
    $item = [PSCustomObject]@{
        Servizio = $ServiceName
        File     = $FilePath
        Modifica = $modTime
        Stato    = ($filteredIssues -join " | ")
    }
    $global:anomalieLista.Add($item)
}

foreach ($service in $services) {
    $serviceName = $service.PSChildName

    try {
        $regKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64
        ).OpenSubKey("SYSTEM\CurrentControlSet\Services\$serviceName")

        if ($regKey) {
            $internalMethod = $regKey.GetType().GetMethod(
                "InternalGetSubKeyTimestamp",
                [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Instance
            )
            if ($internalMethod) {
                $lastWrite = [DateTime]::FromFileTime($internalMethod.Invoke($regKey, $null))
            } else {
                $lastWrite = (Get-Item "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" -ErrorAction SilentlyContinue).LastWriteTime
            }
            $regKey.Close()

            if ($lastWrite -and $lastWrite -ge $timeThreshold) {
                $modificheRecenti.Add("$serviceName | $($lastWrite.ToString('HH:mm:ss dd/MM/yyyy'))")
                $recentlyModifiedSet.Add($serviceName)
            }
        }
    } catch {}

    $parametersPath = "$servicesPath\$serviceName\Parameters"
    if (Test-Path $parametersPath) {
        $serviceDll = (Get-ItemProperty -Path $parametersPath -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll
        if ($serviceDll) {
            $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\$serviceName\Parameters\ServiceDll"
            $fullPath = Resolve-FullPath -Path $serviceDll
            $filePathOnly = Get-FilePathOnly -Path $serviceDll
            $csvData.Add([PSCustomObject]@{
                ServiceName = $serviceName
                RegistryPath = $registryPath
                FullCommand = $fullPath
                FilePath = $filePathOnly
            })
            $expandedPath = [System.Environment]::ExpandEnvironmentVariables($serviceDll)
            if (-not (Split-Path $expandedPath -Parent)) {
                $expandedPath = Join-Path "C:\Windows\System32" $expandedPath
            }
            $issues = Test-FileAnomalies -FilePath $expandedPath -ServiceName $serviceName -CheckMapping $true
            $isRecent = $recentlyModifiedSet.Contains($serviceName)
            Add-Anomaly -ServiceName $serviceName -FilePath $expandedPath -Issues $issues -IsRecentlyModified $isRecent
        }
    }

    $imagePathValue = (Get-ItemProperty -Path "$servicesPath\$serviceName" -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
    if ($imagePathValue) {
        $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\$serviceName\ImagePath"
        $fullPath = Resolve-FullPath -Path $imagePathValue
        $filePathOnly = Get-FilePathOnly -Path $imagePathValue
        $csvData.Add([PSCustomObject]@{
            ServiceName = $serviceName
            RegistryPath = $registryPath
            FullCommand = $fullPath
            FilePath = $filePathOnly
        })
        
        $imagePathAnomalies = Test-ImagePathAnomalies -ImagePath $imagePathValue -ServiceName $serviceName
        if ($imagePathAnomalies.Count -gt 0) {
            $isRecent = $recentlyModifiedSet.Contains($serviceName)
            $global:contatoreAnomalie++
            $expandedPath = [System.Environment]::ExpandEnvironmentVariables($imagePathValue)
            $modTime = if (Test-Path $expandedPath) { (Get-Item $expandedPath).LastWriteTime.ToString("HH:mm:ss dd/MM/yyyy") } else { "N/A" }
            $item = [PSCustomObject]@{
                Servizio = $serviceName
                File     = "ImagePath: $imagePathValue"
                Modifica = $modTime
                Stato    = ($imagePathAnomalies -join " | ")
            }
            $global:anomalieLista.Add($item)
        }
        
        $exePath = Get-ExecutablePathFromImagePath -imagePath $imagePathValue
        if ($exePath) {
            $fullPath = [System.Environment]::ExpandEnvironmentVariables($exePath)
            if (-not (Split-Path $fullPath -Parent)) {
                $fullPath = Join-Path "C:\Windows\System32" $fullPath
            }
            $issues = Test-FileAnomalies -FilePath $fullPath -ServiceName $serviceName -CheckMapping $false
            $isRecent = $recentlyModifiedSet.Contains($serviceName)
            Add-Anomaly -ServiceName $serviceName -FilePath $fullPath -Issues $issues -IsRecentlyModified $isRecent
        }
    }

    $failCmd = (Get-ItemProperty -Path "$servicesPath\$serviceName" -Name FailureCommand -ErrorAction SilentlyContinue).FailureCommand
    if ($failCmd) {
        $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\$serviceName\FailureCommand"
        $fullPath = Resolve-FullPath -Path $failCmd
        $filePathOnly = Get-FilePathOnly -Path $failCmd
        $csvData.Add([PSCustomObject]@{
            ServiceName = $serviceName
            RegistryPath = $registryPath
            FullCommand = $fullPath
            FilePath = $filePathOnly
        })
        
        $exeFromFail = Get-ExecutablePathFromImagePath -imagePath $failCmd
        if ($exeFromFail) {
            $fullFailPath = [System.Environment]::ExpandEnvironmentVariables($exeFromFail)
            if (-not (Split-Path $fullFailPath -Parent)) {
                $fullFailPath = Join-Path "C:\Windows\System32" $fullFailPath
            }
            $issues = Test-FileAnomalies -FilePath $fullFailPath -ServiceName $serviceName -CheckMapping $false
            $isRecent = $recentlyModifiedSet.Contains($serviceName)
            Add-Anomaly -ServiceName $serviceName -FilePath $fullFailPath -Issues $issues -IsRecentlyModified $isRecent
        }
    }

    $perfPath = "$servicesPath\$serviceName\Performance"
    if (Test-Path $perfPath) {
        $perfLib = (Get-ItemProperty -Path $perfPath -Name Library -ErrorAction SilentlyContinue).Library
        if ($perfLib) {
            $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\$serviceName\Performance\Library"
            $fullPath = Resolve-FullPath -Path $perfLib
            $filePathOnly = Get-FilePathOnly -Path $perfLib
            $csvData.Add([PSCustomObject]@{
                ServiceName = $serviceName
                RegistryPath = $registryPath
                FullCommand = $fullPath
                FilePath = $filePathOnly
            })
            
            $fullPerfPath = [System.Environment]::ExpandEnvironmentVariables($perfLib)
            if (-not (Split-Path $fullPerfPath -Parent)) {
                $fullPerfPath = Join-Path "C:\Windows\System32" $fullPerfPath
            }
            $issues = Test-FileAnomalies -FilePath $fullPerfPath -ServiceName $serviceName -CheckMapping $false
            $isRecent = $recentlyModifiedSet.Contains($serviceName)
            Add-Anomaly -ServiceName $serviceName -FilePath $fullPerfPath -Issues $issues -IsRecentlyModified $isRecent
        }
    }

    $acl = Get-Acl -Path "$servicesPath\$serviceName" -ErrorAction SilentlyContinue
    if ($acl) {
        $writeAccess = $false
        foreach ($access in $acl.Access) {
            if ($access.IdentityReference -match "BUILTIN\\Users|Everyone|NT AUTHORITY\\Authenticated Users") {
                if ($access.RegistryRights -match "WriteKey|SetValue|CreateSubKey") {
                    $writeAccess = $true
                    break
                }
            }
        }
        if ($writeAccess) {
            $issues = @("WEAK REGISTRY PERMISSIONS – NON-ADMIN CAN MODIFY")
            $isRecent = $recentlyModifiedSet.Contains($serviceName)
            Add-Anomaly -ServiceName $serviceName -FilePath "N/A (registry key)" -Issues $issues -IsRecentlyModified $isRecent
        }
    }
}

$diagTestHooks = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TestHooks"
if (Test-Path $diagTestHooks) {
    $diagDll1 = (Get-ItemProperty -Path $diagTestHooks -Name TestUndockedAggregatorDll -ErrorAction SilentlyContinue).TestUndockedAggregatorDll
    if ($diagDll1) {
        $registryPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TestHooks\TestUndockedAggregatorDll"
        $fullPath = Resolve-FullPath -Path $diagDll1
        $filePathOnly = Get-FilePathOnly -Path $diagDll1
        $csvData.Add([PSCustomObject]@{
            ServiceName = "DiagTrack_TestHook"
            RegistryPath = $registryPath
            FullCommand = $fullPath
            FilePath = $filePathOnly
        })
        
        $fullDiagPath = [System.Environment]::ExpandEnvironmentVariables($diagDll1)
        if (-not (Split-Path $fullDiagPath -Parent)) {
            $fullDiagPath = Join-Path "C:\Windows\System32" $fullDiagPath
        }
        $issues = Test-FileAnomalies -FilePath $fullDiagPath -ServiceName "DiagTrack_TestHook" -CheckMapping $false
        Add-Anomaly -ServiceName "DiagTrack (Undocked)" -FilePath $fullDiagPath -Issues $issues -IsRecentlyModified $false
    }
    $diagDll2 = (Get-ItemProperty -Path $diagTestHooks -Name TestAggregatorDll -ErrorAction SilentlyContinue).TestAggregatorDll
    if ($diagDll2) {
         $registryPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TestHooks\TestAggregatorDll"
        $fullPath = Resolve-FullPath -Path $diagDll2
        $filePathOnly = Get-FilePathOnly -Path $diagDll2
        $csvData.Add([PSCustomObject]@{
            ServiceName = "DiagTrack_TestHook"
            RegistryPath = $registryPath
            FullCommand = $fullPath
            FilePath = $filePathOnly
        })
        
        $fullDiagPath2 = [System.Environment]::ExpandEnvironmentVariables($diagDll2)
        if (-not (Split-Path $fullDiagPath2 -Parent)) {
            $fullDiagPath2 = Join-Path "C:\Windows\System32" $fullDiagPath2
        }
        $issues = Test-FileAnomalies -FilePath $fullDiagPath2 -ServiceName "DiagTrack_TestHook" -CheckMapping $false
        Add-Anomaly -ServiceName "DiagTrack (Aggregator)" -FilePath $fullDiagPath2 -Issues $issues -IsRecentlyModified $false
    }
}

$winsockPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters"
if (Test-Path $winsockPath) {
    $autoDll = (Get-ItemProperty -Path $winsockPath -Name AutodialDLL -ErrorAction SilentlyContinue).AutodialDLL
    if ($autoDll) {
        $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\AutodialDLL"
        $fullPath = Resolve-FullPath -Path $autoDll
        $filePathOnly = Get-FilePathOnly -Path $autoDll
        $csvData.Add([PSCustomObject]@{
            ServiceName = "Winsock_Autodial"
            RegistryPath = $registryPath
            FullCommand = $fullPath
            FilePath = $filePathOnly
        })
        
        $fullAutoPath = [System.Environment]::ExpandEnvironmentVariables($autoDll)
        if (-not (Split-Path $fullAutoPath -Parent)) {
            $fullAutoPath = Join-Path "C:\Windows\System32" $fullAutoPath
        }
        $issues = Test-FileAnomalies -FilePath $fullAutoPath -ServiceName "Winsock_Autodial" -CheckMapping $false
        Add-Anomaly -ServiceName "Winsock Autodial DLL" -FilePath $fullAutoPath -Issues $issues -IsRecentlyModified $false
    }
}

$csvData | Export-Csv -Path "$outputDir\service_paths.csv" -NoTypeInformation -Encoding UTF8

Write-Host "=============================================" -ForegroundColor DarkGray
Write-Host " SERVICE SCANNER " -ForegroundColor Cyan
Write-Host " User: $userName" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor DarkGray
Write-Host ""
Write-Host "CSV file with registry paths and binary paths written to: $outputDir\service_paths.csv ($($csvData.Count) entries)" -ForegroundColor Cyan
Write-Host ""

if ($contatoreAnomalie -gt 0) {
    Write-Host "ANOMALIES DETECTED: $contatoreAnomalie" -ForegroundColor Red
    Write-Host ""
    foreach ($item in $anomalieLista) {
        Write-Host "[$($item.Servizio)]" -ForegroundColor Yellow
        Write-Host "  File     : $($item.File)"
        Write-Host "  Modified : $($item.Modifica)"
        Write-Host "  Status   : $($item.Stato)" -ForegroundColor Red
        Write-Host ""
    }
} else {
    Write-Host "No anomalies detected." -ForegroundColor Green
    Write-Host ""
}

Write-Host "---------------------------------------------" -ForegroundColor DarkGray
if ($modificheRecenti.Count -gt 0) {
    Write-Host "REGISTRY MODIFIED IN LAST 60 MIN - SUSPICIOUS ($($modificheRecenti.Count)):" -ForegroundColor Yellow
    foreach ($m in $modificheRecenti) {
        Write-Host "  $m"
    }
} else {
    Write-Host "No recent registry modifications (last 60 min)." -ForegroundColor Green
}

Write-Host "---------------------------------------------" -ForegroundColor DarkGray
Write-Host "Scan: $(Get-Date -Format 'HH:mm:ss dd/MM/yyyy')" -ForegroundColor Cyan
Write-Host ""

Write-Host "Press any key to close..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
