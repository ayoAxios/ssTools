[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$servicesPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
$services = Get-ChildItem -Path $servicesPath
$userName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$timeThreshold = (Get-Date).AddMinutes(-60)
Write-Host "made by _.ayo" -ForegroundColor DarkGray

# Existing known mappings
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

# ====== NEW: Additional DLL scanning functions ======

function Test-RegistryKeyForDll {
    param(
        [Microsoft.Win32.RegistryKey]$RegistryKey,
        [string]$ValueName,
        [string]$Context,
        [bool]$CheckMapping = $false,
        [string]$ServiceName = "Unknown"
    )
    
    $anomalies = @()
    $dllPath = $null
    
    try {
        if ($RegistryKey -and $ValueName) {
            $dllPath = $RegistryKey.GetValue($ValueName, $null)
        }
    } catch {
        return $anomalies
    }
    
    if (-not $dllPath) { return $anomalies }
    if ($dllPath -isnot [string]) { 
        $dllPath = $dllPath.ToString()
    }
    
    # Add to CSV
    $fullPath = Resolve-FullPath -Path $dllPath
    $filePathOnly = Get-FilePathOnly -Path $dllPath
    $csvData.Add([PSCustomObject]@{
        ServiceName = "$ServiceName ($Context)"
        RegistryPath = "$($RegistryKey.Name)\$ValueName"
        FullCommand = $fullPath
        FilePath = $filePathOnly
    })
    
    # Check if it's a DLL file
    $expandedPath = [System.Environment]::ExpandEnvironmentVariables($dllPath)
    if (-not (Split-Path $expandedPath -Parent)) {
        $expandedPath = Join-Path "C:\Windows\System32" $expandedPath
    }
    
    # Test file anomalies
    $issues = Test-FileAnomalies -FilePath $expandedPath -ServiceName $ServiceName -CheckMapping $CheckMapping
    foreach ($issue in $issues) {
        $anomalies += "[$Context] $issue"
    }
    
    # Also check the ImagePath anomalies for command-line style entries
    $imageAnomalies = Test-ImagePathAnomalies -ImagePath $dllPath -ServiceName $ServiceName
    foreach ($issue in $imageAnomalies) {
        $anomalies += "[$Context] $issue"
    }
    
    return $anomalies
}

function Scan-RegistryKeyPaths {
    param(
        [string]$RegistryPath,
        [string]$ValueName,
        [string]$Context,
        [bool]$CheckMapping = $false,
        [string]$ServiceName = "RegistryScan"
    )
    
    $results = @()
    try {
        $key = Get-Item -Path $RegistryPath -ErrorAction SilentlyContinue
        if ($key) {
            $issues = Test-RegistryKeyForDll -RegistryKey $key -ValueName $ValueName -Context $Context -CheckMapping $CheckMapping -ServiceName $ServiceName
            $results += $issues
        }
    } catch {
        # Silently continue
    }
    return $results
}

function Scan-RegistrySubKeysForDll {
    param(
        [string]$RegistryPath,
        [string]$ValueName,
        [string]$ContextPrefix,
        [bool]$CheckMapping = $false
    )
    
    $results = @()
    try {
        $parentKey = Get-Item -Path $RegistryPath -ErrorAction SilentlyContinue
        if ($parentKey) {
            $subKeys = $parentKey.GetSubKeyNames()
            foreach ($subKeyName in $subKeys) {
                $subKeyPath = "$RegistryPath\$subKeyName"
                try {
                    $subKey = Get-Item -Path $subKeyPath -ErrorAction SilentlyContinue
                    if ($subKey) {
                        $context = "$ContextPrefix - $subKeyName"
                        $issues = Test-RegistryKeyForDll -RegistryKey $subKey -ValueName $ValueName -Context $context -CheckMapping $CheckMapping -ServiceName $subKeyName
                        $results += $issues
                    }
                } catch {
                    # Silently continue
                }
            }
        }
    } catch {
        # Silently continue
    }
    return $results
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

# ====== NEW: Additional scanning functions for specific registry locations ======

function Scan-WindowsRegistryForDlls {
    $allIssues = @()
    
    # 1. AppInit_DLLs
    Write-Host "Scanning AppInit_DLLs..." -ForegroundColor DarkGray
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ValueName "AppInit_DLLs" -Context "AppInit_DLLs" -ServiceName "AppInit_DLLs"
    $allIssues += $issues
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ValueName "AppInit_VerifierDLLs" -Context "AppInit_VerifierDLLs" -ServiceName "AppInit_VerifierDLLs"
    $allIssues += $issues
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" -ValueName "AppInit_DLLs" -Context "AppInit_DLLs (32-bit)" -ServiceName "AppInit_DLLs_32"
    $allIssues += $issues
    
    # 2. AppCertDLLs
    Write-Host "Scanning AppCertDLLs..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs" -ValueName "Dll" -ContextPrefix "AppCertDLLs" -CheckMapping $false
    $allIssues += $issues
    
    # 3. Winlogon Notifications
    Write-Host "Scanning Winlogon Notifications..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" -ValueName "DllName" -ContextPrefix "Winlogon Notify" -CheckMapping $false
    $allIssues += $issues
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" -ValueName "DllName" -ContextPrefix "Winlogon Notify (32-bit)" -CheckMapping $false
    $allIssues += $issues
    
    # 4. Shell Execute Hooks
    Write-Host "Scanning ShellExecuteHooks..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks" -ValueName "(Default)" -ContextPrefix "ShellExecuteHook" -CheckMapping $false
    $allIssues += $issues
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks" -ValueName "(Default)" -ContextPrefix "ShellExecuteHook (32-bit)" -CheckMapping $false
    $allIssues += $issues
    
    # 5. Shell Extensions
    Write-Host "Scanning Shell Extensions..." -ForegroundColor DarkGray
    $shellExtPaths = @(
        "HKCR:\*\shellex\ContextMenuHandlers",
        "HKCR:\*\shellex\PropertySheetHandlers",
        "HKCR:\Directory\shellex\ContextMenuHandlers",
        "HKCR:\Directory\shellex\PropertySheetHandlers",
        "HKCR:\Folder\shellex\ContextMenuHandlers",
        "HKCR:\Folder\shellex\PropertySheetHandlers"
    )
    foreach ($path in $shellExtPaths) {
        $issues = Scan-RegistrySubKeysForDll -RegistryPath $path -ValueName "(Default)" -ContextPrefix "ShellExtension ($path)" -CheckMapping $false
        $allIssues += $issues
    }
    
    # 6. Browser Helper Objects (BHO)
    Write-Host "Scanning BHOs..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" -ValueName "(Default)" -ContextPrefix "BHO" -CheckMapping $false
    $allIssues += $issues
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" -ValueName "(Default)" -ContextPrefix "BHO (32-bit)" -CheckMapping $false
    $allIssues += $issues
    
    # 7. LSA Notification Packages
    Write-Host "Scanning LSA Packages..." -ForegroundColor DarkGray
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "Notification Packages" -Context "LSA Notification Packages" -ServiceName "LSA_Notification"
    $allIssues += $issues
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "Authentication Packages" -Context "LSA Authentication Packages" -ServiceName "LSA_Auth"
    $allIssues += $issues
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "Security Packages" -Context "LSA Security Packages" -ServiceName "LSA_Security"
    $allIssues += $issues
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "Extensions" -Context "LSA Extensions" -ServiceName "LSA_Extensions"
    $allIssues += $issues
    
    # 8. Winlogon Shell/Userinit
    Write-Host "Scanning Winlogon Shell/Userinit..." -ForegroundColor DarkGray
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "Shell" -Context "Winlogon Shell" -ServiceName "Winlogon_Shell"
    $allIssues += $issues
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "Userinit" -Context "Winlogon Userinit" -ServiceName "Winlogon_Userinit"
    $allIssues += $issues
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "Shell" -Context "Winlogon Shell (32-bit)" -ServiceName "Winlogon_Shell_32"
    $allIssues += $issues
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "Userinit" -Context "Winlogon Userinit (32-bit)" -ServiceName "Winlogon_Userinit_32"
    $allIssues += $issues
    
    # 9. Print Monitors
    Write-Host "Scanning Print Monitors..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors" -ValueName "(Default)" -ContextPrefix "Print Monitor" -CheckMapping $false
    $allIssues += $issues
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\Standard TCP/IP Port" -ValueName "DLL" -ContextPrefix "Print Monitor TCP/IP" -CheckMapping $false
    $allIssues += $issues
    
    # 10. Print Processors
    Write-Host "Scanning Print Processors..." -ForegroundColor DarkGray
    $processorPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors"
    $issues = Scan-RegistrySubKeysForDll -RegistryPath $processorPath -ValueName "(Default)" -ContextPrefix "Print Processor" -CheckMapping $false
    $allIssues += $issues
    $processorPath32 = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows NT x86\Print Processors"
    $issues = Scan-RegistrySubKeysForDll -RegistryPath $processorPath32 -ValueName "(Default)" -ContextPrefix "Print Processor (32-bit)" -CheckMapping $false
    $allIssues += $issues
    
    # 11. Netsh Helpers
    Write-Host "Scanning Netsh Helpers..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\Microsoft\Netsh" -ValueName "(Default)" -ContextPrefix "Netsh Helper" -CheckMapping $false
    $allIssues += $issues
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Netsh" -ValueName "(Default)" -ContextPrefix "Netsh Helper (32-bit)" -CheckMapping $false
    $allIssues += $issues
    
    # 12. Time Providers
    Write-Host "Scanning Time Providers..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders" -ValueName "DllName" -ContextPrefix "Time Provider" -CheckMapping $false
    $allIssues += $issues
    
    # 13. Security Center Providers
    Write-Host "Scanning Security Center Providers..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\Microsoft\Security Center\Provider" -ValueName "(Default)" -ContextPrefix "Security Center Provider" -CheckMapping $false
    $allIssues += $issues
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Security Center\Provider" -ValueName "(Default)" -ContextPrefix "Security Center Provider (32-bit)" -CheckMapping $false
    $allIssues += $issues
    
    # 14. GINA DLL (Legacy)
    Write-Host "Scanning GINA DLLs..." -ForegroundColor DarkGray
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "GinaDLL" -Context "GINA DLL" -ServiceName "GINA"
    $allIssues += $issues
    
    # 15. Crypto Providers
    Write-Host "Scanning Crypto Providers..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\Microsoft\Cryptography\Defaults\Provider" -ValueName "(Default)" -ContextPrefix "Crypto Provider" -CheckMapping $false
    $allIssues += $issues
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider" -ValueName "(Default)" -ContextPrefix "Crypto Provider (32-bit)" -CheckMapping $false
    $allIssues += $issues
    
    # 16. Device Installer
    Write-Host "Scanning Device Installer..." -ForegroundColor DarkGray
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer" -ValueName "DeviceInstallerDLL" -Context "Device Installer DLL" -ServiceName "DeviceInstaller"
    $allIssues += $issues
    
    # 17. Tracing Providers
    Write-Host "Scanning Tracing Providers..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Tracing" -ValueName "DLL" -ContextPrefix "Tracing Provider" -CheckMapping $false
    $allIssues += $issues
    
    # 18. IFEO Debugger (can reference DLLs)
    Write-Host "Scanning IFEO Debuggers..." -ForegroundColor DarkGray
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    try {
        $ifeoKeys = Get-ChildItem -Path $ifeoPath -ErrorAction SilentlyContinue
        foreach ($key in $ifeoKeys) {
            $issues = Scan-RegistryKeyPaths -RegistryPath $key.PSPath -ValueName "Debugger" -Context "IFEO Debugger - $($key.PSChildName)" -ServiceName "IFEO_$($key.PSChildName)"
            $allIssues += $issues
        }
    } catch {
        # Silently continue
    }
    
    # 19. Provider Order
    Write-Host "Scanning Provider Order..." -ForegroundColor DarkGray
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\ProviderOrder" -ValueName "ProviderList" -Context "Provider Order" -ServiceName "ProviderOrder"
    $allIssues += $issues
    
    # 20. DirectShow Filters
    Write-Host "Scanning DirectShow Filters..." -ForegroundColor DarkGray
    $filterPaths = @(
        "HKCR:\CLSID",
        "HKLM:\SOFTWARE\Classes\CLSID"
    )
    foreach ($path in $filterPaths) {
        try {
            $clsidKeys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
            foreach ($clsid in $clsidKeys) {
                $inprocPath = "$($clsid.PSPath)\InprocServer32"
                $issues = Scan-RegistryKeyPaths -RegistryPath $inprocPath -ValueName "(Default)" -Context "DirectShow Filter - $($clsid.PSChildName)" -ServiceName "DirectShow_$($clsid.PSChildName)"
                $allIssues += $issues
            }
        } catch {
            # Silently continue
        }
    }
    
    # 21. KnownDLLs (monitor for tampering)
    Write-Host "Scanning KnownDLLs..." -ForegroundColor DarkGray
    $knownDllsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
    try {
        $knownDlls = Get-Item -Path $knownDllsPath -ErrorAction SilentlyContinue
        if ($knownDlls) {
            $dllValues = $knownDlls.GetValueNames()
            foreach ($dllName in $dllValues) {
                $dllValue = $knownDlls.GetValue($dllName, $null)
                if ($dllValue -and $dllValue -is [string]) {
                    # Check if it references a non-system path
                    if ($dllValue -match "\\" -and $dllValue -notmatch "system32") {
                        $allIssues += "[KnownDLLs] SUSPICIOUS - $dllName = $dllValue (non-standard path)"
                    }
                }
            }
        }
    } catch {
        # Silently continue
    }
    
    return $allIssues
}

# ====== Existing functions (keep as is) ======

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

# ====== NEW: Add all the registry scanning functions that were cut off ======

function Test-RegistryKeyForDll {
    param(
        [Microsoft.Win32.RegistryKey]$RegistryKey,
        [string]$ValueName,
        [string]$Context,
        [bool]$CheckMapping = $false,
        [string]$ServiceName = "Unknown"
    )
    
    $anomalies = @()
    $dllPath = $null
    
    try {
        if ($RegistryKey -and $ValueName) {
            $dllPath = $RegistryKey.GetValue($ValueName, $null)
        }
    } catch {
        return $anomalies
    }
    
    if (-not $dllPath) { return $anomalies }
    if ($dllPath -isnot [string]) { 
        $dllPath = $dllPath.ToString()
    }
    
    # Add to CSV
    $fullPath = Resolve-FullPath -Path $dllPath
    $filePathOnly = Get-FilePathOnly -Path $dllPath
    $csvData.Add([PSCustomObject]@{
        ServiceName = "$ServiceName ($Context)"
        RegistryPath = "$($RegistryKey.Name)\$ValueName"
        FullCommand = $fullPath
        FilePath = $filePathOnly
    })
    
    # Check if it's a DLL file
    $expandedPath = [System.Environment]::ExpandEnvironmentVariables($dllPath)
    if (-not (Split-Path $expandedPath -Parent)) {
        $expandedPath = Join-Path "C:\Windows\System32" $expandedPath
    }
    
    # Test file anomalies
    $issues = Test-FileAnomalies -FilePath $expandedPath -ServiceName $ServiceName -CheckMapping $CheckMapping
    foreach ($issue in $issues) {
        $anomalies += "[$Context] $issue"
    }
    
    # Also check the ImagePath anomalies for command-line style entries
    $imageAnomalies = Test-ImagePathAnomalies -ImagePath $dllPath -ServiceName $ServiceName
    foreach ($issue in $imageAnomalies) {
        $anomalies += "[$Context] $issue"
    }
    
    return $anomalies
}

function Scan-RegistryKeyPaths {
    param(
        [string]$RegistryPath,
        [string]$ValueName,
        [string]$Context,
        [bool]$CheckMapping = $false,
        [string]$ServiceName = "RegistryScan"
    )
    
    $results = @()
    try {
        $key = Get-Item -Path $RegistryPath -ErrorAction SilentlyContinue
        if ($key) {
            $issues = Test-RegistryKeyForDll -RegistryKey $key -ValueName $ValueName -Context $Context -CheckMapping $CheckMapping -ServiceName $ServiceName
            $results += $issues
        }
    } catch {
        # Silently continue
    }
    return $results
}

function Scan-RegistrySubKeysForDll {
    param(
        [string]$RegistryPath,
        [string]$ValueName,
        [string]$ContextPrefix,
        [bool]$CheckMapping = $false
    )
    
    $results = @()
    try {
        $parentKey = Get-Item -Path $RegistryPath -ErrorAction SilentlyContinue
        if ($parentKey) {
            $subKeys = $parentKey.GetSubKeyNames()
            foreach ($subKeyName in $subKeys) {
                $subKeyPath = "$RegistryPath\$subKeyName"
                try {
                    $subKey = Get-Item -Path $subKeyPath -ErrorAction SilentlyContinue
                    if ($subKey) {
                        $context = "$ContextPrefix - $subKeyName"
                        $issues = Test-RegistryKeyForDll -RegistryKey $subKey -ValueName $ValueName -Context $context -CheckMapping $CheckMapping -ServiceName $subKeyName
                        $results += $issues
                    }
                } catch {
                    # Silently continue
                }
            }
        }
    } catch {
        # Silently continue
    }
    return $results
}

function Scan-WindowsRegistryForDlls {
    $allIssues = @()
    
    # 1. AppInit_DLLs
    Write-Host "Scanning AppInit_DLLs..." -ForegroundColor DarkGray
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ValueName "AppInit_DLLs" -Context "AppInit_DLLs" -ServiceName "AppInit_DLLs"
    $allIssues += $issues
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ValueName "AppInit_VerifierDLLs" -Context "AppInit_VerifierDLLs" -ServiceName "AppInit_VerifierDLLs"
    $allIssues += $issues
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" -ValueName "AppInit_DLLs" -Context "AppInit_DLLs (32-bit)" -ServiceName "AppInit_DLLs_32"
    $allIssues += $issues
    
    # 2. AppCertDLLs
    Write-Host "Scanning AppCertDLLs..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs" -ValueName "Dll" -ContextPrefix "AppCertDLLs" -CheckMapping $false
    $allIssues += $issues
    
    # 3. Winlogon Notifications
    Write-Host "Scanning Winlogon Notifications..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" -ValueName "DllName" -ContextPrefix "Winlogon Notify" -CheckMapping $false
    $allIssues += $issues
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" -ValueName "DllName" -ContextPrefix "Winlogon Notify (32-bit)" -CheckMapping $false
    $allIssues += $issues
    
    # 4. Shell Execute Hooks
    Write-Host "Scanning ShellExecuteHooks..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks" -ValueName "(Default)" -ContextPrefix "ShellExecuteHook" -CheckMapping $false
    $allIssues += $issues
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks" -ValueName "(Default)" -ContextPrefix "ShellExecuteHook (32-bit)" -CheckMapping $false
    $allIssues += $issues
    
    # 5. Shell Extensions
    Write-Host "Scanning Shell Extensions..." -ForegroundColor DarkGray
    $shellExtPaths = @(
        "HKCR:\*\shellex\ContextMenuHandlers",
        "HKCR:\*\shellex\PropertySheetHandlers",
        "HKCR:\Directory\shellex\ContextMenuHandlers",
        "HKCR:\Directory\shellex\PropertySheetHandlers",
        "HKCR:\Folder\shellex\ContextMenuHandlers",
        "HKCR:\Folder\shellex\PropertySheetHandlers",
        "HKCR:\Drive\shellex\ContextMenuHandlers",
        "HKCR:\Drive\shellex\PropertySheetHandlers"
    )
    foreach ($path in $shellExtPaths) {
        $issues = Scan-RegistrySubKeysForDll -RegistryPath $path -ValueName "(Default)" -ContextPrefix "ShellExtension" -CheckMapping $false
        $allIssues += $issues
    }
    
    # 6. Browser Helper Objects (BHO)
    Write-Host "Scanning BHOs..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" -ValueName "(Default)" -ContextPrefix "BHO" -CheckMapping $false
    $allIssues += $issues
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" -ValueName "(Default)" -ContextPrefix "BHO (32-bit)" -CheckMapping $false
    $allIssues += $issues
    
    # 7. LSA Notification Packages
    Write-Host "Scanning LSA Packages..." -ForegroundColor DarkGray
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "Notification Packages" -Context "LSA Notification Packages" -ServiceName "LSA_Notification"
    $allIssues += $issues
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "Authentication Packages" -Context "LSA Authentication Packages" -ServiceName "LSA_Auth"
    $allIssues += $issues
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "Security Packages" -Context "LSA Security Packages" -ServiceName "LSA_Security"
    $allIssues += $issues
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "Extensions" -Context "LSA Extensions" -ServiceName "LSA_Extensions"
    $allIssues += $issues
    
    # 8. Winlogon Shell/Userinit
    Write-Host "Scanning Winlogon Shell/Userinit..." -ForegroundColor DarkGray
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "Shell" -Context "Winlogon Shell" -ServiceName "Winlogon_Shell"
    $allIssues += $issues
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "Userinit" -Context "Winlogon Userinit" -ServiceName "Winlogon_Userinit"
    $allIssues += $issues
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "Shell" -Context "Winlogon Shell (32-bit)" -ServiceName "Winlogon_Shell_32"
    $allIssues += $issues
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "Userinit" -Context "Winlogon Userinit (32-bit)" -ServiceName "Winlogon_Userinit_32"
    $allIssues += $issues
    
    # 9. Print Monitors
    Write-Host "Scanning Print Monitors..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors" -ValueName "(Default)" -ContextPrefix "Print Monitor" -CheckMapping $false
    $allIssues += $issues
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\Standard TCP/IP Port" -ValueName "DLL" -ContextPrefix "Print Monitor TCP/IP" -CheckMapping $false
    $allIssues += $issues
    
    # 10. Print Processors
    Write-Host "Scanning Print Processors..." -ForegroundColor DarkGray
    $processorPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors"
    $issues = Scan-RegistrySubKeysForDll -RegistryPath $processorPath -ValueName "(Default)" -ContextPrefix "Print Processor" -CheckMapping $false
    $allIssues += $issues
    $processorPath32 = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows NT x86\Print Processors"
    $issues = Scan-RegistrySubKeysForDll -RegistryPath $processorPath32 -ValueName "(Default)" -ContextPrefix "Print Processor (32-bit)" -CheckMapping $false
    $allIssues += $issues
    
    # 11. Netsh Helpers
    Write-Host "Scanning Netsh Helpers..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\Microsoft\Netsh" -ValueName "(Default)" -ContextPrefix "Netsh Helper" -CheckMapping $false
    $allIssues += $issues
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Netsh" -ValueName "(Default)" -ContextPrefix "Netsh Helper (32-bit)" -CheckMapping $false
    $allIssues += $issues
    
    # 12. Time Providers
    Write-Host "Scanning Time Providers..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders" -ValueName "DllName" -ContextPrefix "Time Provider" -CheckMapping $false
    $allIssues += $issues
    
    # 13. Security Center Providers
    Write-Host "Scanning Security Center Providers..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\Microsoft\Security Center\Provider" -ValueName "(Default)" -ContextPrefix "Security Center Provider" -CheckMapping $false
    $allIssues += $issues
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Security Center\Provider" -ValueName "(Default)" -ContextPrefix "Security Center Provider (32-bit)" -CheckMapping $false
    $allIssues += $issues
    
    # 14. GINA DLL (Legacy)
    Write-Host "Scanning GINA DLLs..." -ForegroundColor DarkGray
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "GinaDLL" -Context "GINA DLL" -ServiceName "GINA"
    $allIssues += $issues
    
    # 15. Crypto Providers
    Write-Host "Scanning Crypto Providers..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\Microsoft\Cryptography\Defaults\Provider" -ValueName "(Default)" -ContextPrefix "Crypto Provider" -CheckMapping $false
    $allIssues += $issues
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider" -ValueName "(Default)" -ContextPrefix "Crypto Provider (32-bit)" -CheckMapping $false
    $allIssues += $issues
    
    # 16. Device Installer
    Write-Host "Scanning Device Installer..." -ForegroundColor DarkGray
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer" -ValueName "DeviceInstallerDLL" -Context "Device Installer DLL" -ServiceName "DeviceInstaller"
    $allIssues += $issues
    
    # 17. Tracing Providers
    Write-Host "Scanning Tracing Providers..." -ForegroundColor DarkGray
    $issues = Scan-RegistrySubKeysForDll -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Tracing" -ValueName "DLL" -ContextPrefix "Tracing Provider" -CheckMapping $false
    $allIssues += $issues
    
    # 18. IFEO Debugger (can reference DLLs)
    Write-Host "Scanning IFEO Debuggers..." -ForegroundColor DarkGray
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    try {
        $ifeoKeys = Get-ChildItem -Path $ifeoPath -ErrorAction SilentlyContinue
        foreach ($key in $ifeoKeys) {
            $issues = Scan-RegistryKeyPaths -RegistryPath $key.PSPath -ValueName "Debugger" -Context "IFEO Debugger - $($key.PSChildName)" -ServiceName "IFEO_$($key.PSChildName)"
            $allIssues += $issues
            # Also check for GlobalFlag which can enable DLL loading
            $globalFlag = Scan-RegistryKeyPaths -RegistryPath $key.PSPath -ValueName "GlobalFlag" -Context "IFEO GlobalFlag - $($key.PSChildName)" -ServiceName "IFEO_$($key.PSChildName)"
            $allIssues += $globalFlag
        }
    } catch {
        # Silently continue
    }
    
    # 19. Provider Order
    Write-Host "Scanning Provider Order..." -ForegroundColor DarkGray
    $issues = Scan-RegistryKeyPaths -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\ProviderOrder" -ValueName "ProviderList" -Context "Provider Order" -ServiceName "ProviderOrder"
    $allIssues += $issues
    
    # 20. DirectShow Filters
    Write-Host "Scanning DirectShow Filters..." -ForegroundColor DarkGray
    $filterPaths = @(
        "HKCR:\CLSID",
        "HKLM:\SOFTWARE\Classes\CLSID"
    )
    foreach ($path in $filterPaths) {
        try {
            $clsidKeys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Select-Object -First 500
            $count = 0
            foreach ($clsid in $clsidKeys) {
                $count++
                if ($count -gt 500) { break }
                $inprocPath = "$($clsid.PSPath)\InprocServer32"
                $issues = Scan-RegistryKeyPaths -RegistryPath $inprocPath -ValueName "(Default)" -Context "DirectShow Filter - $($clsid.PSChildName)" -ServiceName "DirectShow_$($clsid.PSChildName)"
                $allIssues += $issues
            }
        } catch {
            # Silently continue
        }
    }
    
    # 21. KnownDLLs (monitor for tampering)
    Write-Host "Scanning KnownDLLs..." -ForegroundColor DarkGray
    $knownDllsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
    try {
        $knownDlls = Get-Item -Path $knownDllsPath -ErrorAction SilentlyContinue
        if ($knownDlls) {
            $dllValues = $knownDlls.GetValueNames()
            foreach ($dllName in $dllValues) {
                $dllValue = $knownDlls.GetValue($dllName, $null)
                if ($dllValue -and $dllValue -is [string]) {
                    # Check if it references a non-system path
                    if ($dllValue -match "\\" -and $dllValue -notmatch "system32") {
                        $allIssues += "[KnownDLLs] SUSPICIOUS - $dllName = $dllValue (non-standard path)"
                    }
                }
            }
        }
    } catch {
        # Silently continue
    }
    
    # 22. COM Class TreatAs / AutoTreatAs
    Write-Host "Scanning COM TreatAs redirects..." -ForegroundColor DarkGray
    $clsidPaths = @(
        "HKCR:\CLSID",
        "HKLM:\SOFTWARE\Classes\CLSID"
    )
    foreach ($path in $clsidPaths) {
        try {
            $clsidKeys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Select-Object -First 200
            foreach ($clsid in $clsidKeys) {
                $treatAsPath = "$($clsid.PSPath)\TreatAs"
                $issues = Scan-RegistryKeyPaths -RegistryPath $treatAsPath -ValueName "(Default)" -Context "COM TreatAs - $($clsid.PSChildName)" -ServiceName "COM_TreatAs_$($clsid.PSChildName)"
                $allIssues += $issues
                
                $autoTreatPath = "$($clsid.PSPath)\AutoTreatAs"
                $issues = Scan-RegistryKeyPaths -RegistryPath $autoTreatPath -ValueName "(Default)" -Context "COM AutoTreatAs - $($clsid.PSChildName)" -ServiceName "COM_AutoTreatAs_$($clsid.PSChildName)"
                $allIssues += $issues
            }
        } catch {
            # Silently continue
        }
    }
    
    # 23. COM Elevation Policy
    Write-Host "Scanning COM Elevation Policy..." -ForegroundColor DarkGray
    foreach ($path in $clsidPaths) {
        try {
            $clsidKeys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Select-Object -First 200
            foreach ($clsid in $clsidKeys) {
                $elevPath = "$($clsid.PSPath)\Elevation"
                $issues = Scan-RegistryKeyPaths -RegistryPath $elevPath -ValueName "Enabled" -Context "COM Elevation - $($clsid.PSChildName)" -ServiceName "COM_Elevation_$($clsid.PSChildName)"
                $allIssues += $issues
            }
        } catch {
            # Silently continue
        }
    }
    
    # 24. Scheduled Tasks (via registry - tasks can execute rundll32)
    Write-Host "Scanning Scheduled Tasks (registry)..." -ForegroundColor DarkGray
    $taskPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
    )
    foreach ($taskPath in $taskPaths) {
        try {
            $tasks = Get-ChildItem -Path $taskPath -ErrorAction SilentlyContinue
            foreach ($task in $tasks) {
                # Check for actions that reference DLLs
                $actions = $task.GetValue("Actions", $null)
                if ($actions -and $actions -is [string]) {
                    if ($actions -match "rundll32\.exe|regsvr32\.exe") {
                        $allIssues += "[Scheduled Task] SUSPICIOUS DLL execution in task: $($task.PSChildName)"
                        $allIssues += "  Action: $actions"
                    }
                }
            }
        } catch {
            # Silently continue
        }
    }
    
    # 25. Windows Filtering Platform Callouts
    Write-Host "Scanning WFP Callouts..." -ForegroundColor DarkGray
    $wfpPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WFP\Callouts"
    try {
        $callouts = Get-ChildItem -Path $wfpPath -ErrorAction SilentlyContinue
        foreach ($callout in $callouts) {
            $issues = Scan-RegistryKeyPaths -RegistryPath $callout.PSPath -ValueName "DisplayData" -Context "WFP Callout - $($callout.PSChildName)" -ServiceName "WFP_$($callout.PSChildName)"
            $allIssues += $issues
        }
    } catch {
        # Silently continue
    }
    
    return $allIssues
}

# ====== MAIN SCRIPT EXECUTION ======

Write-Host "=============================================" -ForegroundColor DarkGray
Write-Host " STARTING COMPREHENSIVE DLL SCAN " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor DarkGray
Write-Host ""

# Existing service scanning
Write-Host "Scanning Services..." -ForegroundColor Cyan
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

# ====== NEW: Run comprehensive registry scanning ======
Write-Host ""
Write-Host "Scanning Additional Registry Locations for DLLs..." -ForegroundColor Cyan
$additionalIssues = Scan-WindowsRegistryForDlls

# Add any discovered issues to anomalies list
foreach ($issue in $additionalIssues) {
    # Parse the issue format: "[Context] message"
    if ($issue -match '^\[([^\]]+)\]\s*(.*)') {
        $context = $matches[1]
        $message = $matches[2]
        $global:contatoreAnomalie++
        $item = [PSCustomObject]@{
            Servizio = "RegistryScan"
            File     = $context
            Modifica = "N/A"
            Stato    = $message
        }
        $global:anomalieLista.Add($item)
    } else {
        # Fallback for unformatted issues
        $global:contatoreAnomalie++
        $item = [PSCustomObject]@{
            Servizio = "RegistryScan"
            File     = "Registry"
            Modifica = "N/A"
            Stato    = $issue
        }
        $global:anomalieLista.Add($item)
    }
}

# DiagTrack test hooks (existing)
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

# Winsock (existing)
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

# ====== OUTPUT ======

$csvData | Export-Csv -Path "$outputDir\service_paths.csv" -NoTypeInformation -Encoding UTF8

Write-Host "=============================================" -ForegroundColor DarkGray
Write-Host " SERVICE SCANNER COMPLETE " -ForegroundColor Cyan
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
