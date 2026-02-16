$commonSpoofTargets = @('VEN_10EC', 'VEN_8086', 'VEN_1022', 'VEN_1B21')

# These appear multiple times legitimately - skip ONLY the duplicate VEN/DEV check for these
$knownMultiples = @(
    'PCI standard host CPU bridge',
    'PCI standard PCI-to-PCI bridge',
    'PCI Express Root Port',
    'PCI standard ISA bridge',
    'PCI standard RAM Controller'
)

$results = Get-PnpDevice |
Where-Object { $_.InstanceId -like "PCI*" } |
ForEach-Object {
    $instanceId   = $_.InstanceId
    $friendlyName = $_.FriendlyName

    # Call 1 - Driver presence, name, version, date
    $call1 = @{}
    Get-PnpDeviceProperty -InstanceId $instanceId -ErrorAction SilentlyContinue -KeyName @(
        'DEVPKEY_Device_Driver',
        'DEVPKEY_Device_DriverDesc',
        'DEVPKEY_Device_DriverVersion',
        'DEVPKEY_Device_DriverDate',
        'DEVPKEY_Device_DriverInfPath',
        'DEVPKEY_Device_DriverInfSection'
    ) | ForEach-Object { $call1[$_.KeyName] = $_.Data }

    $driverPresent = $call1['DEVPKEY_Device_Driver'] -ne $null -and $call1['DEVPKEY_Device_Driver'] -ne ''

    # Call 2 - Install dates (always fetch, not driver dependent)
    $call2 = @{}
    Get-PnpDeviceProperty -InstanceId $instanceId -ErrorAction SilentlyContinue -KeyName @(
        'DEVPKEY_Device_InstallDate',
        'DEVPKEY_Device_FirstInstallDate'
    ) | ForEach-Object { $call2[$_.KeyName] = $_.Data }

    # Parse IDs
    $ven    = if ($instanceId -match "VEN_[0-9A-F]{4}")    { $matches[0] } else { 'N/A' }
    $dev    = if ($instanceId -match "DEV_[0-9A-F]{4}")    { $matches[0] } else { 'N/A' }
    $subsys = if ($instanceId -match "SUBSYS_[0-9A-F]{8}") { $matches[0] } else { 'N/A' }

    # Resolve full INF path
    $fullInfPath = if ($call1['DEVPKEY_Device_DriverInfPath']) {
        Join-Path "$env:SystemRoot\INF" $call1['DEVPKEY_Device_DriverInfPath']
    } else { 'N/A' }

    # Driver signature check
    $driverSigned = if ($fullInfPath -ne 'N/A' -and (Test-Path $fullInfPath)) {
        $sig = Get-AuthenticodeSignature -FilePath $fullInfPath -ErrorAction SilentlyContinue
        if ($sig) { $sig.Status } else { 'Unknown' }
    } else { 'N/A' }

    # Driver date
    $driverDate = if ($call1['DEVPKEY_Device_DriverDate']) {
        ([DateTime]$call1['DEVPKEY_Device_DriverDate']).ToString('yyyy-MM-dd')
    } else { 'N/A' }

    # Install dates
    $installDate = if ($call2['DEVPKEY_Device_InstallDate']) {
        ([DateTime]$call2['DEVPKEY_Device_InstallDate']).ToString('yyyy-MM-dd HH:mm:ss')
    } else { 'N/A' }

    $firstInstallDate = if ($call2['DEVPKEY_Device_FirstInstallDate']) {
        ([DateTime]$call2['DEVPKEY_Device_FirstInstallDate']).ToString('yyyy-MM-dd HH:mm:ss')
    } else { 'N/A' }

    # Suspicious reasons
    $suspiciousReasons = @()

    if ($driverSigned -eq 'NotSigned') {
        $suspiciousReasons += "Unsigned driver"
    }
    if ($commonSpoofTargets -contains $ven -and -not $driverPresent) {
        $suspiciousReasons += "No driver on common spoof target"
    }
    # Flag if install date is newer than first install - device was reinstalled
    if ($call2['DEVPKEY_Device_InstallDate'] -and $call2['DEVPKEY_Device_FirstInstallDate']) {
        $daysDiff = (([DateTime]$call2['DEVPKEY_Device_InstallDate']) - ([DateTime]$call2['DEVPKEY_Device_FirstInstallDate'])).Days
        if ($daysDiff -gt 0) {
            $suspiciousReasons += "Reinstalled since first install ($daysDiff days later)"
        }
    }

    [PSCustomObject]@{
        FriendlyName      = $friendlyName
        Status            = $_.Status
        VEN               = $ven
        DEV               = $dev
        SUBSYS            = $subsys
        DriverPresent     = if ($driverPresent) { 'Yes' } else { 'No' }
        DriverName        = if ($call1['DEVPKEY_Device_DriverDesc'])      { $call1['DEVPKEY_Device_DriverDesc'] }       else { 'N/A' }
        DriverVersion     = if ($call1['DEVPKEY_Device_DriverVersion'])    { $call1['DEVPKEY_Device_DriverVersion'] }    else { 'N/A' }
        DriverDate        = $driverDate
        DriverSigned      = $driverSigned
        DriverInfPath     = $fullInfPath
        DriverInfSection  = if ($call1['DEVPKEY_Device_DriverInfSection']) { $call1['DEVPKEY_Device_DriverInfSection'] } else { 'N/A' }
        DriverKey         = if ($driverPresent)                             { $call1['DEVPKEY_Device_Driver'] }           else { 'None' }
        FirstInstallDate  = $firstInstallDate
        InstallDate       = $installDate
        KnownMultiple     = if ($knownMultiples -contains $friendlyName)   { 'Yes' }                                     else { 'No' }
        Suspicious        = if ($suspiciousReasons.Count -gt 0) { '⚠️ YES' } else { 'No' }
        SuspiciousReasons = if ($suspiciousReasons.Count -gt 0) { $suspiciousReasons -join ' | ' } else { 'None' }
    }
}

# Post-processing: duplicate VEN/DEV check - skip known multiples ONLY
$venDevGroups = $results |
    Where-Object { $_.KnownMultiple -eq 'No' } |
    Group-Object { "$($_.VEN)_$($_.DEV)" } |
    Where-Object { $_.Count -gt 1 }

$duplicateIds = $venDevGroups | ForEach-Object { $_.Group | ForEach-Object { "$($_.VEN)_$($_.DEV)" } }

$results | ForEach-Object {
    $id = "$($_.VEN)_$($_.DEV)"
    if ($_.KnownMultiple -eq 'No' -and $duplicateIds -contains $id) {
        if ($_.SuspiciousReasons -eq 'None') {
            $_.SuspiciousReasons = 'Duplicate VEN/DEV ID'
        } else {
            $_.SuspiciousReasons += ' | Duplicate VEN/DEV ID'
        }
        $_.Suspicious = '⚠️ YES'
    }
}

$results | Out-GridView -Title "PCI Device & Driver Information"