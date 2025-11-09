Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Section {
    param(
        [Parameter(Mandatory)]
        [string]$Title
    )

    Write-Host ""
    Write-Host ("=== {0} ===" -f $Title) -ForegroundColor Cyan
}

function Format-Value {
    param($Value)

    if ($null -eq $Value) {
        return 'Not configured'
    }

    if ($Value -is [bool]) {
        if ($Value) {
            return 'Enabled'
        }

        return 'Disabled'
    }

    if ($Value -is [DateTime]) {
        return $Value.ToString('yyyy-MM-dd HH:mm:ss')
    }

    if ($Value -is [TimeSpan]) {
        return [DateTime]::Today.Add($Value).ToString('HH:mm')
    }

    $stringValue = $Value.ToString().Trim()
    if ($stringValue.Length -eq 0) {
        return 'Not configured'
    }

    return $stringValue
}

function Get-MappedValue {
    param(
        $Value,
        [hashtable]$Map
    )

    if ($null -eq $Value) {
        return 'Not configured'
    }

    $candidates = @($Value)
    if ($Value -is [System.IConvertible]) {
        try {
            $candidates += [int]$Value
        } catch {
            # ignore cast failures
        }
    }

    foreach ($candidate in $candidates) {
        if ($Map.ContainsKey($candidate)) {
            return $Map[$candidate]
        }
    }

    return "Unknown ($Value)"
}

function Format-AgeDays {
    param($Value)

    if ($null -eq $Value) {
        return 'Unknown'
    }

    try {
        $number = [uint32]$Value
        if ($number -ge [uint32]::MaxValue) {
            return 'Never'
        }
        return ("{0} day(s)" -f $number)
    } catch {
        return $Value
    }
}

function Format-TimeOfDay {
    param($Value)

    if ($null -eq $Value) {
        return 'Not configured'
    }

    if ($Value -is [TimeSpan]) {
        return [DateTime]::Today.Add($Value).ToString('HH:mm')
    }

    return $Value
}

function Show-PolicyBlock {
    param(
        [string]$Title,
        [System.Collections.Specialized.OrderedDictionary]$Items
    )

    if ($null -eq $Items -or $Items.Count -eq 0) {
        return
    }

    Write-Section -Title $Title
    foreach ($key in $Items.Keys) {
        $value = $Items[$key]
        Write-Host ("{0,-42}: {1}" -f $key, (Format-Value $value))
    }
}

function Show-List {
    param(
        [string]$Label,
        $Items
    )

    $list = @()
    if ($null -ne $Items) {
        $list = @(
            @($Items) |
            Where-Object { $_ -and $_.ToString().Trim().Length -gt 0 }
        )
    }

    if ($list.Count -eq 0) {
        Write-Host ("{0,-42}: None" -f $Label)
        return
    }

    Write-Host $Label
    foreach ($entry in $list) {
        Write-Host ("  - {0}" -f $entry)
    }
}

function Show-AsrRules {
    param(
        $Preference,
        [hashtable]$RuleDescriptions,
        [hashtable]$ActionMap
    )

    $ids = @(
        @($Preference.AttackSurfaceReductionRules_Ids) |
        Where-Object { $_ -and $_.ToString().Trim().Length -gt 0 }
    )

    if ($ids.Count -eq 0) {
        Write-Host "No attack surface reduction rules configured."
        return
    }

    $actions = @($Preference.AttackSurfaceReductionRules_Actions)

    Write-Host ("{0,-52} {1,-16} {2}" -f 'Rule', 'Mode', 'GUID')
    Write-Host ("{0,-52} {1,-16} {2}" -f ('-' * 52), ('-' * 16), ('-' * 36))

    for ($i = 0; $i -lt $ids.Count; $i++) {
        $id = $ids[$i]
        $actionValue = $null
        if ($i -lt $actions.Count) {
            $actionValue = $actions[$i]
        }

        if ($null -eq $actionValue -or $actionValue.ToString().Length -eq 0) {
            $actionText = 'Not reported'
        } elseif ($ActionMap.ContainsKey([int]$actionValue)) {
            $actionText = "{0} ({1})" -f $ActionMap[[int]$actionValue], [int]$actionValue
        } else {
            $actionText = "Unknown ($actionValue)"
        }

        $ruleName = $RuleDescriptions[$id.ToLower()]
        if ([string]::IsNullOrWhiteSpace($ruleName)) {
            $ruleName = 'Custom or unknown rule'
        }

        Write-Host ("{0,-52} {1,-16} {2}" -f $ruleName, $actionText, $id)
    }
}

function Invoke-DefenderPolicyReport {
    if (-not (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue)) {
        throw 'Microsoft Defender PowerShell cmdlets are not available on this device.'
    }

    $mpPref = Get-MpPreference
    $mpStatus = Get-MpComputerStatus

    $mapsLevels = @{
        0 = 'Disabled'
        1 = 'Basic'
        2 = 'Advanced'
    }

    $sampleConsent = @{
        0 = 'Always prompt'
        1 = 'Send safe samples automatically'
        2 = 'Never send'
        3 = 'Send all samples automatically'
    }

    $cloudBlockLevel = @{
        0 = 'Default'
        1 = 'High'
        2 = 'High+'
        4 = 'Zero tolerance'
    }

    $networkProtection = @{
        0 = 'Disabled'
        1 = 'Block'
        2 = 'Audit'
    }

    $controlledFolderAccess = @{
        0 = 'Disabled'
        1 = 'Block'
        2 = 'Audit'
        3 = 'Warn'
    }

    $puaMap = @{
        0 = 'Disabled'
        1 = 'Enabled'
        2 = 'Audit'
    }

    $scheduleDayMap = @{
        0 = 'Every day'
        1 = 'Sunday'
        2 = 'Monday'
        3 = 'Tuesday'
        4 = 'Wednesday'
        5 = 'Thursday'
        6 = 'Friday'
        7 = 'Saturday'
        8 = 'Never'
    }

    $asrActionMap = @{
        0 = 'Disabled'
        1 = 'Block'
        2 = 'Audit'
        6 = 'Warn'
    }

    $asrRuleDescriptions = @{
        '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files unless prevalence, age, or trusted list criteria are met'
        '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication apps from creating child processes'
        '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
        '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office apps from creating executable content'
        '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office apps from injecting code into other processes'
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
        'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block web shell creation on servers'
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted or unsigned processes running from USB'
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email clients and webmail'
        'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied or impersonated system tools'
        'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
        'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations originating from PSExec or WMI'
        'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executables'
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block Office apps from creating child processes'
        'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription (no exclusions)'
    }

    Write-Host ("Microsoft Defender policy snapshot for {0}" -f $env:COMPUTERNAME) -ForegroundColor Yellow
    Write-Host ("Generated: {0}`n" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor Yellow

    Show-PolicyBlock -Title 'Engine & Signature State' -Items ([ordered]@{
            'Product version'             = $mpStatus.AMProductVersion
            'Engine version'              = $mpStatus.AMEngineVersion
            'Service enabled'             = $mpStatus.AMServiceEnabled
            'Running mode'                = $mpStatus.AMRunningMode
            'AV signature version'        = $mpStatus.AntivirusSignatureVersion
            'AV signatures last updated'  = $mpStatus.AntivirusSignatureLastUpdated
            'AS signature version'        = $mpStatus.AntispywareSignatureVersion
            'AS signatures last updated'  = $mpStatus.AntispywareSignatureLastUpdated
            'NIS engine version'          = $mpStatus.NISEngineVersion
            'NIS signature version'       = $mpStatus.NISSignatureVersion
            'Tamper protection'           = $mpStatus.IsTamperProtected
            'Smart App Control state'     = $mpStatus.SmartAppControlState
        })

    Show-PolicyBlock -Title 'Real-time & Core Protections' -Items ([ordered]@{
            'Real-time protection'         = $mpStatus.RealTimeProtectionEnabled
            'Behavior monitoring'          = $mpStatus.BehaviorMonitorEnabled
            'IOAV (download) protection'   = $mpStatus.IoavProtectionEnabled
            'On-access protection'         = $mpStatus.OnAccessProtectionEnabled
            'Network inspection system'    = $mpStatus.NISEnabled
            'Antivirus enabled'            = $mpStatus.AntivirusEnabled
            'Antispyware enabled'          = $mpStatus.AntispywareEnabled
            'Potentially unwanted apps'    = Get-MappedValue -Value $mpPref.PUAProtection -Map $puaMap
            'Disable realtime monitoring'  = $mpPref.DisableRealtimeMonitoring
            'Disable script scanning'      = $mpPref.DisableScriptScanning
            'Disable email scanning'       = $mpPref.DisableEmailScanning
        })

    Show-PolicyBlock -Title 'Cloud-delivered Protection & Automation' -Items ([ordered]@{
            'MAPS reporting level'      = Get-MappedValue -Value $mpPref.MAPSReporting -Map $mapsLevels
            'Sample submission'         = Get-MappedValue -Value $mpPref.SubmitSamplesConsent -Map $sampleConsent
            'Cloud block level'         = Get-MappedValue -Value $mpPref.CloudBlockLevel -Map $cloudBlockLevel
            'Extended cloud timeout'    = if ($mpPref.CloudExtendedTimeout -gt 0) { "{0} second(s)" -f $mpPref.CloudExtendedTimeout } else { 'Default (20s)' }
            'Network protection mode'   = Get-MappedValue -Value $mpPref.EnableNetworkProtection -Map $networkProtection
            'Network protection reputation' = $mpPref.NetworkProtectionReputationMode
            'Automatic sample check before scan' = $mpPref.CheckForSignaturesBeforeRunningScan
        })

    Show-PolicyBlock -Title 'Exploit Guard & Ransomware Protections' -Items ([ordered]@{
            'Controlled folder access'             = Get-MappedValue -Value $mpPref.EnableControlledFolderAccess -Map $controlledFolderAccess
            'Convert CFA warn to block'            = $mpPref.EnableConvertWarnToBlock
            'Network protection on server SKUs'    = $mpPref.AllowNetworkProtectionOnWinServer
            'Network protection on down-level OS'  = $mpPref.AllowNetworkProtectionDownLevel
            'Brute force protection state'         = $mpPref.BruteForceProtectionConfiguredState
            'Brute force protection aggressiveness'= $mpPref.BruteForceProtectionAggressiveness
        })

    Write-Section -Title 'Attack Surface Reduction Rules'
    Show-AsrRules -Preference $mpPref -RuleDescriptions $asrRuleDescriptions -ActionMap $asrActionMap

    Write-Section -Title 'Attack Surface Reduction Exclusions'
    Show-List -Label 'ASR-only exclusions' -Items $mpPref.AttackSurfaceReductionOnlyExclusions
    Show-List -Label 'Rule-specific exclusions' -Items $mpPref.AttackSurfaceReductionRules_RuleSpecificExclusions

    Show-PolicyBlock -Title 'Scan Health & Schedule' -Items ([ordered]@{
            'Last quick scan'            = $mpStatus.QuickScanStartTime
            'Quick scan duration'        = if ($mpStatus.QuickScanEndTime) { "{0:g} - {1:g}" -f $mpStatus.QuickScanStartTime, $mpStatus.QuickScanEndTime } else { 'N/A' }
            'Quick scan age'             = Format-AgeDays $mpStatus.QuickScanAge
            'Last full scan'             = if ($mpStatus.FullScanStartTime) { $mpStatus.FullScanStartTime } else { 'Never' }
            'Full scan age'              = Format-AgeDays $mpStatus.FullScanAge
            'Full scan overdue'          = $mpStatus.FullScanOverdue
            'Full scan schedule'         = "{0} at {1}" -f (Get-MappedValue -Value $mpPref.ScanScheduleDay -Map $scheduleDayMap), (Format-TimeOfDay $mpPref.ScanScheduleTime)
            'Quick scan schedule'        = "Every day at {0}" -f (Format-TimeOfDay $mpPref.ScanScheduleQuickScanTime)
            'Randomize scheduled tasks'  = $mpPref.RandomizeScheduleTaskTimes
            'Scan CPU throttle'          = "{0}%" -f $mpPref.ScanAvgCPULoadFactor
        })

    Write-Section -Title 'Exclusions'
    Show-List -Label 'Paths'       -Items $mpPref.ExclusionPath
    Show-List -Label 'Processes'   -Items $mpPref.ExclusionProcess
    Show-List -Label 'Extensions'  -Items $mpPref.ExclusionExtension
    Show-List -Label 'IP addresses'-Items $mpPref.ExclusionIpAddress

    Write-Section -Title 'Controlled Folder Access'
    Show-List -Label 'Protected folders (default + custom)' -Items ($mpPref.ControlledFolderAccessDefaultProtectedFolders + $mpPref.ControlledFolderAccessProtectedFolders)
    Show-List -Label 'Allowed applications' -Items $mpPref.ControlledFolderAccessAllowedApplications
}

Invoke-DefenderPolicyReport
