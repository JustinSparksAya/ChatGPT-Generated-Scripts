[CmdletBinding()]
param(
    [switch]$AsObject,
    [string]$OutFile,
    [ValidateSet('Metadata','Compliance Summary','Engine & Signature State','Real-time & Core Protections','Cloud-delivered Protection & Automation','Exploit Guard & Ransomware Protections','Attack Surface Reduction Rules','Attack Surface Reduction Exclusions','Device Control','Firewall Profiles','Scan Health & Schedule','Exclusions','Controlled Folder Access','EDR Sensor State','Threat History')]
    [string[]]$Section,
    [switch]$IncludeThreatHistory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SectionOrder = @(
    'Metadata',
    'Compliance Summary',
    'Engine & Signature State',
    'Real-time & Core Protections',
    'Cloud-delivered Protection & Automation',
    'Exploit Guard & Ransomware Protections',
    'Attack Surface Reduction Rules',
    'Attack Surface Reduction Exclusions',
    'Device Control',
    'Firewall Profiles',
    'Scan Health & Schedule',
    'Exclusions',
    'Controlled Folder Access',
    'EDR Sensor State',
    'Threat History'
)

$script:MapsLevels = @{ 0 = 'Disabled'; 1 = 'Basic'; 2 = 'Advanced' }
$script:SampleConsent = @{ 0 = 'Always prompt'; 1 = 'Send safe samples automatically'; 2 = 'Never send'; 3 = 'Send all samples automatically' }
$script:CloudBlockLevel = @{ 0 = 'Default'; 1 = 'High'; 2 = 'High+'; 4 = 'Zero tolerance' }
$script:NetworkProtection = @{ 0 = 'Disabled'; 1 = 'Block'; 2 = 'Audit' }
$script:ControlledFolderAccess = @{ 0 = 'Disabled'; 1 = 'Block'; 2 = 'Audit'; 3 = 'Warn' }
$script:PuaMap = @{ 0 = 'Disabled'; 1 = 'Enabled'; 2 = 'Audit' }
$script:ScheduleDayMap = @{ 0 = 'Every day'; 1 = 'Sunday'; 2 = 'Monday'; 3 = 'Tuesday'; 4 = 'Wednesday'; 5 = 'Thursday'; 6 = 'Friday'; 7 = 'Saturday'; 8 = 'Never' }
$script:AsrActionMap = @{ 0 = 'Disabled'; 1 = 'Block'; 2 = 'Audit'; 6 = 'Warn' }

$script:AsrRuleDescriptions = @{ 
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

function Test-IsElevated {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Format-Value {
    param($Value)

    if ($null -eq $Value) { return 'Not configured' }

    if ($Value -is [bool]) {
        if ($Value) { return 'Enabled' }
        return 'Disabled'
    }
    if ($Value -is [DateTime]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
    if ($Value -is [TimeSpan]) { return [DateTime]::Today.Add($Value).ToString('HH:mm') }

    $stringValue = $Value.ToString().Trim()
    if ($stringValue.Length -eq 0) { return 'Not configured' }
    return $stringValue
}

function Get-MappedValue {
    param(
        $Value,
        [hashtable]$Map
    )

    if ($null -eq $Value) { return 'Not configured' }

    $candidates = @($Value)
    if ($Value -is [System.IConvertible]) {
        try { $candidates += [int]$Value } catch { }
    }

    foreach ($candidate in $candidates) {
        if ($Map.ContainsKey($candidate)) { return $Map[$candidate] }
    }

    return "Unknown ($Value)"
}

function Format-AgeDays {
    param($Value)

    if ($null -eq $Value) { return 'Unknown' }

    try {
        $number = [uint32]$Value
        if ($number -ge [uint32]::MaxValue) { return 'Never' }
        return ('{0} day(s)' -f $number)
    } catch {
        return $Value
    }
}

function Format-TimeOfDay {
    param($Value)

    if ($null -eq $Value) { return 'Not configured' }
    if ($Value -is [TimeSpan]) { return [DateTime]::Today.Add($Value).ToString('HH:mm') }
    return $Value
}

function Normalize-List {
    param(
        $Items,
        [switch]$RequireElevation,
        [bool]$IsElevated,
        [string]$PrivilegeMessage = 'Run elevated to view this data'
    )

    if ($RequireElevation -and -not $IsElevated) {
        return @($PrivilegeMessage)
    }

    return @(
        @($Items) |
        Where-Object { $_ -and $_.ToString().Trim().Length -gt 0 -and $_ -notmatch '^N/A:' }
    )
}

function Get-OptionalPropertyValue {
    param(
        $Object,
        [string]$PropertyName
    )

    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$PropertyName]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function New-Section {
    param(
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet('KeyValue','List','Table','Message','ListMap')][string]$Type = 'KeyValue',
        $Data
    )

    return [pscustomobject]@{
        Name = $Name
        Type = $Type
        Data = $Data
    }
}

function Convert-SectionsToText {
    param($Sections)

    $builder = [System.Text.StringBuilder]::new()
    foreach ($section in $Sections) {
        if ($builder.Length -gt 0) { [void]$builder.AppendLine() }
        [void]$builder.AppendLine("=== {0} ===" -f $section.Name)

        switch ($section.Type) {
            'KeyValue' {
                if ($null -eq $section.Data) {
                    [void]$builder.AppendLine('No data')
                    break
                }

                if ($section.Data -is [System.Collections.IDictionary]) {
                    $keys = @($section.Data.Keys)
                    if ($keys.Count -eq 0) {
                        [void]$builder.AppendLine('No data')
                        break
                    }

                    foreach ($key in $keys) {
                        $value = Format-Value $section.Data[$key]
                        [void]$builder.AppendLine(('{0,-42}: {1}' -f $key, $value))
                    }
                } else {
                    $props = @($section.Data.PSObject.Properties)
                    if ($props.Count -eq 0) {
                        [void]$builder.AppendLine('No data')
                        break
                    }

                    foreach ($prop in $props) {
                        $value = Format-Value $prop.Value
                        [void]$builder.AppendLine(('{0,-42}: {1}' -f $prop.Name, $value))
                    }
                }
            }
            'List' {
                $list = @($section.Data)
                if ($list.Count -eq 0) {
                    [void]$builder.AppendLine('None')
                } else {
                    foreach ($item in $list) { [void]$builder.AppendLine('  - ' + (Format-Value $item)) }
                }
            }
            'ListMap' {
                $map = $section.Data
                if ($null -eq $map) {
                    [void]$builder.AppendLine('No data')
                    break
                }

                if (-not ($map -is [System.Collections.IDictionary])) {
                    $map = [ordered]@{ 'Items' = @($map) }
                }

                foreach ($key in $map.Keys) {
                    $items = @($map[$key])
                    if ($items.Count -eq 0) {
                        [void]$builder.AppendLine(('{0,-42}: None' -f $key))
                    } else {
                        [void]$builder.AppendLine($key)
                        foreach ($item in $items) { [void]$builder.AppendLine('  - ' + (Format-Value $item)) }
                    }
                }
            }
            'Table' {
                $rows = @($section.Data)
                if ($rows.Count -eq 0) {
                    [void]$builder.AppendLine('None')
                } else {
                    $tableText = $rows | Format-Table -AutoSize | Out-String
                    [void]$builder.AppendLine($tableText.TrimEnd())
                }
            }
            'Message' {
                $message = if ($section.Data) { $section.Data } else { 'No data' }
                [void]$builder.AppendLine($message)
            }
        }
    }

    return $builder.ToString().TrimEnd()
}

function Get-AsrRuleRows {
    param(
        $Preference,
        [hashtable]$RuleDescriptions,
        [hashtable]$ActionMap
    )

    $ids = @(
        @($Preference.AttackSurfaceReductionRules_Ids) |
        Where-Object { $_ -and $_.ToString().Trim().Length -gt 0 }
    )

    if ($ids.Count -eq 0) { return @() }

    $actions = @($Preference.AttackSurfaceReductionRules_Actions)
    $rows = @(
        foreach ($index in 0..($ids.Count - 1)) {
        $id = $ids[$index]
        $actionValue = $null
        if ($index -lt $actions.Count) { $actionValue = $actions[$index] }

        $actionText = 'Not reported'
        if ($null -ne $actionValue -and $actionValue.ToString().Length -gt 0) {
            try {
                $actionInt = [int]$actionValue
                if ($ActionMap.ContainsKey($actionInt)) {
                    $actionText = '{0} ({1})' -f $ActionMap[$actionInt], $actionInt
                } else {
                    $actionText = 'Unknown ({0})' -f $actionValue
                }
            } catch {
                $actionText = 'Unknown ({0})' -f $actionValue
            }
        }

        $ruleName = $RuleDescriptions[$id.ToLower()]
        if ([string]::IsNullOrWhiteSpace($ruleName)) { $ruleName = 'Custom or unknown rule' }

        [pscustomobject]@{
            Rule = $ruleName
            Mode = $actionText
            Guid = $id
        }
    })

    return $rows
}

function Invoke-DefenderPolicyReportInternal {
    param(
        [switch]$AsObject,
        [string]$OutFile,
        [string[]]$Section,
        [switch]$IncludeThreatHistory
    )

    if (-not (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue)) {
        throw 'Microsoft Defender PowerShell cmdlets are not available on this device.'
    }

    $selectedSections = if ($Section) { $Section } else { $script:SectionOrder }
    $isElevated = Test-IsElevated
    $mpPref = Get-MpPreference
    $mpStatus = Get-MpComputerStatus
    $reportTime = Get-Date

    $sections = [ordered]@{}

    $sections['Metadata'] = New-Section -Name 'Metadata' -Type 'KeyValue' -Data ([ordered]@{
            'Computer name' = $env:COMPUTERNAME
            'User'          = $env:USERNAME
            'Generated'     = $reportTime
            'Elevated'      = $isElevated
        })

    $asrRows = @(
        Get-AsrRuleRows -Preference $mpPref -RuleDescriptions $script:AsrRuleDescriptions -ActionMap $script:AsrActionMap
    )
    $configuredAsr = $asrRows.Count
    $complianceData = [ordered]@{
        'ASR rules configured'              = ('{0}/{1}' -f $configuredAsr, $script:AsrRuleDescriptions.Count)
        'Controlled folder access'          = Get-MappedValue -Value $mpPref.EnableControlledFolderAccess -Map $script:ControlledFolderAccess
        'Network protection'                = Get-MappedValue -Value $mpPref.EnableNetworkProtection -Map $script:NetworkProtection
        'Potentially unwanted apps'         = Get-MappedValue -Value $mpPref.PUAProtection -Map $script:PuaMap
        'Cloud block level'                 = Get-MappedValue -Value $mpPref.CloudBlockLevel -Map $script:CloudBlockLevel
        'Tamper protection'                 = $mpStatus.IsTamperProtected
        'EDR block mode'                    = Get-OptionalPropertyValue -Object $mpStatus -PropertyName 'EdrBlockMode'
    }
    $sections['Compliance Summary'] = New-Section -Name 'Compliance Summary' -Type 'KeyValue' -Data $complianceData

    $sections['Engine & Signature State'] = New-Section -Name 'Engine & Signature State' -Type 'KeyValue' -Data ([ordered]@{
            'Product version'            = $mpStatus.AMProductVersion
            'Engine version'             = $mpStatus.AMEngineVersion
            'Service enabled'            = $mpStatus.AMServiceEnabled
            'Running mode'               = $mpStatus.AMRunningMode
            'AV signature version'       = $mpStatus.AntivirusSignatureVersion
            'AV signatures last updated' = $mpStatus.AntivirusSignatureLastUpdated
            'AS signature version'       = $mpStatus.AntispywareSignatureVersion
            'AS signatures last updated' = $mpStatus.AntispywareSignatureLastUpdated
            'NIS engine version'         = $mpStatus.NISEngineVersion
            'NIS signature version'      = $mpStatus.NISSignatureVersion
            'Smart App Control state'    = $mpStatus.SmartAppControlState
        })

    $sections['Real-time & Core Protections'] = New-Section -Name 'Real-time & Core Protections' -Type 'KeyValue' -Data ([ordered]@{
            'Real-time protection'        = $mpStatus.RealTimeProtectionEnabled
            'Behavior monitoring'         = $mpStatus.BehaviorMonitorEnabled
            'IOAV protection'             = $mpStatus.IoavProtectionEnabled
            'On-access protection'        = $mpStatus.OnAccessProtectionEnabled
            'Network inspection system'   = $mpStatus.NISEnabled
            'Antivirus enabled'           = $mpStatus.AntivirusEnabled
            'Antispyware enabled'         = $mpStatus.AntispywareEnabled
            'Disable realtime monitoring' = $mpPref.DisableRealtimeMonitoring
            'Disable script scanning'     = $mpPref.DisableScriptScanning
            'Disable email scanning'      = $mpPref.DisableEmailScanning
        })

    $sections['Cloud-delivered Protection & Automation'] = New-Section -Name 'Cloud-delivered Protection & Automation' -Type 'KeyValue' -Data ([ordered]@{
            'MAPS reporting level'      = Get-MappedValue -Value $mpPref.MAPSReporting -Map $script:MapsLevels
            'Sample submission'         = Get-MappedValue -Value $mpPref.SubmitSamplesConsent -Map $script:SampleConsent
            'Cloud block level'         = Get-MappedValue -Value $mpPref.CloudBlockLevel -Map $script:CloudBlockLevel
            'Extended cloud timeout'    = if ($mpPref.CloudExtendedTimeout -gt 0) { '{0} second(s)' -f $mpPref.CloudExtendedTimeout } else { 'Default (20s)' }
            'Network protection mode'   = Get-MappedValue -Value $mpPref.EnableNetworkProtection -Map $script:NetworkProtection
            'Network protection reputation' = $mpPref.NetworkProtectionReputationMode
            'Automatic sample pre-scan' = $mpPref.CheckForSignaturesBeforeRunningScan
        })

    $sections['Exploit Guard & Ransomware Protections'] = New-Section -Name 'Exploit Guard & Ransomware Protections' -Type 'KeyValue' -Data ([ordered]@{
            'Controlled folder access'              = Get-MappedValue -Value $mpPref.EnableControlledFolderAccess -Map $script:ControlledFolderAccess
            'Convert CFA warn to block'             = $mpPref.EnableConvertWarnToBlock
            'Network protection on server SKUs'     = $mpPref.AllowNetworkProtectionOnWinServer
            'Network protection on down-level OS'   = $mpPref.AllowNetworkProtectionDownLevel
            'Brute force protection state'          = $mpPref.BruteForceProtectionConfiguredState
            'Brute force protection aggressiveness' = $mpPref.BruteForceProtectionAggressiveness
        })

    $sections['Attack Surface Reduction Rules'] = New-Section -Name 'Attack Surface Reduction Rules' -Type 'Table' -Data $asrRows

    $sections['Attack Surface Reduction Exclusions'] = New-Section -Name 'Attack Surface Reduction Exclusions' -Type 'ListMap' -Data ([ordered]@{
            'ASR-only exclusions' = Normalize-List -Items $mpPref.AttackSurfaceReductionOnlyExclusions -RequireElevation -IsElevated:$isElevated -PrivilegeMessage 'Run elevated to view ASR-only exclusions'
            'Rule-specific exclusions' = Normalize-List -Items $mpPref.AttackSurfaceReductionRules_RuleSpecificExclusions -RequireElevation -IsElevated:$isElevated -PrivilegeMessage 'Run elevated to view rule-specific exclusions'
        })

    $sections['Device Control'] = New-Section -Name 'Device Control' -Type 'KeyValue' -Data ([ordered]@{
            'Device control state'              = $mpStatus.DeviceControlState
            'Default enforcement'              = $mpStatus.DeviceControlDefaultEnforcement
            'Policies last updated'            = $mpStatus.DeviceControlPoliciesLastUpdated
            'Local network blocking'           = $mpPref.BruteForceProtectionLocalNetworkBlocking
            'Max block time (minutes)'         = $mpPref.BruteForceProtectionMaxBlockTime
        })

    $firewallProfiles = @()
    try { $firewallProfiles = @(Get-NetFirewallProfile -ErrorAction Stop) } catch { }
    if ($firewallProfiles.Count -gt 0) {
        $fwRows = foreach ($profile in $firewallProfiles) {
            [pscustomobject]@{
                Profile          = $profile.Name
                Enabled          = $profile.Enabled
                DefaultInbound   = $profile.DefaultInboundAction
                DefaultOutbound  = $profile.DefaultOutboundAction
            }
        }
        $sections['Firewall Profiles'] = New-Section -Name 'Firewall Profiles' -Type 'Table' -Data $fwRows
    } else {
        $sections['Firewall Profiles'] = New-Section -Name 'Firewall Profiles' -Type 'Message' -Data 'Get-NetFirewallProfile unavailable on this system.'
    }

    $sections['Scan Health & Schedule'] = New-Section -Name 'Scan Health & Schedule' -Type 'KeyValue' -Data ([ordered]@{
            'Last quick scan'           = $mpStatus.QuickScanStartTime
            'Quick scan range'          = if ($mpStatus.QuickScanEndTime) { '{0:g} - {1:g}' -f $mpStatus.QuickScanStartTime, $mpStatus.QuickScanEndTime } else { 'N/A' }
            'Quick scan age'            = Format-AgeDays $mpStatus.QuickScanAge
            'Last full scan'            = if ($mpStatus.FullScanStartTime) { $mpStatus.FullScanStartTime } else { 'Never' }
            'Full scan age'             = Format-AgeDays $mpStatus.FullScanAge
            'Full scan overdue'         = $mpStatus.FullScanOverdue
            'Full scan schedule'        = '{0} at {1}' -f (Get-MappedValue -Value $mpPref.ScanScheduleDay -Map $script:ScheduleDayMap), (Format-TimeOfDay $mpPref.ScanScheduleTime)
            'Quick scan schedule'       = 'Every day at {0}' -f (Format-TimeOfDay $mpPref.ScanScheduleQuickScanTime)
            'Randomize scheduled tasks' = $mpPref.RandomizeScheduleTaskTimes
            'Scan CPU throttle'         = '{0}%' -f $mpPref.ScanAvgCPULoadFactor
        })

    $sections['Exclusions'] = New-Section -Name 'Exclusions' -Type 'ListMap' -Data ([ordered]@{
            'Paths'       = Normalize-List -Items $mpPref.ExclusionPath -RequireElevation -IsElevated:$isElevated -PrivilegeMessage 'Run elevated to view path exclusions'
            'Processes'   = Normalize-List -Items $mpPref.ExclusionProcess -RequireElevation -IsElevated:$isElevated -PrivilegeMessage 'Run elevated to view process exclusions'
            'Extensions'  = Normalize-List -Items $mpPref.ExclusionExtension -RequireElevation -IsElevated:$isElevated -PrivilegeMessage 'Run elevated to view extension exclusions'
            'IP addresses' = Normalize-List -Items $mpPref.ExclusionIpAddress -RequireElevation -IsElevated:$isElevated -PrivilegeMessage 'Run elevated to view IP exclusions'
        })

    $sections['Controlled Folder Access'] = New-Section -Name 'Controlled Folder Access' -Type 'ListMap' -Data ([ordered]@{
            'Protected folders' = Normalize-List -Items ($mpPref.ControlledFolderAccessDefaultProtectedFolders + $mpPref.ControlledFolderAccessProtectedFolders) -RequireElevation -IsElevated:$isElevated -PrivilegeMessage 'Run elevated to view protected folders'
            'Allowed applications' = Normalize-List -Items $mpPref.ControlledFolderAccessAllowedApplications -RequireElevation -IsElevated:$isElevated -PrivilegeMessage 'Run elevated to view allowed applications'
        })

    $sections['EDR Sensor State'] = New-Section -Name 'EDR Sensor State' -Type 'KeyValue' -Data ([ordered]@{
        'Sense running state' = Get-OptionalPropertyValue -Object $mpStatus -PropertyName 'SenseRunningState'
        'Sense version'       = Get-OptionalPropertyValue -Object $mpStatus -PropertyName 'SenseVersion'
        'EDR block mode'      = Get-OptionalPropertyValue -Object $mpStatus -PropertyName 'EdrBlockMode'
            'Product status (dec)'= $mpStatus.ProductStatus
            'Product status (hex)'= if ($mpStatus.ProductStatus) { '0x{0:X}' -f $mpStatus.ProductStatus } else { 'N/A' }
        })

    if ($IncludeThreatHistory) {
        try {
            $threatRows = Get-MpThreatDetection -ErrorAction Stop |
                Sort-Object -Property InitialDetectionTime -Descending |
                Select-Object -First 5 |
                ForEach-Object {
                    [pscustomobject]@{
                        Detected    = $_.InitialDetectionTime
                        Threat      = $_.ThreatName
                        Severity    = $_.ThreatSeverity
                        Action      = $_.ActionSuccess
                    }
                }

            $sections['Threat History'] = New-Section -Name 'Threat History' -Type 'Table' -Data $threatRows
        } catch {
            $sections['Threat History'] = New-Section -Name 'Threat History' -Type 'Message' -Data ('Unable to collect threat history: {0}' -f $_.Exception.Message)
        }
    } else {
        $sections['Threat History'] = New-Section -Name 'Threat History' -Type 'Message' -Data 'Not collected. Re-run with -IncludeThreatHistory to capture recent detections.'
    }

    $filteredSections = @()
    foreach ($name in $script:SectionOrder) {
        if ($selectedSections -contains $name -and $sections.Contains($name)) {
            $filteredSections += $sections[$name]
        }
    }

    if ($filteredSections.Count -eq 0) { $filteredSections = $sections.Values }

    $needsText = (-not $AsObject) -or $OutFile
    $text = $null
    if ($needsText) { $text = Convert-SectionsToText -Sections $filteredSections }

    if ($OutFile) {
        $directory = Split-Path -Path $OutFile -Parent
        if ($directory -and -not (Test-Path -Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        Set-Content -Path $OutFile -Value $text -Encoding ASCII
    }

    if ($AsObject) {
        return $filteredSections
    }

    Write-Output $text
}

Invoke-DefenderPolicyReportInternal @PSBoundParameters -IncludeThreatHistory
