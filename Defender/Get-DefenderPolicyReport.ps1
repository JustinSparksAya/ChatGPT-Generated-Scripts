[CmdletBinding()]
param(
    [switch]$AsObject,
    [string]$OutFile,
    [ValidateSet('Metadata','Compliance Summary','Engine & Signature State','Real-time & Core Protections','Cloud-delivered Protection & Automation','Exploit Guard & Ransomware Protections','Attack Surface Reduction Rules','Attack Surface Reduction Exclusions','Device Control','Firewall Profiles','Scan Health & Schedule','Exclusions','Controlled Folder Access','EDR Sensor State','Threat History')]
    [string[]]$Section,
    [switch]$IncludeThreatHistory,
    [string]$CsvPath,
    [string]$HtmlPath,
    [string]$AsrCatalogPath,
    [string]$AsrCatalogUri = 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference',
    [switch]$RefreshAsrCatalog
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $PSCommandPath }
if (-not $AsrCatalogPath -or $AsrCatalogPath.Trim().Length -eq 0) {
    $AsrCatalogPath = Join-Path -Path $script:ScriptRoot -ChildPath 'data\asr-catalog.json'
}
if (-not $PSBoundParameters.ContainsKey('AsrCatalogPath')) {
    $PSBoundParameters['AsrCatalogPath'] = $AsrCatalogPath
}
Write-Verbose ("Script root resolved to: {0}" -f $script:ScriptRoot)
Write-Verbose ("ASR catalog path resolved to: {0}" -f $AsrCatalogPath)

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

$script:DefaultAsrRuleDescriptions = @{
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

function Get-DeviceSummary {
    $summary = [ordered]@{}

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs) {
            $summary['Manufacturer'] = $cs.Manufacturer
            $summary['Model'] = $cs.Model
            if ($cs.TotalPhysicalMemory) {
                $summary['Physical memory'] = (“{0:N2} GB” -f ($cs.TotalPhysicalMemory / 1GB))
            }
            $summary['Logical processors'] = $cs.NumberOfLogicalProcessors
        }
    } catch {
        Write-Verbose ("Unable to query Win32_ComputerSystem: {0}" -f $_.Exception.Message)
    }

    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        if ($cpu) {
            $summary['Processor'] = $cpu.Name
        }
    } catch {
        Write-Verbose ("Unable to query Win32_Processor: {0}" -f $_.Exception.Message)
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($os) {
            $summary['Operating system'] = $os.Caption
            $summary['OS version'] = (“{0} (Build {1})” -f $os.Version, $os.BuildNumber)
            if ($os.InstallDate) {
                $installDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate)
                $summary['OS installed'] = $installDate.ToString('yyyy-MM-dd')
            }
            if ($os.LastBootUpTime) {
                $boot = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
                $uptime = (Get-Date) - $boot
                $summary['System uptime'] = (“{0:%d}d {0:%h}h {0:%m}m” -f $uptime)
            }
        }
    } catch {
        Write-Verbose ("Unable to query Win32_OperatingSystem: {0}" -f $_.Exception.Message)
    }

    try {
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
        if ($disks) {
            $total = ($disks | Measure-Object -Property Size -Sum).Sum
            $free = ($disks | Measure-Object -Property FreeSpace -Sum).Sum
            if ($total -gt 0) {
                $summary['Storage (total)'] = (“{0:N2} GB” -f ($total / 1GB))
            }
            if ($free -ge 0) {
                $summary['Storage (free)'] = (“{0:N2} GB” -f ($free / 1GB))
            }
        }
    } catch {
        Write-Verbose ("Unable to query Win32_LogicalDisk: {0}" -f $_.Exception.Message)
    }

    return $summary
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

function Convert-SectionsToFlatRows {
    param($Sections)

    $rows = @()
    foreach ($section in $Sections) {
        if ($null -eq $section) { continue }
        $sectionName = $section.Name
        switch ($section.Type) {
            'KeyValue' {
                $data = $section.Data
                if ($null -eq $data) { continue }
                if ($data -is [System.Collections.IDictionary]) {
                    foreach ($key in $data.Keys) {
                        $rows += [pscustomobject]@{
                            Section = $sectionName
                            Item    = $key
                            Value   = Format-Value $data[$key]
                        }
                    }
                } else {
                    foreach ($prop in $data.PSObject.Properties) {
                        $rows += [pscustomobject]@{
                            Section = $sectionName
                            Item    = $prop.Name
                            Value   = Format-Value $prop.Value
                        }
                    }
                }
            }
            'List' {
                $items = @($section.Data)
                if ($items.Count -eq 0) {
                    $rows += [pscustomobject]@{ Section = $sectionName; Item = 'Item'; Value = 'None' }
                } else {
                    $index = 1
                    foreach ($item in $items) {
                        $rows += [pscustomobject]@{
                            Section = $sectionName
                            Item    = "Item $index"
                            Value   = Format-Value $item
                        }
                        $index++
                    }
                }
            }
            'ListMap' {
                $map = $section.Data
                if ($null -eq $map) { continue }
                if (-not ($map -is [System.Collections.IDictionary])) {
                    $map = [ordered]@{ Items = @($map) }
                }

                foreach ($key in $map.Keys) {
                    $items = @($map[$key])
                    if ($items.Count -eq 0) {
                        $rows += [pscustomobject]@{ Section = $sectionName; Item = $key; Value = 'None' }
                    } else {
                        foreach ($item in $items) {
                            $rows += [pscustomobject]@{
                                Section = $sectionName
                                Item    = $key
                                Value   = Format-Value $item
                            }
                        }
                    }
                }
            }
            'Table' {
                $tableRows = @($section.Data)
                if ($tableRows.Count -eq 0) {
                    $rows += [pscustomobject]@{ Section = $sectionName; Item = 'Row'; Value = 'None' }
                } else {
                    $rowIndex = 1
                    foreach ($row in $tableRows) {
                        $rows += [pscustomobject]@{
                            Section = $sectionName
                            Item    = "Row $rowIndex"
                            Value   = ($row | ConvertTo-Json -Depth 5 -Compress)
                        }
                        $rowIndex++
                    }
                }
            }
            'Message' {
                $rows += [pscustomobject]@{
                    Section = $sectionName
                    Item    = 'Message'
                    Value   = Format-Value $section.Data
                }
            }
        }
    }

    return $rows
}

function Convert-SectionsToHtml {
    param(
        $Sections,
        [string]$Title = 'Microsoft Defender Policy Report'
    )

    $encode = {
        param($text)
        if ($null -eq $text) { return '' }
        return [System.Net.WebUtility]::HtmlEncode(($text).ToString())
    }

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.AppendLine('<!DOCTYPE html>')
    [void]$builder.AppendLine('<html lang="en">')
    [void]$builder.AppendLine('<head>')
    [void]$builder.AppendLine('<meta charset="utf-8" />')
    [void]$builder.AppendLine("<title>$([System.Net.WebUtility]::HtmlEncode($Title))</title>")
    [void]$builder.AppendLine('<style>
        :root{
            color-scheme: light dark;
            --bg:#f4f6fb;
            --card:#ffffff;
            --border:#d8dce7;
            --text:#1f2430;
            --accent:#2563eb;
        }
        body{
            font-family:"Segoe UI",Roboto,Arial,sans-serif;
            margin:0;
            background:var(--bg);
            color:var(--text);
        }
        header{
            background:var(--card);
            padding:24px 32px;
            box-shadow:0 2px 8px rgba(15,23,42,.08);
            position:sticky;
            top:0;
            z-index:10;
        }
        h1{margin:0;font-size:26px;}
        .toolbar{
            display:flex;
            gap:12px;
            margin-top:12px;
            flex-wrap:wrap;
        }
        .toolbar input{
            flex:1;
            min-width:220px;
            padding:10px 14px;
            border:1px solid var(--border);
            border-radius:8px;
            font-size:14px;
        }
        .toolbar button{
            padding:10px 16px;
            background:var(--accent);
            color:#fff;
            border:none;
            border-radius:8px;
            cursor:pointer;
            font-size:14px;
        }
        main{
            padding:32px;
            display:grid;
            grid-template-columns:repeat(auto-fit,minmax(320px,1fr));
            gap:24px;
        }
        .section-card{
            background:var(--card);
            border:1px solid var(--border);
            border-radius:14px;
            box-shadow:0 6px 20px rgba(15,23,42,.08);
            padding:20px 22px;
        }
        .section-header{
            display:flex;
            justify-content:space-between;
            align-items:center;
            margin-bottom:12px;
            gap:8px;
        }
        .section-header h2{
            margin:0;
            font-size:18px;
        }
        .section-header button{
            background:none;
            border:1px solid var(--border);
            border-radius:8px;
            padding:4px 10px;
            cursor:pointer;
            font-size:12px;
            color:var(--text);
        }
        .section-content.collapsed{display:none;}
        .table-wrapper{
            border-radius:12px;
            border:1px solid var(--border);
            overflow:hidden;
            box-shadow:0 4px 14px rgba(15,23,42,.08);
            margin-bottom:12px;
        }
        table{
            width:100%;
            border-collapse:separate;
            border-spacing:0;
        }
        th,td{
            padding:10px 14px;
            text-align:left;
            font-size:13px;
            border-bottom:1px solid var(--border);
        }
        th{
            background:linear-gradient(135deg,#eef2ff 0%,#e0e7ff 100%);
            font-weight:600;
            letter-spacing:.02em;
        }
        tr:nth-child(even) td{
            background:#f8f9ff;
        }
        tr:hover td{
            background:#ecf2ff;
        }
        tr:last-child td{
            border-bottom:none;
        }
        ul{
            padding-left:18px;
            margin:0;
        }
        li{margin-bottom:4px;}
        @media (max-width:768px){
            main{grid-template-columns:1fr;padding:18px;}
            header{position:static;}
        }
    </style>')
    [void]$builder.AppendLine('</head>')
    [void]$builder.AppendLine('<body>')
    [void]$builder.AppendLine('<header id="top">')
    [void]$builder.AppendLine("<h1>$([System.Net.WebUtility]::HtmlEncode($Title))</h1>")
    [void]$builder.AppendLine('<div class="toolbar"><input id="filterBox" type="search" placeholder="Filter sections..." /><button id="expandAll" type="button">Expand all</button><button id="collapseAll" type="button">Collapse all</button></div>')
    [void]$builder.AppendLine('</header>')
    [void]$builder.AppendLine('<main id="sections">')

    $sectionIndex = 0
    foreach ($section in $Sections) {
        if ($null -eq $section) { continue }
        $sectionIndex++
        $sectionId = [System.Text.RegularExpressions.Regex]::Replace($section.Name.ToLowerInvariant(), '[^a-z0-9]+', '-').Trim('-')
        if ([string]::IsNullOrWhiteSpace($sectionId)) { $sectionId = "section-$sectionIndex" }
        $searchPayload = ($section | ConvertTo-Json -Depth 5 -Compress)
        $searchText = ($section.Name + ' ' + $searchPayload).ToLowerInvariant()
        [void]$builder.AppendLine("<article class='section-card' id='$sectionId' data-search='$($encode.Invoke($searchText))'>")
        [void]$builder.AppendLine("<div class='section-header'><h2>$($encode.Invoke($section.Name))</h2><button type='button' class='toggle'>Collapse</button></div>")
        [void]$builder.AppendLine("<div class='section-content'>")

        switch ($section.Type) {
            'KeyValue' {
                $data = $section.Data
                if ($null -eq $data) {
                    [void]$builder.AppendLine('<p>No data</p>')
                    break
                }

                $rows = @()
                if ($data -is [System.Collections.IDictionary]) {
                    foreach ($key in $data.Keys) {
                        $rows += [pscustomobject]@{ Key = $key; Value = Format-Value $data[$key] }
                    }
                } else {
                    foreach ($prop in $data.PSObject.Properties) {
                        $rows += [pscustomobject]@{ Key = $prop.Name; Value = Format-Value $prop.Value }
                    }
                }

                if ($rows.Count -eq 0) {
                    [void]$builder.AppendLine('<p>No data</p>')
                } else {
                    [void]$builder.AppendLine('<div class="table-wrapper"><table><thead><tr><th>Setting</th><th>Value</th></tr></thead><tbody>')
                    foreach ($row in $rows) {
                        [void]$builder.AppendLine("<tr><th>$($encode.Invoke($row.Key))</th><td>$($encode.Invoke($row.Value))</td></tr>")
                    }
                    [void]$builder.AppendLine('</tbody></table></div>')
                }
            }
            'List' {
                $items = @($section.Data)
                if ($items.Count -eq 0) {
                    [void]$builder.AppendLine('<p>None</p>')
                } else {
                    [void]$builder.AppendLine('<ul>')
                    foreach ($item in $items) {
                        [void]$builder.AppendLine("<li>$($encode.Invoke((Format-Value $item)))</li>")
                    }
                    [void]$builder.AppendLine('</ul>')
                }
            }
            'ListMap' {
                $map = $section.Data
                if ($null -eq $map) {
                    [void]$builder.AppendLine('<p>No data</p>')
                    break
                }

                if (-not ($map -is [System.Collections.IDictionary])) {
                    $map = [ordered]@{ Items = @($map) }
                }

                foreach ($key in $map.Keys) {
                    $items = @($map[$key])
                    if ($items.Count -eq 0) {
                        [void]$builder.AppendLine("<p><strong>$($encode.Invoke($key))</strong>: None</p>")
                    } else {
                        [void]$builder.AppendLine("<p><strong>$($encode.Invoke($key))</strong></p>")
                        [void]$builder.AppendLine('<ul>')
                        foreach ($item in $items) {
                            [void]$builder.AppendLine("<li>$($encode.Invoke((Format-Value $item)))</li>")
                        }
                        [void]$builder.AppendLine('</ul>')
                    }
                }
            }
            'Table' {
                $tableRows = @($section.Data)
                if ($tableRows.Count -eq 0) {
                    [void]$builder.AppendLine('<p>None</p>')
                } else {
                    $properties = $tableRows[0].PSObject.Properties.Name
                    [void]$builder.AppendLine('<div class="table-wrapper"><table><thead><tr>')
                    foreach ($propName in $properties) {
                        [void]$builder.AppendLine("<th>$($encode.Invoke($propName))</th>")
                    }
                    [void]$builder.AppendLine('</tr></thead><tbody>')
                    foreach ($row in $tableRows) {
                        [void]$builder.AppendLine('<tr>')
                        foreach ($propName in $properties) {
                            $value = $row.$propName
                            [void]$builder.AppendLine("<td>$($encode.Invoke((Format-Value $value)))</td>")
                        }
                        [void]$builder.AppendLine('</tr>')
                    }
                    [void]$builder.AppendLine('</tbody></table></div>')
                }
            }
            'Message' {
                [void]$builder.AppendLine("<p>$($encode.Invoke((Format-Value $section.Data)))</p>")
            }
        }

        [void]$builder.AppendLine('</div></article>')
    }

    [void]$builder.AppendLine('</main>')
    [void]$builder.AppendLine('<script>
        (function(){
            const filterBox = document.getElementById("filterBox");
            const cards = Array.from(document.querySelectorAll(".section-card"));
            const expandAll = document.getElementById("expandAll");
            const collapseAll = document.getElementById("collapseAll");

            const setCollapsed = (collapsed) => {
                cards.forEach(card => {
                    const content = card.querySelector(".section-content");
                    const toggle = card.querySelector(".toggle");
                    if (!content || !toggle) { return; }
                    content.classList.toggle("collapsed", collapsed);
                    toggle.textContent = collapsed ? "Expand" : "Collapse";
                });
            };

            filterBox.addEventListener("input", () => {
                const term = filterBox.value.trim().toLowerCase();
                cards.forEach(card => {
                    const matches = card.dataset.search.includes(term);
                    card.style.display = matches ? "" : "none";
                });
            });

            cards.forEach(card => {
                const toggle = card.querySelector(".toggle");
                const content = card.querySelector(".section-content");
                if (!toggle || !content) { return; }
                toggle.addEventListener("click", () => {
                    const collapsed = content.classList.toggle("collapsed");
                    toggle.textContent = collapsed ? "Expand" : "Collapse";
                });
            });

            expandAll.addEventListener("click", () => setCollapsed(false));
            collapseAll.addEventListener("click", () => setCollapsed(true));
        })();
    </script>')
    [void]$builder.AppendLine('</body>')
    [void]$builder.AppendLine('</html>')
    return $builder.ToString()
}

function Ensure-DirectoryForFile {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }

    $directory = Split-Path -Path $Path -Parent
    if ($directory -and -not (Test-Path -Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
}

function Update-AsrCatalog {
    param(
        [Parameter(Mandatory)][string]$CatalogPath,
        [Parameter(Mandatory)][string]$CatalogUri
    )

    Write-Verbose ("Refreshing ASR catalog from {0}" -f $CatalogUri)
    $response = Invoke-WebRequest -Uri $CatalogUri -UseBasicParsing
    $html = $response.Content
    $pattern = '<td style="text-align: left;">(?<name>.*?)</td>\s*<td style="text-align: left;">(?<guid>[0-9a-fA-F-]{36})</td>'
    $matches = [System.Text.RegularExpressions.Regex]::Matches($html, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

    $rules = $matches | ForEach-Object {
        [pscustomobject]@{
            guid = $_.Groups['guid'].Value.ToLower()
            name = ([System.Net.WebUtility]::HtmlDecode($_.Groups['name'].Value).Trim())
        }
    } | Sort-Object guid -Unique

    if ($rules.Count -eq 0) {
        throw "Failed to parse ASR rule data from $CatalogUri"
    }

    $catalog = [ordered]@{
        source    = $CatalogUri
        generated = (Get-Date).ToString('s')
        ruleCount = $rules.Count
        rules     = $rules
    }

    Ensure-DirectoryForFile -Path $CatalogPath
    $json = $catalog | ConvertTo-Json -Depth 5
    Set-Content -Path $CatalogPath -Value $json -Encoding UTF8
}

function Load-AsrCatalog {
    param([string]$CatalogPath)

    if ([string]::IsNullOrWhiteSpace($CatalogPath)) { return $null }

    if (-not (Test-Path -Path $CatalogPath)) { return $null }

    try {
        $raw = Get-Content -Path $CatalogPath -Raw -Encoding UTF8 -ErrorAction Stop
        return $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Warning ("Unable to read ASR catalog from {0}: {1}" -f $CatalogPath, $_.Exception.Message)
        return $null
    }
}

function Get-AsrRuleDescriptions {
    param(
        [string]$CatalogPath,
        [switch]$Refresh,
        [string]$CatalogUri,
        [hashtable]$Fallback
    )

    if ($Refresh) {
        try {
            Update-AsrCatalog -CatalogPath $CatalogPath -CatalogUri $CatalogUri
        } catch {
            Write-Warning $_.Exception.Message
        }
    }

    $catalog = Load-AsrCatalog -CatalogPath $CatalogPath

    if ($null -eq $catalog -and -not $Refresh) {
        try {
            Update-AsrCatalog -CatalogPath $CatalogPath -CatalogUri $CatalogUri
            $catalog = Load-AsrCatalog -CatalogPath $CatalogPath
        } catch {
            Write-Warning $_.Exception.Message
        }
    }

    $descriptions = @{}

    if ($null -ne $catalog) {
        $ruleObjects = @()
        if ($catalog.PSObject.Properties['rules']) {
            $ruleObjects = @($catalog.rules)
        } elseif ($catalog -is [System.Collections.IEnumerable] -and -not ($catalog -is [string])) {
            $ruleObjects = @($catalog)
        }

        foreach ($rule in $ruleObjects) {
            $guid = $rule.guid
            if (-not $guid -and $rule.PSObject.Properties['Guid']) { $guid = $rule.Guid }
            $name = $rule.name
            if (-not $name -and $rule.PSObject.Properties['Name']) { $name = $rule.Name }

            if ([string]::IsNullOrWhiteSpace($guid) -or [string]::IsNullOrWhiteSpace($name)) { continue }
            $descriptions[$guid.ToLower()] = $name.Trim()
        }
    }

    if ($descriptions.Count -eq 0 -and $Fallback) {
        Write-Verbose 'Falling back to built-in ASR rule catalog.'
        $descriptions = $Fallback
    }

    return $descriptions
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
        [switch]$IncludeThreatHistory,
        [string]$CsvPath,
        [string]$HtmlPath,
        [string]$AsrCatalogPath,
        [string]$AsrCatalogUri,
        [switch]$RefreshAsrCatalog
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

    $asrRuleDescriptions = Get-AsrRuleDescriptions -CatalogPath $AsrCatalogPath -Refresh:$RefreshAsrCatalog -CatalogUri $AsrCatalogUri -Fallback $script:DefaultAsrRuleDescriptions
    if ($null -eq $asrRuleDescriptions) { $asrRuleDescriptions = @{} }

    $deviceSummary = Get-DeviceSummary
    $metadataData = [ordered]@{
        'Computer name' = $env:COMPUTERNAME
        'User'          = $env:USERNAME
        'Generated'     = $reportTime
        'Elevated'      = $isElevated
    }
    if ($deviceSummary) {
        foreach ($key in $deviceSummary.Keys) {
            $metadataData[$key] = $deviceSummary[$key]
        }
    }
    $sections['Metadata'] = New-Section -Name 'Metadata' -Type 'KeyValue' -Data $metadataData

    $asrRows = @(
        Get-AsrRuleRows -Preference $mpPref -RuleDescriptions $asrRuleDescriptions -ActionMap $script:AsrActionMap
    )
    $configuredAsr = $asrRows.Count
    $complianceData = [ordered]@{
        'ASR rules configured'              = ('{0}/{1}' -f $configuredAsr, $asrRuleDescriptions.Count)
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

    if ($CsvPath) {
        $csvRows = Convert-SectionsToFlatRows -Sections $filteredSections
        Ensure-DirectoryForFile -Path $CsvPath
        $csvRows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    }

    if ($HtmlPath) {
        $htmlTitle = "Microsoft Defender Policy Report - $($env:COMPUTERNAME)"
        $htmlContent = Convert-SectionsToHtml -Sections $filteredSections -Title $htmlTitle
        Ensure-DirectoryForFile -Path $HtmlPath
        Set-Content -Path $HtmlPath -Value $htmlContent -Encoding UTF8
        try {
            if (Test-Path -Path $HtmlPath) {
                Start-Process -FilePath $HtmlPath | Out-Null
            }
        } catch {
            Write-Verbose ("Unable to open HTML report {0}: {1}" -f $HtmlPath, $_.Exception.Message)
        }
    }

    if ($OutFile) {
        Ensure-DirectoryForFile -Path $OutFile
        Set-Content -Path $OutFile -Value $text -Encoding ASCII
    }

    if ($AsObject) {
        return $filteredSections
    }

    Write-Output $text
}

Invoke-DefenderPolicyReportInternal @PSBoundParameters -HtmlPath $env:temp\defender-report.html
