<#
.SYNOPSIS
    MITRE ATT&CK APT Group TTP & IOC Scraper.

.DESCRIPTION
    Lists the MITRE ATT&CK threat groups (APT groups) and lets you select one or more.
    For each selected group it generates a compact Markdown (.md) and HTML cheat sheet.
    Markdown files go to a 'markdown' folder and HTML files to an 'html' folder next to
    the script (or under -OutputDir):

      * Group header (name, G-code, aliases, short summary)
      * TTPs grouped by tactic - one row per technique with:
          - TTP ID + full name
          - a one-line topic descriptor
          - a compact group of IOCs to look for (processes, command patterns, ports,
            domains, registry keys, Windows event IDs)
          - a General query auto-generated from the technique's Detection
            Strategies / Analytics (the modern 'what to look for')
      * Software used (S-codes) at the bottom, plus attributed Campaigns
      * Auto-extracted behavioral IOCs (processes, commands, registry keys, file
        paths, domains, ports) pulled from the detection/procedure text

    KQL queries are heuristic - generated from MITRE detection/analytic text via
    regex (ECS field mappings) and are meant as starting points for hunting.

    DATA SOURCE
    Instead of scraping HTML, the script consumes the official MITRE CTI
    STIX 2.1 bundle that the attack.mitre.org website is generated from:
        https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
    The full bundle (~48 MB) is downloaded once and cached, then a slim
    subset (only the object types we need) is cached to make later runs fast.

.EXAMPLE
    .\MITRE-Scraper.ps1                     # interactive: pick group(s) from a menu

.EXAMPLE
    .\MITRE-Scraper.ps1 -Group G0007,G0006  # generate APT28 + APT1 non-interactively

.EXAMPLE
    .\MITRE-Scraper.ps1 -Group G0007 -Refresh -NoMarkdown   # force re-download, HTML only

.EXAMPLE
    .\MITRE-Scraper.ps1 -All              # generate reports for every group

.NOTES
    Author  : Kevin C. Jones
    Site    : 4n6post.com
    Requires: PowerShell 7 for best performance (the ~48 MB JSON parses much
              faster than under Windows PowerShell 5.1, which still works but
              is slow and memory hungry).
    License : MIT; data (c) The MITRE Corporation. This tool is not affiliated
              with or endorsed by MITRE.
#>
[CmdletBinding()]
param(
    # Force re-download of the STIX bundle and rebuild the slim cache.
    [Parameter()][switch]$Refresh,

    # One or more group IDs (G0007) or names (APT28) to process without the menu.
    [Parameter()][Alias('Groups')][string[]]$Group,

    # Generate reports for every group (non-interactive; overrides -Group).
    [Parameter()][switch]$All,

    # Output directory (defaults to the script's folder).
    [Parameter()][string]$OutputDir,

    # Directory used for the cached ATT&CK data (defaults to .\.cache).
    [Parameter()][string]$CacheDir,

    # Skip Markdown generation.
    [Parameter()][switch]$NoMarkdown,

    # Skip HTML generation.
    [Parameter()][switch]$NoHtml
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
$StixUrl       = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
$GroupBaseUrl  = 'https://attack.mitre.org/groups/'
$TechBaseUrl   = 'https://attack.mitre.org/techniques/'

$ScriptRoot    = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$CacheDir      = if ($CacheDir) { $CacheDir } else { Join-Path $ScriptRoot '.cache' }
$BundlePath    = Join-Path $CacheDir 'enterprise-attack.json'
$SlimPath      = Join-Path $CacheDir 'enterprise-attack.slim.json'

# Object types we need from the bundle (everything else is discarded for speed).
# Includes the modern detection model: x-mitre-detection-strategy + x-mitre-analytic
# (the per-technique 'Detection' prose was removed from the STIX data in recent releases).
$KeepTypes = @('intrusion-set', 'attack-pattern', 'malware', 'tool', 'campaign', 'relationship',
    'x-mitre-detection-strategy', 'x-mitre-analytic', 'x-mitre-data-component', 'x-mitre-data-source')

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
function Write-Status {
    param([Parameter(Mandatory)][string]$Message, [ConsoleColor]$ForegroundColor = 'Gray')
    Write-Host $Message -ForegroundColor $ForegroundColor
}

# Safe property getter - returns $null when the property is absent.
function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

# Null-safe lookup into the id->object map (hashtable indexers throw on $null keys).
function Get-LookupValue {
    param($Data, [object]$Key)
    if ($null -eq $Key -or $null -eq $Data -or $null -eq $Data.Lookup) { return $null }
    return $Data.Lookup[$Key]
}

# Aliases: current STIX 2.1 data uses the native 'aliases' field; older exports used
# 'x_mitre_aliases'. Return whichever is present.
function Get-Aliases {
    param($Object)
    $a = @(Get-Prop $Object 'aliases')
    if ($a.Count) { return $a }
    return @(Get-Prop $Object 'x_mitre_aliases')
}

# Returns the ATT&CK code for an object (G-code for groups, T-code for
# techniques, S-code for software, C-code for campaigns) or $null.
function Get-GroupCode {
    param($Object)
    foreach ($r in @(Get-Prop $Object 'external_references')) {
        if ((Get-Prop $r 'source_name') -eq 'mitre-attack') {
            return (Get-Prop $r 'external_id')
        }
    }
    return $null
}

# Returns the canonical attack.mitre.org URL for an object.
function Get-MitreUrl {
    param($Object)
    foreach ($r in @(Get-Prop $Object 'external_references')) {
        if ((Get-Prop $r 'source_name') -eq 'mitre-attack') {
            $u = Get-Prop $r 'url'
            if ($u) { return $u }
        }
    }
    # Fallback for techniques/sub-techniques: T1059.001 -> /techniques/T1059/001/
    $code = Get-GroupCode $Object
    if ($code -and $code -match '^(T\d+)(?:\.(\d+))?$') {
        return "$TechBaseUrl$($Matches[1])/$(if ($Matches[2]) { "$($Matches[2])/" } else { '' })"
    }
    return $null
}

function ConvertTo-TitleCase {
    param([string]$Text)
    if (-not $Text) { return $Text }
    return (Get-Culture).TextInfo.ToTitleCase(($Text -replace '-', ' '))
}

# File-safe name for output files (spaces/special chars -> dashes).
function ConvertTo-FileSafeName {
    param([string]$Name)
    return (($Name -replace '[^\w\-]', '-' -replace '\-+', '-').Trim('-'))
}

# Extract code snippets from a STIX description (fenced ``` blocks, `inline` code,
# and the HTML <code> tags MITRE uses in the current data).
function Get-CodeSnippets {
    param([string]$Text)
    $snippets = [System.Collections.Generic.List[string]]::new()
    if (-not $Text) { return @($snippets) }
    foreach ($m in [regex]::Matches($Text, '(?s)```[^\r\n]*\r?\n(.*?)```')) {
        $snippets.Add($m.Groups[1].Value.Trim())
    }
    foreach ($m in [regex]::Matches($Text, '`([^`\r\n]+)`')) {
        $snippets.Add($m.Groups[1].Value.Trim())
    }
    foreach ($m in [regex]::Matches($Text, '(?i)<code>(.*?)</code>')) {
        $snippets.Add($m.Groups[1].Value.Trim())
    }
    return @($snippets | Select-Object -Unique)
}

# Clean MITRE's rich-text description: <code> -> backticks, strip other HTML tags
# and the (Citation: ...) markers so the text reads cleanly in Markdown/HTML.
function ConvertTo-CleanText {
    param([string]$Text)
    if (-not $Text) { return '' }
    $t = $Text
    $t = [regex]::Replace($t, '(?i)<code>(.*?)</code>', '`$1`')
    $t = [regex]::Replace($t, '(?i)<[^>]+>', '')
    $t = [regex]::Replace($t, '\(Citation:[^)]*\)', '')
    $t = $t -replace ' +', ' '
    return $t.Trim()
}

# ---------------------------------------------------------------------------
# Data layer: download + parse + cache the STIX bundle
# ---------------------------------------------------------------------------
function Read-StixObjects {
    param([string]$Path)
    $raw  = Get-Content -Raw -Path $Path
    $data = ConvertFrom-Json -InputObject $raw -Depth 12
    # Supports both a {"objects":[...]} bundle wrapper and a bare array.
    if ($null -ne $data -and $data.PSObject.Properties['objects']) {
        return @($data.objects)
    }
    return @($data)
}

function Get-AttackData {
    if (-not (Test-Path $CacheDir)) { New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null }

    $needFull  = $Refresh -or -not (Test-Path $BundlePath)
    $needParse = $needFull -or -not (Test-Path $SlimPath)

    if ($needFull) {
        Write-Status 'Downloading MITRE ATT&CK STIX bundle (~48 MB, one time)...' -ForegroundColor Cyan
        # PowerShell 5.1 needs TLS 1.2 for raw.githubusercontent.com.
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
        try {
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $StixUrl -OutFile $BundlePath -UseBasicParsing
        } catch {
            throw "Download failed: $($_.Exception.Message)"
        }
        $needParse = $true
    }

    if ($needParse) {
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            Write-Status 'NOTE: parsing the full bundle under Windows PowerShell 5.1 is slow. Consider pwsh 7.' -ForegroundColor Yellow
        }
        Write-Status 'Parsing ATT&CK STIX data...' -ForegroundColor Cyan
        $objects     = Read-StixObjects -Path $BundlePath
        $slimObjects = @($objects | Where-Object { $_.type -in $KeepTypes })
        $slimBundle  = [pscustomobject]@{ type = 'bundle'; objects = $slimObjects }
        $slimBundle | ConvertTo-Json -Depth 12 | Set-Content -Path $SlimPath -Encoding UTF8
        $slimMb = [math]::Round((Get-Item $SlimPath).Length / 1MB, 1)
        Write-Status "Cached slim dataset ($slimMb MB, $($slimObjects.Count) objects)." -ForegroundColor DarkGray
    } else {
        Write-Status 'Using cached ATT&CK data (slim subset).' -ForegroundColor DarkGray
        $objects = Read-StixObjects -Path $SlimPath
    }

    $lookup = @{}
    foreach ($o in $objects) { $lookup[$o.id] = $o }

    $rels = @($objects | Where-Object { $_.type -eq 'relationship' })
    # Index relationships by target so per-technique lookups are fast (matters for -All).
    $relsByTarget = @{}
    foreach ($r in $rels) {
        $t = Get-Prop $r 'target_ref'
        if (-not $t) { continue }
        if (-not $relsByTarget.ContainsKey($t)) { $relsByTarget[$t] = [System.Collections.Generic.List[object]]::new() }
        $relsByTarget[$t].Add($r)
    }

    return [pscustomobject]@{
        Lookup       = $lookup
        Rels         = $rels
        RelsByTarget = $relsByTarget
        Groups       = @($objects | Where-Object { $_.type -eq 'intrusion-set' })
        Source       = $(if ($needParse) { 'full' } else { 'slim' })
    }
}

# ---------------------------------------------------------------------------
# Group picker menu
# ---------------------------------------------------------------------------
function Resolve-Selection {
    param([string]$InputText, [int]$Count)
    $indices = [System.Collections.Generic.SortedSet[int]]::new()
    foreach ($t in (($InputText -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        if ($t -match '^(?i)all$') {
            for ($i = 0; $i -lt $Count; $i++) { $null = $indices.Add($i) }
        } elseif ($t -match '^(\d+)-(\d+)$') {
            $lo = [Math]::Min([int]$Matches[1], [int]$Matches[2])
            $hi = [Math]::Max([int]$Matches[1], [int]$Matches[2])
            for ($i = $lo; $i -le $hi; $i++) { if ($i -ge 1 -and $i -le $Count) { $null = $indices.Add($i - 1) } }
        } elseif ($t -match '^(\d+)$') {
            $n = [int]$Matches[1]
            if ($n -ge 1 -and $n -le $Count) { $null = $indices.Add($n - 1) }
        } else {
            Write-Warning "Ignoring invalid selection token: $t"
        }
    }
    return @($indices)
}

function Show-GroupMenu {
    param([Parameter(Mandatory)][object[]]$Groups)
    Write-Host ''
    Write-Host "MITRE ATT&CK Threat Groups  ($($Groups.Count) total)" -ForegroundColor Cyan
    Write-Host ('-' * 70) -ForegroundColor DarkGray
    for ($i = 0; $i -lt $Groups.Count; $i++) {
        $g     = $Groups[$i]
        $name  = Get-Prop $g 'name'
        $code  = Get-GroupCode $g
        $alias = @(Get-Aliases $g)
        $aliasText = ''
        if ($alias.Count) {
            $shown = ($alias | Select-Object -First 3) -join ', '
            $aliasText = "  [$shown$(if ($alias.Count -gt 3) { ', …' } else { '' })]"
        }
        Write-Host ('{0,3}. {1,-6} {2}{3}' -f ($i + 1), $code, $name, $aliasText)
    }

    while ($true) {
        Write-Host ''
        Write-Host -NoNewline 'Select group(s) [e.g. 1,3,7  or  1-5;  "all" or 0 = every group;  Enter to quit]: ' -ForegroundColor Cyan
        $answer = Read-Host
        if ([string]::IsNullOrWhiteSpace($answer)) { return @() }
        if ($answer -match '^(?i)q(?:uit)?$') { return @() }
        if ($answer -match '^(?i)(all|0)$') { return @($Groups) }
        $idx = Resolve-Selection -InputText $answer -Count $Groups.Count
        if ($idx.Count -eq 0) {
            Write-Host 'No valid selection. Try again.' -ForegroundColor Yellow
            continue
        }
        return @($idx | ForEach-Object { $Groups[$_] })
    }
}

# ---------------------------------------------------------------------------
# TTP / relationship mapping
# ---------------------------------------------------------------------------
function Get-GroupProfile {
    param($Data, $Group)
    $gid = Get-Prop $Group 'id'
    $techMap = @{}
    $softMap = @{}
    $campMap = @{}

    foreach ($r in $Data.Rels) {
        $srcId = Get-Prop $r 'source_ref'
        $tgtId = Get-Prop $r 'target_ref'
        if ($srcId -ne $gid -and $tgtId -ne $gid) { continue }
        $otherId = if ($srcId -eq $gid) { $tgtId } else { $srcId }
        $other   = Get-LookupValue -Data $Data -Key $otherId
        if (-not $other) { continue }
        $desc = Get-Prop $r 'description'
        switch (Get-Prop $other 'type') {
            'attack-pattern' {
                $extId = Get-GroupCode $other
                if (-not $extId) { break }
                if (-not $techMap.ContainsKey($extId)) {
                    $techMap[$extId] = [pscustomobject]@{
                        Pattern         = $other
                        Id              = $extId
                        Name            = Get-Prop $other 'name'
                        GroupDescription = $desc
                    }
                } elseif ($desc -and -not $techMap[$extId].GroupDescription) {
                    $techMap[$extId].GroupDescription = $desc
                }
            }
            { $_ -in @('malware', 'tool') } {
                $extId = Get-GroupCode $other
                if (-not $extId) { break }
                if (-not $softMap.ContainsKey($extId)) {
                    $softMap[$extId] = [pscustomobject]@{
                        Object      = $other
                        Id          = $extId
                        Name        = Get-Prop $other 'name'
                        Type        = Get-Prop $other 'type'
                        Description = $desc
                    }
                } elseif ($desc -and -not $softMap[$extId].Description) {
                    $softMap[$extId].Description = $desc
                }
            }
            'campaign' {
                $extId = Get-GroupCode $other
                if (-not $extId) { break }
                if (-not $campMap.ContainsKey($extId)) {
                    $campMap[$extId] = [pscustomobject]@{
                        Object      = $other
                        Id          = $extId
                        Name        = Get-Prop $other 'name'
                        Description = Get-Prop $other 'description'
                    }
                }
            }
        }
    }

    return [pscustomobject]@{
        Group      = $Group
        Techniques = @($techMap.Values | Sort-Object Id)
        Software   = @($softMap.Values | Sort-Object Name)
        Campaigns  = @($campMap.Values | Sort-Object Id)
    }
}

# Procedure-example code blocks come from relationships where a malware/tool
# "uses" the technique (the description carries the code such as Start-Process).
function Get-ProcedureExamples {
    param($Data, $Pattern)
    $patternId = Get-Prop $Pattern 'id'
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $out  = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($Data.RelsByTarget[$patternId])) {
        if ((Get-Prop $r 'relationship_type') -ne 'uses') { continue }
        $src = Get-LookupValue -Data $Data -Key (Get-Prop $r 'source_ref')
        if (-not $src) { continue }
        if ((Get-Prop $src 'type') -notin @('malware', 'tool')) { continue }
        $name = Get-Prop $src 'name'
        $desc = Get-Prop $r 'description'
        if (-not $name -or -not $desc -or $seen.Contains($name)) { continue }
        $null = $seen.Add($name)
        $out.Add([pscustomobject]@{
            Name        = $name
            Id          = Get-GroupCode $src
            Description = $desc
            Code        = @(Get-CodeSnippets $desc)
        })
    }
    return @($out | Sort-Object Name)
}

# Sub-techniques store only their sub-name (e.g. 'PowerShell'). The website shows
# the full 'Parent: Sub' name, so compose it from the parent attack-pattern.
function Get-FullTechniqueName {
    param($Data, $Pattern)
    $name = Get-Prop $Pattern 'name'
    if (-not [bool](Get-Prop $Pattern 'x_mitre_is_subtechnique')) { return $name }
    $code = Get-GroupCode $Pattern
    if ($code -and $code -match '^(T\d+)\.\d+$') {
        $parentCode = $Matches[1]
        $parent = $Data.Lookup.Values | Where-Object {
            $_.type -eq 'attack-pattern' -and (Get-GroupCode $_) -eq $parentCode -and -not [bool](Get-Prop $_ 'x_mitre_is_subtechnique')
        } | Select-Object -First 1
        if ($parent) { return "$(Get-Prop $parent 'name'): $name" }
    }
    return $name
}

# The modern 'what to look for': detection strategies (DET codes) whose analytics
# (AN codes) carry the actual detection guidance prose.
function Get-DetectionStrategies {
    param($Data, $Pattern)
    $patternId = Get-Prop $Pattern 'id'
    $seenAn = [System.Collections.Generic.HashSet[string]]::new()
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($Data.RelsByTarget[$patternId])) {
        if ((Get-Prop $r 'relationship_type') -ne 'detects') { continue }
        $strat = Get-LookupValue -Data $Data -Key (Get-Prop $r 'source_ref')
        if (-not $strat -or (Get-Prop $strat 'type') -ne 'x-mitre-detection-strategy') { continue }
        foreach ($anRef in @(Get-Prop $strat 'x_mitre_analytic_refs')) {
            $an = Get-LookupValue -Data $Data -Key $anRef
            if (-not $an -or $seenAn.Contains((Get-Prop $an 'id'))) { continue }
            $null = $seenAn.Add((Get-Prop $an 'id'))
            $out.Add([pscustomobject]@{
                DetCode     = Get-GroupCode $strat
                DetName     = Get-Prop $strat 'name'
                AnCode      = Get-GroupCode $an
                AnName      = Get-Prop $an 'name'
                Description = Get-Prop $an 'description'
            })
        }
    }
    return @($out)
}

# One-line topic descriptor for compact tables (first sentence, capped).
function Get-ShortDescriptor {
    param([string]$Description)
    $d = ConvertTo-CleanText $Description
    if (-not $d) { return '' }
    $sentences = @($d -split '(?<=[.!?])\s+')
    $s = if ($sentences.Count) { $sentences[0] } else { $d }
    if ($s.Length -lt 30 -and $sentences.Count -gt 1) { $s = $sentences[0] + ' ' + $sentences[1] }
    if ($s.Length -gt 110) { $s = $s.Substring(0, 110).TrimEnd() + '…' }
    return $s
}

# Per-technique detection-focused signals used to build the KQL query and the
# compact 'Look for' chip list. Text = detection strategies + description + group usage.
function Get-TechSignals {
    param([string]$Text)
    $sig = [ordered]@{}
    $sig['Procs']    = @()
    $sig['Patterns'] = @()
    $sig['Ports']    = @()
    $sig['Domains']  = @()
    $sig['Registry'] = @()
    $sig['EventIds'] = @()
    if (-not $Text) { return $sig }
    $t = ConvertTo-CleanText $Text
    $t = [regex]::Replace($t, '\[[^\]]+\]\([^)\s]+\)', '')

    $exeRe = '(?i)(?<![A-Za-z0-9_\\\\.])\b[A-Za-z0-9_][A-Za-z0-9_.\-]*\.(?:exe|dll|ps1|bat|cmd|vbs|js|scr|msi|cpl|hta)\b'
    $sig['Procs'] = @([regex]::Matches($t, $exeRe) | ForEach-Object { $_.Value.ToLowerInvariant() } | Sort-Object -Unique | Select-Object -First 4)

    $patTerms = @('-enc', '-e ', '-exec bypass', '-windowstyle hidden', '-w hidden', '-nop', '-noprofile',
        'IEX', 'DownloadString', 'FromBase64String', 'EncodedCommand', 'Invoke-Expression', 'Reflection.Assembly', 'Add-Type')
    $pats = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $patTerms) { if ($t -match [regex]::Escape($p)) { $pats.Add($p) } }
    $sig['Patterns'] = @($pats | Select-Object -First 4)

    $ports = [System.Collections.Generic.List[int]]::new()
    foreach ($m in [regex]::Matches($t, '(?i)\bport\s+(?:number\s+)?(\d{1,5})\b|\b(\d{1,5})\s*/\s*(?:tcp|udp)\b')) {
        foreach ($g in @($m.Groups[1].Value, $m.Groups[2].Value)) {
            if ($g) { $n = [int]$g; if ($n -ge 1 -and $n -le 65535 -and -not $ports.Contains($n)) { $ports.Add($n) } }
        }
    }
    $sig['Ports'] = @($ports | Sort-Object | Select-Object -First 3)

    $tlds = @('com', 'net', 'org', 'io', 'co', 'ru', 'cn', 'biz', 'info', 'gov', 'mil', 'edu', 'xyz', 'top',
        'online', 'site', 'store', 'tech', 'me', 'tv', 'cc', 'us', 'uk', 'de', 'fr', 'jp', 'kr', 'au', 'ca',
        'nl', 'se', 'no', 'fi', 'dk', 'pl', 'cz', 'it', 'es', 'pt', 'ch', 'at', 'be', 'gr', 'tr', 'in', 'br',
        'mx', 'ar', 'za', 'nz', 'hk', 'sg', 'tw', 'th', 'my', 'id', 'ph', 'vn', 'ae', 'sa', 'il', 'eg', 'ma',
        'ng', 'ke', 'gh', 'ua', 'by', 'kz', 'uz', 'ir', 'pk', 'bd', 'lk', 'np', 'ro', 'hu', 'bg', 'hr', 'si',
        'sk', 'lt', 'lv', 'ee', 'is', 'ie', 'lu')
    $tldSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$tlds)
    $benign = @('.mitre.org', 'github.com', 'wikipedia.org', 'google.com', 'microsoft.com', 'example.com',
        'youtube.com', 'twitter.com', 'x.com', 'facebook.com', 'linkedin.com', 'medium.com', 'bit.ly', 'ow.ly',
        'tinyurl.com', 'goo.gl', 'reddit.com', 'arstechnica.com', 'securelist.com', 'blogspot.com', 'virustotal.com',
        'scholar.google.com')
    $domains = [System.Collections.Generic.List[string]]::new()
    foreach ($m in [regex]::Matches($t, '(?i)(?<![\w.@/])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(?![\w.])')) {
        $d = $m.Groups[1].Value.ToLowerInvariant() -replace '^www\.', ''
        $labels = $d -split '\.'
        $lastDot = $d.LastIndexOf('.')
        $tld = if ($lastDot -gt 0) { $d.Substring($lastDot + 1) } else { '' }
        if (-not $tldSet.Contains($tld) -or $labels[0].Length -lt 3 -or $d -in @('asp.net', 'vb.net', 'msdn.net')) { continue }
        if ($domains.Contains($d) -or ($benign | Where-Object { $d.EndsWith($_) })) { continue }
        $domains.Add($d)
    }
    $sig['Domains'] = @($domains | Select-Object -First 3)

    $regRe = '(?i)\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[A-Za-z0-9_\\.\-]{2,}'
    $sig['Registry'] = @([regex]::Matches($t, $regRe) | ForEach-Object { $_.Value.TrimEnd(' ', '\') } | Sort-Object -Unique | Select-Object -First 2)

    $sig['EventIds'] = @([regex]::Matches($t, '(?i)\bevent\s+id\s+(\d+)\b') | ForEach-Object { [int]$_.Groups[1].Value } | Sort-Object -Unique | Select-Object -First 3)

    return $sig
}

# Build a compact general query from the per-technique signals (heuristic).
function Get-KqlQuery {
    param($Signals)
    $clauses = [System.Collections.Generic.List[string]]::new()
    $procs    = @($Signals.Procs)
    $patterns = @($Signals.Patterns)
    $ports    = @($Signals.Ports)
    $domains  = @($Signals.Domains)
    $registry = @($Signals.Registry)
    $events   = @($Signals.EventIds)

    if ($procs.Count)    { $clauses.Add('process.name : (' + (($procs | ForEach-Object { "`"$_`"" }) -join ' or ') + ')') }
    if ($patterns.Count) { $clauses.Add('process.command_line : (' + (($patterns | ForEach-Object { "`"*$_*`"" }) -join ' or ') + ')') }
    if ($ports.Count)    { $clauses.Add('destination.port : (' + (($ports | ForEach-Object { "$_" }) -join ' or ') + ')') }
    if ($domains.Count)  { $clauses.Add('dns.question.name : (' + (($domains | ForEach-Object { "`"$_`"" }) -join ' or ') + ')') }
    if ($registry.Count) { $clauses.Add('registry.path : "' + ($registry[0] -replace '\\', '\\') + '"') }
    if ($events.Count)   { $clauses.Add('winlog.event_id : (' + (($events | ForEach-Object { "$_" }) -join ' or ') + ')') }

    $q = ($clauses -join ' or ')
    if ($q.Length -gt 240) { $q = $q.Substring(0, 240) + '…' }
    return $q
}

# Fallback ECS field derived from the technique's data components / tactic.
function Get-PrimaryField {
    param($Data, $Pattern)
    $comps = @()
    foreach ($ref in @(Get-Prop $Pattern 'x_mitre_data_components')) {
        $comp = Get-LookupValue -Data $Data -Key $ref
        if ($comp) { $comps += [string](Get-Prop $comp 'name') }
    }
    $map = @(
        @('command', 'process.command_line'), @('process', 'process.name'), @('powershell', 'process.name'),
        @('dns', 'dns.question.name'), @('network', 'network.transport'), @('registry', 'registry.path'),
        @('file', 'file.name'), @('application log', 'winlog.event_id'), @('windows', 'winlog.event_id')
    )
    foreach ($c in $comps) {
        $cl = $c.ToLowerInvariant()
        foreach ($m in $map) { if ($cl -like "*$($m[0])*") { return $m[1] } }
    }
    $tac = @(Get-Prop $Pattern 'kill_chain_phases' | ForEach-Object { Get-Prop $_ 'phase_name' })
    if ($tac -contains 'command-and-control' -or $tac -contains 'exfiltration') { return 'network.transport' }
    if ($tac -contains 'persistence' -or $tac -contains 'defense-impairment') { return 'registry.path' }
    if ($tac -contains 'stealth') { return 'file.name' }
    return 'process.name'
}

# Full "what to look for" package for one technique used by the group.
function Get-TechniqueDetail {
    param($Data, $Tech)
    $pat = $Tech.Pattern
    $tactics   = @(Get-Prop $pat 'kill_chain_phases' | ForEach-Object { ConvertTo-TitleCase (Get-Prop $_ 'phase_name') } | Where-Object { $_ })
    $platforms = @(Get-Prop $pat 'x_mitre_platforms' | Where-Object { $_ })
    $ds = @(Get-Prop $pat 'x_mitre_data_sources' | Where-Object { $_ })
    foreach ($ref in @(Get-Prop $pat 'x_mitre_data_components')) {
        $comp = Get-LookupValue -Data $Data -Key $ref
        if ($comp) { $ds += (Get-Prop $comp 'name') }
    }
    $ds = @($ds | Sort-Object -Unique)
    $detStrat = @(Get-DetectionStrategies -Data $Data -Pattern $pat)

    # Detection-focused signal text: strategies + description + what THIS group did.
    $sigText = New-Object System.Text.StringBuilder
    foreach ($s in $detStrat) { $null = $sigText.AppendLine([string]$s.Description) }
    $null = $sigText.AppendLine([string](Get-Prop $pat 'description'))
    $null = $sigText.AppendLine([string]$Tech.GroupDescription)
    $signals = Get-TechSignals -Text $sigText.ToString()

    $kql = Get-KqlQuery -Signals $signals
    if (-not $kql) {
        # No in-network signals: use a topical field query when a detection strategy
        # exists; otherwise mark as not-detectable (e.g. pre-intrusion TTPs).
        $kql = if ($detStrat.Count) { "$(Get-PrimaryField -Data $Data -Pattern $pat) : *" } else { '—' }
    }

    return [pscustomobject]@{
        Id                  = $Tech.Id
        Name                = Get-FullTechniqueName -Data $Data -Pattern $pat
        TacticPrimary       = if ($tactics.Count) { $tactics[0] } else { 'Other' }
        Tactic              = ($tactics -join ', ')
        Platforms           = ($platforms -join ', ')
        DataSources         = ($ds -join ', ')
        Description         = Get-Prop $pat 'description'
        ShortDesc           = Get-ShortDescriptor (Get-Prop $pat 'description')
        DetectionStrategies = $detStrat
        Signals             = $signals
        Kql                 = $kql
        Url                 = Get-MitreUrl $pat
        GroupUsage          = $Tech.GroupDescription
        ProcedureExamples   = @(Get-ProcedureExamples -Data $Data -Pattern $pat)
    }
}

# ---------------------------------------------------------------------------
# IOC extraction (heuristic regex over the text that is relevant to the group)
# ---------------------------------------------------------------------------
function Get-IocText {
    param($Prof, $Details)
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine([string](Get-Prop $Prof.Group 'description'))
    foreach ($d in $Details) {
        $null = $sb.AppendLine([string]$d.GroupUsage)
        foreach ($s in $d.DetectionStrategies) { $null = $sb.AppendLine([string]$s.Description) }
        foreach ($pe in $d.ProcedureExamples) { $null = $sb.AppendLine([string]$pe.Description) }
    }
    foreach ($s in $Prof.Software) {
        $null = $sb.AppendLine([string](Get-Prop $s.Object 'description'))
        $null = $sb.AppendLine([string]$s.Description)
    }
    return $sb.ToString()
}

function Get-Indicators {
    param([string]$Text)
    $iocs = [ordered]@{}
    $iocs['Processes'] = @()
    $iocs['Commands']  = @()
    $iocs['Registry']  = @()
    $iocs['FilePaths'] = @()
    $iocs['Domains']   = @()
    $iocs['Ports']     = @()
    if (-not $Text) { return $iocs }

    # Work from cleaned text so <code>/citation markup does not pollute matches.
    $clean = ConvertTo-CleanText $Text

    # --- Executables / process binaries (not path segments) ---
    $exeRe = '(?i)(?<![A-Za-z0-9_\\\.])\b[A-Za-z0-9_][A-Za-z0-9_.\-]*\.(?:exe|dll|ps1|bat|cmd|vbs|js|scr|msi|cpl|hta)\b'
    $iocs['Processes'] = @([regex]::Matches($clean, $exeRe) |
        ForEach-Object { $_.Value.ToLowerInvariant() } | Sort-Object -Unique)

    # --- Commands (known Windows/adversary command verbs + a few args) ---
    # Only keep verb+args that look command-like (flags, switches, paths, redirection)
    # and truncate prose tails (e.g. 'certutil -decode to decode contents').
    $verbs = 'reg|rundll32|powershell|pwsh|cmd|net|netsh|certutil|vssadmin|cipher|wevtutil|sc|schtasks|wmic|whoami|ipconfig|nltest|tasklist|taskkill|mshta|wscript|cscript|bitsadmin|curl|wget|regsvr32|forfiles|psexec|procdump|mimikatz|winexe'
    $cmdRe = "(?i)\b($verbs)(?:\.exe)?\b(?:(?:\s+\S+){1,5})?"
    $cmdText = [regex]::Replace($clean, '\[[^\]]+\]\([^)\s]+\)', '')
    $cmds = [System.Collections.Generic.List[string]]::new()
    foreach ($m in [regex]::Matches($cmdText, $cmdRe)) {
        $v = ($m.Value -replace '\s+', ' ').Trim()
        $v = $v -replace '[.,;:>"]+$', ''
        # cut at the first prose stopword after the command itself
        $v = [regex]::Replace($v, '\s+(?:to|and|with|for|that|via|using|use|of|the|an|a|in|on|from|which|can|may|also|have|has|had|be|is|are|was|were|not|its|their|it|as|by|such|like)\b.*$', '')
        # command-signal filter: flags/switches/backslash/=,<>/%var%/.exe or a bare verb
        $signal = ($v -match '(?i)(^|\s)-{1,2}\S') -or ($v -match '(?i)(^|\s)/\S') -or ($v -match '\\') -or `
            ($v -match '=') -or ($v -match '[<>]') -or ($v -match '(?i)%\w+%') -or `
            ($v -match '(?i)\b\w+\.(?:exe|dll|ps1|bat|cmd|vbs|js|com|msi)\b') -or ($v -notmatch '\s')
        if ($signal -and $v.Length -ge 3 -and $v.Length -le 120) { $cmds.Add($v) }
    }
    $iocs['Commands'] = @($cmds | Sort-Object -Unique)

    # --- Registry paths (no spaces in segment class -> avoids grabbing prose) ---
    $regRe = '(?i)\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[A-Za-z0-9_\\.\-]{2,}'
    $iocs['Registry'] = @([regex]::Matches($clean, $regRe) |
        ForEach-Object { $_.Value.TrimEnd(' ', '\') } | Sort-Object -Unique)

    # --- File paths ---
    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($m in [regex]::Matches($clean, '(?i)\b[A-Za-z]:\\[^\s"<>|`;\r\n]{1,120}\b')) { $paths.Add($m.Value) }
    foreach ($m in [regex]::Matches($clean, '(?i)%\w+%\\[^\s"<>|`;\r\n]{1,120}\b')) { $paths.Add($m.Value) }
    $iocs['FilePaths'] = @($paths | Sort-Object -Unique)

    # --- Domains / FQDNs (TLD whitelist; strip markdown-link URLs first) ---
    $tlds = @('com', 'net', 'org', 'io', 'co', 'ru', 'cn', 'biz', 'info', 'gov', 'mil', 'edu', 'xyz', 'top',
        'online', 'site', 'store', 'tech', 'me', 'tv', 'cc', 'us', 'uk', 'de', 'fr', 'jp', 'kr', 'au', 'ca',
        'nl', 'se', 'no', 'fi', 'dk', 'pl', 'cz', 'it', 'es', 'pt', 'ch', 'at', 'be', 'gr', 'tr', 'in', 'br',
        'mx', 'ar', 'za', 'nz', 'hk', 'sg', 'tw', 'th', 'my', 'id', 'ph', 'vn', 'ae', 'sa', 'il', 'eg', 'ma',
        'ng', 'ke', 'gh', 'ua', 'by', 'kz', 'uz', 'ir', 'pk', 'bd', 'lk', 'np', 'ro', 'hu', 'bg', 'hr', 'si',
        'sk', 'lt', 'lv', 'ee', 'is', 'ie', 'lu')
    $tldSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$tlds)
    $benign = @('.mitre.org', 'github.com', 'wikipedia.org', 'google.com', 'microsoft.com', 'example.com',
        'youtube.com', 'twitter.com', 'x.com', 'facebook.com', 'linkedin.com', 'medium.com', 'bit.ly', 'ow.ly',
        'tinyurl.com', 'goo.gl', 'reddit.com', 'arstechnica.com', 'securelist.com', 'blogspot.com', 'virustotal.com',
        'scholar.google.com')
    $stripLinks = [regex]::Replace($clean, '\]\(https?://[^)\s]+\)', ']')
    $domainRe = '(?i)(?<![\w.@/])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(?![\w.])'
    $domains = [System.Collections.Generic.List[string]]::new()
    foreach ($m in [regex]::Matches($stripLinks, $domainRe)) {
        $d = $m.Groups[1].Value.ToLowerInvariant()
        $d = $d -replace '^www\.', ''
        $labels = $d -split '\.'
        $lastDot = $d.LastIndexOf('.')
        $tld = if ($lastDot -gt 0) { $d.Substring($lastDot + 1) } else { '' }
        if (-not $tldSet.Contains($tld)) { continue }
        if ($labels[0].Length -lt 3 -or $d -in @('asp.net', 'vb.net', 'msdn.net')) { continue }
        if ($domains.Contains($d) -or ($benign | Where-Object { $d.EndsWith($_) })) { continue }
        $domains.Add($d)
    }
    $iocs['Domains'] = @($domains | Sort-Object)

    # --- Ports ---
    $ports = [System.Collections.Generic.List[int]]::new()
    foreach ($m in [regex]::Matches($clean, '(?i)\bport\s+(?:number\s+)?(\d{1,5})\b|\b(\d{1,5})\s*/\s*(?:tcp|udp)\b')) {
        foreach ($g in @($m.Groups[1].Value, $m.Groups[2].Value)) {
            if ($g) {
                $n = [int]$g
                if ($n -ge 1 -and $n -le 65535 -and -not $ports.Contains($n)) { $ports.Add($n) }
            }
        }
    }
    $iocs['Ports'] = @($ports | Sort-Object)

    return $iocs
}

# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------
function New-MarkdownReport {
    param($Prof, $Details, $Iocs)
    $g       = $Prof.Group
    $gName   = Get-Prop $g 'name'
    $gCode   = Get-GroupCode $g
    $aliases = @(Get-Aliases $g)
    $version = Get-Prop $g 'x_mitre_version'
    $gDesc   = ConvertTo-CleanText ([string](Get-Prop $g 'description'))

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine("# $gName ($gCode) — MITRE ATT&CK Cheat Sheet")
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine("> **Group:** $gName | **ID:** $gCode | **Aliases:** $($aliases -join ', ') | **Version:** $version")
    $null = $sb.AppendLine("> **Source:** $GroupBaseUrl$gCode  •  Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
    $null = $sb.AppendLine("> 💡 KQL queries are auto-generated from MITRE detection strategies (heuristic, ECS fields). '—' = no in-network detection signal.")
    $null = $sb.AppendLine('')
    if ($gDesc) {
        $gShort = if ($gDesc.Length -gt 240) { $gDesc.Substring(0, 240) + '…' } else { $gDesc }
        $null = $sb.AppendLine($gShort)
        $null = $sb.AppendLine('')
    }

    # --- TTPs grouped by tactic (compact: ID + topic + look-for chips + KQL) ---
    $tacticOrder = @('Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence',
        'Privilege Escalation', 'Defense Impairment', 'Stealth', 'Credential Access', 'Discovery', 'Lateral Movement',
        'Collection', 'Command and Control', 'Exfiltration', 'Impact')
    $primaries = @($Details | ForEach-Object { $_.TacticPrimary } | Sort-Object -Unique)
    foreach ($tactic in $tacticOrder) {
        if ($tactic -notin $primaries) { continue }
        $tds = @($Details | Where-Object { $_.TacticPrimary -eq $tactic } | Sort-Object Id)
        $null = $sb.AppendLine("## $tactic ($($tds.Count))")
        $null = $sb.AppendLine('')
        $null = $sb.AppendLine('| TTP | Topic | General Query |')
        $null = $sb.AppendLine('|---|---|---|')
        foreach ($d in $tds) {
            $null = $sb.AppendLine("| [$($d.Id)]($($d.Url)) $($d.Name) | $($d.ShortDesc -replace '\|', '\|') | ``$($d.Kql -replace '\|', '\|')`` |")
        }
        $null = $sb.AppendLine('')
    }
    $other = @($Details | Where-Object { $_.TacticPrimary -notin $tacticOrder } | Sort-Object Id)
    if ($other.Count) {
        $null = $sb.AppendLine("## Other ($($other.Count))")
        $null = $sb.AppendLine('')
        $null = $sb.AppendLine('| TTP | Topic | General Query |')
        $null = $sb.AppendLine('|---|---|---|')
        foreach ($d in $other) {
            $null = $sb.AppendLine("| [$($d.Id)]($($d.Url)) $($d.Name) | $($d.ShortDesc -replace '\|', '\|') | ``$($d.Kql -replace '\|', '\|')`` |")
        }
        $null = $sb.AppendLine('')
    }

    # --- Software used ---
    $null = $sb.AppendLine("## Software Used ($($Prof.Software.Count))")
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('| ID | Name | Type | Notes |')
    $null = $sb.AppendLine('|---|---|---|---|')
    foreach ($s in $Prof.Software) {
        $note = ConvertTo-CleanText $s.Description
        if (-not $note) { $note = ConvertTo-CleanText ([string](Get-Prop $s.Object 'description')) }
        if (-not $note) { $note = '' }
        $note = ($note -replace '\r?\n', ' ' -replace '\|', '/')
        if ($note.Length -gt 200) { $note = $note.Substring(0, 200) + '…' }
        $null = $sb.AppendLine("| [$($s.Id)](https://attack.mitre.org/software/$($s.Id)) | $($s.Name) | $($s.Type) | $note |")
    }
    $null = $sb.AppendLine('')

    # --- Campaigns ---
    if ($Prof.Campaigns.Count) {
        $null = $sb.AppendLine("## Campaigns ($($Prof.Campaigns.Count))")
        $null = $sb.AppendLine('')
        $null = $sb.AppendLine('| ID | Name | Description |')
        $null = $sb.AppendLine('|---|---|---|')
        foreach ($c in $Prof.Campaigns) {
            $cd = ConvertTo-CleanText ([string]$c.Description)
            $cd = ($cd -replace '\r?\n', ' ' -replace '\|', '/')
            $null = $sb.AppendLine("| [$($c.Id)](https://attack.mitre.org/campaigns/$($c.Id)) | $($c.Name) | $cd |")
        }
        $null = $sb.AppendLine('')
    }

    # --- IOCs ---
    $null = $sb.AppendLine('## IOCs (auto-extracted — heuristic)')
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('> ⚠ These were pulled from MITRE detection/procedure text by regex. MITRE publishes')
    $null = $sb.AppendLine('> *behavioral* IOCs only (no hashes/IPs). Review and enrich before operational use.')
    $null = $sb.AppendLine('')
    foreach ($cat in @('Processes', 'Commands', 'Registry', 'FilePaths', 'Domains', 'Ports')) {
        $items = @($Iocs[$cat])
        $null = $sb.AppendLine("### $cat ($($items.Count))")
        if ($items.Count) {
            $null = $sb.AppendLine('')
            foreach ($it in $items) { $null = $sb.AppendLine("- ``$it``") }
        } else {
            $null = $sb.AppendLine('')
            $null = $sb.AppendLine('_none extracted_')
        }
        $null = $sb.AppendLine('')
    }

    return $sb.ToString()
}

# ---------------------------------------------------------------------------
# HTML report (self-contained styles.css: base + mitre overrides)
# ---------------------------------------------------------------------------
function ConvertTo-HtmlText {
    param([string]$Text)
    if (-not $Text) { return '' }
    $t = [System.Net.WebUtility]::HtmlEncode((ConvertTo-CleanText $Text))
    $t = [regex]::Replace($t, '`([^`\r\n]+)`', '<code>$1</code>')
    $t = [regex]::Replace($t, '\[([^\]]+)\]\(([^)\s]+)\)', '<a href="$2">$1</a>')
    $t = [regex]::Replace($t, '\r?\n', '<br/>')
    return $t
}

function New-TopicSection {
    param([int]$Num, [string]$Title, [string]$Theme, [string]$Body)
    $head = '        <section class="topic span-full" data-theme="' + $Theme + '">'
    $head += "`n          <div class=""topic-header""><h2>$Title</h2><span class=""topic-tag"">$Num</span></div>"
    $head += "`n" + $Body + "`n        </section>"
    return $head
}

function New-HtmlReport {
    param($Prof, $Details, $Iocs)
    $g       = $Prof.Group
    $gName   = Get-Prop $g 'name'
    $gCode   = Get-GroupCode $g
    $aliases = @(Get-Aliases $g)
    $version = Get-Prop $g 'x_mitre_version'
    $gDesc   = ConvertTo-CleanText ([string](Get-Prop $g 'description'))
    $short   = if ($gDesc.Length -gt 320) { $gDesc.Substring(0, 320) + '…' } else { $gDesc }

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('<!DOCTYPE html>')
    $null = $sb.AppendLine('<html lang="en">')
    $null = $sb.AppendLine('  <head>')
    $null = $sb.AppendLine('    <meta charset="UTF-8" />')
    $null = $sb.AppendLine('    <meta name="viewport" content="width=device-width, initial-scale=1.0" />')
    $null = $sb.AppendLine("    <title>MITRE ATT&amp;CK: $([System.Net.WebUtility]::HtmlEncode($gName)) ($gCode) — TTP &amp; IOC Cheat Sheet</title>")
    $null = $sb.AppendLine('    <link rel="stylesheet" href="styles.css" />')
    $null = $sb.AppendLine('  </head>')
    $null = $sb.AppendLine('  <body class="mitre">')
    $null = $sb.AppendLine('    <div class="shell">')

    # ---- Hero ----
    $null = $sb.AppendLine('      <header class="hero">')
    $null = $sb.AppendLine('        <div class="hero-inner">')
    $null = $sb.AppendLine('          <span class="eyebrow">Kevin C. Jones - 4n6post.com</span>')
    $null = $sb.AppendLine("          <h1>MITRE ATT&amp;CK: $([System.Net.WebUtility]::HtmlEncode($gName)) ($gCode)</h1>")
    $null = $sb.AppendLine("          <p class=""subtitle"">$(ConvertTo-HtmlText $short)</p>")
    $null = $sb.AppendLine('          <div class="badges">')
    $null = $sb.AppendLine("            <span class=""badge"">Aliases: $([System.Net.WebUtility]::HtmlEncode($aliases -join ', '))</span>")
    $null = $sb.AppendLine("            <span class=""badge"">$($Prof.Techniques.Count) techniques</span>")
    $null = $sb.AppendLine("            <span class=""badge"">$($Prof.Software.Count) software</span>")
    $null = $sb.AppendLine("            <span class=""badge"">$($Prof.Campaigns.Count) campaigns</span>")
    $null = $sb.AppendLine("            <span class=""badge"">ATT&amp;CK v$version</span>")
    $null = $sb.AppendLine("            <span class=""badge"">$(Get-Date -Format 'yyyy-MM-dd HH:mm')</span>")
    $null = $sb.AppendLine('          </div>')
    $null = $sb.AppendLine('        </div>')
    $null = $sb.AppendLine('      </header>')
    $null = $sb.AppendLine('      <main class="grid">')

    # ---- 1. Group summary ----
    $metaRows = @(
        "<tr><td>ID</td><td>$gCode</td></tr>",
        "<tr><td>Aliases</td><td>$(ConvertTo-HtmlText ($aliases -join ', '))</td></tr>",
        "<tr><td>Version</td><td>$version</td></tr>",
        "<tr><td>Source</td><td><a href=`"$GroupBaseUrl$gCode`">$GroupBaseUrl$gCode</a></td></tr>"
    )
    $body1 = "          <p class=""mini"">$(ConvertTo-HtmlText $gDesc)</p>`n          <p class=""mini"">💡 KQL queries are auto-generated from MITRE detection strategies (heuristic, ECS fields). '—' = no in-network detection signal.</p>`n          <div class=""table-wrap""><table><tbody>$(($metaRows -join "`n"))</tbody></table></div>"
    $null = $sb.AppendLine((New-TopicSection -Num 1 -Title 'Group Summary' -Theme 'slate' -Body $body1))

    # ---- 2+ TTPs grouped by tactic ----
    $tacticOrder = @('Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence',
        'Privilege Escalation', 'Defense Impairment', 'Stealth', 'Credential Access', 'Discovery', 'Lateral Movement',
        'Collection', 'Command and Control', 'Exfiltration', 'Impact')
    $primaries = @($Details | ForEach-Object { $_.TacticPrimary } | Sort-Object -Unique)
    $themes = @('blue', 'green', 'amber', 'rose', 'violet', 'cyan', 'red')
    $topicNum = 2
    $ti = 0
    foreach ($tactic in $tacticOrder) {
        if ($tactic -notin $primaries) { continue }
        $tds = @($Details | Where-Object { $_.TacticPrimary -eq $tactic } | Sort-Object Id)
        $rows = New-Object System.Collections.Generic.List[string]
        foreach ($d in $tds) {
            $rows.Add("<tr><td><a href=`"$($d.Url)`">$($d.Id)</a><br/><span class=""mini"">$(ConvertTo-HtmlText $d.Name)</span></td><td>$(ConvertTo-HtmlText $d.ShortDesc)</td><td><code class=""kql"">$([System.Net.WebUtility]::HtmlEncode($d.Kql))</code></td></tr>")
        }
        $body = '          <div class="table-wrap"><table class="ttp-table"><thead><tr><th>TTP</th><th>Topic</th><th>General Query</th></tr></thead><tbody>' + ($rows -join "`n") + '</tbody></table></div>'
        $null = $sb.AppendLine((New-TopicSection -Num $topicNum -Title "$tactic ($($tds.Count))" -Theme $themes[$ti % $themes.Count] -Body $body))
        $topicNum++; $ti++
    }
    $other = @($Details | Where-Object { $_.TacticPrimary -notin $tacticOrder } | Sort-Object Id)
    if ($other.Count) {
        $rows = New-Object System.Collections.Generic.List[string]
        foreach ($d in $other) {
            $rows.Add("<tr><td><a href=`"$($d.Url)`">$($d.Id)</a><br/><span class=""mini"">$(ConvertTo-HtmlText $d.Name)</span></td><td>$(ConvertTo-HtmlText $d.ShortDesc)</td><td><code class=""kql"">$([System.Net.WebUtility]::HtmlEncode($d.Kql))</code></td></tr>")
        }
        $body = '          <div class="table-wrap"><table class="ttp-table"><thead><tr><th>TTP</th><th>Topic</th><th>General Query</th></tr></thead><tbody>' + ($rows -join "`n") + '</tbody></table></div>'
        $null = $sb.AppendLine((New-TopicSection -Num $topicNum -Title "Other ($($other.Count))" -Theme 'slate' -Body $body))
        $topicNum++
    }

    # ---- Software used ----
    $rows = New-Object System.Collections.Generic.List[string]
    foreach ($s in $Prof.Software) {
        $note = ConvertTo-CleanText $s.Description
        if (-not $note) { $note = ConvertTo-CleanText ([string](Get-Prop $s.Object 'description')) }
        if (-not $note) { $note = '' }
        if ($note.Length -gt 240) { $note = $note.Substring(0, 240) + '…' }
        $rows.Add("<tr><td><a href=`"https://attack.mitre.org/software/$($s.Id)`">$($s.Id)</a></td><td>$(ConvertTo-HtmlText $s.Name)</td><td>$($s.Type)</td><td>$(ConvertTo-HtmlText $note)</td></tr>")
    }
    $bodyS = '          <div class="table-wrap"><table><thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Notes</th></tr></thead><tbody>' + ($rows -join "`n") + '</tbody></table></div>'
    $null = $sb.AppendLine((New-TopicSection -Num $topicNum -Title "Software Used ($($Prof.Software.Count))" -Theme 'green' -Body $bodyS))
    $topicNum++

    # ---- Campaigns ----
    if ($Prof.Campaigns.Count) {
        $rows = New-Object System.Collections.Generic.List[string]
        foreach ($c in $Prof.Campaigns) {
            $rows.Add("<tr><td><a href=`"https://attack.mitre.org/campaigns/$($c.Id)`">$($c.Id)</a></td><td>$(ConvertTo-HtmlText $c.Name)</td><td>$(ConvertTo-HtmlText ([string]$c.Description))</td></tr>")
        }
        $bodyC = '          <div class="table-wrap"><table><thead><tr><th>ID</th><th>Name</th><th>Description</th></tr></thead><tbody>' + ($rows -join "`n") + '</tbody></table></div>'
        $null = $sb.AppendLine((New-TopicSection -Num $topicNum -Title "Campaigns ($($Prof.Campaigns.Count))" -Theme 'amber' -Body $bodyC))
        $topicNum++
    }

    # ---- IOCs ----
    $rows = New-Object System.Collections.Generic.List[string]
    foreach ($cat in @('Processes', 'Commands', 'Registry', 'FilePaths', 'Domains', 'Ports')) {
        $items = @($Iocs[$cat])
        $html  = if ($items.Count) { (($items | ForEach-Object { "<code>$([System.Net.WebUtility]::HtmlEncode([string]$_))</code>" }) -join '<br/>') } else { '<span class="mini">none extracted</span>' }
        $rows.Add("<tr><td>$cat</td><td>$html</td></tr>")
    }
    $bodyI = '          <p class="mini">⚠ Auto-extracted from MITRE detection/procedure text via regex. MITRE publishes behavioral IOCs only (no hashes/IPs) — review and enrich before operational use.</p>' +
             '          <div class="table-wrap"><table><thead><tr><th>Category</th><th>Indicators</th></tr></thead><tbody>' + ($rows -join "`n") + '</tbody></table></div>'
    $null = $sb.AppendLine((New-TopicSection -Num $topicNum -Title 'IOCs (auto-extracted)' -Theme 'violet' -Body $bodyI))

    $null = $sb.AppendLine('      </main>')
    $null = $sb.AppendLine('    </div>')
    $null = $sb.AppendLine('  </body>')
    $null = $sb.AppendLine('</html>')
    return $sb.ToString()
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'

try {
    $Data = Get-AttackData
} catch {
    Write-Host "ERROR: $_" -ForegroundColor Red
    exit 1
}

$groupList = @($Data.Groups | Sort-Object { Get-Prop $_ 'name' })
if ($groupList.Count -eq 0) {
    Write-Host 'No groups found in the ATT&CK data.' -ForegroundColor Yellow
    exit 1
}

# Select groups (non-interactive -All/-Group, or interactive menu).
$selected = @()
if ($All) {
    $selected = @($groupList)
    Write-Status "Parsing ALL $($selected.Count) groups..." -ForegroundColor Cyan
    Write-Status 'This writes a Markdown + HTML report per group and may take a few minutes.' -ForegroundColor DarkGray
} elseif ($PSBoundParameters.ContainsKey('Group')) {
    foreach ($g in $Group) {
        foreach ($part in (($g -split ',' | ForEach-Object { $_.Trim() }) | Where-Object { $_ })) {
            $m = $groupList | Where-Object { (Get-Prop $_ 'name') -ieq $part -or (Get-GroupCode $_) -ieq $part } | Select-Object -First 1
            if ($m) { $selected += $m } else { Write-Warning "Group '$part' not found." }
        }
    }
    if ($selected.Count -eq 0) {
        Write-Host 'No matching groups selected.' -ForegroundColor Yellow
        exit 1
    }
} else {
    $selected = Show-GroupMenu -Groups $groupList
    if ($selected.Count -eq 0) {
        Write-Host 'No selection made. Exiting.' -ForegroundColor Yellow
        exit 0
    }
}

$outDir = if ($OutputDir) { $OutputDir } else { $ScriptRoot }
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$mdDir = Join-Path $outDir 'markdown'
if (-not (Test-Path $mdDir)) { New-Item -ItemType Directory -Path $mdDir -Force | Out-Null }
$htmlDir = Join-Path $outDir 'html'
if (-not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }

foreach ($g in $selected) {
    $gName = Get-Prop $g 'name'
    Write-Status "Building profile: $gName ($(Get-GroupCode $g))..." -ForegroundColor Green

    $prof = Get-GroupProfile -Data $Data -Group $g
    $details = @($prof.Techniques | ForEach-Object { Get-TechniqueDetail -Data $Data -Tech $_ })
    $iocs    = Get-Indicators -Text (Get-IocText -Prof $prof -Details $details)
    $fileSafe = ConvertTo-FileSafeName $gName

    if (-not $NoMarkdown) {
        $mdPath = Join-Path $mdDir ("MITRE-$fileSafe.md")
        Set-Content -Path $mdPath -Value (New-MarkdownReport -Prof $prof -Details $details -Iocs $iocs) -Encoding UTF8
        Write-Status "  Markdown -> $mdPath" -ForegroundColor DarkGray
    }
    if (-not $NoHtml) {
        $htmlPath = Join-Path $htmlDir ("MITRE-$fileSafe.html")
        Set-Content -Path $htmlPath -Value (New-HtmlReport -Prof $prof -Details $details -Iocs $iocs) -Encoding UTF8
        Write-Status "  HTML     -> $htmlPath" -ForegroundColor DarkGray
    }

    Write-Status "  Done: $($prof.Techniques.Count) techniques, $($prof.Software.Count) software, $($prof.Campaigns.Count) campaigns." -ForegroundColor DarkGray
}

Write-Host 'All reports generated.' -ForegroundColor Green
