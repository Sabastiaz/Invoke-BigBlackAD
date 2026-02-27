#Requires -Version 3.0
<#
.SYNOPSIS
Advanced Active Directory Enumeration and Security Assessment Tool

.DESCRIPTION
Comprehensive AD enumeration tool with BloodHound integration, Kerberos attacks, 
share enumeration, and domain analysis capabilities.

.EXAMPLE
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/ChickenLoner/Invoke-BigBlackAD/main/Invoke-BigBlackAD.ps1')
Invoke-BigBlackAD -FullEnumeration

.NOTES
Author : Sabastiaz and Chick
Version : 9.0
#>

# -------------------
# Internal Toolkit Helpers (no network auto-fetch)
# -------------------
function Import-BBOptionalScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ScriptPath,
        [Parameter(Mandatory=$true)][string]$ProbeCommand,
        [switch]$Quiet
    )

    if (Get-Command $ProbeCommand -ErrorAction SilentlyContinue) { return $true }

    if (!(Test-Path -LiteralPath $ScriptPath)) {
        if (-not $Quiet) { Write-Host "[!] Optional tool not found at: $ScriptPath" -ForegroundColor Yellow }
        return $false
    }

    try {
        . $ScriptPath
        if (Get-Command $ProbeCommand -ErrorAction SilentlyContinue) {
            if (-not $Quiet) { Write-Host "[+] Loaded optional tool: $ScriptPath" -ForegroundColor Green }
            return $true
        }
        if (-not $Quiet) { Write-Host "[-] Loaded script but probe command not found: $ProbeCommand" -ForegroundColor Red }
        return $false
    }
    catch {
        if (-not $Quiet) { Write-Host "[-] Failed to load optional tool: $_" -ForegroundColor Red }
        return $false
    }
}

function Import-BBPowerView {
    [CmdletBinding()]
    param(
        [string]$ToolsPath = (Join-Path $PSScriptRoot "Tools"),
        [switch]$Quiet
    )

    # NOTE: Load only a *local, vetted* copy placed by the operator.
    # No auto-download to avoid noisy / unsafe behavior in enterprise environments.
    $pv = Join-Path $ToolsPath "PowerView.ps1"
    return (Import-BBOptionalScript -ScriptPath $pv -ProbeCommand "Get-DomainUser" -Quiet:$Quiet)
}

function Invoke-BigBlackAD {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$FullEnumeration,
        
        [Parameter(Mandatory=$false)]
        [string]$DomainController,
        
        [Parameter(Mandatory=$false)]
        [pscredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = ".\AD_Enum_Results",

        [Parameter(Mandatory=$false)]
        [ValidateSet('Lab','Audit')]
        [string]$Mode = 'Audit',

        [Parameter(Mandatory=$false)]
        [switch]$EnableOptionalTools,

        [Parameter(Mandatory=$false)]
        [string]$ToolsPath = (Join-Path $PSScriptRoot 'Tools')
        
    )
    # Optional third-party tooling (Lab only / explicitly enabled)
    if (($Mode -eq 'Lab') -or $EnableOptionalTools) {
        Import-BBPowerView -ToolsPath $ToolsPath -Quiet
    }

    # Banner and Initialization
    $Banner = @"
  ____  _         ____  _            _    
 | __ )(_) __ _  | __ )| | __ _  ___| | __
 |  _ \| |/ _' | |  _ \| |/ _' |/ __| |/ /
 | |_) | | (_| | | |_) | | (_| | (__|   < 
 |____/|_|\__, | |____/|_|\__,_|\___|_|\_\
           |___/                           
                    >> A D  W H I S P E R E R <<
"@

    Write-Host $Banner -ForegroundColor Cyan
    Write-Host "[*] Initializing Advanced AD Enumeration Toolkit..." -ForegroundColor Yellow
    Start-Sleep -Seconds 1

    # Create output directory
    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Host "[+] Created output directory: $OutputPath" -ForegroundColor Green
    }

    # Function: Check AD Module
    function Test-ADModule {
        Write-Host "[*] Checking Active Directory Module..." -ForegroundColor Yellow
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Write-Host "[+] Active Directory Module loaded successfully" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "[-] Active Directory Module not available" -ForegroundColor Red
            Write-Host "[*] Attempting to import from RSAT..." -ForegroundColor Yellow
            try {
                Import-Module "C:\Program Files\RSAT\ActiveDirectory\Microsoft.ActiveDirectory.Management.dll" -ErrorAction Stop
                return $true
            }
            catch {
                Write-Host "[-] Using alternative enumeration methods" -ForegroundColor Yellow
                return $false
            }
        }
    }

    # Function: Enumerate Domain Information
    function Get-DomainInfo {
        Write-Host "[*] Enumerating Domain Information..." -ForegroundColor Yellow
        $domainInfo = @{}
        
        try {
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $domainInfo['DomainName'] = $domain.Name
            $domainInfo['DomainMode'] = $domain.DomainMode
            $domainInfo['ForestName'] = $domain.Forest.Name
            $domainInfo['ForestMode'] = $domain.Forest.ForestMode
            $domainInfo['PDC'] = $domain.PdcRoleOwner.Name
            $domainInfo['SchemaMaster'] = $domain.SchemaRoleOwner.Name
            $domainInfo['DomainControllers'] = $domain.DomainControllers | ForEach-Object {$_.Name}
            
            Write-Host "[+] Domain: $($domain.Name)" -ForegroundColor Green
            Write-Host "[+] Forest: $($domain.Forest.Name)" -ForegroundColor Green
            Write-Host "[+] Domain Controllers: $($domain.DomainControllers.Count)" -ForegroundColor Green
            
            $domainInfo | Export-Clixml "$OutputPath\DomainInfo.xml"
        }
        catch {
            Write-Host "[-] Error enumerating domain: $_" -ForegroundColor Red
        }
        
        return $domainInfo
    }

    Function Get-BloodHoundData {

        [CmdletBinding()]
        Param (
            #[Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
            [Parameter(Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [String]
            $Domain,

            [Parameter(Mandatory = $false)]
            [ValidateNotNullOrEmpty()]
            [String]
            $Server,

            [Parameter(Mandatory = $false)]
            [Switch]
            $OPSEC,

            [Parameter(Mandatory = $false)]
            [Switch]
            $SSL,

            [Parameter(Mandatory = $false)]
            [Switch]
            $BloodHoundLegacy,

            [Parameter(Mandatory = $false,HelpMessage="Switch SharpHound enumeration mode, e.g. ALL")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("Default", "All", "DCOnly")]
            [String[]]
            $Scope = [string[]] @('DCOnly')
        )

        <# +++++ Starting BloodHound Enumeration +++++ #>
        $ErrorActionPreference = "Continue"
        Invoke-Logger -Class Info -Value "Searching for Detailed Active Directory Information with BloodHound"
        
        # Building searcher arguments for the following PowerView requests
        $SearcherArguments = @{}
        
        $SearcherArguments['Collectionmethods'] = $Scope
        Write-Verbose "[Get-BloodHoundData] Using Collectionmethod '$Scope' for SharpHound Ingestor"

        if ($PSBoundParameters['Domain']) {
            $SearcherArguments['Domain'] = $Domain
            Write-Verbose "[Get-BloodHoundData] Using '$Domain' as target Active Directory domain"
        }
        if ($PSBoundParameters['Server']) {
            $SearcherArguments['DomainController'] = $Server
            Write-Verbose "[Get-BloodHoundData] Using '$Server' as target domain controller"
        }
        if ($PSBoundParameters['SSL']) {
            if ($PSBoundParameters['BloodHoundLegacy']){
                $SearcherArguments['SecureLdap'] = $True
            } else {
                $SearcherArguments['ForceSecureLdap'] = $True
            }
            Write-Verbose "[Get-BloodHoundData] Using LDAPS over port 636"
        }
        if ($PSBoundParameters['BloodHoundLegacy']) {
            $SearcherArguments['BloodHoundLegacy'] = $True
            Write-Verbose "[Get-BloodHoundData] Using SharpHound Ingestor for BloodHound-Legacy"
        }

        try {
            if ($PSBoundParameters['OPSEC']) {
                Invoke-Logger -Class Note -Value "Due to OPSEC reasons no SharpHound collector started"
            } else {
                Invoke-Bloodhound @SearcherArguments -OutputPrefix $Domain -OutputDirectory ($pwd).path
            }
        }
        catch {
            Write-Warning "[Get-BloodHoundData] Error starting SharpHound collector: $_"
        }
    }


    # Function: Enumerate Users
    function Get-UserEnum {
        Write-Host "[`n[*] Enumerating Domain Users..." -ForegroundColor Yellow
        
        try {
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.PageSize = 1000
            $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
            $searcher.PropertiesToLoad.AddRange(@("samaccountname", "mail", "userprincipalname", "badpwdcount", "lockouttime", "lastlogon", "pwdlastset", "accountexpires", "useraccountcontrol"))
            
            $users = $searcher.FindAll()
            Write-Host "[+] Total Users Found: $($users.Count)" -ForegroundColor Green
            
            $userReport = @()
            $interestingUsers = @()
            
            foreach ($user in $users) {
                $props = $user.Properties
                $uac = [int]$props.useraccountcontrol[0]
                
                $userObj = [PSCustomObject]@{
                    Username = $props.samaccountname -join ', '
                    UPN = $props.userprincipalname -join ', '
                    UACValue = $uac
                }
                $userReport += $userObj
                
                # Check for interesting user accounts
                if ($uac -band 0x2) { # Account disabled
                    if ($props.samaccountname -notmatch '\$') {
                        $interestingUsers += "[!] Disabled Account: $($props.samaccountname)"
                    }
                }
                if ($uac -band 0x10) { # Lockout
                    $interestingUsers += "[!] Locked Account: $($props.samaccountname)"
                }
                if ($uac -band 0x40) { # Password not required
                    $interestingUsers += "[!] Password NOT Required: $($props.samaccountname)"
                }
                if ($uac -band 0x80) { # Cannot change password
                    $interestingUsers += "[!] Cannot Change Password: $($props.samaccountname)"
                }
                if ($uac -band 0x10000) { # Password never expires
                    $interestingUsers += "[!] Password Never Expires: $($props.samaccountname)"
                }
            }
            
            $userReport | Export-Csv "$OutputPath\UserEnumeration.csv" -NoTypeInformation
            
            Write-Host "[`n[*] Interesting User Findings:" -ForegroundColor Yellow
            $interestingUsers | ForEach-Object { Write-Host $_ -ForegroundColor Magenta }
        }
        catch {
            Write-Host "[-] Error enumerating users: $_" -ForegroundColor Red
        }
    }

    # Function: AS-REP Roasting
    function Get-ASREPRoast {
        Write-Host "[`n[*] Checking for AS-REP Roastable Users..." -ForegroundColor Yellow
        
        try {
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.PageSize = 1000
            $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
            $searcher.PropertiesToLoad.AddRange(@("samaccountname", "distinguishedname"))
            
            $asrepUsers = $searcher.FindAll()
            
            if ($asrepUsers.Count -gt 0) {
                Write-Host "[!] Found $($asrepUsers.Count) AS-REP Roastable Users:" -ForegroundColor Red
                foreach ($user in $asrepUsers) {
                    Write-Host "    [-] $($user.Properties.samaccountname)" -ForegroundColor Yellow
                }
                
                $asrepUsers | ForEach-Object { $_.Properties.samaccountname } | 
                    Export-Csv "$OutputPath\ASREP_Roastable_Users.csv" -NoTypeInformation
            } else {
                Write-Host "[+] No AS-REP Roastable users found" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "[-] Error checking AS-REP roast: $_" -ForegroundColor Red
        }
    }

    # Function: Kerberoasting
    function Get-Kerberoastable {
        Write-Host "[`n[*] Checking for Kerberoastable Accounts..." -ForegroundColor Yellow
        
        try {
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.PageSize = 1000
            $searcher.Filter = "(&(objectCategory=user)(servicePrincipalName=*))"
            $searcher.PropertiesToLoad.AddRange(@("samaccountname", "serviceprincipalname"))
            
            $kerberoastUsers = $searcher.FindAll()
            
            if ($kerberoastUsers.Count -gt 0) {
                Write-Host "[!] Found $($kerberoastUsers.Count) Kerberoastable Accounts:" -ForegroundColor Red
                foreach ($user in $kerberoastUsers) {
                    Write-Host "    [-] $($user.Properties.samaccountname)" -ForegroundColor Yellow
                    Write-Host "        SPNs: $($user.Properties.serviceprincipalname -join ', ')" -ForegroundColor Gray
                }
                
                $kerberoastUsers | ForEach-Object { 
                    [PSCustomObject]@{
                        Username = $_.Properties.samaccountname[0]
                        SPNs = ($_.Properties.serviceprincipalname -join ';')
                    }
                } | Export-Csv "$OutputPath\Kerberoastable_Accounts.csv" -NoTypeInformation
            } else {
                Write-Host "[+] No Kerberoastable accounts found" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "[-] Error checking Kerberoastable: $_" -ForegroundColor Red
        }
    }

    function Get-NetworkShares {

    Write-Host "`n[*] Enumerating Network Shares (Fast Mode)..." -ForegroundColor Yellow

    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $dc = $domain.PdcRoleOwner.Name  # ใช้แค่ PDC

        Write-Host "[*] Checking shares on $dc..." -ForegroundColor Gray

        $shares = cmd /c "net view \\$dc" 2>$null

        $results = @()

        foreach ($line in $shares) {
            if ($line -match "Disk") {
                $shareName = ($line -split '\s+')[0]

                if ($shareName -notmatch '\$$') {
                    $results += [PSCustomObject]@{
                        Server = $dc
                        ShareName = $shareName
                    }

                    Write-Host "    [+] Found Share: \\$dc\$shareName" -ForegroundColor Green
                }
            }
        }

        $results | Export-Csv "$OutputPath\NetworkShares.csv" -NoTypeInformation

        Write-Host "[+] Total shares found: $($results.Count)" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Error enumerating shares: $_" -ForegroundColor Red
    }
}

    # Function: Enumerate Groups and Members
    function Get-GroupEnum {
        Write-Host "[`n[*] Enumerating Domain Groups..." -ForegroundColor Yellow
        
        try {
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.PageSize = 1000
            $searcher.Filter = "(&(objectCategory=group))"
            $searcher.PropertiesToLoad.AddRange(@("name", "samaccountname", "member", "groupType"))
            
            $groups = $searcher.FindAll()
            Write-Host "[+] Total Groups Found: $($groups.Count)" -ForegroundColor Green
            
            $privilegedGroups = @()
            
            foreach ($group in $groups) {
                $groupName = $group.Properties.name[0]
                $memberCount = $group.Properties.member.Count
                
                # Check for privileged groups
                if ($groupName -match 'Admin|Domain Admins|Enterprise Admins|Schema Admins|Account Operators|Backup Operators') {
                    $privilegedGroups += [PSCustomObject]@{
                        GroupName = $groupName
                        MemberCount = $memberCount
                        Members = if ($memberCount -gt 0) { $group.Properties.member -join '; ' } else { 'None' }
                    }
                }
            }
            
            if ($privilegedGroups.Count -gt 0) {
                Write-Host "[`n[*] Privileged Groups Analysis:" -ForegroundColor Yellow
                $privilegedGroups | ForEach-Object {
                    Write-Host "    [!] $($_.GroupName): $($_.MemberCount) members" -ForegroundColor Magenta
                    if ($_.MemberCount -gt 0) {
                        Write-Host "        Members: $($_.Members)" -ForegroundColor Gray
                    }
                }
                
                $privilegedGroups | Export-Csv "$OutputPath\PrivilegedGroups.csv" -NoTypeInformation
            }
        }
        catch {
            Write-Host "[-] Error enumerating groups: $_" -ForegroundColor Red
        }
    }

    # Function: BloodHound Data Collection
    function Get-BloodHoundData {
        Write-Host "[`n[*] Collecting BloodHound Data..." -ForegroundColor Yellow
        
        try {
            # Check for SharpHound
            $sharphoundPaths = @(
                ".\SharpHound.exe",
                ".\SharpHound.ps1",
                "C:\Tools\SharpHound.exe"
            )
            
            $sharphoundFound = $false
            foreach ($path in $sharphoundPaths) {
                if (Test-Path $path) {
                    Write-Host "[+] Found SharpHound at: $path" -ForegroundColor Green
                    
                    if ($path -match '\.exe$') {
                        Write-Host "[*] Executing SharpHound collector..." -ForegroundColor Yellow
                        $output = "$OutputPath"
                        & $path `
                            --collectionmethods All `
                            --zipfilename BBAD
                            
                            
                        $sharphoundFound = $true
                    }
                    elseif ($path -match '\.ps1$') {
                        Write-Host "[*] Importing SharpHound PowerShell module..." -ForegroundColor Yellow
                        . $path
                        Get-Command Invoke-BloodHound
                        
                        Invoke-BloodHound -CollectionMethod All -OutputDirectory $OutputPath -OutputPrefix "BBAD"
                        $sharphoundFound = $true
                    }
                    break
                }
            }
            
            if (-not $sharphoundFound) {
                Write-Host "[!] SharpHound not found. Download from: https://github.com/BloodHoundAD/BloodHound/releases" -ForegroundColor Yellow
                Write-Host "[*] Attempting manual data collection..." -ForegroundColor Yellow
                
                # Manual data collection for BloodHound
                Write-Host "[*] Collecting Users, Computers, Groups, and Sessions..." -ForegroundColor Gray
                
                # Collect users
                Get-ADUser -Filter * -Properties * | 
                    Select-Object SamAccountName, DistinguishedName, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, 
                        ServicePrincipalName, MemberOf, ObjectSid | 
                    Export-Csv "$OutputPath\users.csv" -NoTypeInformation
                
                # Collect computers
                Get-ADComputer -Filter * -Properties * | 
                    Select-Object Name, DNSHostName, OperatingSystem, OperatingSystemVersion, LastLogonDate, PasswordLastSet, 
                        DistinguishedName, ObjectSid | 
                    Export-Csv "$OutputPath\computers.csv" -NoTypeInformation
                
                # Collect groups
                Get-ADGroup -Filter * -Properties * | 
                    Select-Object Name, DistinguishedName, GroupCategory, GroupScope, Members, ObjectSid | 
                    Export-Csv "$OutputPath\groups.csv" -NoTypeInformation
                
                Write-Host "[+] Manual data collection complete" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "[-] Error collecting BloodHound data: $_" -ForegroundColor Red
        }
    }

    # Function: Check Delegation
    function Get-DelegationCheck {
        Write-Host "[`n[*] Checking for Unconstrained Delegation..." -ForegroundColor Yellow
        
        try {
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.PageSize = 1000
            $searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
            $searcher.PropertiesToLoad.AddRange(@("name", "dnshostname"))
            
            $unconstrainedDelegation = $searcher.FindAll()
            
            if ($unconstrainedDelegation.Count -gt 0) {
                Write-Host "[!] Found $($unconstrainedDelegation.Count) computers with Unconstrained Delegation:" -ForegroundColor Red
                foreach ($computer in $unconstrainedDelegation) {
                    Write-Host "    [-] $($computer.Properties.name)" -ForegroundColor Yellow
                }
                
                $unconstrainedDelegation | ForEach-Object { 
                    [PSCustomObject]@{
                        ComputerName = $_.Properties.name[0]
                        DNSHostName = $_.Properties.dnshostname[0]
                    }
                } | Export-Csv "$OutputPath\UnconstrainedDelegation.csv" -NoTypeInformation
            } else {
                Write-Host "[+] No unconstrained delegation found" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "[-] Error checking delegation: $_" -ForegroundColor Red
        }
    }

    # Function: Check ACLs
    function Get-ACLCheck {
        Write-Host "[`n[*] Checking Interesting ACLs..." -ForegroundColor Yellow
        
        try {
            $domainDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext
            
            # Check for AdminSDHolder
            $adminSDHolder = [ADSI]"LDAP://CN=AdminSDHolder,CN=System,$domainDN"
            $adminSDHolderSecurity = $adminSDHolder.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
            
            Write-Host "[*] AdminSDHolder ACLs:" -ForegroundColor Gray
            $interestingACLs = @()
            
            foreach ($rule in $adminSDHolderSecurity) {
                if ($rule.IdentityReference -notlike '*Domain Admins*' -and $rule.IdentityReference -notlike '*Enterprise Admins*' -and $rule.AccessControlType -eq 'Allow') {
                    $interestingACLs += [PSCustomObject]@{
                        Target = "AdminSDHolder"
                        Identity = $rule.IdentityReference
                        Rights = $rule.ActiveDirectoryRights
                        Type = $rule.AccessControlType
                    }
                }
            }
            
            if ($interestingACLs.Count -gt 0) {
                Write-Host "[!] Found $($interestingACLs.Count) interesting AdminSDHolder permissions:" -ForegroundColor Red
                $interestingACLs | Format-Table -AutoSize
                $interestingACLs | Export-Csv "$OutputPath\InterestingACLs.csv" -NoTypeInformation
            }
        }
        catch {
            Write-Host "[-] Error checking ACLs: $_" -ForegroundColor Red
        }
    }

#function Restore
    function Restore-DeletedADObject {

    [CmdletBinding()]
    param(
        [string]$SearchName,
        [int]$MaxResults = 50
    )

    Write-Host "`n[*] Checking Active Directory Recycle Bin (Read-Only Mode)..." -ForegroundColor Yellow

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Host "[-] ActiveDirectory module not available." -ForegroundColor Red
        return
    }

    try {
        $domainDN = (Get-ADDomain).DistinguishedName
        $deletedBase = "CN=Deleted Objects,$domainDN"

        $ldapFilter = "(isDeleted=TRUE)"

        $deletedObjects = Get-ADObject `
            -SearchBase $deletedBase `
            -LDAPFilter $ldapFilter `
            -IncludeDeletedObjects `
            -ResultSetSize $MaxResults `
            -Properties Name,ObjectClass,ObjectGUID,lastKnownParent

        if ($SearchName) {
            $deletedObjects = $deletedObjects | Where-Object {
                $_.Name -like "*$SearchName*"
            }
        }

        if (-not $deletedObjects) {
            Write-Host "[+] No deleted objects found." -ForegroundColor Green
            return
        }

        Write-Host "[+] Showing up to $MaxResults deleted objects" -ForegroundColor Green

        $deletedObjects |
            Select-Object Name,ObjectClass,lastKnownParent,ObjectGUID |
            Format-Table -AutoSize

    }
    catch {
        Write-Host "[-] Error accessing deleted objects: $_" -ForegroundColor Red
    }
}

    function Get-TokenPrivilegeReport {
        [CmdletBinding()]
        param(
            [string]$OutputPath = ".\AD_Enum_Results"
        )

        Write-Host "`n[*] Token / Privilege / Identity Report..." -ForegroundColor Yellow

        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }

        $outDir = Join-Path $OutputPath "HostContext"
        if (-not (Test-Path $outDir)) {
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        }

        # ---------- Helpers ----------
        function _TryRun([string]$Cmd, [string]$OutFile) {
            try {
                $o = cmd.exe /c $Cmd 2>&1
                $o | Out-File -FilePath $OutFile -Encoding UTF8
                return $o
            } catch {
                "ERROR running: $Cmd`n$_" | Out-File -FilePath $OutFile -Encoding UTF8
                return @()
            }
        }

        function _TryRegGet([string]$Path, [string]$Name) {
            try {
                $v = (Get-ItemProperty -Path $Path -ErrorAction Stop).$Name
                return $v
            } catch { return $null }
        }

        function _ParseWhoamiPriv($lines) {
            # whoami /priv output is table-like; parse lines with "Se" privilege entries
            $items = @()
            foreach ($l in $lines) {
                if ($l -match '^\s*(Se[A-Za-z]+Privilege)\s+(.+?)\s+(Enabled|Disabled)\s*$') {
                    $items += [PSCustomObject]@{
                        Privilege = $matches[1]
                        Description = ($matches[2].Trim())
                        State = $matches[3]
                    }
                }
            }
            return $items
        }

        # ---------- Identity / Token ----------
        $id = [PSCustomObject]@{
            Timestamp     = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            ComputerName  = $env:COMPUTERNAME
            UserName      = $env:USERNAME
            UserDomain    = $env:USERDOMAIN
            UserDNSDomain = $env:USERDNSDOMAIN
            IsAdmin       = $false
            IsElevated    = $false
            Integrity     = $null
            PSVersion     = $PSVersionTable.PSVersion.ToString()
        }

        try {
            $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
            $wp = New-Object Security.Principal.WindowsPrincipal($wi)
            $id.IsAdmin = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

            # Integrity Level via token groups (S-1-16-*)
            $integritySid = $wi.Groups | Where-Object { $_.Value -like "S-1-16-*" } | Select-Object -First 1
            if ($integritySid) {
                switch ($integritySid.Value) {
                    "S-1-16-4096"  { $id.Integrity = "Low" }
                    "S-1-16-8192"  { $id.Integrity = "Medium" }
                    "S-1-16-8448"  { $id.Integrity = "MediumPlus" }
                    "S-1-16-12288" { $id.Integrity = "High" }
                    "S-1-16-16384" { $id.Integrity = "System" }
                    default        { $id.Integrity = $integritySid.Value }
                }
            }

            # Elevated heuristic: High/System integrity implies elevated in most cases
            if ($id.Integrity -in @("High","System")) { $id.IsElevated = $true }
        } catch {}

        # ---------- Run commands ----------
        $whoamiPrivPath   = Join-Path $outDir "whoami_priv.txt"
        $whoamiAllPath    = Join-Path $outDir "whoami_all.txt"
        $whoamiGroupsPath = Join-Path $outDir "whoami_groups.txt"
        $whoamiUserPath   = Join-Path $outDir "whoami_user.txt"

        $privLines   = _TryRun "whoami /priv"   $whoamiPrivPath
        $allLines    = _TryRun "whoami /all"    $whoamiAllPath
        $groupsLines = _TryRun "whoami /groups" $whoamiGroupsPath
        $userLines   = _TryRun "whoami /user"   $whoamiUserPath

        $privParsed = _ParseWhoamiPriv $privLines

        # ---------- Registry posture (read-only) ----------
        $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

        $uacEnableLUA          = _TryRegGet $uacPath "EnableLUA"
        $uacConsentPromptAdmin = _TryRegGet $uacPath "ConsentPromptBehaviorAdmin"
        $uacPromptOnSecureDesk = _TryRegGet $uacPath "PromptOnSecureDesktop"
        $localTokenFilter      = _TryRegGet $lsaPath "LocalAccountTokenFilterPolicy"
        $runAsPPL              = _TryRegGet $lsaPath "RunAsPPL"

        $posture = [PSCustomObject]@{
            EnableLUA                   = $uacEnableLUA
            ConsentPromptBehaviorAdmin  = $uacConsentPromptAdmin
            PromptOnSecureDesktop       = $uacPromptOnSecureDesk
            LocalAccountTokenFilterPolicy = $localTokenFilter
            RunAsPPL                    = $runAsPPL
        }

        # ---------- Highlight interesting privileges (read-only assessment) ----------
        $interesting = @(
            "SeImpersonatePrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeDebugPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege",
            "SeTcbPrivilege",
            "SeManageVolumePrivilege"
        )

        $enabledInteresting = @()
        foreach ($p in $privParsed) {
            if ($interesting -contains $p.Privilege -and $p.State -eq "Enabled") {
                $enabledInteresting += $p
            }
        }

        # ---------- Build summary ----------
        $summary = [PSCustomObject]@{
            Identity   = $id
            Posture    = $posture
            Privileges = [PSCustomObject]@{
                TotalParsed = ($privParsed | Measure-Object).Count
                EnabledInteresting = $enabledInteresting
            }
            OutputFiles = [PSCustomObject]@{
                WhoamiPriv   = $whoamiPrivPath
                WhoamiAll    = $whoamiAllPath
                WhoamiGroups = $whoamiGroupsPath
                WhoamiUser   = $whoamiUserPath
            }
        }

        # ---------- Export ----------
        $csvPrivPath   = Join-Path $outDir "privileges_parsed.csv"
        $jsonSummary   = Join-Path $outDir "token_priv_summary.json"

        $privParsed | Export-Csv -NoTypeInformation -Path $csvPrivPath
        ($summary | ConvertTo-Json -Depth 6) | Out-File -FilePath $jsonSummary -Encoding UTF8

        # ---------- Console output ----------
        Write-Host "[+] Saved whoami outputs + parsed report to: $outDir" -ForegroundColor Green
        Write-Host "[*] Identity: $($id.UserDomain)\$($id.UserName) on $($id.ComputerName)" -ForegroundColor Cyan
        Write-Host "[*] Admin: $($id.IsAdmin) | Elevated: $($id.IsElevated) | Integrity: $($id.Integrity)" -ForegroundColor Cyan

        if (($enabledInteresting | Measure-Object).Count -gt 0) {
            Write-Host "`n[!] Enabled Interesting Privileges:" -ForegroundColor Yellow
            $enabledInteresting | Select-Object Privilege,State,Description | Format-Table -AutoSize
        } else {
            Write-Host "`n[+] No enabled privileges from the high-interest list found (based on whoami /priv)." -ForegroundColor Green
        }

        Write-Host "`n[*] UAC/LSA posture (read-only):" -ForegroundColor Yellow
        $posture | Format-List

        #return $summary
    }



    # Function: Generate Summary Report
    function New-SummaryReport {
        Write-Host "[`n[*] Generating Summary Report..." -ForegroundColor Yellow




        $report = @"
===========================================
    BIG BLACK AD ENUMERATION REPORT
===========================================
Generated: $(Get-Date)
Domain: $env:USERDNSDOMAIN
User: $env:USERNAME
Computer: $env:COMPUTERNAME

ENUMERATION SUMMARY:
-------------------
- Domain Information: $OutputPath\DomainInfo.xml
- User Enumeration: $OutputPath\UserEnumeration.csv
- AS-REP Roastable Users: $OutputPath\ASREP_Roastable_Users.csv
- Kerberoastable Accounts: $OutputPath\Kerberoastable_Accounts.csv
- Network Shares: $OutputPath\NetworkShares.csv
- Privileged Groups: $OutputPath\PrivilegedGroups.csv
- Unconstrained Delegation: $OutputPath\UnconstrainedDelegation.csv
- Interesting ACLs: $OutputPath\InterestingACLs.csv
- BloodHound Data: $OutputPath\


"@
        
        $report | Out-File "$OutputPath\SummaryReport.txt"
        Write-Host "[+] Summary report saved to: $OutputPath\SummaryReport.txt" -ForegroundColor Green
        Write-Host $report -ForegroundColor Cyan
    }

    # Main Execution Flow
    Write-Host "[`n[*] Starting Big Black AD Enumeration..." -ForegroundColor Magenta
    Write-Host "[*] Target Domain: $env:USERDNSDOMAIN" -ForegroundColor Yellow
    Write-Host "[*] Current User: $env:USERNAME" -ForegroundColor Yellow
    Start-Sleep -Seconds 2

    # Check if running with appropriate privileges
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[!] Not running as Administrator. Some features may not work." -ForegroundColor Yellow
    }

    # Execute enumeration modules
    $adModuleAvailable = Test-ADModule
    
    Get-DomainInfo
    Get-UserEnum
    Get-ASREPRoast
    Get-Kerberoastable
    
    if ($FullEnumeration) {
        Get-NetworkShares
        Get-GroupEnum
        Get-DelegationCheck
        Get-ACLCheck
        Get-BloodHoundData
        Restore-DeletedADObject
        Get-TokenPrivilegeReport
    }
    
    New-SummaryReport

    # Final Message
    Write-Host @"

+--------------------------------------------------------------------------+
|                                                                          |
|     BIG BLACK AD ENUMERATION COMPLETE!                                   |
|                                                                          |
|     Results saved to: $OutputPath                 |
|                                                                          |
|     For advanced AD hacking assistance:                                  |
|     >> https://www.facebook.com/sabastian.fhantomhive                    |
|                                                                          |
|     Tell him: Big Black sent me for AD help!                            |
|                                                                          |
+--------------------------------------------------------------------------+
"@ -ForegroundColor Green

    # Open external link (Lab mode only)
    try {
        Start-Process "https://www.facebook.com/sabastian.fhantomhive"
        Write-Host "[+] Facebook profile opened. Go ask Big Black for advanced AD help!" -ForegroundColor Cyan
        Write-Host "[+] Please feel free to contact me, Ratthapong Sommanus." -ForegroundColor Red
    }
    catch {
        Write-Host "[!] Could not open browser automatically" -ForegroundColor Yellow
        
    }
}

# Auto-execute if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    if ($args.Count -eq 0) {
        Invoke-BigBlackAD
    }
    else {
        & Invoke-BigBlackAD @args
    }
}
