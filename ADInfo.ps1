$ErrorActionPreference = 'SilentlyContinue'

# CSS Styles

$css = @"
<style>
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }
h1 { color: #005a9e; border-bottom: 2px solid #005a9e; padding-bottom: 5px; text-align: center; margin-bottom: 20px; }
h2 { color: #005a9e; margin-top: 30px; border-bottom: 1px solid #ccc; padding-bottom: 3px;}
h3 { color: #333; margin-top: 20px; }
table { border-collapse: collapse; width: 100%; margin-top: 15px; box-shadow: 0 2px 3px rgba(0,0,0,0.1); background-color: #fff; }
th, td { border: 1px solid #ddd; padding: 10px; text-align: left; vertical-align: top; word-wrap: break-word; } /* Added word-wrap */
th { background-color: #0078d4; color: white; font-weight: bold; }
tr:nth-child(even) { background-color: #f2f2f2; }
tr:hover { background-color: #e2e2e2; }
.section { margin-bottom: 30px; padding: 20px; background-color: #fff; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
.property-name { font-weight: bold; color: #555; min-width: 180px; display: inline-block; } /* Style for property names */
.list-item { margin-bottom: 8px; } /* Style for list items */
.list-item .property-name { vertical-align: top; } /* Align label with value */
.list-item span:last-child { margin-left: 10px; } /* Space between label and value */
.code { font-family: Consolas, monospace; background-color: #eee; padding: 2px 5px; border-radius: 3px;} /* Style for code/paths */
.highlight-pentest { background-color: #fff9c4; padding: 2px 4px; border-radius: 3px; font-weight: bold; border: 1px solid #fbc02d; } /* Style for highlighting pentest info */
pre { background-color: #eee; padding: 10px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; font-family: Consolas, monospace; border: 1px solid #ccc; margin-top: 10px; max-height: 400px; overflow-y: auto; } /* Style for preformatted output */
.table-container { max-height: 500px; overflow-y: auto; margin-top: 10px; border: 1px solid #ddd; } /* Container for long tables with border */
.error-message { color: red; font-style: italic; margin-top: 5px; } /* Style for error messages */
.module-warning { color: orange; font-style: italic; margin-top: 5px; } /* Style for AD module warnings */
</style>
"@

# System information gathering.

Write-Host "Gathering system information..."

# Check Admin Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Check PowerShell v2 Engine Availability
$psV2Available = $false
try {
    if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
        $psV2Feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction Stop
        if ($psV2Feature -and $psV2Feature.State -eq 'Enabled') { $psV2Available = $true }
    } else { Write-Warning "Cmdlet Get-WindowsOptionalFeature not found. Unable to verify PowerShell v2 status." }
} catch { Write-Warning "Unable to verify PowerShell v2 status using Get-WindowsOptionalFeature. Error: $($_.Exception.Message)" }

# Check Active Directory Module Availability
$adModuleAvailable = $false
if (Get-Module -ListAvailable -Name ActiveDirectory) { $adModuleAvailable = $true }


# Operating System Information
$osInfoObj = Get-CimInstance Win32_OperatingSystem
$osInfo = $osInfoObj | Select-Object @{N='Host Name';E={$env:COMPUTERNAME}},
    @{N='OS Name';E={$_.Caption}}, @{N='OS Version';E={$_.Version}}, @{N='OS Manufacturer';E={$_.Manufacturer}},
    @{N='OS Configuration';E={if ($_.ProductType -eq 1) {'Workstation'} elseif ($_.ProductType -eq 2) {'Domain Controller'} else {'Server'}}},
    @{N='OS Build Type';E={$_.BuildType}}, @{N='Registered Owner';E={$_.RegisteredUser}}, @{N='Registered Organization';E={$_.Organization}},
    @{N='Product ID';E={$_.SerialNumber}}, @{N='Original Installation Date';E={$_.InstallDate}}, @{N='System Boot Time';E={$_.LastBootUpTime}},
    @{N='Windows Directory';E={$_.WindowsDirectory}}, @{N='System Directory';E={$_.SystemDirectory}}, @{N='Boot Device';E={$_.BootDevice}},
    @{N='System Locale';E={$_.SystemLocale}}, @{N='Input Locale';E={$_.InputLocale}}, @{N='Time Zone';E={(Get-TimeZone).DisplayName}},
    @{N='Total Physical Memory (MB)';E={if($_.TotalVisibleMemorySize) {[math]::Round($_.TotalVisibleMemorySize / 1KB)} else {'N/A'}}},
    @{N='Available Physical Memory (MB)';E={if($_.FreePhysicalMemory) {[math]::Round($_.FreePhysicalMemory / 1KB)} else {'N/A'}}},
    @{N='Virtual Memory: Max Size (MB)';E={if($_.TotalVirtualMemorySize) {[math]::Round($_.TotalVirtualMemorySize / 1KB)} else {'N/A'}}},
    @{N='Virtual Memory: Available (MB)';E={if($_.FreeVirtualMemory) {[math]::Round($_.FreeVirtualMemory / 1KB)} else {'N/A'}}},
    @{N='Virtual Memory: In Use (MB)';E={if($_.TotalVirtualMemorySize -and $_.FreeVirtualMemory) {[math]::Round( ($_.TotalVirtualMemorySize - $_.FreeVirtualMemory) / 1KB )} else {'N/A'}}}

# Hardware and Domain Information
$compSysInfoObj = Get-CimInstance Win32_ComputerSystem
$compSysInfo = $compSysInfoObj | Select-Object @{N='System Manufacturer';E={$_.Manufacturer}},
    @{N='System Model';E={$_.Model}}, @{N='System Type';E={$_.SystemType}}, @{N='Domain';E={$_.Domain}},
    @{N='Domain Member';E={$_.PartOfDomain}}, @{N='Logon Server';E={$env:LOGONSERVER}}

$primaryDC = "N/A"
$domainDN = "N/A" # Initialize to N/A
$domainName = $compSysInfoObj.Domain # domain name from WMI as fallback
$adErrorMsg = "" # For specific AD error messages
$domainInfoRetrievedSuccessfully = $false # Flag to track Get-ADDomain success

if ($adModuleAvailable) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop # Explicitly import
        $currentDomain = Get-ADDomain -ErrorAction Stop
        if ($currentDomain) { # Check if Get-ADDomain returned something
             $domainDN = $currentDomain.DistinguishedName
             $primaryDC = (Get-ADDomainController -DomainName $currentDomain.DNSRoot -Discover -Service Primary -ErrorAction Stop).HostName
             $domainInfoRetrievedSuccessfully = $true # Set flag to true
        } else {
             $adErrorMsg = "Get-ADDomain did not return domain information."
             Write-Warning $adErrorMsg
             # Attempt to construct DN from WMI domain name
             if ($domainName -and $domainName -ne $env:COMPUTERNAME) { # Ensure it's a domain, not a workgroup
                 $domainDN = "DC=" + ($domainName -split '\.' -join ',DC=')
                 Write-Warning "Attempting to construct Domain DN from WMI: $domainDN"
             } else {
                 $adErrorMsg += " Unable to construct DN from WMI (Domain Name: $domainName)."
                 $domainDN = "N/A" # Reset if it cannot be constructed
             }
        }
    } catch {
        $adErrorMsg = "Unable to get AD domain information: $($_.Exception.Message)"
        Write-Warning $adErrorMsg
        # Attempt to construct the DN from the WMI domain name as an extreme fallback
        if ($domainName -and $domainName -ne $env:COMPUTERNAME) {
             $domainDN = "DC=" + ($domainName -split '\.' -join ',DC=')
             Write-Warning "Attempting to construct Domain DN from WMI (fallback): $domainDN"
        } else {
             $adErrorMsg += " Unable to construct DN from WMI (Domain Name: $domainName)."
             $domainDN = "N/A"
        }
    }
} else {
     $adErrorMsg = "Active Directory module not available."
     Write-Warning $adErrorMsg
     # Still attempt to construct DN from WMI if the machine appears to be in a domain
     if ($compSysInfoObj.PartOfDomain -and $domainName -and $domainName -ne $env:COMPUTERNAME) {
         $domainDN = "DC=" + ($domainName -split '\.' -join ',DC=')
         Write-Warning "Attempting to construct Domain DN from WMI (no AD module): $domainDN"
     } else {
         $domainDN = "N/A"
     }
}
$compSysInfo | Add-Member -NotePropertyName 'Primary Domain Controller' -NotePropertyValue $primaryDC

# Processor Information
$processorInfo = Get-CimInstance Win32_Processor | Select-Object @{N='Name';E={$_.Name}},
    @{N='Number of Cores';E={$_.NumberOfCores}}, @{N='Logical Processors';E={$_.NumberOfLogicalProcessors}}, @{N='Max Clock Speed (MHz)';E={$_.MaxClockSpeed}}

# BIOS Information
$biosInfo = Get-CimInstance Win32_BIOS | Select-Object @{N='BIOS Version/Date';E={$_.SMBIOSBIOSVersion}}, Manufacturer, @{N='Release Date';E={$_.ReleaseDate}}

# Paging File Information
$pageFileInfo = Get-CimInstance Win32_PageFileUsage | Select-Object @{N='Paging File Path';E={$_.Name}},
    @{N='Current Size (MB)';E={if($_.CurrentUsage) {[math]::Round($_.CurrentUsage)} else {'N/A'}}},
    @{N='Allocated Size (MB)';E={if($_.AllocatedBaseSize) {[math]::Round($_.AllocatedBaseSize)} else {'N/A'}}}

# Network Configuration (Active Adapters)
$networkAdapters = Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up'}
$networkInfo = @()
foreach ($adapter in $networkAdapters) {
    $ipconfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex | Where-Object {$_.IPv4Address -ne $null}
    if ($ipconfig) {
        $networkInfo += [PSCustomObject]@{
            'Description' = $adapter.InterfaceDescription; 'DHCP Enabled' = $adapter.Dhcp; 'Physical Address (MAC)' = $adapter.MacAddress;
            'IPv4 Address' = ($ipconfig.IPv4Address.IPAddress -join ', '); 'Subnet Mask (CIDR)' = ($ipconfig.IPv4Address.PrefixLength -join ', ');
            'IPv4 Default Gateway' = ($ipconfig.IPv4DefaultGateway.NextHop -join ', '); 'DNS Servers' = ($ipconfig.DNSServer.ServerAddresses -join ', ');
            'DHCP Server' = ($ipconfig.DhcpServer.ServerAddresses -join ', ')
        }
    }
}

# Installed Hotfixes (wmic qfe)
$hotfixInfo = Get-HotFix | Select-Object @{N='Hotfix ID';E={$_.HotFixID}}, Description, @{N='Installed On';E={$_.InstalledOn}}

# PowerShell Information
$psInfo = [PSCustomObject]@{
    'Current Admin Privileges' = $isAdmin; 'PowerShell Version' = $PSVersionTable.PSVersion; 'PowerShell Edition' = $PSVersionTable.PSEdition;
    'PowerShell v2 Available (for Downgrade)' = $psV2Available;
    'Execution Policy (MachinePolicy)' = (Get-ExecutionPolicy -List | Where-Object Scope -eq 'MachinePolicy').ExecutionPolicy;
    'Execution Policy (UserPolicy)' = (Get-ExecutionPolicy -List | Where-Object Scope -eq 'UserPolicy').ExecutionPolicy;
    'Execution Policy (Process)' = (Get-ExecutionPolicy -List | Where-Object Scope -eq 'Process').ExecutionPolicy;
    'Execution Policy (CurrentUser)' = (Get-ExecutionPolicy -List | Where-Object Scope -eq 'CurrentUser').ExecutionPolicy;
    'Execution Policy (LocalMachine)' = (Get-ExecutionPolicy -List | Where-Object Scope -eq 'LocalMachine').ExecutionPolicy
}
# Loaded Modules
$psModules = Get-Module | Select-Object Name, Version

# Environment Variables
$envVars = Get-ChildItem Env: | Select-Object @{N='Variable';E={$_.Name}}, @{N='Value';E={$_.Value}}

# --- Defense Control Section ---
Write-Host "Checking local defenses..."
$firewallStatus = try { (netsh advfirewall show allprofiles | Out-String).Trim() } catch { "netsh error: $($_.Exception.Message)" }
$defenderServiceStatus = try { (sc.exe query windefend | Out-String).Trim() } catch { "sc query error: $($_.Exception.Message)" }
$defenderDetailedStatus = $null
if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        $defenderDetailedStatus = $mpStatus | Select-Object @{N='Antivirus Enabled';E={$_.AntivirusEnabled}},
            @{N='Real-Time Protection Enabled';E={$_.RealTimeProtectionEnabled}}, @{N='Antispyware Enabled';E={$_.AntispywareEnabled}},
            @{N='IOAV Protection Enabled';E={$_.IoavProtectionEnabled}}, @{N='Behavior Monitor Enabled';E={$_.BehaviorMonitorEnabled}},
            @{N='Antivirus Signature Version';E={$_.AntivirusSignatureVersion}}, @{N='Antivirus Signature Last Updated';E={$_.AntivirusSignatureLastUpdated}},
            @{N='Antispyware Signature Version';E={$_.AntispywareSignatureVersion}}, @{N='Antispyware Signature Last Updated';E={$_.AntispywareSignatureLastUpdated}},
            @{N='Antimalware Engine Version';E={$_.AMEngineVersion}}, @{N='Antimalware Platform Version';E={$_.AMProductVersion}}
    } catch { $defenderDetailedStatus = [PSCustomObject]@{'Error' = "Get-MpComputerStatus: $($_.Exception.Message)"} }
} else { $defenderDetailedStatus = [PSCustomObject]@{'Status' = "Cmdlet Get-MpComputerStatus not available."} }

# --- Connected Users and Additional Network Information Section ---
Write-Host "Checking connected users and additional network information..."
$loggedInUsers = try {
    if (Get-Command qwinsta -ErrorAction SilentlyContinue) { (qwinsta | Out-String).Trim() }
    elseif (Get-Command 'query' -ErrorAction SilentlyContinue) { (query user | Out-String).Trim() }
    else { "Commands 'qwinsta' and 'query user' not found." }
} catch { "qwinsta/query error: $($_.Exception.Message)" }
$arpTable = try { (arp -a | Out-String).Trim() } catch { "arp error: $($_.Exception.Message)" }
$routingTable = try {
    $rawRoute = route print | Out-String
    $ipv4Start = $rawRoute.IndexOf('IPv4 Route Table'); $ipv4End = $rawRoute.IndexOf('Persistent Routes:')
    if ($ipv4Start -ge 0 -and $ipv4End -gt $ipv4Start) { $rawRoute.Substring($ipv4Start, $ipv4End - $ipv4Start).Trim() }
    elseif ($ipv4Start -ge 0) { $rawRoute.Substring($ipv4Start).Trim() } else { "IPv4 routing table not found." }
} catch { "route print error: $($_.Exception.Message)" }

# --- WMI Information Section ---
Write-Host "Gathering WMI information..."
$wmiCompSys = try { $compSysInfoObj | Select-Object @{N='Name';E={$_.Name}}, @{N='Domain';E={$_.Domain}}, @{N='Manufacturer';E={$_.Manufacturer}},
                                   @{N='Model';E={$_.Model}}, @{N='UserName';E={$_.UserName}}, @{N='Roles';E={$_.Roles -join ', '}} } catch { [PSCustomObject]@{'Error'="Win32_ComputerSystem: $($_.Exception.Message)"} }
$ntDomainInfo = try { Get-CimInstance Win32_NTDomain | Select-Object Caption, Description, DnsForestName, DomainName, DomainControllerAddress } catch { @{'Error'="Win32_NTDomain: $($_.Exception.Message)"} }
$allUsers = try { Get-CimInstance Win32_UserAccount | Select-Object Name, Domain, SID, Status, Disabled, Lockout, PasswordRequired, PasswordChangeable, LocalAccount } catch { @{'Error'="Win32_UserAccount: $($_.Exception.Message)"} }
$localGroupsWmi = try { Get-CimInstance Win32_Group -Filter "LocalAccount=True" | Select-Object Name, SID, Description, Status } catch { @{'Error'="Win32_Group: $($_.Exception.Message)"} } # Renamed
$sysAccounts = try { Get-CimInstance Win32_SystemAccount | Select-Object Name, Domain, SID, SIDType, Status } catch { @{'Error'="Win32_SystemAccount: $($_.Exception.Message)"} }
$runningProcesses = try { Get-CimInstance Win32_Process | Select-Object Name, ProcessId, ExecutablePath, @{N='Owner';E={(Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User}} } catch { @{'Error'="Win32_Process: $($_.Exception.Message)"} }

# --- Net Command Equivalents (Active Directory & Local) ---
Write-Host "Gathering Active Directory and local information (Net command equivalents)..."
$domainPasswordPolicy = $null; $domainGroups = $null; $domainAdmins = $null; $domainControllers = $null
$domainComputers = $null; $domainUsers = $null; $adErrorNet = $null # Renamed to avoid conflicts

# Execute only if the AD module is available AND domain info was successfully retrieved
if ($adModuleAvailable -and $domainInfoRetrievedSuccessfully) {
    try {
        $domainPasswordPolicy = Get-ADDefaultDomainPasswordPolicy | Select-Object -Property *
        $domainGroups = Get-ADGroup -Filter * | Select-Object Name, GroupScope, GroupCategory, Description
        $domainAdmins = Get-ADGroupMember "Domain Admins" | Select-Object Name, SAMAccountName, objectClass
        $domainControllers = Get-ADGroupMember "Domain Controllers" | Select-Object Name, SAMAccountName, objectClass
        $domainComputers = Get-ADComputer -Filter * | Select-Object Name, OperatingSystem, Enabled, DistinguishedName
        $domainUsers = Get-ADUser -Filter * -Properties Enabled, LastLogonDate | Select-Object Name, SAMAccountName, Enabled, LastLogonDate, DistinguishedName -First 100
    } catch { $adErrorNet = "Error executing AD commands (Net Equivalents): $($_.Exception.Message)"; Write-Error $adErrorNet }
} elseif (-not $adModuleAvailable) {
    $adErrorNet = "Active Directory module not found (Net Equivalents)."
    Write-Warning $adErrorNet
    # Set variables to an error message
    $domainPasswordPolicy = @{'Error'=$adErrorNet}; $domainGroups = @{'Error'=$adErrorNet}; $domainAdmins = @{'Error'=$adErrorNet}
    $domainControllers = @{'Error'=$adErrorNet}; $domainComputers = @{'Error'=$adErrorNet}; $domainUsers = @{'Error'=$adErrorNet}
} else { # Module available but Get-ADDomain failed
     $adErrorNet = "Domain information not retrieved (Get-ADDomain failed?). Unable to query AD (Net Equivalents)."
     Write-Warning $adErrorNet
     $domainPasswordPolicy = @{'Error'=$adErrorNet}; $domainGroups = @{'Error'=$adErrorNet}; $domainAdmins = @{'Error'=$adErrorNet}
     $domainControllers = @{'Error'=$adErrorNet}; $domainComputers = @{'Error'=$adErrorNet}; $domainUsers = @{'Error'=$adErrorNet}
}

# Local commands (executed anyway)
$localGroupsNet = try { Get-LocalGroup | Select-Object Name, Description, SID } catch { @{'Error'="Get-LocalGroup: $($_.Exception.Message)"} }
$localAdminsNet = try { Get-LocalGroupMember Administrators | Select-Object Name, PrincipalSource, ObjectClass, SID } catch { @{'Error'="Get-LocalGroupMember: $($_.Exception.Message)"} }
$smbShares = try { Get-SmbShare | Select-Object Name, Path, Description, ScopeName } catch { @{'Error'="Get-SmbShare: $($_.Exception.Message)"} }
$netViewOutput = try { (net view | Out-String).Trim() } catch { "net view error: $($_.Exception.Message)" }

# --- NEW SECTION: Dsquery Equivalents (Active Directory) ---
Write-Host "Executing Dsquery-like queries (Active Directory)..."
$dsQueryAllUsers = $null # New
$dsQueryAllComputers = $null # New
$dsQueryUsersInUsersOU = $null
$dsQueryPasswdNotReqd = $null
$dsQueryComputersLimit5 = $null
$dsQueryError = $null

# Execute only if the AD module is available AND domain info was successfully retrieved
if ($adModuleAvailable -and $domainInfoRetrievedSuccessfully) {
    try {
        # Equivalent: dsquery user (all users, DN only)
        $dsQueryAllUsers = try { Get-ADUser -Filter * -ErrorAction Stop | Select-Object DistinguishedName } catch { @{'Error'="Get-ADUser -Filter *: $($_.Exception.Message)"} }

        # Equivalent: dsquery computer (all computers, DN only)
        $dsQueryAllComputers = try { Get-ADComputer -Filter * -ErrorAction Stop | Select-Object DistinguishedName } catch { @{'Error'="Get-ADComputer -Filter *: $($_.Exception.Message)"} }

        # Equivalent: dsquery * "CN=Users,DC=..."
        # Execute this query only if $domainDN is valid (contains DC=)
        if ($domainDN -like '*DC=*') {
            $usersOUPath = "CN=Users,$domainDN"
            #Write-Host "Attempting Dsquery on: $usersOUPath" # Debug
            # CORRECTION v9: Added -Filter * to avoid interactive prompt
            $dsQueryUsersInUsersOU = try { Get-ADObject -Filter * -SearchBase $usersOUPath -SearchScope OneLevel -ErrorAction Stop | Select-Object Name, objectClass, DistinguishedName } catch { @{'Error'="Get-ADObject in CN=Users ($usersOUPath): $($_.Exception.Message)"} }
        } else {
            $dsQueryUsersInUsersOU = @{'Error'="Invalid or not found domain DN ($domainDN). Unable to query CN=Users."}
            Write-Warning $dsQueryUsersInUsersOU.Error
        }

        # Equivalent: dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" ...
        $uacPasswdNotReqd = 32
        $dsQueryPasswdNotReqd = try { Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=$uacPasswdNotReqd))" -Properties DistinguishedName, userAccountControl -ErrorAction Stop | Select-Object Name, DistinguishedName, UserAccountControl } catch { @{'Error'="Get-ADUser PASSWD_NOTREQD: $($_.Exception.Message)"} }

        # Equivalent: dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 ...
        $uacWorkstationTrust = 8192
        # CORRECTION v11: Use Select-Object -First 5 instead of -ResultSize
        $dsQueryComputersLimit5 = try { Get-ADComputer -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=$uacWorkstationTrust)" -Properties SAMAccountName -ErrorAction Stop | Select-Object Name, SAMAccountName -First 5 } catch { @{'Error'="Get-ADComputer WORKSTATION_TRUST: $($_.Exception.Message)"} }

    } catch {
        # General catch for unexpected errors in the Dsquery block
        $dsQueryError = "Generic error executing Dsquery equivalents: $($_.Exception.Message)"
        Write-Error $dsQueryError
    }
} else { # Module not available or Get-ADDomain failed
    if (-not $adModuleAvailable) {
        $dsQueryError = "Active Directory module not found. Unable to execute Dsquery equivalents."
    } else {
        $dsQueryError = "Domain information not retrieved (Get-ADDomain failed?). Unable to execute Dsquery queries."
    }
    Write-Warning $dsQueryError
    # Set variables to an error message
    $dsQueryAllUsers = @{'Error'=$dsQueryError}
    $dsQueryAllComputers = @{'Error'=$dsQueryError}
    $dsQueryUsersInUsersOU = @{'Error'=$dsQueryError}
    $dsQueryPasswdNotReqd = @{'Error'=$dsQueryError}
    $dsQueryComputersLimit5 = @{'Error'=$dsQueryError}
}
# --- End of Data Gathering Sections ---


Write-Host "Generating HTML report..."

# --- HTML Generation ---
# Helper function to create HTML list sections, with highlighting
function ConvertTo-HtmlListFragment {
    param(
        [Parameter(Mandatory=$true)] $InputObject, # Can be PSCustomObject or Hashtable
        [string]$Title
    )
    $html = ""; if ($Title) { $html += "<h3>$Title</h3>" }
    $html += "<div class='list-items'>"
    $properties = if ($InputObject -is [hashtable]) { $InputObject.GetEnumerator() } elseif ($InputObject -is [PSCustomObject]) { $InputObject.PSObject.Properties } else { @() }

    $properties | ForEach-Object {
        $propName = if ($InputObject -is [hashtable]) { $_.Key } else { $_.Name }
        $propValue = $_.Value; $highlightClass = ''

        $isDCHost = ($propName -eq 'OS Configuration' -and $propValue -eq 'Domain Controller')
        $isExecPolicy = ($propName -match 'Execution Policy')
        $isPSVersion = ($propName -eq 'PowerShell Version')
        $isAdminHighlight = ($propName -eq 'Current Admin Privileges' -and $propValue -eq $true)
        $isPSv2Highlight = ($propName -eq 'PowerShell v2 Available (for Downgrade)' -and $propValue -eq $true)
       $isDefenseDisabled = (($propName -match 'Enabled' -or $propName -match 'Enabled') -and $propValue -eq $false)

        if ($isDCHost -or $isExecPolicy -or $isPSVersion -or $isAdminHighlight -or $isPSv2Highlight -or $isDefenseDisabled) { $highlightClass = 'highlight-pentest' }

        if ($propValue -is [datetime]) { $propValue = $propValue.ToString('yyyy-MM-dd HH:mm:ss') }
        if ($propValue -is [System.TimeSpan]) { $propValue = $propValue.ToString() }
        if ($propName -like '*Directory' -or $propName -like '*Path*' -or $propName -like '*Device*') { $propValue = "<span class='code'>$propValue</span>" }
        if ($null -eq $propValue -or $propValue -is [string] -and [string]::IsNullOrWhiteSpace($propValue)) { $propValue = 'N/A' }
        if ($highlightClass) { $propValue = "<span class='$highlightClass'>$propValue</span>" }

        $html += "<div class='list-item'><span class='property-name'>${propName}:</span><span>$propValue</span></div>"
    }
    $html += "</div>"; return $html
}

# Helper function to create sections with preformatted text
function ConvertTo-HtmlPreFragment {
    param(
        [Parameter(Mandatory=$true)] [string]$InputText,
        [string]$Title
    )
    $html = ""; if ($Title) { $html += "<h3>$Title</h3>" }
    if ([string]::IsNullOrWhiteSpace($InputText)) { $encodedText = "N/A" }
    else { $encodedText = [System.Web.HttpUtility]::HtmlEncode($InputText) }
    $html += "<pre>$encodedText</pre>"; return $html
}

# Helper function to create HTML tables from arrays, handling errors
function ConvertTo-HtmlTableFragment {
    param(
        [Parameter(Mandatory=$true)] $InputArray,
        [string]$Title
    )
    $html = ""; if ($Title) { $html += "<h3>$Title</h3>" }
    if ($InputArray -is [hashtable] -and $InputArray.ContainsKey('Error')) {
        $html += "<p class='error-message'>Error: $($InputArray['Error'])</p>"
    } elseif ($InputArray -ne $null -and $InputArray.Count -gt 0) {
        $html += "<div class='table-container'>"
       if ($InputArray -is [PSCustomObject] -and -not($InputArray -is [array])) {
            $html += @($InputArray) | Select-Object * | ConvertTo-Html -Fragment
        } elseif ($InputArray -is [array] -and $InputArray.Count -gt 0 -and $InputArray[0] -is [psobject]) {
            $html += $InputArray | Select-Object * | ConvertTo-Html -Fragment
        } else {
            $html += $InputArray | ConvertTo-Html -Fragment
        }
        $html += "</div>"
    } elseif ($InputArray -eq $null) {
         $html += "<p>No data found (variable is null).</p>"
    } else { # $InputArray.Count -eq 0
        $html += "<p>No data found (array is empty).</p>"
    }
    return $html
}


# Convert the various sections to HTML fragments.
$osHtml = ConvertTo-HtmlListFragment -InputObject $osInfo -Title '<span style="font-size: 1.2em; margin-right: 8px;">🖥️</span>Operating System'
$compSysHtml = ConvertTo-HtmlListFragment -InputObject $compSysInfo -Title '<span style="font-size: 1.2em; margin-right: 8px;">⚙️</span>System & Domain (General)'
$biosHtml = ConvertTo-HtmlListFragment -InputObject $biosInfo -Title '<span style="font-size: 1.2em; margin-right: 8px;">💾</span>BIOS'
$processorHtml = $processorInfo | ConvertTo-Html -Fragment -PreContent '<h2><span style="font-size: 1.2em; margin-right: 8px;">🧠</span>Processor(s)</h2>'
$pageFileHtml = $pageFileInfo | ConvertTo-Html -Fragment -PreContent '<h3>Paging File</h3>'
$networkHtml = ConvertTo-HtmlTableFragment -InputArray $networkInfo -Title '<span style="font-size: 1.2em; margin-right: 8px;">📶</span>Network Configuration (Active Adapters)'
$hotfixHtml = ConvertTo-HtmlTableFragment -InputArray $hotfixInfo -Title '<span style="font-size: 1.2em; margin-right: 8px;">🩹</span>Installed Hotfixes (wmic qfe equivalent)'
$psInfoHtml = ConvertTo-HtmlListFragment -InputObject $psInfo -Title '<span style="font-size: 1.2em; margin-right: 8px;">🚀</span>PowerShell Information & Security'
$psModulesHtml = ConvertTo-HtmlTableFragment -InputArray $psModules -Title '<h3>Loaded Modules</h3>'
$envVarsHtml = ConvertTo-HtmlTableFragment -InputArray $envVars -Title '<span style="font-size: 1.2em; margin-right: 8px;">🌳</span>Environment Variables'

# Convert defense check output
$firewallHtml = ConvertTo-HtmlPreFragment -InputText $firewallStatus -Title 'Firewall Status (netsh advfirewall show allprofiles)'
$defenderServiceHtml = ConvertTo-HtmlPreFragment -InputText $defenderServiceStatus -Title 'WinDefend Service Status (sc query windefend)'
$defenderDetailedHtml = ConvertTo-HtmlListFragment -InputObject $defenderDetailedStatus -Title 'Windows Defender Detailed Status (Get-MpComputerStatus)'

# Convert connected users and additional network info output
$loggedInUsersHtml = ConvertTo-HtmlPreFragment -InputText $loggedInUsers -Title 'Logged-in Users (qwinsta / query user)'
$arpTableHtml = ConvertTo-HtmlPreFragment -InputText $arpTable -Title 'ARP Table (arp -a)'
$routingTableHtml = ConvertTo-HtmlPreFragment -InputText $routingTable -Title 'IPv4 Routing Table (route print)'

# Convert WMI output
$wmiCompSysHtml = ConvertTo-HtmlListFragment -InputObject $wmiCompSys -Title 'Computer System (Win32_ComputerSystem - Specific Data)'
$ntDomainHtml = ConvertTo-HtmlTableFragment -InputArray $ntDomainInfo -Title 'Detected NT Domains (Win32_NTDomain)'
$allUsersHtml = ConvertTo-HtmlTableFragment -InputArray $allUsers -Title 'All User Accounts (Win32_UserAccount)'
$localGroupsWmiHtml = ConvertTo-HtmlTableFragment -InputArray $localGroupsWmi -Title 'Local Groups (Win32_Group)'
$sysAccountsHtml = ConvertTo-HtmlTableFragment -InputArray $sysAccounts -Title 'System Accounts (Win32_SystemAccount)'
$processesHtml = ConvertTo-HtmlTableFragment -InputArray $runningProcesses -Title 'Running Processes (Win32_Process)'

# Convert Net Command Equivalents output
$adWarningNetHtml = "" # Renamed to avoid conflicts
if (-not $adModuleAvailable) { $adWarningNetHtml = "<p class='module-warning'>Active Directory module not found. Domain information may be incomplete or missing.</p>" }
elseif ($adErrorNet) { $adWarningNetHtml = "<p class='error-message'>$adErrorNet</p>" } # Use renamed variable
$domainPolicyHtml = ConvertTo-HtmlListFragment -InputObject $domainPasswordPolicy -Title 'Domain Password Policy (Get-ADDefaultDomainPasswordPolicy)'
$domainGroupsHtml = ConvertTo-HtmlTableFragment -InputArray $domainGroups -Title 'Domain Groups (Get-ADGroup)'
$domainAdminsHtml = ConvertTo-HtmlTableFragment -InputArray $domainAdmins -Title 'Domain Admins Members (Get-ADGroupMember)'
$domainControllersHtml = ConvertTo-HtmlTableFragment -InputArray $domainControllers -Title 'Domain Controllers (Get-ADGroupMember)'
$domainComputersHtml = ConvertTo-HtmlTableFragment -InputArray $domainComputers -Title 'Domain Computers (Get-ADComputer)'
$domainUsersHtml = ConvertTo-HtmlTableFragment -InputArray $domainUsers -Title 'Domain Users (Get-ADUser - first 100)'
$localGroupsNetHtml = ConvertTo-HtmlTableFragment -InputArray $localGroupsNet -Title 'Local Groups (Get-LocalGroup)'
$localAdminsNetHtml = ConvertTo-HtmlTableFragment -InputArray $localAdminsNet -Title 'Local Administrators Members (Get-LocalGroupMember)'
$smbSharesHtml = ConvertTo-HtmlTableFragment -InputArray $smbShares -Title 'Local SMB Shares (Get-SmbShare)'
$netViewHtml = ConvertTo-HtmlPreFragment -InputText $netViewOutput -Title 'Network View (net view)'

# Convert Dsquery Equivalents output
$dsQueryWarningHtml = ""
if (-not $adModuleAvailable) { $dsQueryWarningHtml = "<p class='module-warning'>Active Directory module not found. Unable to execute Dsquery equivalents.</p>" }
elseif ($dsQueryError) { $dsQueryWarningHtml = "<p class='error-message'>$dsQueryError</p>" }
# Add the new tables
$dsQueryAllUsersHtml = ConvertTo-HtmlTableFragment -InputArray $dsQueryAllUsers -Title 'All Domain Users (DN)'
$dsQueryAllComputersHtml = ConvertTo-HtmlTableFragment -InputArray $dsQueryAllComputers -Title 'All Domain Computers (DN)'
# Handle specific error for this table
if ($dsQueryUsersInUsersOU -is [hashtable] -and $dsQueryUsersInUsersOU.ContainsKey('Error')) {
    $dsQueryUsersOUHtml = "<p class='error-message'>Error: $($dsQueryUsersInUsersOU['Error'])</p>"
} else {
    $dsQueryUsersOUHtml = ConvertTo-HtmlTableFragment -InputArray $dsQueryUsersInUsersOU -Title 'Objects in Users Container (Get-ADObject)'
}
$dsQueryPasswdNotReqdHtml = ConvertTo-HtmlTableFragment -InputArray $dsQueryPasswdNotReqd -Title 'Users with Password Not Required (Get-ADUser - UAC 32)'
$dsQueryComputersHtml = ConvertTo-HtmlTableFragment -InputArray $dsQueryComputersLimit5 -Title 'First 5 Computer Accounts (Get-ADComputer - UAC 8192)'


# Combine the HTML fragments into a complete document.
$reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$htmlBody = "
<h1><span style='font-size: 1.5em; margin-right: 10px;'>📊</span> Detailed System Information Report ($($env:COMPUTERNAME))</h1>
<p style='text-align:center;'>Report generated on: $reportDate</p>

<div class='section'>
    <h2><span style='font-size: 1.2em; margin-right: 8px;'>ℹ️</span>General Information</h2>
    $osHtml
    $compSysHtml $biosHtml
    $pageFileHtml
</div>

<div class='section'>
    $processorHtml
</div>

<div class='section'>
    $networkHtml
</div>

<div class='section'>
    <h2><span style='font-size: 1.2em; margin-right: 8px;'>🧑‍💻</span>Connected Users and Additional Network Info</h2>
    $loggedInUsersHtml
    $arpTableHtml
    $routingTableHtml
</div>

<div class='section'>
    <h2><span style='font-size: 1.2em; margin-right: 8px;'>⚙️</span>WMI Information</h2>
    $wmiCompSysHtml
    $ntDomainHtml $allUsersHtml $localGroupsWmiHtml
    $sysAccountsHtml $processesHtml
</div>

<div class='section'>
    <h2><span style='font-size: 1.2em; margin-right: 8px;'>🌐</span>Net Command Equivalents (Active Directory & Local)</h2>
    $adWarningNetHtml $domainPolicyHtml
    $domainGroupsHtml
    $domainAdminsHtml
    $domainControllersHtml
    $domainComputersHtml
    $domainUsersHtml
    $localGroupsNetHtml
    $localAdminsNetHtml
    $smbSharesHtml
    $netViewHtml
</div>

<div class='section'>
    <h2><span style='font-size: 1.2em; margin-right: 8px;'>🔍</span>Dsquery Equivalents (Active Directory)</h2>
    $dsQueryWarningHtml
    $dsQueryAllUsersHtml $dsQueryAllComputersHtml $dsQueryUsersOUHtml $dsQueryPasswdNotReqdHtml
    $dsQueryComputersHtml
</div>

<div class='section'>
    $hotfixHtml
</div>

<div class='section'>
    $psInfoHtml
    $psModulesHtml
</div>

<div class='section'>
    <h2><span style='font-size: 1.2em; margin-right: 8px;'>🛡️</span>Local Defenses Check</h2>
    $firewallHtml
    $defenderServiceHtml
    $defenderDetailedHtml
</div>

<div class='section'>
    $envVarsHtml
</div>
"
# Create the complete HTML
$htmlOutput = ConvertTo-Html -Head "<title>System Information Report - $($env:COMPUTERNAME)</title>$css" -Body $htmlBody

# --- Export to HTML ---
# Define the output file path in the root of C:\.
# WARNING: This may require administrator privileges to write to C:\.
$outputFilePath = "C:\SystemInfo.html"

# Save the HTML string to the specified file, using UTF8 encoding.
# Use a try-catch block to handle potential permission errors.
try {
    Add-Type -AssemblyName System.Web
    $htmlOutput | Out-File -FilePath $outputFilePath -Encoding UTF8 -ErrorAction Stop
    Write-Host "System information gathered and successfully exported to the HTML file: '$outputFilePath'" -ForegroundColor Green
} catch [System.UnauthorizedAccessException] {
    Write-Error "Error: Access denied. Unable to write to '$outputFilePath'. Try running the script as an administrator."
} catch {
    Write-Error "Error saving HTML file: $($_.Exception.Message)"
}

Write-Host "Script completed."
