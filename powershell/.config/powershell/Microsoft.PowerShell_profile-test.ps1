<#
    .SYNOPSIS
        J-Dub's GitHub Central PowerShell Profile
    .DESCRIPTION
        Default name of the PS Profile loading this is: Microsoft.Powershell_profile.ps1
    
    	OS Platform True/False Check Variables are: $IsMacOS, $IsLinux, and $IsWindows  
    	  
        Locations of this Profile depending on OS:
        Windows - $Home\[My ]Documents\PowerShell\Microsoft.PowerShell_profile.ps1
		Linux - ~/.config/powershell/Microsoft.Powershell_profile.ps1
		macOS - ~/.config/powershell/Microsoft.Powershell_profile.ps1
		
		The profile paths include the following variables:
		The $PSHOME variable, which stores the installation directory for PowerShell
		The $Home variable, which stores the current user's home directory
		Current User, All Hosts - $PROFILE.CurrentUserAllHosts
		Current User, Current Host - $PROFILE.CurrentUserCurrentHost or just $PROFILE
		
		Many aliases & functions were sourced from:
		https://gist.github.com/apfelchips/62a71500a0f044477698da71634ab87b
		
    .NOTES
        Julian West
        julianwest.me
        @julian_west
#>
# This is my GitHub Remote PS Profile - which is cached & called by my local $Profile.CurrentUserAllHosts PS Profile script



#src: https://stackoverflow.com/a/34098997/7595318
function Test-IsInteractive {
    # Test each Arg for match of abbreviated '-NonInteractive' command.
    $NonInteractiveFlag = [Environment]::GetCommandLineArgs() | Where-Object{ $_ -like '-NonInteractive' }
    if ( (-not [Environment]::UserInteractive) -or ( $NonInteractiveFlag -ne $null ) ) {
        return $false
    }
    return $true
}


if ( Test-IsInteractive ) {
# Clear-Host # remove advertisements (preferably use -noLogo)

#########################
# WINDOWS, PATH, HELP   #
#########################
#On MacOS the Default Modules Path is /usr/local/microsoft/powershell/7/Modules
#On Windows the Default Modules Path is C:\Windows\System32\WindowsPowerShell\v1.0\Modules
#On Linux the Default Modules Path is /usr/share/powershell/Modules

If($IsMacOS -eq $true){$env:USERPROFILE=$home}

if ($IsMacOS -eq $true) {
    if (Test-Path $env:USERPROFILE/OneDrive) { $OneDriveRoot = "$env:USERPROFILE/OneDrive" }
}elseif($IsMacOS -eq $true){
    if (Test-Path $env:USERPROFILE\OneDrive) { $OneDriveRoot = "$env:USERPROFILE\OneDrive" }
    <# Action when this condition is true #>
}else {
}

# Refresh my local help
Start-Job -Name "UpdateHelp" -ScriptBlock { Update-Help -Force } | Out-Null
Write-Host "Updating Help in background (Get-Help to check)" -ForegroundColor Yellow

# Show PS Version and date/time
Write-Host "PowerShell Version: $($psversiontable.psversion) - ExecutionPolicy: $(Get-ExecutionPolicy)" -ForegroundColor yellow

# Set Path to Github
Set-Location $home\onedrive\development\github

If  ($IsWindows -eq $true) {
# Check Admin Elevation
$WindowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$WindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($WindowsIdentity)
$Administrator = [System.Security.Principal.WindowsBuiltInRole]::Administrator
$IsAdmin = $WindowsPrincipal.IsInRole($Administrator)

# Custom Window
#  Set Window Title
    if ($isAdmin)
    {
     $host.UI.RawUI.WindowTitle = "Administrator: $ENV:USERNAME@$ENV:COMPUTERNAME - $env:userdomain"
    
    }else{
    $host.UI.RawUI.WindowTitle = "$ENV:USERNAME@$ENV:COMPUTERNAME - $env:userdomain"
    }
}


###############
# CREDENTIALS #
###############
# Set default variables
$adminUPN = "jwest@mckoolsmith.onmicrosoft.com"
$sharepointAdminUrl = "https://mckoolsmith.sharepoint.com"


###########
# ALIASES #
###########

Set-Alias env        Get-Environment -Option AllScope

# custom aliases

If($IsMacOS -eq $true) {

Set-Alias flush-dns  Clear-DnsClientCache -Option AllScope
# bash-like
Set-Alias cat        Get-Content -Option AllScope
Set-Alias cd         Set-Location -Option AllScope
Set-Alias clear      Clear-Host -Option AllScope
Set-Alias cp         Copy-Item -Option AllScope
Set-Alias history    Get-History -Option AllScope
Set-Alias kill       Stop-Process -Option AllScope
Set-Alias lp         Out-Printer -Option AllScope
#Set-Alias ls         Get-Childitem -Option AllScope
Set-Alias ll         Get-Childitem -Option AllScope
Set-Alias mv         Move-Item -Option AllScope
Set-Alias ps         Get-Process -Option AllScope
Set-Alias pwd        Get-Location -Option AllScope
Set-Alias which      Get-Command -Option AllScope

Set-Alias open       Invoke-Item -Option AllScope
Set-Alias basename   Split-Path -Option AllScope
Set-Alias realpath   Resolve-Path -Option AllScope

# cmd-like
Set-Alias rm         Remove-Item -Option AllScope
Set-Alias rmdir      Remove-Item -Option AllScope
Set-Alias echo       Write-Output -Option AllScope
Set-Alias cls        Clear-Host -Option AllScope

Set-Alias chdir      Set-Location -Option AllScope
Set-Alias copy       Copy-Item -Option AllScope
Set-Alias del        Remove-Item -Option AllScope
Set-Alias dir        Get-Childitem -Option AllScope
Set-Alias erase      Remove-Item -Option AllScope
Set-Alias move       Move-Item -Option AllScope
Set-Alias rd         Remove-Item -Option AllScope
Set-Alias ren        Rename-Item -Option AllScope
Set-Alias set        Set-Variable -Option AllScope
Set-Alias type       Get-Content -Option AllScope

}

If  ($IsWindows -eq $true) {
Set-Alias -Name npp -Value notepad++.exe
Set-Alias -Name np -Value notepad.exe
}


##########
# MODULE #
##########

#  PSReadLine
Import-Module -Name PSReadline

if (Get-Module -name PSReadline) {
    # Set Shortcuts for History Search
    #  Start typing, for example "Get-" then press up and down arrow, it'll show all
    #  commands in my story that started by "Get-"
    Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
    Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
    Set-PSReadlineOption -EditMode Windows
}


#############
# Functions #
#############

# This will change the prompt
#function prompt {
    #Get-location
#    Write-Output "PS [julianwest.me]> "
#}


# The $global:lastHistoryCount variable is used by the prompt() function.
# The prompt() function determines how your command prompt is formatted.
$global:lastHistoryCount = 0 
function prompt 
{ 
    if ( @(Get-History).Count -ne $global:lastHistoryCount ) 
    { 
        $timer = '{0:0.000}' -f $(New-TimeSpan -Start ((Get-History)[-1]).StartExecutionTime -End ((Get-History)[-1]).EndExecutionTime).TotalSeconds 
        $global:lastHistoryCount = @(Get-History).Count
    }
    else 
    {
        $timer = '0.000'
    } 

    "[$timer] " + $($executionContext.SessionState.Path.CurrentLocation).Path + '> ' 
}

# Replicate bash aliases here as functions:
#function ll { ls -Flash } 
#function py { ping -c 2 www.yahoo.com | egrep 'bytes' } 

# Get the current script directory

function Get-ScriptDirectory{
    # If PSScriptRoot is set, simply return its value
    if ($global:PSScriptRoot){
        return $global:PSScriptRoot
    }else{
        # If the script file is running from the ISE
        if ($psise){
            # Create/set the global $PSScriptRoot variable from the $psise automatic variable
            $global:PSScriptRoot = $psise.CurrentFile.FullPath | Split-Path
        }else{
            # Create/set the global $PSScriptRoot variable from the $MyInvocation automatic variable
            $global:PSScriptRoot = $MyInvocation.MyCommand.Definition | Split-Path
        }

        # Return the determined script path
        return $global:PSScriptRoot
    }
}


#src: https://devblogs.microsoft.com/scripting/use-a-powershell-function-to-see-if-a-command-exists/
function Test-CommandExists {
    Param ($command)
    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try { Get-Command $command; return $true }
    catch {return $false}
    finally { $ErrorActionPreference=$oldErrorActionPreference }
}

function Get-ModulesAvailable {
    if ( $args.Count -eq 0 ) {
        Get-Module -ListAvailable
    } else {
        Get-Module -ListAvailable $args
    }
}

function Get-DefaultAliases {
    Get-Alias | Where-Object { $_.Options -match "ReadOnly" }
}

function Remove-CustomAliases { # https://stackoverflow.com/a/2816523
    Get-Alias | Where-Object { ! $_.Options -match "ReadOnly" } | % { Remove-Item alias:$_ }
}

function set-x {
    Set-PSDebug -trace 2
}

function set+x {
    Set-PSDebug -trace 0
}

function Get-Environment {  # Get-Variable to show all Powershell Variables accessible via $
    if ( $args.Count -eq 0 ) {
        Get-Childitem env:
    } elseif( $args.Count -eq 1 ) {
        Start-Process (Get-Command $args[0]).Source
    } else {
        Start-Process (Get-Command $args[0]).Source -ArgumentList $args[1..($args.Count-1)]
    }
}

function .. { Set-Location ".." }
function .... { Set-Location (Join-Path -Path ".." -ChildPath "..") }

function TryImport-Module{
    param(
        [parameter(Mandatory = $true)][string] $name
    )

    $retVal = $true

    if (!(Get-Module -Name $name)){
        $retVal = Get-Module -ListAvailable | where { $_.Name -eq $name }
		if ($retVal){
            try{
                Import-Module $name -ErrorAction SilentlyContinue
            }catch{
                $retVal = $false
            }
        }
    }
	return $retVal
}


function Select-Value { # src: https://geekeefy.wordpress.com/2017/06/26/selecting-objects-by-value-in-powershell/
    [Cmdletbinding()]
    param(
        [parameter(Mandatory=$true)] [String] $Value,
        [parameter(ValueFromPipeline=$true)] $InputObject
    )
    process {
        # Identify the PropertyName for respective matching Value, in order to populate it Default Properties
        $Property = ($PSItem.properties.Where({$_.Value -Like "$Value"})).Name
        If ( $Property ) {
            # Create Property a set which includes the 'DefaultPropertySet' and Property for the respective 'Value' matched
            $DefaultPropertySet = $PSItem.PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames
            $TypeName = ($PSItem.PSTypenames)[0]
            Get-TypeData $TypeName | Remove-TypeData
            Update-TypeData -TypeName $TypeName -DefaultDisplayPropertySet ($DefaultPropertySet+$Property |Select-Object -Unique)

            $PSItem | Where-Object {$_.properties.Value -like "$Value"}
        }
    }
}

function all {
    process { $_ | Select-Object * }
}

function list { # fl is there by default
    process { $_ | Format-List * }
}

function string {
    process { $_ | Out-String -Stream }
}

function grep {
    process { $_ | Select-String -Pattern $args }
}

function man {
    Get-Help $args[0] | out-host -paging
}

function mkdir {
    New-Item -type directory -path (Join-Path "$args" -ChildPath "")
}

function md {
    New-Item -type directory -path (Join-Path "$args" -ChildPath "")
}


function pause($message="Press any key to continue . . . ") {
    Write-Host -NoNewline $message
    $i=16,17,18,20,91,92,93,144,145,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183
    while ($k.VirtualKeyCode -eq $null -or $i -Contains $k.VirtualKeyCode){
        $k = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    Write-Host ""
}

# native touch implementation
# src: https://ss64.com/ps/syntax-touch.html
function Set-FileTime {
    param(
        [string[]]$paths,
        [bool]$only_modification = $false,
        [bool]$only_access = $false
    )

    begin {
        function updateFileSystemInfo([System.IO.FileSystemInfo]$fsInfo) {
            $datetime = Get-Date
            if ( $only_access ) {
                $fsInfo.LastAccessTime = $datetime
            } elseif ( $only_modification ) {
                $fsInfo.LastWriteTime = $datetime
            } else {
                $fsInfo.CreationTime = $datetime
                $fsInfo.LastWriteTime = $datetime
                $fsInfo.LastAccessTime = $datetime
            }
        }

        function touchExistingFile($arg) {
            if ( $arg -is [System.IO.FileSystemInfo] ) {
                    updateFileSystemInfo($arg)
                } else {
                $resolvedPaths = Resolve-Path $arg
                foreach ($rpath in $resolvedPaths) {
                    if ( Test-Path -type Container $rpath ) {
                        $fsInfo = New-Object System.IO.DirectoryInfo($rpath)
                    } else {
                        $fsInfo = New-Object System.IO.FileInfo($rpath)
                    }
                    updateFileSystemInfo($fsInfo)
                }
            }
        }

        function touchNewFile([string]$path) {
            #$null > $path
            Set-Content -Path $path -value $null;
        }
    }

    process {
        if ( $_ ) {
            if ( Test-Path $_ ) {
                touchExistingFile($_)
            } else {
                touchNewFile($_)
            }
        }
    }

    end {
        if ( $paths ) {
            foreach ( $path in $paths ) {
                if ( Test-Path $path ) {
                    touchExistingFile($path)
                } else {
                    touchNewFile($path)
                }
            }
        }
    }
}
Set-Alias touch Set-FileTime -Option AllScope

function Reload-Profile {
    . $PROFILE.CurrentUserCurrentHost
}


function Install-MyModules {
    PowerShellGet\Install-Module -Name PSReadLine -Scope CurrentUser -AllowPrerelease -Force -AllowClobber
    PowerShellGet\Install-Module -Name posh-git -Scope CurrentUser -Force -AllowClobber
    PowerShellGet\Install-Module -Name PSFzf -Scope CurrentUser -Force -AllowClobber

    PowerShellGet\Install-Module -Name PSProfiler -Scope CurrentUser -Force -AllowClobber # --> Measure-Script

    # serialization tools: eg. ConvertTo-HashString / ConvertTo-HashTable https://github.com/torgro/HashData
    PowerShellGet\Install-Module -Name hashdata -Scope CurrentUser -Force -AllowClobber

    # useful Tools eg. ConvertTo-FlatObject, Join-Object... https://github.com/RamblingCookieMonster/PowerShell
    PowerShellGet\Install-Module -Name WFTools -Scope CurrentUser -Force -AllowClobber

    # https://old.reddit.com/r/AZURE/comments/fh0ycv/azuread_vs_azurerm_vs_az/
    # https://docs.microsoft.com/en-us/microsoft-365/enterprise/connect-to-microsoft-365-powershell
    PowerShellGet\Install-Module -Name AzureAD -Scope CurrentUser -Force -AllowClobber

    PowerShellGet\Install-Module -Name SqlServer -Scope CurrentUser -Force -AllowClobber

    if ( $IsWindows ){
        # Windows Update CLI tool http://woshub.com/pswindowsupdate-module/#h2_2
        # Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
        # native alternative: WindowsUpdateProvider\Install-WUUpdates >= Windows Server 2019
        PowerShellGet\Install-Module -Name PSWindowsUpdate -Scope CurrentUser -Force -AllowClobber
    }
}

function Import-MyModules {
    TryImport-Module PSProfiler
    TryImport-Module hashdata
    TryImport-Module WFTools
    TryImport-Module AzureAD
    TryImport-Module SqlServer
    TryImport-Module PSWindowsUpdate
}

# Display IPv4 cheat sheet
function cheat-ipv4
{
$cheat = @'

CIDR    Mask        # of Networks   #  of Hosts
/1      128.0.0.0       128 A       2,147,483,392
/2      192.0.0.0       64          1,073,741,696
/3      224.0.0.0       32          536,870,848
/4      240.0.0.0       16          268,435,424
/5      248.0.0.0       8 A         134,217,712
/6      252.0.0.0       4 A         67,108,856
/7      254.0.0.0       2 A         33,554,428
/8      255.0.0.0       1 A         16,777,214
/9      255.128.0.0     128 B       8,388,352
/10     255.192.0.0     64 B        4,194,176
/11     255.224.0.0     32 B        2,097,088
/12     255.240.0.0     16 B        1,048,544
/13     255.248.0.0     8 B         524,772
/14     255.252.0.0     4 B         262,136
/15     255.254.0.0     2 B         131,068
/16     255.255.0.0     1 B         65,024
/17     255.255.128.0   128 C       32,512
/18     255.255.192.0   64 C        16,256
/19     255.255.224.0   32 C        8,128
/20     255.255.240.0   16 C        4,064
/21     255.255.248.0   8 C         2,032
/22     255.255.252.0   4 C         1,016
/23     255.255.254.0   2 C         508
/24     255.255.255.0   1 C         254
/25     255.255.255.128 2 subnets   124
/26     255.255.255.192	4 subnets   62
/27     255.255.255.224	8 subnets   30
/28     55.255.255.240	16 subnets  14
/29     255.255.255.248	32          6
/30     255.255.255.252	64          2
/31     255.255.255.254	none        none
/32     255.255.255.255	none        1

***Address Scopes***
127.0.0.0       Loopback
0.0.0.0         Default Route
224.0.0.0       Local Multicast (well-known)
224.0.1.0       Internetwork control
232.0.0.0       Source-specific multicast
239.0.0.0       Admin-scopped Multicast


Binary      0   0   0   0   0   0   0   0
Decimal     128	64  32  16  8   4   2   1

Decimal     8 Bit Binary        Binary
2           0 0 0 0 0 0 1 0     10
37          0 0 1 0 0 1 0 1     100101
98          0 1 1 0 0 0 1 0     1100010
200         1 1 0 0 1 0 0 0     11001000
255         1 1 1 1 1 1 1 1     11111111

***Ports and Services***
Link-Local          Multicast Name Resolution (LLMNR)
LLMNR uses          224.0.0.252 on UDP/TCP/5355
mdnsresponder       Multicast Name Resolution (Multicast DNS Responder IPC)
mdnsresponder uses  224.0.0.251 on UDP/TCP/5354

DHCP Client = UDP/68
DHCP Server = UDP/67 

'@

"`n $cheat `n"
}

# Display IPv6 cheat sheet
function cheat-ipv6
{
$cheat = @'

***CIDR Masks***                             Colon Groups:
FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF/128     (8/8)
FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:0000/112     (7/8) 
FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:0000:0000/96      (6/8)
FFFF:FFFF:FFFF:FFFF:FFFF:0000:0000:0000/80      (5/8)
FFFF:FFFF:FFFF:FFFF:0000:0000:0000:0000/64      (4/8)
FFFF:FFFF:FFFF:0000:0000:0000:0000:0000/48      (3/8)
FFFF:FFFF:0000:0000:0000:0000:0000:0000/32      (2/8)
FFFF:0000:0000:0000:0000:0000:0000:0000/16      (1/8)
FF00:0000:0000:0000:0000:0000:0000:0000/8    
FE00:0000:0000:0000:0000:0000:0000:0000/7    

***Address Scopes***
::1/128         Loopback
::/0            Default Route
::/128          Unspecified
2001:0000:/32   Teredo
2002:/16        6to4
FC00:/7         Unique Local Unicast (Always FD00:/8 in practice)
FD00:/8         Unique Local Unicast (Locally-Assigned Random)
FE80:/10        Link-Local Unicast
FF00:/8         Multicast

***Multicast Scopes***
[After "FF", flags nibble, then scope nibble.]
FF00:Reserved               FF01:Interface-Local        
FF02:Link-Local             FF03:Reserved
FF04:Admin-Local            FF05:Site-Local
FF06:Unassigned             FF07:Unassigned
FF08:Organization-Local     FF09:Unassigned
FF0A:Unassigned             FF0B:Unassigned
FF0C:Unassigned             FF0D:Unassigned
FF0E:Global                 FF0F:Reserved

***Ports and Services***
Link-Local Multicast Name Resolution (LLMNR)
LLMNR uses FF02::1:3 on UDP/TCP/5355

DHCPv6 Client = UDP/546
DHCPv6 Server = UDP/547 

'@

"`n $cheat `n"
}



# Display regular expressions cheat sheet
function cheat-regex
{
$rx = @'

^      Start of string
$      End of string
*      Zero or more of prior
+      One or more of prior
?      One or zero or prior
.      Just one right here

{2}    Exactly two of prior
{4,}   Four or more
{1,7}  One to seven

[xy]   Match alternatives
[^xy]  Negative match
[a-z]  Range 
[^a-z] Negative range 

(x|y)  x or y in submatch

\      Literal escape
\t     Tab
\n     New line
\r     Carriage return
\f     Form feed
\w     Word = [A-Za-z0-9_]
\W     Non-word = [^A-Za-z0-9_]
\s     White space = [ \f\n\r\t\v]
\S     Non-white space = [^ \f\n\r\t\v]
\d     Digit = [0-9]
\D     Non-digit = [^0-9]

'@

$rx 
}

if ( -not $IsWindows ) {
    function Test-IsAdmin {
        if ( (id -u) -eq 0 ) {
            return $true
        }
        return $false
    }
}

if ( $IsWindows ) {
    # src: http://serverfault.com/questions/95431
    function Test-IsAdmin {
        $user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return $(New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }

    function Restart-Explorer {
        Get-Process explorer | Stop-Process
        Start-Process "$(Get-HostExecutable)" -ArgumentList "-noProfile -noLogo -Command 'Get-Process explorer | Stop-Process'" -verb "runAs"
    }

    function Reset-Spooler {
        Start-Process "$(Get-HostExecutable)" -ArgumentList "-noProfile -noLogo -Command 'Stop-Service -Name Spooler -Force; Get-Item ${env:SystemRoot}\System32\spool\PRINTERS\* | Remove-Item -Force -Recurse; Start-Service -Name Spooler'" -verb "runAs"
    }

    function subl {
        Start-Process "${Env:ProgramFiles}\Sublime Text\subl.exe" -ArgumentList $args -WindowStyle Hidden # hide subl shim script
    }

    function stree($directory = $pwd) {
        $gitrootdir = (Invoke-Command{Set-Location $args[0]; git rev-parse --show-toplevel 2>&1;} -ArgumentList $directory)

        if ( Test-Path -Path "$gitrootdir\.git" -PathType Container) {
            $newestExe = Get-Item "${env:ProgramFiles(x86)}\Atlassian\SourceTree\SourceTree.exe" | select -Last 1
            Write-Debug "Opening $gitrootdir with $newestExe"
            Start-Process -filepath $newestExe -ArgumentList "-f `"$gitrootdir`" log"
        } else {
            Write-Error "git directory not found"
        }
    }
    if ( "${env:ChocolateyInstall}" -eq "" ) {
        function Install-Chocolatey {
            if (Get-Command choco -ErrorAction SilentlyContinue) {
                Write-Error "chocolatey already installed!"
            } else {
                Start-Process (Get-HostExecutable) -ArgumentList "-Command Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1') -verb RunAs"
            }
        }
    } else {
        function choco {
            Start-Process (Get-HostExecutable) -ArgumentList "-noProfile -noLogo -Command choco.exe ${args}; pause" -verb runAs
        }
    }

    TryImport-Module "${env:ChocolateyInstall}\helpers\chocolateyProfile.psm1"
}

function Get-HostExecutable {
    if ( $PSVersionTable.PSEdition -eq "Core" ) {
        $ConsoleHostExecutable = (get-command pwsh).Source
    } else {
        $ConsoleHostExecutable = (get-command powershell).Source
    }
    return $ConsoleHostExecutable
}

# don't override chocolatey sudo or unix sudo
if ( -not $(Test-CommandExists 'sudo') ) {
    function sudo() {
        if ( $args.Length -eq 0 ) {
            Start-Process $(Get-HostExecutable) -verb "runAs"
        } elseif ( $args.Length -eq 1 ) {
            Start-Process $args[0] -verb "runAs"
        } else {
            Start-Process $args[0] -ArgumentList $args[1..$args.Length] -verb "runAs"
        }
    }
}

function Clear-SavedHistory { # src: https://stackoverflow.com/a/38807689
  [CmdletBinding(ConfirmImpact='High', SupportsShouldProcess)]
  param()
  $havePSReadline = ( $(Get-Module PSReadline -ea SilentlyContinue) -ne $null )
  $target = if ( $havePSReadline ) { "entire command history, including from previous sessions" } else { "command history" }
  if ( -not $pscmdlet.ShouldProcess($target) ) { return }
  if ( $havePSReadline ) {
        Clear-Host
        # Remove PSReadline's saved-history file.
        if ( Test-Path (Get-PSReadlineOption).HistorySavePath ) {
            # Abort, if the file for some reason cannot be removed.
            Remove-Item -ea Stop (Get-PSReadlineOption).HistorySavePath
            # To be safe, we recreate the file (empty).
            $null = New-Item -Type File -Path (Get-PSReadlineOption).HistorySavePath
        }
        # Clear PowerShell's own history
        Clear-History
        [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()
    } else { # Without PSReadline, we only have a *session* history.
        Clear-Host
        Clear-History
    }
}

if ( ($host.Name -eq 'ConsoleHost') -and ($null -ne (Get-Module -ListAvailable -Name PSReadLine)) ) {
    # example: https://github.com/PowerShell/PSReadLine/blob/master/PSReadLine/SamplePSReadLineProfile.ps1
    TryImport-Module PSReadLine

    # Set-PSReadLineOption -EditMode Emac
    Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete

    Set-PSReadLineOption -HistorySearchCursorMovesToEnd
    Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
    Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
    Set-PSReadlineKeyHandler -Chord 'Shift+Tab' -Function Complete

    if ( $(Get-Module PSReadline).Version -ge 2.2 ) {
        Set-PSReadLineOption -predictionsource history -ea SilentlyContinue
    }

    if ( $(Get-Module PSFzf) -ne $null ) {
        #Set-PSReadLineKeyHandler -Key Tab -ScriptBlock { Invoke-FzfTabCompletion }
        #$FZF_COMPLETION_TRIGGER='...'
        Set-PsFzfOption -PSReadlineChordProvider 'Ctrl+t' -PSReadlineChordReverseHistory 'Ctrl+r'
    }
}

if ( ($host.Name -eq 'ConsoleHost') -and ($null -ne (Get-Module -ListAvailable -Name posh-git)) ) {
        TryImport-Module posh-git
}

# already expanded to save time https://github.com/nvbn/thefuck/wiki/Shell-aliases#powershell
if ( $(Test-CommandExists 'thefuck') ) {
    function fuck {
        $PYTHONIOENCODING_BKP=$env:PYTHONIOENCODING
        $env:PYTHONIOENCODING="utf-8"
        $history = (Get-History -Count 1).CommandLine

        if (-not [string]::IsNullOrWhiteSpace($history)) {
            $fuck = $(thefuck $args $history)
            if ( -not [string]::IsNullOrWhiteSpace($fuck) ) {
                if ( $fuck.StartsWith("echo") ) { $fuck = $fuck.Substring(5) } else { iex "$fuck" }
            }
        }
        [Console]::ResetColor()
        $env:PYTHONIOENCODING=$PYTHONIOENCODING_BKP
    }
    Set-Alias f fuck -Option AllScope
}


Write-Host "PSVersion: $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor).$($PSVersionTable.PSVersion.Patch)"
Write-Host "PSEdition: $($PSVersionTable.PSEdition)"
Write-Host "Profile:   $PSCommandPath"



####################################

$MyInvocation.MyCommand

# DOT Source External Functions
$currentpath = Get-ScriptDirectory

If  ($IsWindows -eq $true) {
. (Join-Path -Path $currentpath -ChildPath "\functions\Show-Object.ps1")
. (Join-Path -Path $currentpath -ChildPath "\functions\Connect-Office365.ps1")
. (Join-Path -Path $currentpath -ChildPath "\functions\Test-Port.ps1")
. (Join-Path -Path $currentpath -ChildPath "\functions\Get-NetAccelerator.ps1")
. (Join-Path -Path $currentpath -ChildPath "\functions\Clx.ps1")
. (Join-Path -Path $currentpath -ChildPath "\functions\Test-DatePattern.ps1")
. (Join-Path -Path $currentpath -ChildPath "\functions\View-Cats.ps1")
. (Join-Path -Path $currentpath -ChildPath "\functions\Find-Apartment.ps1")
. (Join-Path -Path $currentpath -ChildPath "\functions\Launch-AzurePortal.ps1")
. (Join-Path -Path $currentpath -ChildPath "\functions\Launch-ExchangeOnline.ps1")
. (Join-Path -Path $currentpath -ChildPath "\functions\Launch-InternetExplorer.ps1")
. (Join-Path -Path $currentpath -ChildPath "\functions\Launch-Office365Admin.ps1")
}


############
# LEARNING #
############

# Learn something today (show a random cmdlet help and "about" article
If  ($IsWindows -eq $true) {
Get-Command -Module Microsoft*, Cim*, PS*, ISE | Get-Random | Get-Help -ShowWindow
Get-Random -input (Get-Help about*) | Get-Help -ShowWindow
}

# Debugging
# $ErrorView = $Error.CategoryInfo.gettype()

} # interactive test close
