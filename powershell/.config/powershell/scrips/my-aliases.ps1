# Aliases

#New-Alias -Name np -Value C:\Windows\System32\notepad.exe
#New-Item alias:x -Value "exit"
#Set-Location ~

# Add the path to my powershell-scripts
if ($isLinux){
    $env:PATH += ":$env:HOME\repos\powershell-stuff"
}
else {
    $env:Path += ";$env:UserProfile\repos\powershell-stuff"
}

# Remove built in aliases
Remove-Item alias:curl 2>$null
Remove-Item alias:wget 2>$null
Remove-Item alias:diff -Force 2>$null
Remove-Item alias:ls -Force 2>$null

# Set own aliases
Set-Alias -Name src -Value reload-powershell-profile
Set-Alias -Name alias -Value Search-Alias

Set-Alias -Name crep -Value ~\repos\powershell-stuff\check-repos.ps1
Set-Alias -Name upr -Value ~\Repos\powershell-stuff\update-repos.ps1
Set-Alias -Name ups -Value ~\Repos\powershell-stuff\update-status.ps1

Set-Alias -Name em -Value emacs-client
Set-Alias -Name emx -Value emacs-client

Set-Alias -Name l -Value Get-Content
Set-Alias -Name du -Value disk-usage
Set-Alias -Name oc -Value org-commit
Set-Alias -Name poff -Value Stop-Computer
Set-Alias -Name poffr -Value Restart-Computer
Set-Alias -Name ql -Value New-List
Set-Alias -Name st -Value Start-Transcript
Set-Alias -Name which -Value Get-Command
Set-Alias -Name gs -Value Get-CommandSyntax

Set-Alias -Name gnc -Value Get-NetConnectionProfile
Set-Alias -Name kb -Value keybase
Set-Alias -Name yodl -Value youtube-dl

Set-Alias -Name lll -Value Find-Links

Set-Alias -Name lok -Value find-dropbox-conflicts
Set-Alias -Name loo -Value find-onedrive-conflicts

Set-Alias -Name ra -Value resolve-address

Set-alias -Name gts -Value Get-MyGitStatus
Set-Alias -Name gtl -Value Get-MyGitLog

Set-Alias -Name dk -Value 'docker'
Set-Alias -Name dco -Value 'docker-compose'
Set-Alias -Name cfd -Value 'ConvertFrom-Docker'

Set-Alias -Name ci -Value code-insiders

# Ubuntu multipass virtual servers
Set-Alias -Name mps -Value multipass

# Defender
Set-Alias -Name mdatp -Value  'C:\Program Files\Windows Defender\MpCmdRun.exe'

# Firefox
Set-Alias -Name ff -Value Start-Firefox

#Functions
function .. {
    cd ..
}
function ... {
    cd ..\..
}
function cdh {
    Set-Location ~
}
function cdm {
    Set-Location ~\Videos
}
function cdr {
    Set-Location ~\repos
}
function cdrw {
    Set-Location ~\Work
}
function cdw {
    Set-Location ~\Downloads
}
function cdv {
    Set-Location ~\Vagrantdir
}
function ls {
    Get-ChildItem $args -Attributes H,!H,A,!A,S,!S
}
function ll {
    [cmdletbinding()]
    Param (
        $Path
    )

        Get-ChildItem $Path -Attributes H,!H,A,!A,S,!S
}

function lla {
    [cmdletbinding()]
    Param (
        $Path
    )
    Get-ChildItem $Path -Attributes H,!H,A,!A,S,!S,C,!C,E,!E
}

function lls {
    [cmdletbinding()]
    Param (
        $Path
    )
    Get-ChildItem $Path -Attributes H,!H,A,!A,S,!S|Sort-Object Length
}

function llt {
    [cmdletbinding()]
    Param (
        $Path
    )
    Get-ChildItem $Path -Attributes H,!H,A,!A,S,!S| Sort-Object lastwritetime
}
function now {
    Get-Date -Format yyyyMMdd-HH:mm:ss
}
Function disk-usage {
    param(
        $Path = $(Resolve-Path .)
    )
    $dirs = Get-ChildItem -Path $Path -Recurse -ErrorAction Ignore
    $result = [PSCustomObject]@{
        "Directories" = ($dirs | Where-Object PSIsContainer -eq $true | Measure-Object).Count
        "Files" = ($dirs | Where-Object PSIsContainer -eq $false | Measure-Object).Count
        "Sum" = ($dirs | Measure-Object -Property Length -Sum).Sum
    }
    $result
}

# Alias for help-command
function gh([string]$help) {
    $ErrorActionPreference = "Ignore"
    Get-Help -Name $help -Online
}
# Alias for help-command local window
function ghl([string]$help) {
    $ErrorActionPreference = "Ignore"
    Get-Help -Name $help -ShowWindow
}
# Shortcut to create an array
Function New-List {
    $args
}

# Equivalent of linux wc, word counts
Function wc {
    Get-Content $args| Measure-Object -Character -Line -Word| select lines,words,characters
}

# Search an alias or display all of them
Function Search-Alias {
    param (
        [string]$alias
    )

    if ($alias){
        Get-Alias| Where DisplayName -Match $alias
    }
    else {
        Get-Alias
    }
}

# Show aliases online
Function check-alias {
    $tmp = New-TemporaryFile
    Rename-Item -Path $tmp  -NewName "$tmp.html"
    $tmp="$tmp.html"
    Get-Alias|Sort-Object Definition|ConvertTo-Html -Property Name,Definition -Title "Powershell aliases"> $tmp
    Invoke-Item $tmp
    # Sleep before removal
    Start-Sleep 2
    Remove-Item $tmp
}

# Debug emacs
Function emdi {
    emacs.exe --debug-init
}

function emacs-client() {
    $date =  Get-Date -Format 'yyyyMMdd-HH.mm.ss'
    $logfile = Join-Path $(Resolve-path ~/tmp) "emacs-client-${date}.log"
    # Workaround for using chemacs2 with server in Windows10
    $serverfile = $(Resolve-Path ~/.config/emacs.default/server/server).Path

    $cmd = Get-Command emacsclientw.exe
    $options = @(
        "--quiet"
        "--alternate-editor=runemacs.exe"
        "--server-file=${serverfile}"
        "--create-frame"
    )

    # Starts emacsclient and daemon if not started
    if ($args.count -eq 0 ) {
        # Create a new frame if no files as argument
        & $cmd @options *> $logfile
    }
    else {
        # Dont create a new frame if files exists as argument
        & $cmd @options  $args *> $logfile
    }
}
# Show dns search suffix
function Get-dns-suffix() {
    (Get-DnsClientGlobalSetting).SuffixSearchList
}
function reload-powershell-profile {
    . $profile.CurrentUserAllHosts
    . $DirScripts\aliases.ps1
    . $DirScripts\functions.ps1
}
function show-profiles {
    $profile|Get-Member -MemberType NoteProperty
}
function show-colors {
    [enum]::GetValues([System.ConsoleColor]) | Foreach-Object {Write-Host $_ -ForegroundColor $_}
}
function show-path {
    $env:Path.split(";")
}
function ipv4 {
    $interfaces = (Get-NetAdapter| select Name,ifIndex,Status| where Status -eq Up)
    foreach  ($if in $interfaces) {
        $ipv4 = (Get-NetIPAddress -ifIndex ($if).ifIndex -Type Unicast -AddressFamily IPv4).IPAddress
        $ifName = ($if).Name
        $ifIndex = ($if).ifIndex

        # Write every ipv6 address for the interface on a separate line
        foreach ($addr in $ipv4) {
            # Format for ipv4-address, and longest interfacename, Virtualbox
            "{0,-62} {1,-15}" -f "Interface $ifName ($ifIndex) has ipv4-address =",$addr
        }
    }
}
function ipv6 {
    $interfaces = (Get-NetAdapter| select Name,ifIndex,Status| where Status -eq Up)
    foreach  ($if in $interfaces) {
        $ipv6 = (Get-NetIPAddress -ifIndex ($if).ifIndex -Type Unicast -AddressFamily IPv6).IPAddress
        $ifName = ($if).Name
        $ifIndex = ($if).ifIndex

        # Write every ipv6 address for the interface on a separate line
        foreach ($addr in $ipv6) {
            # Format for ipv6-address, and longest interfacename, Virtualbox
            "{0,-62} {1,-39}" -f "Interface $ifName ($ifIndex) has ipv6-address =",$addr
        }
    }
}
# Check installed software
function check-software {
    Get-ItemProperty HKLM:\Software\WoW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*| Select-Object Displayname,DisplayVersion,Publisher,Installdate|Sort-Object -Property DisplayName
}
# Check windows optional packages
Function check-packages {
    [cmdletbinding()]
    Param (
        [switch]$Disabled
    )

    if ($Disabled){
        $state = "Disabled"
    }
    else {
        $state = "Enabled"
    }

    Get-WindowsOptionalFeature -online|
      where state -eq $state|
      select FeatureName, State|
      SOrt-Object -Property Featurename
}

# Package mgmt functions
function apc($application) {
    choco search $application
}
function apd {
    choco upgrade all  -y
}
function apo {
    choco outdated
}
function api {
    choco list -LocalOnly
}
# Function to commit changes to org-files quickly
function org-commit {
    $gitdir = (Convert-Path ${env:USERPROFILE}\.orgit).replace("\","/")
    $workdir = Convert-Path ${env:USERPROFILE}\OneDrive\emacs
    $gitfile = Join-Path $workdir .git
    $date = (Get-Date -Format yyyyMMdd-HH:mm:ss)

    Write-Host -ForeGroundColor green "Commiting changes to org-files to local repo."
    Set-Content -Path $gitfile -Value "gitdir: $gitdir" -Force

    Push-Location $workdir
    orgit add org/*.org
    orgit add org/archive/*.org
    orgit add bookmarks
    orgit commit -m "Comitting changes $date"
    orgit push -q --all
    Pop-Location
}

    # Check for admin
    function Test-Admin
    {
        $wid = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $prp = New-Object System.Security.Principal.WindowsPrincipal($wid)
        $adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
        $prp.IsInRole($adm)
    }

    # Alias for git status
    Function Get-MyGitStatus {
        git status -sb
    }
    # Alias for git log
    Function Get-MyGitLog {
        param(
            $path = ".",
            $count = 40
        )
        $path = Convert-Path $path
        if ( Test-Path $path -Type Leaf){
            $path=Split-Path $path -Parent
        }
        git -C $path log --oneline --all --graph --decorate --max-count=$count
    }

    # Create a .gitattributes-file if it doesnt exist
    function Add-GitAttributesFile {

        # Text to add in the file
        $text = @"
# Set the default behavior, in case people don't have core.autocrlf set.
* text=auto

# Explicitly declare text files you want to always be normalized and converted
# to native line endings on checkout.
*.c text
*.h text

# Declare files that will always have LF line endings on checkout.
*.sh text eol=lf
*.ps1 text eol=lf
*.psd1 text eol=lf
*.psm1 text eol=lf

# Denote all files that are truly binary and should not be modified.
*.png binary
*.jpg binary
"@

        if (Test-Path -Path .git -PathType Container) {
            if (-not (Test-Path -Path .gitattributes -PathType Leaf)){
                Set-Content -Path .gitattributes -Value $text
                Write-Output "Added a new .gitattributesfile"
            }
            else {
                Write-Output "A .gitattributesfile already exists."
            }
        }
        else {
            Write-Output "Not a repository."
        }
    }

    # Reset the terminal settings. From http://windowsitpro.com/powershell/powershell-basics-console-configuration
    function fix-tty {
        $console.ForegroundColor = "white"
        $console.BackgroundColor = "black"
        Clear-Host
    }
    function keybase {
        $prg = $env:LocalAppData + "\Keybase\keybase.exe"
        & $prg $args
    }
    # Checks for proxy settings
    function Get-proxy {
        $regKey="HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $proxysettings="ProxyEnable","ProxyServer","ProxyOverride","AutoConfigURL"
        $proxyenabled= (Get-ItemProperty -path $regKey).ProxyEnable

        if ( $proxyenabled -eq 0) {
            Write-Host "No proxy enabled"
        }
        else {
            Write-Host "Proxy enabled"
        }

        foreach ($setting in $proxysettings) {
            $value = (Get-ItemProperty -path $regKey).$setting
            "$setting is:`t$value"
        }

    }

    # Get all my github repos
    Function Get-MyRepos {
        $MyRepos = Invoke-RestMethod -Uri "https://api.github.com/users/sdaaish"
        Set-Location ${Convert-Path ~/repos}
        $MyRepos | ForEach-Object {git clone $_.git_url}
    }

    # My local files in a bare git repo
    Function dotgit {
    if  ($isLinux){
    }
    else {
        $gitdir = Join-Path ${env:USERPROFILE} ".dotgit"
        $workdir = ${env:USERPROFILE}
        $cmd = Get-Command git.exe

        $options = @(
            "--git-dir=${gitdir}"
            "--work-tree=${workdir}"
        )
        Write-Verbose "$cmd @options $args"
        & $cmd @options $args
    }
}

# My local files in a bare git repo
Function clone-dotgit {
    [cmdletbinding(
         SupportsShouldProcess,
         ConfirmImpact = 'High'
     )]
    Param (
        [Switch]$Force
    )

    if  ($isLinux){
    }
    else {
        if ($Force){
            $ConfirmPreference = 'None'
        }

        $gitdir = Join-Path ${env:USERPROFILE} ".dotgit"
        $workdir = ${env:USERPROFILE}
        $tmpdir = Join-Path ${env:USERPROFILE} "tmpdir"
        $gitrepo = "https://github.com/sdaaish/windotfiles.git"
        $cmd = Get-Command git.exe

        New-Item -Path $tmpdir -ItemType Directory -Force|Out-Null

        # Options to clone github to tmp-dir with separate git-repo
        $options = @(
            "clone"
            "--separate-git-dir=${gitdir}"
            "$gitrepo"
            "${tmpdir}"
        )
        Write-Verbose "$cmd @options"
        & $cmd @options

        # Add default settings
        dotgit config status.showUntrackedFiles no

        # Copy files recursivly
        if ($Force -or $PSCmdlet.ShouldProcess($gitdir,'Overwrite  files')){
            Copy-Item -Path $tmpdir/* -Destination $workdir -Recurse -Force
        }
        else {
            Copy-Item -Path $tmpdir/* -Destination $workdir -Recurse
        }

        # Clone submodules
        dotgit submodule update --init --force --remote

        # Delete tmp
        if ($Force -or $PSCmdlet.ShouldProcess($tmpdir,'Remove files')){
            Remove-Item -Path $tmpdir -Recurse
        }
    }
}

# Store emacs and org-files in a local repository and not in Onedrive
Function orgit {
    if  ($isLinux){
    }
    else {
        $gitdir = Join-Path ${env:USERPROFILE} ".orgit"
        $workdir = Join-Path ${env:USERPROFILE} Onedrive/emacs
        $cmd = Get-Command git.exe

        $options = @(
            "--git-dir=${gitdir}"
            "--work-tree=${workdir}"
        )
        Write-Verbose "$cmd @options $args"
        & $cmd @options $args
    }
}

# Display current dns-servers for active interfaces
# Get-NetIPConfiguration| select InterfaceAlias,IPv4Address,serveraddresses -ExpandProperty dnsserver -ea ign
Function Get-DNSServers {
    $interfaces = (Get-NetAdapter| select Name,ifIndex,Status| where Status -eq Up)
    foreach ($if in $interfaces){
        $dnsserver = (Get-DNSClientServerAddress -InterfaceIndex $if.ifIndex)
        Write-Host -NoNewLine "Interface: "
        $if.Name
        $dnsserver.ServerAddresses
    }
}

# Set my explorer preferences
# See also https://gallery.technet.microsoft.com/scriptcenter/8ac61441-1ad2-4334-b69c-f9189c605f83
function my-explorer {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    Set-ItemProperty $key AlwaysShowMenus 1
    Set-ItemProperty $key AutoCheckSelect 1
    Set-ItemProperty $key DisablePreviewDesktop 0
    Set-ItemProperty $key DontPrettyPath 0
    Set-ItemProperty $key DontUsePowerShellOnWinX 0
    Set-ItemProperty $key Filter 0
    Set-ItemProperty $key Hidden 1
    Set-ItemProperty $key HideDrivesWithNoMedia 0
    Set-ItemProperty $key HideDrivesWithNoMedia 1
    Set-ItemProperty $key HideFileExt 0
    Set-ItemProperty $key HideIcons 0
    Set-ItemProperty $key HideMergeConflicts 0
    Set-ItemProperty $key IconsOnly 0
    Set-ItemProperty $key ListviewAlphaSelect 1
    Set-ItemProperty $key ListviewShadow 1
    Set-ItemProperty $key MMTaskbarEnabled 0
    Set-ItemProperty $key MapNetDrvBtn 0
    Set-ItemProperty $key MultiTaskingAltTabFilter 3
    Set-ItemProperty $key NavPaneExpandToCurrentFolder 1
    Set-ItemProperty $key NavPaneShowAllFolders 1
    Set-ItemProperty $key ReindexedProfile 1
    Set-ItemProperty $key SeparateProcess 0
    Set-ItemProperty $key ServerAdminUI 0
    Set-ItemProperty $key SharingWizardOn 0
    Set-ItemProperty $key ShellViewReentered 1
    Set-ItemProperty $key ShowCompColor 1
    Set-ItemProperty $key ShowEncryptCompressedColor 1
    Set-ItemProperty $key ShowInfoTip 1
    Set-ItemProperty $key ShowStatusBar 1
    Set-ItemProperty $key ShowStatusBar 1
    Set-ItemProperty $key ShowSuperHidden 1
    Set-ItemProperty $key ShowTypeOverlay 1
    Set-ItemProperty $key Start_SearchFiles 2
    Set-ItemProperty $key StoreAppsOnTaskbar 1
    Set-ItemProperty $key TaskbarAnimations 1
    Set-ItemProperty $key TaskbarSmallIcons 1
    Set-ItemProperty $key WebView 1
    Stop-Process -processname explorer
    Start-Process explorer
}
# Settings for TaskMgr
# Only stub for now, more info: https://msitpros.com/?p=1136
function my-taskmgr {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager'
    Get-ItemProperty $key
    # reg export HKCU\Software\Microsoft\Windows\CurrentVersion\TaskManager .\conf\taskmgr.reg /y
    # reg import .\conf\taskmgr.reg
}
# Kill explorer and restart it
function pse {
    Get-Process -Name explorer|Stop-Process -force
    Write-Host "Explorer restarted"
}

# show top 10 processes regarding cpu usage
Function top {
    Get-Process| ? cpu -gt 5|Sort-Object cpu -Descending| Select-Object -First 10
}

# Show filehash for all executables running
function Get-ProcessHash {
    Get-Process|
      Where-Object {$_.Path}|
      Sort-Object -Property Path -Unique|
      Foreach-Object {Get-FileHash $_.Path}|
      Select-Object Hash,Path
}

# Show services
Function my-service {
    Get-Service| Sort -Property @{Expression = "Status"; Descending = "True"},@{Expression = "Name"}|Out-GridView
}

# Find links in the filesystem
function Find-Links {
    [cmdletbinding()]
    Param (
        $Path
    )
    Get-ChildItem $Path -ErrorAction SilentlyContinue|
      Where-Object {$_.Linktype}|
      Select-Object FullName, Target,LastWriteTime,LinkType
}

# Find conflicts in Dropbox
Function find-dropbox-conflicts {
    Get-ChildItem -r -Path ~/Dropbox -Name *konflikt*
}
# Find conflicts in Onedrive
Function find-onedrive-conflicts {
    Get-ChildItem -r -Path ~/OneDrive -Name *konflikt*
}

# Start hugo locally and fire up a webpage
Function test-hugo {
    Start-Job -ScriptBlock {& hugo server -D --disableFastRender}
    Start-Process http://localhost:1313/
}

# Create a module base directory
# From https://ramblingcookiemonster.github.io/Building-A-PowerShell-Module/
# and https://kevinmarquette.github.io/2017-05-27-Powershell-module-building-basics/
Function New-ModuleDir {
    param(
        [Parameter(Mandatory=$True)]
        $Path,
        [Parameter(Mandatory=$True)]
        $ModuleName,
        [Parameter(Mandatory=$True)]
        $Author,
        [Parameter(Mandatory=$True)]
        $Description
    )

    $ModuleDir = "$Path\$ModuleName"

    # Create the module and private function directories
    New-Item "$ModuleDir" -ItemType Directory
    New-Item "$ModuleDir\Private" -ItemType Directory
    New-Item "$ModuleDir\Public" -ItemType Directory
    New-Item "$ModuleDir\en-US" -ItemType Directory # For about_Help files
    New-Item "$Path\Tests" -ItemType Directory

    #Create the module and related files
    New-Item "$ModuleDir\$ModuleName.psm1" -ItemType File
    New-Item "$ModuleDir\$ModuleName.Format.ps1xml" -ItemType File
    New-Item "$ModuleDir\en-US\about_$ModuleName.help.txt" -ItemType File
    New-Item "$ModuleDir\Tests\$ModuleName.Tests.ps1" -ItemType File

    $manifest = @{
        Path              = "$ModuleDir\$ModuleName.psd1"
        RootModule        = "$MyModuleName.psm1"
        Author            = "$Author"
        Description       = "$Description"
        FormatsToProcess  = "$ModuleName.Format.ps1xml"
    }
    New-ModuleManifest @manifest
}

# Fix for Outlook/Office that cannot open links in Windows 10,
# and you don't want to install IE.
# https://support.microsoft.com/sv-se/help/310049/hyperlinks-are-not-working-in-outlook
# https://answers.microsoft.com/en-us/msoffice/forum/msoffice_outlook-mso_win10/outlook-2013-email-links-arent-working/7122799b-798e-4439-8108-69fa86900a16
# And my preferred browser is Firefox.

function fix-outlook-hyperlink-error {
    [cmdletbinding()]

    $admincheck = Test-Admin
    if ( $admincheck ){
        Write-Output "User $env:USERNAME has admin rights."

        # Create a list of htmlfiles
        $htmlfiles =  @(
            ".html",
            ".htm",
            ".shtm",
            ".shtml"
        )

        ### This part needs administrative privileges

        # Create a PSDrive for HKCR if it doesn't exist
        if (-not (Test-Path HKCR:)){
            New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
        }

        # Change the suffixes to be of type "htmlfile"
        foreach($suffix in $htmlfiles){
            $path = "HKCR:" + $suffix
            Set-ItemProperty -Path $path -Name '(Default)' -Value "htmlfile"
            Set-ItemProperty -Path $path -Name 'Content Type' -Value "text/html"
            Set-ItemProperty -Path $path -Name 'PercievedType' -Value "text"
        }

        # Create the registry key and set its value to the preferred browser
        New-Item HKCR:\htmlfile\shell\open\command -Force | Out-Null
        New-ItemProperty -LiteralPath HKCR:\htmlfile\shell\open\command -Name '(Default)' -Value '"C:\Program Files\Mozilla Firefox\firefox.exe" -osint -url "%1"' -Force | Out-Null

        # Print results
        Write-Output "Changed settings to:"
        foreach($suffix in $htmlfiles){
            $path = "HKCR:" + $suffix
            Get-ItemProperty -Path $path | Select-Object "PSPath","(default)","Content Type","PercievedType"
        }
        Get-ItemProperty -LiteralPath HKCR:\htmlfile\shell\open\command -Name '(Default)'| Select-Object "PSPath","(default)"
    }
    else {
        Write-Output "You dont have administrative rights to change this!"
    }
}

# Starts VS Code with a profile. It creates a new profile if -Config don't exists
Function Start-VSCode {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        $Path,
        [Parameter(Mandatory)]
        $Config,
        [string[]]$File
    )

    Write-Verbose "Checking for VS Code."
    if ($code = Get-Command code -ErrorAction SilentlyContinue){
        $code = $code.source
        Write-Verbose "VS Code executable is: $code"
    }
    else
    {
        Throw "VS Code is not in current path."
    }

    if (Test-Path $Path){
        Write-Verbose "Start VScode in $Path with profile: `'$Config`'"

        $ext = Join-Path -Path $(Convert-Path $Path) -ChildPath $Config -AdditionalChildPath "ext"
        $data = Join-Path -Path $(Convert-Path $Path) -ChildPath $Config -AdditionalChildPath "data"

        Write-Verbose "Read extensions from: $ext"
        Write-Verbose "Read user-data from: $data"

        Write-Verbose "Start VScode with file: `'$File`'"
        & $code --extensions-dir $ext --user-data-dir $data $File
    }
    else {
        Throw "No such directory, $Path"
    }
}

# Start VScode with a default settings
Function vsd {
    [cmdletbinding()]
    param(
        $File
    )
    Start-VSCode -Path ~/repos/code -Config default -File $File
}

# Start VScode with powershell settings
Function vsp {
    [cmdletbinding()]
    param(
        $File
    )
    Start-VSCode -Path ~/repos/code -Config powershell -File $File
}

# Lists extensions in VSCode profile
Function Get-VSCodeExtensions {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory)]
        $Path
    )

    begin {
        Write-Verbose "Checking for VS Code."
        if ($code = Get-Command code -ErrorAction SilentlyContinue){
            $code = $code.source
            Write-Verbose "VS Code executable is: $code"
        }
        else
        {
            Throw "VS Code is not in current path."
        }
    }

    process
    {
        $config=Get-ChildItem -Path $Path -Depth 0 -Directory -Exclude .git
        Write-Verbose "Found following config: $config"

        foreach($conf in $config){
            $extdir = Join-Path -Path $conf -ChildPath ext
            $userdir = Join-Path -Path $conf -ChildPath data
            [string[]]$extension = code --extensions-dir $extdir --user-data-dir $userdir $File --list-extensions
            "Config for $(Split-Path -Leaf $conf) has the following extensions:"
            foreach($ext in $extension) {
                "- $ext"
            }
        }
    }
}
Function Get-CommandSyntax {
    [cmdletbinding()]
    Param (
        $command
    )
    Get-Command $command -Syntax
}

Function Ignore-SelfSignedCerts {
    try {
        Write-Host "Adding TrustAllCertsPolicy type." -ForegroundColor White
        Add-Type -TypeDefinition  @"
          using System.Net;
          using System.Security.Cryptography.X509Certificates;
          public class TrustAllCertsPolicy : ICertificatePolicy {
              public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {
                  return true
                }
          }
"@

        Write-Host "TrustAllCertsPolicy type added." -ForegroundColor White
    }

    catch {
        Write-Host $_ -ForegroundColor "Yellow"
    }

    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

Function Kill-F5VpnProcess {
    Get-Process| Where-Object ProcessName -Match f5| Stop-Process -Force
}

# Find the corretc Path for firefox
Function Start-Firefox {
    [cmdletbinding()]
    Param (
        [string]$InitProfile = "HOME",
        [string]$Url
    )

    if (Test-Path 'C:\Program Files\Mozilla FireFox\firefox.exe') {
        $firefox =  'C:\Program Files\Mozilla FireFox\firefox.exe'
    }
    elseif (Test-Path ${env:USERPROFILE}/scoop/apps/firefox/current/firefox.exe) {
        $firefox = Resolve-Path ${env:USERPROFILE}/scoop/apps/firefox/current/firefox.exe
    }
    else {
        $package = Get-AppxPackage Mozilla.MozillaFirefox
        [xml]$AppManifest = Get-Content ([System.IO.Path]::Combine($package.InstallLocation,"AppxManifest.xml"))
        $firefox = Join-Path $package.InstallLocation $AppManifest.Package.Applications.Application.Executable
    }
    $options = @(
        "-P", $InitProfile
        "-new-tab", $Url
    )
    Write-Verbose "InitProfile: ${InitProfile}, Url: ${Url}"
    Write-Verbose "Firefox: ${firefox}"
    & "$firefox" @options
}
