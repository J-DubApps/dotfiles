<#
    .SYNOPSIS
        J-Dub's PowerShell Profile
    .DESCRIPTION
        Default name of this Profile is Microsoft.Powershell_profile.ps1
    	Copy is kept at a Secret GitHub Gist @ https://gist.github.com/J-DubApps/664dc50200b7dd0a9c881ac012d6542d
        
        Locations to download this Profile depending on OS:
        Windows - $Home\[My ]Documents\PowerShell\Microsoft.PowerShell_profile.ps1
        Linux - ~/.config/powershell/Microsoft.Powershell_profile.ps1
        macOS - ~/.config/powershell/Microsoft.Powershell_profile.ps1
        
        Loads PSProfile @ https://gist.github.com/J-DubApps/abd4984a4563a8f0d808a89717f79fd5#file-psprofile
        PSPRofile Gist ID abd4984a4563a8f0d808a89717f79fd5
		
        Invoke-Expression (Invoke-RestMethod https://api.github.com/gists/abd4984a4563a8f0d808a89717f79fd5).files.PSProfile.content
		
        Based on https://xkln.net/blog/securely-synchronizing-powershell-profiles-across-multiple-computers/

        NOTE: You *MUST* be signed-into GitHub to use this Profile!!
    .NOTES
        Julian West
        julianwest.me
        @julian_west
#>
# This is my local $Profile.CurrentUserAllHosts PS Profile script 

# Define Gist Id which contains our profile script
$ProfileGistID = 'abd4984a4563a8f0d808a89717f79fd5'

function VerifyRemoteProfile {

    Param(
        [Parameter(Mandatory=$true)]
        [psobject]$Gist,
        [Parameter(Mandatory=$true)]
        [string]$PSCachedProfile
    )

    # Define possible profile loading options
    Add-Type -TypeDefinition @"
        public enum ProfileLoadOption {
            LoadCached,
            LoadRemote
         }
"@

    # Set default to load locally cached profile
    $LoadProfile = [ProfileLoadOption]::LoadCached

    $PSRemoteProfileVersionFile = ([System.IO.FileInfo]$profile).DirectoryName + "\PSRemoteProfileVersions.json"

    # Load current profile versions or create new instance if none are present
    try {
        $VersionData = Get-Content $PSRemoteProfileVersionFile -Raw -ErrorAction Stop | ConvertFrom-Json
        $NewFile = $false
    }
    catch {
        Write-Host "No profile version file found, creating..."
        $VersionData = New-Object -TypeName PSObject -Property @{
            LastModified = Get-Date -Year 1900 -Format u
            LastCommitHash = "None"
        }
        $NewFile = $true
    }

    # Loading Gist data
    $LastModified = $Gist.updated_at
    $LastCommitHash = $Gist.history[0].version

    # Request approval if remote profile has changed, otherwise load cached version
    if (($VersionData.LastModified -ne $LastModified) -or ($VersionData.LastCommitHash -ne $LastCommitHash)) {
        Write-Host "-----------------------------------------"
        Write-Host "Local Last Modified timestamp is $(([datetime]$VersionData.LastModified).ToLocalTime().ToString()), remote is $(([datetime]$LastModified).ToLocalTime().ToString())"
        Write-Host "Local Commit Hash is $($VersionData.LastCommitHash), remote is $LastCommitHash"
        Write-Host "-----------------------------------------"

        # Show diff if $NewFile is False
        if ($NewFile -eq $false) {

            $CurrentProfile = Get-Content $PSCachedProfile
            $NewProfile = $Gist.files.PSProfile.content.Split([Environment]::NewLine)

            Write-Host "[+] Added Lines"
            $NewProfile | % { if ($_ -notin $CurrentProfile) {Write-Host $_ -ForegroundColor Green}}

            Write-Host "[+] Removed Lines"
            $CurrentProfile | % { if ($_ -notin $NewProfile) {Write-Host $_ -ForegroundColor Red}}
        }

        # Present options to accept or reject changed profile
        $Deny = New-Object System.Management.Automation.Host.ChoiceDescription '&Deny','Do not allow loading of the new profile'
        $Allow = New-Object System.Management.Automation.Host.ChoiceDescription '&Allow','Allow loading of the new profile'
        $Choices = [System.Management.Automation.Host.ChoiceDescription[]]($Deny,$Allow)

        $Prompt = 'Do you wish to allow loading the changed profile?'
        $Result = $Host.UI.PromptForChoice($null, $Prompt, $Choices, 0)
    
        if ($Result -eq 1) {
            $LoadProfile = [ProfileLoadOption]::LoadRemote
            
            # Upading local version file
            $VersionData.LastModified = $LastModified
            $VersionData.LastCommitHash = $LastCommitHash
            $VersionData | ConvertTo-Json | Out-File $PSRemoteProfileVersionFile -Force

            # Upading cached profile
            $Gist.files.PSProfile.content | Out-File $PSCachedProfile -Force
        } 
        else {
            Write-Host "Loading remote profile rejected, falling back to locally cached version"
            $LoadProfile = [ProfileLoadOption]::LoadCached
        }
    } else {
        $LoadProfile = [ProfileLoadOption]::LoadCached
    }

    Write-Output $LoadProfile
}

$PSCachedProfile = ([System.IO.FileInfo]$profile).DirectoryName + "\PSCachedProfile.ps1"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Gist = Invoke-RestMethod https://api.github.com/gists/$ProfileGistID
    $LoadProfile = VerifyRemoteProfile -Gist $Gist -PSCachedProfile $PSCachedProfile

    # Load remote profile
    if ($LoadProfile -eq "LoadRemote") {
        Write-Host "Loading remote profile" -ForegroundColor Green
        Invoke-Expression ($Gist).files.PSProfile.content
    }

    # Load cached profile
    if ($LoadProfile -eq "LoadCached") {
        . $PSCachedProfile
    }

} catch {
    # Load cached version in the event of an error
    if (!(Test-Path $PSCachedProfile)) {
        Write-Warning "Locally cached copy of remote profile not found, expected at $PSCachedProfile"
    } else {
        . $PSCachedProfile
    }
}

# Clean up after ourselves
Remove-Variable Gist, LoadProfile, ProfileGistID, PSCachedProfile -ErrorAction SilentlyContinue
