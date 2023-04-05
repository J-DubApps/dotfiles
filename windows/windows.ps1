Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))


chocolatey feature enable -n allowGlobalConfirmation #avoids need for -y confirmation arguement

Install-Module -Name Evergreen

choco install Boxstarter


Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force -ErrorAction Ignore

# Don't set this before Set-ExecutionPolicy as it throws an error
$ErrorActionPreference = "stop"

# Remove HTTP listener
Remove-Item -Path WSMan:\Localhost\listener\listener* -Recurse

# WinRM

cmd.exe /c winrm quickconfig -q
cmd.exe /c winrm quickconfig '-transport:http'
cmd.exe /c winrm set "winrm/config" '@{MaxTimeoutms="1800000"}'
cmd.exe /c winrm set "winrm/config/winrs" '@{MaxMemoryPerShellMB="1024"}'
cmd.exe /c winrm set "winrm/config/service" '@{AllowUnencrypted="true"}'
cmd.exe /c winrm set "winrm/config/client" '@{AllowUnencrypted="true"}'
cmd.exe /c winrm set "winrm/config/service/auth" '@{Basic="true"}'
cmd.exe /c winrm set "winrm/config/client/auth" '@{Basic="true"}'
cmd.exe /c winrm set "winrm/config/service/auth" '@{CredSSP="true"}'
cmd.exe /c winrm set "winrm/config/listener?Address=*+Transport=HTTP" '@{Port="5985"}'
cmd.exe /c netsh advfirewall firewall set rule group="remote administration" new enable=yes
cmd.exe /c netsh advfirewall firewall add rule name="Open Port 5985" dir=in action=allow protocol=TCP localport=5985
cmd.exe /c net stop winrm
cmd.exe /c sc config winrm start= auto
cmd.exe /c net start winrm 

# Cloud Mgmt Modules
choco install azurepowershell
Register-PSRepository -Name "PSGallery" –SourceLocation "https://www.powershellgallery.com/api/v2/" -InstallationPolicy Trusted$env:ProgramFiles\PowerShell\7
Install-Module SharePointPnPPowerShellOnline


# Win10 Dev / DevOps VM
## Windows / .net / c# Development
choco install dotnetcore-sdk
choco install powershell-core --ia='ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=0'
choco install nuget.commandlines
choco install nugetpackageexplorer
choco install GoogleChrome  ## This browser is starting to suck more and more...very too much bloating, sir :(
choco install firefox
choco install microsoft-edge #if Windows Server pre 2022 or Windows 10 pre 20H2
choco install putty
choco install curl
choco install sysinternals
choco install notepadplusplus.install
choco install notepadreplacer --params "'/NOTEPAD:C:\Program Files\Notepad++\notepad++.exe'"
choco install sql-server-management-studio
choco install treesizefree ## Leaner version of windirstat more file location options
choco install golang ## Work only systems
choco install powerbi ## Work only systems
choco install postman ## Work systems only
choco install mysql.workbench
choco install baretail ## Windows based log-file realtime monitoring tool
choco install python2
choco install python3
choco install vscode #visual studio code opensource from Microsoft
choco install vscode-pull-request-github
choco install pywin32
choco install 7zip
choco install powershell-core --ia='ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=0'
choco install powershellhere
choco install sandboxie.install
choco install vmrc
choco install nmap
choco install wireshark
choco install winpcap ## Optional - needed to support promiscuous wireshark sessions
# choco install puppet ## Optional
choco install openssh ## OpenSSH for Windows
# choco install jre8 ## only install if needed
 choco install winlogbeat  ## Optional - useful for shipping Windows logs to Elastic search and getting system insights
# choco install vcredist140  ## Eventually this seems to be needed
# choco install rundeck ## Optional - open source automation for DC or cloud environments
choco install baretail ## Windows based log-file realtime monitoring tool
choco install mremoteng
choco install vnc-viewer # RealVNC viewer
choco install autohotkey.portable
choco install nodejs.install  ## Optional
choco install treesizefree ## Leaner version of windirstat more file location options
choco install windirstat  ## Excellent file/drive space consumption visualization
choco install winscp.install ## Windows secure file copy utility for Linux/Unix
choco install beyondcompare  ## Good replacement for Windiff (file comparison utility)
choco install microsoft-teams.install
choco install vlc
choco install winmerge
choco install zoom
# choco install zoom-outlook
choco install slack 

## Sysinternals / Monitoring / File Analysis
# complete Sysinterals install is too noisy use WSSC instead
choco install procexp
choco install autoruns
choco install pstools
choco install dbgview
choco install sysmon # advanced logging / auditing service https://github.com/SwiftOnSecurity/sysmon-config#use

## Cleanup
choco install bleachbit
choco install treesizefree
choco install dupeguru # duplicate finder gui
choco install revo-uninstaller

#run Windows Updates

#Create file named %WINDIR%\Setup\Scripts\SetupComplete.cmd with the following cmd:

net user administrator /ACTIVE:YES

#Lastly run this command:

C:\Windows\System32\sysprep\sysprep /oobe /generalize /shutdown

# Create VMWare Template & make sure that %WINDIR%\Setup\Scripts\SetupComplete.cmd
