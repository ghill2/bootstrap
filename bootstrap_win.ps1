# https://github.com/soda3x/windows-bootstrap/blob/main/elevated-bootstrap.ps1


# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
}

# Enable SMB
Write-Output "Enabling SMB..."
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart

# Turn off UAC
Write-Output "Turning off UAC..."
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
Write-Output "Done."

# Show Hidden Files, Protected OS Files and File Extensions in Explorer
Write-Output "Configuring explorer (show hidden files / folders, protected OS files and file extensions)..."
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Set-ItemProperty $key Hidden 1
Set-ItemProperty $key HideFileExt 0
Set-ItemProperty $key ShowSuperHidden 1
Stop-Process -processname explorer
Write-Output "Done."

# Enable SSH client
Write-Output "Installing OpenSSH.Client..."
$capability = Get-WindowsCapability -Online | Where-Object Name -like "OpenSSH.Client*"
Write-Information $capability
if($capability.State -ne "Installed") {
    Write-Information "Installing OpenSSH client"
    Add-WindowsCapability -Online -Name $capability.Name
} else {
    Write-Information "OpenSSH client installed"
}
$sshAgent = Get-Service ssh-agent
if($sshAgent.Status -eq "Stopped") {$sshAgent | Start-Service}
if($sshAgent.StartType -eq "Disabled") {$sshAgent | Set-Service -StartupType Automatic }

# Enable SSH server
Write-Output "Installing OpenSSH.Server..."
$capability = Get-WindowsCapability -Online | Where-Object Name -like "OpenSSH.Server*"
Write-Information $capability
if($capability.State -ne "Installed") {
    Write-Information "Installing OpenSSH server"
    Add-WindowsCapability -Online -Name $capability.Name
    # sc config sshd start=auto # start server automatically
} else {
    Write-Information "OpenSSH server installed"
}
$sshd = Get-Service sshd
if($sshd.Status -eq "Stopped") {$sshd | Start-Service}
if($sshd.StartType -eq "Disabled") {$sshd | Set-Service -StartupType Automatic }

# Get the PowerShell version: Get-Host | Select-Object Version
# NOTE: the path it version 1.0 but the powershell.exe will use the upgraded version after using ```Install-Module -Name PowerShellGet```
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
# Write default config NOT NEEDED! password authentication enabled by default.
# $file = "C:\ProgramData\ssh\sshd_config"
# if (-not (Test-Path -Path $file)) {
#     $text = "PasswordAuthentication yes"
#     $text | Out-File -FilePath $file -Encoding UTF8
# }



# Installs choco and cChoco DSM module so can use package definition file. (choco.ps1)
# Disable Hyper-V  and Ethernet adapter to fix this
# WinRM firewall exception will not work since one of the network connection types on this machine is set to Public. Change the network connection type to either Domain or Private and try again.
winrm quickconfig
Set-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Value 16384
Enable-PSRemoting -SkipNetworkProfileCheck -Force
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
# Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force;
Install-Module cChoco;

# Set the hostname
$hostname = Read-Host -Prompt 'Enter the new hostname'
$computer = Get-WmiObject -Class Win32_ComputerSystem
$computer.Rename($hostname)


# Install Powershell 5: not needed, Windows 11 ships with version 5.1
# Install PowerShell
# Install-Module -Name PowerShellGet -Force -AllowClobber -SkipPublisherCheck
# Install-Package -Name PowerShell -ProviderName PowerShellGet -Force -AllowClobber
# Set-Alias -Name powershell -Value pwsh
# refreshenv
# $PSVersionTable.PSVersion # To verify that you are using the latest version of PowerShell, you can run the following command:


# Make sure the cChoco DSM module is installed. Use installChoco to install it

# Set-ExecutionPolicy Bypass -Scope Process -Force
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force;


# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# NOT sure why running all of these worked from a fresh install?
# Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force
# # Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

# # Enable Hyper-V:
# Write-Output "Turning on Hyper-V..."
# Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart
# Write-Output "Done."

# # Enable WSL:
# Write-Output "Turning on WSL..."
# Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -All -NoRestart
# Write-Output "Done."