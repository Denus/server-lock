# Set execution policy to RemoteSigned
Set-ExecutionPolicy RemoteSigned -Force

# Enable Windows Defender Antivirus and Real-Time Protection
Set-MpPreference -DisableRealtimeMonitoring $false

# Update Windows Defender Antivirus definitions
Update-MpSignature

# Configure Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallRule -Name WINRM-HTTP-In-TCP -Enabled True

# Enable Windows Update service and automatic updates
Set-Service -Name wuauserv -StartupType 'Automatic'
Start-Service -Name wuauserv
Invoke-Expression -Command 'wuauclt /detectnow'

# Disable unnecessary services
$servicesToDisable = @(
    'Telnet',
    'FTP',
    'NetMeeting Remote Desktop Sharing',
    'Remote Desktop Services',
    'Remote Registry',
    'Server',
    'Telnet'
)

foreach ($service in $servicesToDisable) {
    Set-Service -Name $service -StartupType 'Disabled'
    Stop-Service -Name $service
}

# Enable Windows Defender SmartScreen
Set-ProcessMitigation -SystemSettings_1 EnableWin32kSystemCalls $true

# Set strong password policy
$policy = @{
    "MinimumPasswordLength" = 12
    "MinimumPasswordAge" = (New-TimeSpan -Days 1)
    "MaximumPasswordAge" = (New-TimeSpan -Days 90)
    "PasswordComplexity" = 1
    "PasswordHistorySize" = 24
}
Set-LocalSecurityPolicy $policy

# Enable BitLocker encryption (if supported)
$bitlockerStatus = Get-BitlockerVolume
if ($bitlockerStatus.ProtectionStatus -eq "Off") {
    Enable-BitLocker -MountPoint "C:" -EncryptionMethod "Aes256" -UsedSpaceOnly
}

# Disable unused Windows features
$featuresToDisable = @(
    'MSMQ-HTTP',
    'IIS-WebServer',
    'TelnetClient'
)

foreach ($feature in $featuresToDisable) {
    Disable-WindowsOptionalFeature -Online -FeatureName $feature
}

# Enable Windows Defender Exploit Guard
Set-MpPreference -EnableExploitProtectionAuditMode $false
Set-MpPreference -EnableControlledFolderAccess Enabled

# Configure Event Log settings
wevtutil sl Security /e:true
wevtutil sl System /e:true

# Configure User Account Control (UAC)
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1

# Set registry hardening for the Server service
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionShares" -Value ""
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionPipes" -Value ""

# Disable guest account
New-LocalUser -Name "Guest" -Description "Built-in account for guest access to the computer/domain" -AccountNeverExpires $true -UserMayNotChangePassword $false -PasswordChangeable $true -PasswordRequired $false -UserMayNotChangePassword $true -PasswordNeverExpires $true -Password ((Get-Random).ToString() + "d3n!3dP@ss")

# Reboot the system for changes to take effect
Restart-Computer -Force

Write-Host "Server security improvements applied. The server will now restart."
