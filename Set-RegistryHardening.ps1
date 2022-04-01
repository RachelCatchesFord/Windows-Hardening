<#
    Author: Rachel Ford
    Version: 1.0.0.0
    Date: 2019-02-27

    Purpose: Makes Windows 10 Look PRETTY!

#>

Write-Host ('***CONFIGURATIONS***')

# ================================================================ #
# ======================= REGISTRY SETTINGS ====================== #
# ================================================================ #

Write-Host ("Setting File Explorer to Launch to ThisPC")
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name LaunchTo -PropertyType DWORD -Value 1 -Force

Write-Host ("Setting Desktop Icons (ThisPC, User Profile, Recycle Bin, Control Panel)")
# ThisPC
New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value 0 -Force
# Recycle Bin
New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{645FF040-5081-101B-9F08-00AA002F954E}' -Value 0 -Force
# Control Panel
New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value 0 -Force
# Network
# New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' -Value 0 -Force
# User Files
New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value 0 -Force

Write-Host ("Setting File Explorer to Show Extensions (HKLM)")
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideFileExt -PropertyType DWORD -Value 0 -Force

Write-Host ("Setting File Explorer to Show Extensions (HKCU)")
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideFileExt -PropertyType DWORD -Value 0 -Force

#Write-Host ("Removing 'Edit with Paint 3D' option from File Explorer")
#Remove-Item -Path 'HKCU:\SOFTWARE\Classes\SystemFileAssociations\.jpeg\Shell\3D Edit' -Recurse -Force
#Remove-Item -Path 'HKCU:\SOFTWARE\Classes\SystemFileAssociations\.jpg\Shell\3D Edit' -Recurse -Force
#Remove-Item -Path 'HKCU:\SOFTWARE\Classes\SystemFileAssociations\.bmp\Shell\3D Edit' -Recurse -Force
#Remove-Item -Path 'HKCU:\SOFTWARE\Classes\SystemFileAssociations\.png\Shell\3D Edit' -Recurse -Force

Write-Host ("Hiding Windows Defender from System Tray")
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center' -ItemType KEY -Name Systray -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray' -PropertyType DWORD -Name HideSystray -Value 1 -Force

Write-Host ("Setting Remote Desktop Permissions")
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -PropertyType DWORD -Value 0 -Force
# Setting the NLA (Network Level Authentication) information to Disabled
(Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $env:ComputerName -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)

Write-Host ("Preventing UUID Logon Error after OSD Upgrade")
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services' -Name 'gpsvc' -Value '0x10' -Force

Write-Host ("Turning off Smart Screen prompts for Files in Windows Defender")
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'PreventOverrideAppRepUnknown' -Value '0' -Force

# ================================================================ #
# ======================== SYSTEM SERVICES ======================= #
# ================================================================ #

Write-Host ("Setting System Services Startup Type")
#New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\bowser' -Name 'Start' -Value '4' -Force -Verbose
#New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\IISADMIN' -Name 'Start' -Value '4' -Force -Verbose
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\irmon' -Name 'Start' -Value '4' -Force -Verbose
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess' -Name 'Start' -Value '4' -Force -Verbose
#New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LxssManager' -Name 'Start' -Value '4' -Force -Verbose
#New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\FTPSVC' -Name 'Start' -Value '4' -Force -Verbose
#New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd' -Name 'Start' -Value '4' -Force -Verbose
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator' -Name 'Start' -Value '4' -Force -Verbose
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess' -Name 'Start' -Value '4' -Force -Verbose
#New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\simptcp' -Name 'Start' -Value '4' -Force -Verbose
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV' -Name 'Start' -Value '4' -Force -Verbose
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\upnphost' -Name 'Start' -Value '4' -Force -Verbose
#New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WMSvc' -Name 'Start' -Value '4' -Force -Verbose
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc' -Name 'Start' -Value '4' -Force -Verbose
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\icssvc' -Name 'Start' -Value '4' -Force -Verbose
#New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC' -Name 'Start' -Value '4' -Force -Verbose
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc' -Name 'Start' -Value '4' -Force -Verbose
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\xboxgip' -Name 'Start' -Value '4' -Force -Verbose
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager' -Name 'Start' -Value '4' -Force -Verbose
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave' -Name 'Start' -Value '4' -Force -Verbose
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc' -Name 'Start' -Value '4' -Force -Verbose