<#
    Author: Rachel Catches-Ford
    Version: 1.0.0.0
    Date: 2019-02-26

    Purpose: Imports local GPO settings,
            installs LAPS, adds Registry settings
            for hardening purposes, sets the 
            interactive logon message text and title,
            runs Decrapifier which also disables startup
            types for services. Restarts at the end.

#>

$ReleaseId = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId).ReleaseId
$CurrentBuild = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuildNumber).CurrentBuildNumber
$DisplayVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion).DisplayVersion

Write-Host ('***SECURITY HARDENING***')

    switch($CurrentBuild){
        "22000"{ # Windows 11 build 21H2
            $Subfolder2 = "$PSScriptRoot\Windows_11_21H2_Enterprise\Level_1_NoDefender_Bitlocker"
            Write-Host ("Not importing Bitlocker settings, using $build Hardening")
        }
        "19044"{ #Windows 10 build 21H2
            $Subfolder2 = "$PSScriptRoot\Windows_10_21H2_Enterprise\Level_1_NoDefender_Bitlocker"
            Write-Host ("Not importing Bitlocker settings, using $build Hardening")
        }
        "19042"{ #Windows 10 build 20H2
            $Subfolder2 = "$PSScriptRoot\Windows_10_20H2_Enterprise\Level_1_NoDefender_Bitlocker"
            Write-Host ("Not importing Bitlocker settings, using $build Hardening")
        }
    }

$MsgTxt = "This system is for the use of authorized users only. Individuals using this computer system without authority, or in excess of their authority, are subject to having all of their activities on this system monitored and recorded by system personnel. In the course of monitoring individuals improperly using this system, or in the course of system maintenance, the activities of authorized users may also be monitored. Anyone using this system expressly consents to such monitoring and is advised that if such monitoring reveals possible evidence of criminal activity, system personnel may provide the evidence of such monitoring to law enforcement officials."
$MsgTitle = "-- WARNING --"
$NodeTypeReg = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
$RemoteSAMReg = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$MsgReg = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$LAPS = "$PSScriptRoot\LAPS.x64.msi"
$PasswordManager = "$PSScriptRoot\SecurePasswordExtension_x64.msi"
$Arguments = '/q /norestart'


Write-Host ('Installing LAPS')
& Start-Process -File $LAPS -ArgumentList $Arguments -PassThru | Wait-Process

#Write-Host ('Install One Identity Password Manager Extension')
#& Start-Process -File $PasswordManager -ArgumentList $Arguments -PassThru | Wait-Process

Write-Host ('Copying Google Chrome Policy Definitions')
$Templates = "$PSScriptRoot\ADMX_ADML_Templates"
Copy-Item "$Templates\*.admx" -Destination "$env:windir\PolicyDefinitions" -Force
Copy-Item "$Templates\en-US\*.adml" -Destination "$env:windir\PolicyDefinitions\en-US" -Force


Write-Host ("Importing Hardening Registry settings for build $build")
& "$PSScriptRoot\LGPO.exe" /m "$Subfolder2\comp_registry.pol" /s "$Subfolder2\GptTmpl.inf" /ac "$Subfolder2\audit.csv" /u "$Subfolder2\user_registry.pol" /v

# HARDENING: 18.5.4.1 (L1) Set 'NetBIOS node type' to 'P-node' (Ensure NetBT Parameter 'NodeType' is set to '0x2 (2)')
New-ItemProperty -Path $NodeTypeReg -Name NodeType -PropertyType DWORD -Value 2 -Force

# HARDENING: 2.3.10.10 (L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'
New-ItemProperty -Path $RemoteSAMReg -Name restrictremotesam -PropertyType String -Value "O:BAG:BAD:(A;;RC;;;BA)" -Force

Write-Host ('Setting message text in the Registry')
New-ItemProperty -Path $MsgReg -Name LegalNoticeText -PropertyType String -Value $MsgTxt -Force

Write-Host ('Setting message title in the Registry')
New-ItemProperty -Path $MsgReg -Name LegalNoticeCaption -PropertyType String -Value $MsgTitle -Force
