<#
    Set the default user profile settings to include:
    -Show File Extension in Explorer
    -Set Desktop Icons to include:
        -ThisPC, User Profile, Recycle Bin, Control Panel
#>

$DefaultProfile = "" | Select-Object SID, UserHive
$DefaultProfile.SID = ".DEFAULT"
$DefaultProfile.Userhive = "C:\Users\Default\NTuser.dat"

Write-Host ('Loading Default Profile Registry')
Start-Process -FilePath "CMD.exe" -ArgumentList "/C Reg.exe LOAD HKU\$($DefaultProfile.SID) $($DefaultProfile.Userhive)" -Wait -WindowStyle Hidden

Write-Host ("Setting Dark Mode (Default User)")
$Theme = "Registry::HKEY_USERS\$($DefaultProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes"
New-Item -Path $Theme -Name "Personalize" -Force -ErrorAction SilentlyContinue
$Personalize = "Registry::HKEY_USERS\$($DefaultProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
New-ItemProperty -Path $Personalize -Name "AppsUseLightTheme" -PropertyType DWORD -Value 0 -Force | Out-Null
New-ItemProperty -Path $Personalize -Name "SystemUsesLightTheme" -PropertyType DWORD -Value 0 -Force | Out-Null
New-ItemProperty -Path $Personalize -Name "EnableTransparency" -PropertyType DWORD -Value 0 -Force | Out-Null

Write-Host ("Setting File Explorer to Show Extensions (Default User)")
$key = "Registry::HKEY_USERS\$($DefaultProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
New-ItemProperty -Path $key -Name HideFileExt -PropertyType DWORD -Value 0 -Force | Out-Null

Write-Host ('Setting File Explorer to Show Extensions for the Current User')
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name HideFileExt -PropertyType DWORD -Value 0 -Force -Verbose

Write-Host ('Setting File Explorer to Show Extensions (HKLM)')
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name HideFileExt -PropertyType DWORD -Value 0 -Force -Verbose

Write-Host ('Deleting the Edge icon from the Default Users Desktop')
$key = "Registry::HKEY_USERS\$($DefaultProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
New-ItemProperty -Path $key -Name DisableEdgeDesktopShortcutCreation -PropertyType DWORD -Value 1 -Force | Out-Null

Write-Host ('Unload Default Profile Registry')
Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($DefaultProfile.SID)" -Wait -WindowStyle Hidden| Out-Null

Write-Host ('Deleting Enterprise Mode Site List Manager and Google Chrome from C:\Users\Public\Desktop')
Remove-Item -Path "C:\Users\Public\Desktop\Google*.*" -Force -Verbose -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\Public\Desktop\Enterprise*.*" -Force -Verbose -ErrorAction SilentlyContinue

Write-Host ('Removing Saved Games, OneDrive, and 3D Objects from the default profile')
Remove-Item "C:\Users\$env:UserName\Saved Games" -Recurse -Force -Verbose -ErrorAction SilentlyContinue
Remove-Item "C:\Users\$env:UserName\3D Objects" -Recurse -Force -Verbose -ErrorAction SilentlyContinue
Remove-Item "C:\Users\$env:UserName\OneDrive" -Recurse -Force -Verbose -ErrorAction SilentlyContinue