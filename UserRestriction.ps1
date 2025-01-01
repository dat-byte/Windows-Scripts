function Deny-PowerShellAndCommandPromptToCurrentUser
{
    # TODO: Change ME
    $AllowedUser = "david"

    $powershellPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    $PowershellPathIse = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe"

    $powershellPathx86 = "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
    $PowershellPathx86Ise = "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe"

    $cmdPath = "C:\Windows\System32\cmd.exe"

    takeown /f $powerShellPath       | Out-Null
    takeown /f $powerShellPathIse    | Out-Null
    takeown /f $powerShellPathx86    | Out-Null
    takeown /f $PowershellPathx86Ise | Out-Null
    takeown /f $cmdPath              | Out-Null

    icacls $powershellPath /reset    | Out-Null
    icacls $powershellPathx86 /reset | Out-Null
    icacls $cmdPath /reset           | Out-Null

    $currentUser = (Get-CimInstance -Class Win32_ComputerSystem).UserName
    $nameOfCurrentUser = $currentUser -split '\\' | Select-Object -Last 1

    if ($nameOfCurrentUser -eq $AllowedUser)
    {
        Write-Host "'$currentUser' is an allowed user" -ForegroundColor Green
        icacls $powershellPath       /grant "${currentUser}:(RX)" | Out-Null
        icacls $powershellPathIse    /grant "${currentUser}:(RX)" | Out-Null
        icacls $powershellPathx86    /grant "${currentUser}:(RX)" | Out-Null
        icacls $powershellPathx86Ise /grant "${currentUser}:(RX)" | Out-Null
        icacls $cmdPath              /grant "${currentUser}:(RX)" | Out-Null
    }
    else 
    {
        Write-Host "'$currentUser' IS NOT an allowed user" -ForegroundColor Red
        icacls $cmdPath              /deny "${currentUser}:(RX)" | Out-Null
        icacls $powershellPath       /deny "${currentUser}:(RX)" | Out-Null
        icacls $PowershellPathIse    /deny "${currentUser}:(RX)" | Out-Null
        icacls $powershellPathx86    /deny "${currentUser}:(RX)" | Out-Null
        icacls $PowershellPathx86Ise /deny "${currentUser}:(RX)" | Out-Null
    }   
}

function Change-LocationValueAndSettingsPageVisibility
{
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-ItemProperty -Path $regPath -Name "SettingsPageVisibility" -Value "hide:privacy-location"
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy /v LetAppsAccessLocation /t REG_DWORD /d 1 /f
}

function Prevent-UserFromResettingPc
{
    Start-Process "reagentc.exe" -ArgumentList "/disable" -Verb RunAs -Wait
    
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $regValue = "HideAdvancedStartup"

    if (-not (Test-Path $regPath)) 
    {
        New-Item -Path $regPath -Force
    }

    Set-ItemProperty -Path $regPath -Name $regValue -Value 1
    Write-Host "Advanced startup has been disabled." -Foreground Green


    $gpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Recovery"
    $gpValue = "AllowAdvancedStartup"

    if (-not (Test-Path $gpPath))
    {
        New-Item -Path $gpPath -Force
    }

    Set-ItemProperty -Path $gpPath -Name $gpValue -Value 0
    Write-Host "Advanced Startup has been blocked by Group Policy." -ForegroundColor Green


    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $regValue = "DisableBootMenu"

    if (-not (Test-Path $regPath)) 
    {
        New-Item -Path $regPath -Force
    }

    Set-ItemProperty -Path $regPath -Name $regValue -Value 1
    Write-Host "Boot Menu has been disabled." -ForegroundColor Green
}

Deny-PowerShellAndCommandPromptToCurrentUser
Change-LocationValueAndSettingsPageVisibility
Prevent-UserFromResettingPc

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$folderPath = Join-Path -Path $scriptRoot -ChildPath $timestamp
New-Item -Path $folderPath -ItemType Directory | Out-Null
