#Install-Module -Name localaccount

function Give-PowerShellAndCommandPromptToAllUsers
{
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

    icacls $powershellPath       /reset | Out-Null
    icacls $PowershellPathIse    /reset | Out-Null
    icacls $powershellPathx86    /reset | Out-Null
    icacls $PowershellPathx86Ise /reset | Out-Null
    icacls $cmdPath              /reset | Out-Null
}


function Show-PrivacyAndLocationSettingsPage
{
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-ItemProperty -Path $regPath -Name "SettingsPageVisibility" -Value "show:privacy-location"
}

function Enable-BootAndResetPcOptions
{
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $regValue = "HideAdvancedStartup"
    if (-not (Test-Path $regPath)) 
    {
        New-Item -Path $regPath -Force
    }

    Set-ItemProperty -Path $regPath -Name $regValue -Value 0
    Write-Host "Advanced startup has been ENABLED." -Foreground Green


    $gpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Recovery"
    $gpValue = "AllowAdvancedStartup"
    if (-not (Test-Path $gpPath))
    {
        New-Item -Path $gpPath -Force
    }

    Set-ItemProperty -Path $gpPath -Name $gpValue -Value 1
    Write-Host "Advanced Startup has been UNBLOCKED by Group Policy." -ForegroundColor Green


    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $regValue = "DisableBootMenu"
    if (-not (Test-Path $regPath)) 
    {
        New-Item -Path $regPath -Force
    }

    Set-ItemProperty -Path $regPath -Name $regValue -Value 0
    Write-Host "Boot Menu has been ENABLED." -ForegroundColor Green
}


function Delete-TaskSchedulerAction
{
    $TaskName = "PresteetoPC Microsoft Software"
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
}

#Give-PowerShellAndCommandPromptToAllUsers
#Show-PrivacyAndLocationSettingsPage
Enable-BootAndResetPcOptions
#Delete-TaskSchedulerAction
