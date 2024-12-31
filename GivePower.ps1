#Install-Module -Name localaccount

function Give-PowerShellAndCommandPromptToAllUsers
{
    $powershellPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    $powershellPathx86 = "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
    $cmdPath = "C:\Windows\System32\cmd.exe"


    $allUsers = Get-LocalUser | Where-Object {
        $_.Name -notin @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')
    }

    if ($allUsers.Count -eq 0)
    {
        Write-Host "No local users found" -ForegroundColor Yellow
        return
    }

    foreach($user in $allUsers)
    {
        $fullUser = "$env:COMPUTERNAME\$($user.Name)"
        
        takeown /f $powerShellPath
        takeown /f $powerShellPathx86
        takeown /f $cmdPath

        icacls $powershellPath /grant "${fullUser}:(F)"
        icacls $powershellPathx86 /grant "${fullUser}:(F)"
        icacls $cmdPath /grant "${fullUser}:(F)"

        Write-Host "'$fullUser' has been granted permission for PowerShell and Command Prompt" -ForegroundColor Green
    }
}


function Show-PrivacyAndLocationSettingsPage
{
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-ItemProperty -Path $regPath -Name "SettingsPageVisibility" -Value "show:privacy-location"
}


Give-PowerShellAndCommandPromptToAllUsers
#Show-PrivacyAndLocationSettingsPage
