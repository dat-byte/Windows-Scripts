# This will be part of the Installation Script

function Create-CustomerAccount
{
    $newUserName = Read-Host "Enter the new USERNAME you want to create: "
    $securePassword = Read-Host -AsSecureString "Enter the new user's password (input will be hidden): "

    $newUserPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    )

    $computerName = $env:COMPUTERNAME
    $fullUser = "$computerName\$newUserName"
    
    $userExists = Get-LocalUser | Where-Object { $_.Name -eq $newUserName }
    if ($userExists) 
    {
        Write-Host "The user '$newUserName' already exists. Not creating user" -ForegroundColor Yellow
        Write-Host "Moving onto blocking PowerShell and Command Prompt" -ForegroundColor Yellow
    }
    else 
    {
        Write-Host "Creating user '$newUserName' with the provided password"
        net user $newUserName $newUserPassword /add
        net localgroup Administrators $newUserName /add
        Write-Host "User `$newUserName` created and added to Administrators group." -ForegroundColor Green
    }

    try 
    {
        Block-PowerShellAndCommandPrompt -fullUser $fullUser
        Write-Host "User '$newUserName' is now blocked from running PowerShell and Command Prompt" -ForegroundColor Green
    }
    catch 
    {
        Write-Error "Error in blocking Block-PowerShellAndCommandPrompt function"
        throw
    }
    
}


function Block-PowerShellAndCommandPrompt
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$fullUser
    )

    try
    {
        $powershellPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        $powershellPathx86 = "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
        Write-Host "Applying ACL deny execution for PowerShell..." -ForegroundColor Red
        takeown /f $powershellPath
        takeown /f $powershellPathx86
        
        # deny everyone for powershell execept PresteetoPc
        icacls $powershellPath /deny "BUILTIN\Administrators:(RX)"
        icacls $powershellPath /deny "NT AUTHORITY\Authenticated Users:(RX)"
        icacls $powershellPath /grant "$env:COMPUTERNAME\kelsei:(RX)"

        #icacls $powershellPathx86 /deny "${fullUser}:(RX)"
    }
    catch 
    {
        Write-Error "Error blocking powershell.exe"
        Write-Error "$_"
        throw
    }
    
    try 
    {
        $cmdPath = "C:\Windows\System32\cmd.exe"
        Write-Host "Applying ACL deny execution for Command Prompt..."
        takeown /f $cmdPath
        icacls $cmdPath /deny "${fullUser}:(RX)"

        Write-Host "ACL modifications complete." -ForegroundColor Green
    }
    catch
    {
        Write-Host "Error blocking cmd.exe"
        Write-Host "$_"
        throw
    }
}


function Hide-PrivacyAndLocationSettingsPage
{
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-ItemProperty -Path $regPath -Name "SettingsPageVisibility" -Value "hide:privacy-location"
}


Create-CustomerAccount
#Hide-PrivacyAndLocationSettingsPage
