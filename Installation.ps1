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
        Write-Host "User '$newUserName' created and added to Administrators group." -ForegroundColor Green
    }
}

function Create-LogOnTaskScheduler
{
    # TODO: VERIFY ME
    $ScriptPath = "C:\PresteetoPc\UserRestriction.ps1"
    $TaskName = "PresteetoPC Microsoft Software"

    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe"` "-NoProfile -ExecutionPolicy Bypass -Command -File `"$ScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal

    Write-Host "Scheduled task was made for LogOn.ps1 scripts" -ForegroundColor Green
}


Create-CustomerAccount
