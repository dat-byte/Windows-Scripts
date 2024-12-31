# This will be inside installer

function Create-LogOnTaskScheduler
{
    # TODO: VERIFY ME
    $ScriptPath = "C:\Program Files\Scripts\LogOn.ps1"
    $TaskName = "PresteetoPC Microsoft Software"

    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe"`-Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
    Write-Host "Scheduled task was made for LogOn.ps1 scripts" -ForegroundColor Green
}

Create-LogOnTaskScheduler
