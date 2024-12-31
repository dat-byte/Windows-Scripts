# Upon Log-On Scripts


function Deny-PowerShellAndCommandPromptToCurrentUser
{
    # TODO: Change ME
    $AllowedUser = "kelsei"

    $powershellPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    $powershellPathx86 = "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
    $cmdPath = "C:\Windows\System32\cmd.exe"

    takeown /f $powerShellPath    | Out-Null
    takeown /f $powerShellPathx86 | Out-Null
    takeown /f $cmdPath           | Out-Null

    icacls $powershellPath /reset    | Out-Null
    icacls $powershellPathx86 /reset | Out-Null
    icacls $cmdPath /reset           | Out-Null

    if ($env:USERNAME -eq $AllowedUser)
    {
        icacls $powershellPath    /grant "${env:COMPUTERNAME}\${AllowedUser}:(RX)" | Out-Null
        icacls $powershellPathx86 /grant "${env:COMPUTERNAME}\${AllowedUser}:(RX)" | Out-Null
        icacls $cmdPath           /grant "${env:COMPUTERNAME}\${AllowedUser}:(RX)" | Out-Null
    }
    else 
    {
        $currentUser = (Get-CimInstance -Class Win32_ComputerSystem).UserName
        icacls $cmdPath           /deny "${currentUser}:(RX)" | Out-Null
        icacls $powershellPath    /deny "${currentUser}:(RX)" | Out-Null
        icacls $powershellPathx86 /deny "${currentUser}:(RX)" | Out-Null
    }
    
}
