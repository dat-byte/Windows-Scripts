$SUBJECT = "PresteetoPc"
$ZIP_FILE_PATH = Join-Path -Path $PSSCriptRoot -ChildPath "PresteetoPc_LocationTracker.zip"
$PACKAGE_PATH = "$env:USERPROFILE\Documents\PresteetoPc_LocationTracker"
$MSIX_FILE_NAME = "PresteetoPc_LocationTracker_1.0.1.0_x64.msix"


function Get-CurrentUser 
{
    $user = (Get-WmiObject -Class Win32_ComputerSystem).Username.Split('\')[-1]
    return $user
}


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
        net user $newUserName $newUserPassword /add     | Out-Null
        net localgroup Administrators $newUserName /add | Out-Null
        Write-Host "User '$newUserName' created and added to Administrators group." -ForegroundColor Green
    }

    return $fullUser
}


function Copy-ZipFileToCDrive
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZipFilePath
    )

    if (-not (Test-Path $ZipFilePath))
    {
        Write-Error "The specified ZIP file does not exist: $ZipFilePath"
        exit 1
    }

    $destinationFilePath = "$env:USERPROFILE\Documents"
    Copy-FileToPath -SourcePath $ZipFilePath -DestinationPath $destinationFilePath
    Expand-Archive -Path (Join-Path -Path $destinationFilePath -ChildPath (Split-Path $ZipFilePath -Leaf)) -DestinationPath $destinationFilePath -Force | Out-Null
}


function Copy-FileToPath
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath
    )

    if (-not (Test-Path -Path $SourcePath))
    {
        Write-Host "'$SourcePath' does not exist" -ForegroundColor Red
        Exit 1
    }

    if (-not (Test-Path -Path $DestinationPath))
    {
        New-Item -ItemType Directory -Path $DestinationPath
    }

    Copy-Item -Path $SourcePath -Destination $DestinationPath -Force | Out-Null
    Write-Host "Copied $SourcePath to $DestinationPath" -ForegroundColor Green
}


function Create-CertificateFile 
{
    param (
        [string]$ItemToSign,
        [string]$Subject,
        [string]$CertLocation,
        [string]$PackagePath
    )
    
    $Certificate = New-SelfSignedCertificate -HashAlgorithm sha256 -Subject $Subject -CertStoreLocation $CertLocation -NotAfter (Get-Date).AddYears(3) -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
    if (-not $Certificate)
    {
        Write-Error "Failed to create self-signed certificate"
        exit 1
    }

    $user = Get-CurrentUser
    $CertPath = "$PackagePath\$Subject.cer"

    try
    {
        Export-Certificate -Cert $Certificate -FilePath $CertPath | Out-Null
        Write-Host "Certificate was created"
    } 
    catch
    {
        Write-Error "Failed to export certificate: $_"
        exit 1
    } 

    try 
    {
        Write-Host "Adding Certificate $CertPath to root"
        Import-Certificate -FilePath $CertPath -CertStoreLocation "Cert:\LocalMachine\Root" -ErrorAction SilentlyContinue -Confirm | Out-Null
        Write-Host "Certificate installed to Trusted Root Certification Authorities." -ForegroundColor Green
    }
    catch 
    {
        Write-Error "Failed to import certficate: $_"
        exit 1
    }
}


function Sign-Packages
{
    param(
        [string]$Item,
        [string]$CertFileName
    )

     $SignToolPath = Join-Path -Path $PSScriptRoot -ChildPath "signtool.exe"
     if (Test-Path $SignToolPath)
     {
        try 
        {
            Write-Host "Signing File: $Item"
            Write-Host "Certificate File Path: $CertFileName"

            Start-Process -FilePath $SignToolPath -ArgumentList @(
                "sign",
                "/f $CertFileName",
                "/fd sha256",
                "$Item"
            ) -NoNewWindow -Wait | Out-Null

        } 
        catch 
        {
            Write-Error "Failed to sign file: $_"
            exit 1
        }
    }
}


function Install-PresteetoPcPackage
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$MsixFileLocation,
        [Parameter(Mandatory = $true)]
        [string]$CertificatePath
    )
    Write-Host "Msix File Location: $MsixFileLocation"
    Write-Host "Certificate Path: $CertificatePath"

    Add-AppxPackage -Path $MsixFileLocation
}


function Get-PackageFullName 
{
    $package = Get-AppxPackage | Where-Object { $_.Name -like "*PresteetoPc*" }
    if ($null -eq $package)
    {
        Write-Error "No matching app package for PresteetoPc"
        exit 1
    }

    return $package.PackageFamilyName
}


function Create-UWPAppTaskScheduler 
{
    param (
        [string]$taskName = "DamnAssFuck",
        [string]$programPath = "explorer.exe",
        [datetime]$startTime = (Get-Date).Date.AddHours(10) # Default is 10:00 AM today
    )

    try 
    {
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
        {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }

        $packageFullName = Get-PackageFullName
        $appArgument = "shell:AppsFolder\$packageFullName!App"

        $trigger = New-ScheduledTaskTrigger -Daily -At $startTime
        $action = New-ScheduledTaskAction -Execute $programPath -Argument $appArgument

        # TODO: FIX THIS BY DEFAULT SYSTEM USER DOES NOT HAVE A UI NEEDS TO BE THE CURRENT USER (AKA CUSTOMER)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1)
        Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -Principal $principal -Settings $settings
    } 
    catch 
    {
        Write-Host "Error creating task: $_"
    }
}


function Create-LogOnTaskScheduler
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$ScriptPath,
        [Parameter(Mandatory=$true)]
        [string]$TaskName
    )

    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    {
        Write-Host "'$TaskName' has already been created. Deleting so can add new task" -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe"` "-NoProfile -ExecutionPolicy Bypass -Command ""& { & '$ScriptPath'; Start-Sleep -Seconds 10 }"""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal | Out-Null
    Write-Host "Created Task: $TaskName" -ForegroundColor Green
}


function Install-PresteetoPcSoftware
{
    param(
        [string]$Subject,
        [string]$PackagePath,
        [string]$MsixFileName,
        [string] $ZipFilePath
    )
    <#
    Copy-ZipFileToCDrive -ZipFilePath $ZipFilePath
    Create-CertificateFile  -Subject $Subject -CertLocation "cert:\CurrentUser\My" -PackagePath $PackagePath    
    
    $Item = Join-Path -Path $PackagePath -ChildPath $MsixFileName
    if (-not (Test-Path $Item))
    {
        Write-Error "MSIX file not found at $Item"
        exit 1
    }

    $user = Get-CurrentUser
    Sign-Packages -Item $Item -CertFileName "C:\Users\$user\Documents\PresteetoPc_LocationTracker\PresteetoPc.cer" -Password $Password
    Install-PresteetoPcPackage -MsixFileLocation $Item -CertificatePath "C:\Users\$user\Documents\PresteetoPc_LocationTracker\PresteetoPc.cer"
    #>

    $UserRestrictionScriptDirectory = "C:\Windows\PresteetoPc\"
    Copy-FileToPath -SourcePath "${PSScriptRoot}UserRestriction.ps1" -DestinationPath $UserRestrictionScriptDirectory
    Create-LogOnTaskScheduler -ScriptPath "${UserRestrictionScriptDirectory}\UserRestriction.ps1" -TaskName "PresteetoPC Microsoft Software"
    
    #$CustomerName = Create-CustomerAccount
    # Step 8) Create a task to run the UWP tracking software - LEE
    # TODO: Create a task action to run UWP tracking software
}


$commands = @{
    Subject = $SUBJECT
    PackagePath = $PACKAGE_PATH
    MsixFileName = $MSIX_FILE_NAME
    ZipFilePath = $ZIP_FILE_PATH
}


Install-PresteetoPcSoftware @commands
