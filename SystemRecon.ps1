#Author: @browninfosecguy

<#

TODO1: (DONE)Need lot of cleanup for running processes and installed sodtware onthe system. 
TODO2: (DONE)Add more scirpt to fetch starup processes during bootup
TODO3: (DONE) Need to add fucntionality to spit output in clean format maybe in HTML files and then zip them to a folder (Research more on Compress-Archive)
TODO4: Need to add Remoting fucntionality to the script to gather data from systems in the network

#>

$cssTable="h1, h5, th { text-align: center; }
table { margin: auto; font-family: Segoe UI; box-shadow: 10px 10px 5px #888; border: thin ridge grey; }
th { background: #0046c3; color: #fff; max-width: 400px; padding: 5px 10px; }
td { font-size: 11px; padding: 5px 20px; color: #000; }
tr { background: #b8d1f3; }
tr:nth-child(even) { background: #dae5f4; }
tr:nth-child(odd) { background: #b8d1f3; }"


$cssTable | Out-File "C:\table.css"


function format{
        Write-Output "*************************************************************" | Out-File -Append C:\$computerName`_SystemInfo.txt
}

function testInternet{
Param(
[int]$code = 0
)

    try{
        #Invoke-WebRequest "https://google.ca" | Select-Object Statuscode
        $code=(Invoke-WebRequest "https://google.ca" -timeoutsec 30).statuscode
        Write-Output $code
        }
    catch{
        Write-Output $code
        }
}

function checkProcessVendor{

        $recognizedVendor = "Microsoft Corporation","Google Inc.","Oracle Corporation"

        $company = Get-Process | Select-Object Name, Company, Path

        $company | ForEach-Object{if(!$recognizedVendor.contains($_.Company)){Write-output  $_.Name,$_.path}}

}

$computerName = (Get-WmiObject -class Win32_computerSystem).Name.ToString()

Write-Output "*************************************************************" | Out-File C:\$computerName`_SystemInfo.txt
Write-Output "Name of the System" | Out-File -Append C:\$computerName`_SystemInfo.txt 
format
Get-WmiObject -class Win32_computerSystem | Select-Object Name | Out-File -Append C:\$computerName`_SystemInfo.txt 
format
Write-Output "Date and Time Zone" | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Get-Date | Out-File -Append C:\$computerName`_SystemInfo.txt
Get-TimeZone | Out-File -Append C:\$computerName`_SystemInfo.txt
format
#Get Network Adapter Information
Write-Output "IP Configuration" | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Get-NetIPConfiguration | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Write-Output "System Information" | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Get-ComputerInfo | Out-File -Append C:\$computerName`_SystemInfo.txt
format
#Get a list of Running Processes
Write-Output "Processes Running on the System" | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Get-Process | Select-Object Name,Path,ProductVersion,Description, Company | ConvertTo-Html -CssUri table.css| Out-File C:\$computerName`_SystemInfo_RunningProcesses.html
format
#Get a list of Services
Write-Output "List of Services on the System (Running and Stopped)" | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Get-Service | Select-Object DisplayName,Status | Sort-Object Status -Descending | Out-File -Append C:\$computerName`_SystemInfo.txt
format
#Get a list of Patches Applied
Write-Output "List of Patches Applied to the Server" | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Get-hotFix | Sort-Object InstalledOn| Out-File -Append C:\$computerName`_SystemInfo.txt
format
Write-Output "List of Installed Software" | Out-File -Append C:\$computerName`_SystemInfo.txt
format
#Get-WmiObject -class win32_Product | Out-File -Append C:\$computerName_SystemInfo.txt
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate|ConvertTo-Html -CssUri table.css | Out-File C:\$computerName`_SystemInfo_InstalledPrograms32Bit.html
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |ConvertTo-Html -CssUri table.css| Out-File C:\$computerName`_SystemInfo_InstalledPrograms64Bit.html
#Get-CimInstance -class Win32_Product| Select-Object Name,Vendor,Version | Out-File -Append C:\$computerName`_SystemInfo.txt
format
#Get NTP server setting
Write-Output "NTP Settings" | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Get-ItemProperty -path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters|Out-File -Append C:\$computerName`_SystemInfo.txt
format
Write-Output "Run Key" | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Write-Output "Testing for External Internet Connectivity" | Out-File -Append C:\$computerName`_SystemInfo.txt
format
$return = testInternet

if ($return -eq 200)
{
    Write-Output "The host was able to reach Google.ca Successfully" | Out-File -Append C:\$computerName`_SystemInfo.txt
}
else
{
    Write-Output "The host failed to reach Google.ca" | Out-File -Append C:\$computerName`_SystemInfo.txt
}
format
#Get a List of Ports Listening
Write-Output "List of Open Ports on the System"|Out-File -Append C:\$computerName`_SystemInfo.txt
format
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,State | Sort-Object LocalPort -Descending | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Write-Output "List of Unknown Processes Running on the Sytem" | Out-File -Append C:\$computerName`_SystemInfo.txt
checkProcessVendor | Out-File -Append C:\$computerName`_SystemInfo.txt
format
#Get a list of Local Accounts
Write-Output "List of Local Account on System"|Out-File -Append C:\$computerName`_SystemInfo.txt
format
Get-LocalUser| Select-Object Name,Enabled,PasswordExpires,PasswordLastSet,PasswordRequired,AccountExpires | Out-File -Append C:\$computerName`_SystemInfo.txt
format
#Get a list of Startup Programs
Write-Output "List of Startup Programs"|Out-File -Append C:\$computerName`_SystemInfo.txt
format
Get-CimInstance -class Win32_StartupCommand | Out-File -Append C:\$computerName`_SystemInfo.txt



#Compress Everything and put files in a ZIP Folder.
Compress-Archive -LiteralPath C:\table.css,C:\$computerName`_SystemInfo.txt,C:\$computerName`_SystemInfo_RunningProcesses.html,C:\$computerName`_SystemInfo_InstalledPrograms32Bit.html,C:\$computerName`_SystemInfo_InstalledPrograms64Bit.html -DestinationPath C:\$computerName`_SystemInfo.zip -Force

Remove-Item -LiteralPath C:\table.css,C:\$computerName`_SystemInfo.txt,C:\$computerName`_SystemInfo_RunningProcesses.html,C:\$computerName`_SystemInfo_InstalledPrograms32Bit.html,C:\$computerName`_SystemInfo_InstalledPrograms64Bit.html

