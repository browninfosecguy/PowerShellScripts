#Author: @browninfosecguy

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
Write-Output "IP Configuration" | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Get-NetIPConfiguration | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Write-Output "System Information" | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Get-ComputerInfo | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Write-Output "Processes Running on the System" | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Get-Process | Select-Object Name,Path,ProductVersion,Description | Format-List| Out-File -Append C:\$computerName`_SystemInfo.txt
format
Write-Output "List of Services on the System (Running and Stopped)" | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Get-Service | Select-Object DisplayName,Status | Sort-Object Status -Descending | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Write-Output "List of Paatches Applied to the Server" | Out-File -Append C:\$computerName`_SystemInfo.txt
format
Get-hotFix | Sort-Object InstalledOn| Out-File -Append C:\$computerName`_SystemInfo.txt
format
Write-Output "List of Installed Software" | Out-File -Append C:\$computerName`_SystemInfo.txt
format
#Get-WmiObject -class win32_Product | Out-File -Append C:\$computerName_SystemInfo.txt
Get-CimInstance -class Win32_Product| Select-Object Name,Vendor,Version | Out-File -Append C:\$computerName`_SystemInfo.txt
format
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
    Write-Output "The host was able to ping Google.ca Successfully" | Out-File -Append C:\$computerName`_SystemInfo.txt
}
else
{
    Write-Output "The host failed to ping Googel.ca" | Out-File -Append C:\$computerName`_SystemInfo.txt
}
format
