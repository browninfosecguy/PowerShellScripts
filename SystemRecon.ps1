Write-Output "*************************************************************" | Out-File C:\SystemInfo.txt
Write-Output "Name of the System" | Out-File -Append C:\SystemInfo.txt 
Get-WmiObject -class Win32_computerSystem | Select-Object Name | Out-File -Append C:\SystemInfo.txt 
Write-Output "*************************************************************" | Out-File -Append C:\SystemInfo.txt
Write-Output "Date and Time Zone" | Out-File -Append C:\SystemInfo.txt
Get-Date | Out-File -Append C:\SystemInfo.txt
Get-TimeZone | Out-File -Append C:\SystemInfo.txt
Write-Output "*************************************************************" | Out-File -Append C:\SystemInfo.txt
Write-Output "IP Configuration" | Out-File -Append C:\SystemInfo.txt
Get-NetIPConfiguration | Out-File -Append C:\SystemInfo.txt
Write-Output "*************************************************************" | Out-File -Append C:\SystemInfo.txt
Write-Output "System Information" | Out-File -Append C:\SystemInfo.txt
Get-ComputerInfo | Out-File -Append C:\SystemInfo.txt
Write-Output "*************************************************************" | Out-File -Append C:\SystemInfo.txt
Write-Output "Processes Running on the System" | Out-File -Append C:\SystemInfo.txt
Get-Process | Select-Object Name,Path,ProductVersion,Description | Format-List| Out-File -Append C:\SystemInfo.txt
Write-Output "*************************************************************" | Out-File -Append C:\SystemInfo.txt
Write-Output "List of Services on the System (Running and Stopped)" | Out-File -Append C:\SystemInfo.txt
Get-Service | Select-Object DisplayName,Status | Sort-Object Status -Descending | Out-File -Append C:\SystemInfo.txt
Write-Output "*************************************************************" | Out-File -Append C:\SystemInfo.txt
Write-Output "List of Paatches Applied to the Server" | Out-File -Append C:\SystemInfo.txt
Get-hotFix | Sort-Object InstalledOn| Out-File -Append C:\SystemInfo.txt
Write-Output "*************************************************************" | Out-File -Append C:\SystemInfo.txt
Write-Output "List of Installed Software" | Out-File -Append C:\SystemInfo.txt
#Get-WmiObject -class win32_Product | Out-File -Append C:\SystemInfo.txt
Get-CimInstance -class Win32_Product| Select-Object Name,Vendor,Version | Out-File -Append C:\SystemInfo.txt
Write-Output "*************************************************************" | Out-File -Append C:\SystemInfo.txt
Write-Output "NTP Settings" | Out-File -Append C:\SystemInfo.txt
Get-ItemProperty -path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters
Write-Output "*************************************************************" | Out-File -Append C:\SystemInfo.txt
Write-Output "Run Key" | Out-File -Append C:\SystemInfo.txt
Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
