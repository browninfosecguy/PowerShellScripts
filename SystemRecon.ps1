Write-Output "*************************************************************" | Out-File C:\SystemInfo.txt
Write-Output "Name of the System" | Out-File -Append C:\SystemInfo.txt 
Get-WmiObject -class Win32_computerSystem | Select-Object Name | Out-File -Append C:\SystemInfo.txt 
Write-Output "*************************************************************" | Out-File -Append C:\SystemInfo.txt
Get-Date | Out-File -Append C:\SystemInfo.txt
Get-TimeZone | Out-File -Append C:\SystemInfo.txt
Get-NetIPConfiguration | Out-File -Append C:\SystemInfo.txt
Get-ComputerInfo | Out-File -Append C:\SystemInfo.txt
Get-Process | Select-Object Name,Path,ProductVersion,Description | Format-List| Out-File -Append C:\SystemInfo.txt
Get-Service | Select-Object DisplayName,Status | Sort-Object Status -Descending | Out-File -Append C:\SystemInfo.txt
Get-hotFix | Out-File -Append C:\SystemInfo.txt
Get-WmiObject -class win32_Product | Out-File -Append C:\SystemInfo.txt
 Get-CimInstance -class Win32_Product| Select-Object Name,Vendor,Version | Out-File -Append C:\SystemInfo.txt
