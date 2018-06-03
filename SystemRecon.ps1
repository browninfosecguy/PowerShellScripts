Get-WmiObject -class Win32_computerSystem | Select-Object Name | Out-File C:\SystemInfo.txt 
Get-Date | Out-File -Append C:\SystemInfo.txt
Get-TimeZone | Out-File -Append C:\SystemInfo.txt
Get-NetIPConfiguration | Out-File -Append C:\SystemInfo.txt
Get-ComputerInfo | Out-File -Append C:\SystemInfo.txt
Get-Process | Out-File -Append C:\SystemInfo.txt
Get-Service | Out-File -Append C:\SystemInfo.txt
Get-hotFix | Out-File -Append C:\SystemInfo.txt
Get-WmiObject -class win32_Product | Out-File -Append C:\SystemInfo.txt

