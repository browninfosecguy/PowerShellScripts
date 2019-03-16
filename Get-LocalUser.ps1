
<#

Following script can be used to Check local users on systems across your organization.
This script is best when you run on a DC

#>
Start-Transcript -Path "C:\WindowsLocalUser_Evidence.txt"

$cred = Get-Credential -Message "Please provide DC Admin Credentials"

$computername = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

foreach($name in $computername)
{

    try {
        $psession = New-PSSession -ComputerName $name -Credential $cred -ErrorAction Stop

        Invoke-Command -Session $psession -ScriptBlock {Get-LocalUser | where-object {$_.enabled}} -ErrorAction Stop
        
    }
    catch {
        
        Write-Host "Could not connect with $name"
        
    }
    finally{
        Remove-PSSession -Session $psession
    }   

}


Stop-Transcript