
<#

Following script can be used to Check the latest update applied to systems across your organization.
This script is best when you run on a DC

#>
Start-Transcript -Path "C:\WindowsUpdate_Evidence.txt"

$cred = Get-Credential -Message "Please provide DC Admin Credentials"

$computername = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

foreach($name in $computername)
{

    try {
        $psession = New-PSSession -ComputerName $name -Credential $cred -ErrorAction Stop

        Invoke-Command -Session $psession -ScriptBlock {(Get-HotFix|Sort-Object InstalledOn)[-1]} -ErrorAction Stop
        
    }
    catch {

        Write-Host "Cannot connect with $name"
        
    }
    finally{
        Remove-PSSession -Session $psession
    }
    

    

}
Stop-Transcript