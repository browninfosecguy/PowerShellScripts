
<#

Following script can be used to Check the latest update applied to systems across your organization.
This script is best when you run on a DC

#>

$cred = Get-Credential -Message "Please provide DC Admin Credentials"

$computername = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

foreach($name in $computername)
{

    $psession = New-PSSession -ComputerName $name -Credential $cred

    Invoke-Command -Session $psession -ScriptBlock {(Get-HotFix|Sort-Object InstalledOn)[-1]}

    Remove-PSSession -Session $psession

}
