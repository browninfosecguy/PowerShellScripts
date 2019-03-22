$computername = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

$total =  ($computername).Count

$sample = 10%($total)

$servers = Get-Random -InputObject $computername -Count $sample

foreach($name in $servers)
{
    try {
        $psession = New-PSSession -ComputerName $name -Credential $cred -ErrorAction Stop

        Invoke-Command -Session $psession -ScriptBlock {(Get-HotFix|Sort-Object InstalledOn)[-1]} -ErrorAction Stop
    
    }
    catch {
    
        Write-Host "Could not connect with $name"
    
    }
    finally{
        try{
            Remove-PSSession -Session $psession
        }
        catch{}
        
    }
    
}