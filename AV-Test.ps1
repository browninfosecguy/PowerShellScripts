
$avTest ='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

$cred = Get-Credential

$cname = Read-Host "Enter the name of computer system to test"

try {
    $psession = New-PSSession -ComputerName $cname -Credential $cred -ErrorAction Stop

    Invoke-Command -Session $psession -ScriptBlock { param ($var) Out-File  -FilePath "$env:HOMEPATH\AVTest.txt" -InputObject $var -Encoding ASCII} -ArgumentList $avTest -ErrorAction Stop
        
}
catch {
    
    Write-Host "Could not connect with $name"
    
}
finally{
    Remove-PSSession -Session $psession
}   