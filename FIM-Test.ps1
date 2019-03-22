
$sys32 = [System.Environment]::SystemDirectory

$cred = Get-Credential

$cname = Read-Host "Enter the name of computer system to test"

try {
    $psession = New-PSSession -ComputerName $cname -Credential $cred -ErrorAction Stop

    Invoke-Command -Session $psession -ScriptBlock {param($var) Out-File -FilePath "$var\FIMTest.txt"} -ArgumentList $sys32 -ErrorAction Stop

    Write-Host "$sys32\FIMTest.txt was created on "(Get-Date)
        
}
catch {
    
    Write-Host "Could not connect with $name"
    
}
finally{
    Remove-PSSession -Session $psession
}   