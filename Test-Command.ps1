 $newObject = New-Object -TypeName psobject
$newObject | Add-Member -MemberType NoteProperty -Name "Name" -Value "MicrosoftEdge"

$Names = @(
'ParameterBinderBase',
'ParameterBinderController',
'ParameterBinding',
'TypeConversion'
)

Trace-Command -Name $Names -Expression {$newObject |Stop-Process} -PSHost
 
