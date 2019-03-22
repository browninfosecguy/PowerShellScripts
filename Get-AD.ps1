<#

    Major part of this script is re use from Patrick Gruenauer work.
    Here is the link to his excellent work https://sid-500.com/2018/05/22/active-directory-domain-services-section-version-1-1/


#>
$cred=Get-Credential -Message 'Enter Username and Password of a Member of the Domain Admins Group'

$avTest ='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


function Get-AD {

    $line='========================================================='

    $line2='________________________________________________________'

    if (Get-Module -ListAvailable -Name ActiveDirectory) {

        Import-Module ActiveDirectory

    } else {

    ''

        Write-Host "Operation aborted. No Active Directory Module found. Run this tool on a Domain Controller." -ForegroundColor Red

    ''

    throw "Error"

}



cls


do {


Write-Host '---------------------------------------------------------'

Write-Host '           Windows Test Cases' -ForegroundColor Yellow

Write-Host '---------------------------------------------------------'

Write-Host " 1 - Forest | Domain | Sites Configuration ($env:userdnsdomain)"

Write-Host ' 2 - List Domain Controller'

Write-Host ' 3 - Show Default Domain Password Policy'

Write-Host ' 4 - List Domain Admins'

Write-Host ' 5 - List of Active GPOs'

Write-Host ' 6 - List all Windows Clients'

Write-Host ' 7 - List all Windows Server'

Write-Host ' 8 - List all Computers (by Operatingsystem)'

Write-Host '9 - Run Systeminfo on Remote Computers'

Write-Host '10 - List all Groups'

Write-Host '11 - List Group Membership by User'

Write-Host '12 - List all Users (enabled)'

Write-Host '13 - Find orphaned User or Computer Accounts'

Write-Host '14 - Check Installed Updates on a Machine'

Write-Host '15 - Check Internet Connectivity of a Machine'

Write-Host '16 - Check Open Ports on a Machine'

Write-Host '17 - Installed Programs on a Machine'

Write-Host '18 - Get a list of Local user account from a Machine'

Write-Host '19 - Generate the GPO Configured'

Write-Host '20 - Windows Update: Generate list of last update applied on computer in the domain'

Write-Host '21 - Generate the list of local user account on each computer in the domain'

Write-Host '22 - EICAR test file: Script will create test file named AVTest.txt in home directory'

Write-Host '23 - FIM Test: A file will be created at DRIVE:\Windows\system32 named FIMTest.txt'

Write-Host '0  - Quit' -ForegroundColor Red

Write-Host ''

$input=Read-Host 'Select'

switch ($input) 

 { 

 1 {

  
    Write-Host -ForegroundColor Green 'FOREST Configuration' 

    $get=Get-ADForest

    $forest+=New-Object -TypeName PSObject -Property ([ordered]@{

        'Root Domain'=$get.RootDomain

        'Forest Mode'=$get.ForestMode

        'Domains'=$get.Domains -join ','

        'Sites'=$get.Sites -join ','

    })

   

    $forest | Format-Table -AutoSize -Wrap

    
    Write-Host -ForegroundColor Green 'DOMAIN Configuration' 

    Get-ADDomain | Format-Table DNSRoot, DomainMode, ComputersContainer, DomainSID -AutoSize -Wrap

    Write-Host -ForegroundColor Green 'SITES Configuration'

        $GetSite = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites

        $Sites = @()

        foreach ($Site in $GetSite) {

        $Sites += New-Object -TypeName PSObject -Property (

        @{

        'SiteName'  = $site.Name

        'SubNets' = $site.Subnets -Join ','

        'Servers' = $Site.Servers -Join ','

        }

        )

        }

        $Sites | Format-Table -AutoSize -Wrap

    Write-Host -ForegroundColor Green 'Enabled OPTIONAL FEATURES' 

    Get-ADOptionalFeature -Filter * | Format-Table Name,RequiredDomainMode,RequiredForestMode -AutoSize -Wrap

 
    Read-Host 'Press 0 and Enter to continue'

	

    } 
 2 {

    $dcs=Get-ADDomainController -Filter * 

    $dccount=$dcs | Measure-Object | Select-Object -ExpandProperty count

    ''

    Write-Host -ForegroundColor Green "Active Directory Domain Controller ($env:userdnsdomain)" 

   $domdc=@()



    foreach ($dc in $dcs) {

    $domdc += New-Object -TypeName PSObject -Property (



    [ordered]@{

    'Name' = $dc.Name

    'IP Address' = $dc.IPv4Address

    'OS' = $dc.OperatingSystem

    'Site' = $dc.Site

    'Global Catalog' = $dc.IsGlobalCatalog

    'FSMO Roles' = $dc.OperationMasterRoles -join ','

    }

    )

    }

   $domdc | Format-Table -AutoSize -Wrap

    Write-Host 'Total Number: '$dccount"" -ForegroundColor Yellow

    $ping=Read-Host "Do you want to test connectivity (ping) to these Domain Controllers? (Y/N)"



    If ($ping -eq 'Y') {

	foreach ($items in $dcs.Name) {

	Test-Connection $items -Count 1 | Format-Table Address, IPv4Address, ReplySize, ResponseTime}

    Read-Host 'Press 0 and Enter to continue'

    }

    

    else {

    ''

    Read-Host 'Press 0 and Enter to continue'

    }



    }

 3 {

    ''

     Write-Host -ForegroundColor Green 'The Default Domain Policy is configured as follows:'`n 

     Get-ADDefaultDomainPasswordPolicy | Format-List ComplexityEnabled, LockoutDuration,LockoutObservationWindow,LockoutThreshold,MaxPasswordAge,MinPasswordAge,MinPasswordLength,PasswordHistoryCount,ReversibleEncryptionEnabled

     

     Read-Host 'Press 0 and Enter to continue' 

    

    } 

4 {


    Write-Host -ForegroundColor Green 'The following users are member of the Domain Admins group:'`n

    $sid=(Get-ADDomain).DomainSid.Value + '-512'

    Get-ADGroupMember -identity $sid | Format-Table Name,SamAccountName,SID -AutoSize -Wrap

    ''

    Read-Host 'Press 0 and Enter to continue'

    

    } 

5 {

    ''

    Write-Host -ForegroundColor Green 'The GPOs below are linked to AD Objects:'`n 

    Get-GPO -All | ForEach-Object {

    If ( $_ | Get-GPOReport -ReportType XML | Select-String '<LinksTo>' ) {

    Write-Host $_.DisplayName}}

    ''

    Read-Host 'Press 0 and Enter to continue'

    }
 
 6 {

    $client=Get-ADComputer -Filter {operatingsystem -notlike '*server*'} -Properties Name,Operatingsystem,OperatingSystemVersion,IPv4Address 

    $ccount=$client | Measure-Object | Select-Object -ExpandProperty count

    ''

    Write-Host -ForegroundColor Green "Windows Clients $env:userdnsdomain"

    

    Write-Output $client | Sort-Object Operatingsystem | Format-Table Name,Operatingsystem,OperatingSystemVersion,IPv4Address -AutoSize

    ''

    Write-Host 'Total: '$ccount"" -ForegroundColor Yellow

    ''

    Read-Host 'Press 0 and Enter to continue'

    }

 7 {

    $server=Get-ADComputer -Filter {operatingsystem -like '*server*'} -Properties Name,Operatingsystem,OperatingSystemVersion,IPv4Address 

    $scount=$server | Measure-Object | Select-Object -ExpandProperty count

    ''

    Write-Host -ForegroundColor Green "Windows Server $env:userdnsdomain" 

   

    Write-Output $server | Sort-Object Operatingsystem | Format-Table Name,Operatingsystem,OperatingSystemVersion,IPv4Address

    ''

    Write-Host 'Total: '$scount"" -ForegroundColor Yellow

    ''

    Read-Host 'Press 0 and Enter to continue'

    }

 8 {

    $all=Get-ADComputer -Filter * -Properties Name,Operatingsystem,OperatingSystemVersion,IPv4Address 

    $acount=$all | Measure-Object | Select-Object -ExpandProperty count

    ''

    Write-Host -ForegroundColor Green "All Computer $env:userdnsdomain" 

     

    Write-Output $all | Select-Object Name,Operatingsystem,OperatingSystemVersion,IPv4Address | Sort-Object OperatingSystem | Format-Table -GroupBy OperatingSystem 

    Write-Host 'Total: '$acount"" -ForegroundColor Yellow

    ''

    Read-Host 'Press 0 and Enter to continue'

    }

 9  {    do {



        Write-Host ''

        Write-Host 'This runs systeminfo on specific computers. Select scope:' -ForegroundColor Green

        Write-Host ''

        Write-Host '1 - Localhost' -ForegroundColor Yellow

        Write-Host '2 - Remote Computer (Enter Computername)' -ForegroundColor Yellow

        Write-Host '3 - All Windows Server' -ForegroundColor Yellow

        Write-Host '4 - All Windows Computer' -ForegroundColor Yellow

        Write-Host '0 - Quit' -ForegroundColor Yellow

        Write-Host ''

        $scopesi=Read-Host 'Select'

        $header='Host Name','OS','Version','Manufacturer','Configuration','Build Type','Registered Owner','Registered Organization','Product ID','Install Date','Boot Time','System Manufacturer','Model','Type','Processor','Bios','Windows Directory','System Directory','Boot Device','Language','Keyboard','Time Zone','Total Physical Memory','Available Physical Memory','Virtual Memory','Virtual Memory Available','Virtual Memory in Use','Page File','Domain','Logon Server','Hotfix','Network Card','Hyper-V'

        switch ($scopesi) {

        1 {

            & "$env:windir\system32\systeminfo.exe" /FO CSV | Select-Object -Skip 1 | ConvertFrom-Csv -Header $header | Out-Host

          }

        2 {

            ''

            Write-Host 'Separate multiple computernames by comma. (example: server01,server02)' -ForegroundColor Yellow

            Write-Host ''

            $comps=Read-Host 'Enter computername'

            $comp=$comps.Split(',')

            Invoke-Command -ComputerName $comps -Credential $cred {systeminfo /FO CSV | Select-Object -Skip 1} -ErrorAction SilentlyContinue | ConvertFrom-Csv -Header $header | Out-Host

            }

        3 { 
        
            Invoke-Command -ComputerName (Get-ADComputer -Filter {operatingsystem -like '*server*'}).Name -Credential $cred {systeminfo /FO CSV | Select-Object -Skip 1} -ErrorAction SilentlyContinue | ConvertFrom-Csv -Header $header | Out-Host

            }

        4 {

            Invoke-Command -ComputerName (Get-ADComputer -Filter *).Name -Credential $cred {systeminfo /FO CSV | Select-Object -Skip 1} -ErrorAction SilentlyContinue | ConvertFrom-Csv -Header $header | Out-Host

            }



            }  

            

            }

        while ($scopesi -ne '0')

            }

 10 {

    ''

        Write-Host 'Overview of all Active Directory Groups' -ForegroundColor Green

        Get-ADGroup -Filter * -Properties * | Sort-Object Name | Format-Table Name,GroupCategory,GroupScope,SID -AutoSize -Wrap | more

        Read-Host 'Press 0 and Enter to continue'

    }

 11 {

        do {

        ''

        $groupm=Read-Host 'Enter group name'

        ''

        Write-Host "Group Members of $groupm" -ForegroundColor Green

        Get-ADGroupMember $groupm | Format-Table Name,SamAccountName,SID -AutoSize -Wrap

        $input=Read-Host 'Quit searching groups? (Y/N)'

        }

        while ($input -eq 'N')

    }

 12 { 

        ''

        Write-Host "The following users in $env:userdnsdomain are enabled:" -ForegroundColor Green

        Get-ADUser -Filter {enabled -eq $true} -Properties CanonicalName,whenCreated | Sort-Object Name | Format-Table Name,SamAccountName,CanonicalName,whenCreated -AutoSize -wrap | more

        Read-Host 'Press 0 and Enter to continue'

     

     } 

 13 {

    $span = 90

    Write-Host "The following USERS are enabled and have not logged on for $span days:" -ForegroundColor Green


    Get-ADUser -Filter 'enabled -ne $false' -Properties LastLogonDate,whenCreated | Where-Object {$_.lastlogondate -ne $null -and $_.lastlogondate -le ((get-date).adddays(-$span))} | Format-Table Name,SamAccountName,LastLogonDate,whenCreated


    Write-Host "The following COMPUTERS are enabled have not logged on for $span days:" -ForegroundColor Green

    Get-ADComputer -Filter 'enabled -ne $false' -Properties LastLogonDate,whenCreated | Where-Object {$_.lastlogondate -ne $null -and $_.lastlogondate -le ((get-date).adddays(-$span))} | Format-Table Name,SamAccountName,LastLogonDate,whenCreated


    Read-Host 'Press 0 and Enter to continue'

        

}

 14 {


   Write-Host "This menu item get the most recent hotfix" -ForegroundColor Green

   $ComputerName = Read-Host "Enter Computer Name"

   $csession = New-PSSession -ComputerName $ComputerName -Credential $cred

   Invoke-command  -Session $csession -ScriptBlock {(Get-HotFix | sort installedon)[-1]}

   Read-Host 'Press 0 and Enter to continue'

}

15 {

   Write-Host "This menu item get the most recent hotfix" -ForegroundColor Green

   $ComputerName = Read-Host "Enter Computer Name" 

   $csession = New-PSSession -ComputerName $ComputerName -Credential $cred

   $code = $false

    $version = Invoke-Command -Session $csession -ScriptBlock {$PSVersionTable.PSVersion.Major}

    if($version -lt 3)
    {
        Invoke-Command -Session $csession -ScriptBlock {ping -n 2 -4 8.8.8.8}
    }
    else
    {

    try{

        $code = Invoke-Command -Session $csession -ScriptBlock {(Test-NetConnection -ComputerName 8.8.8.8).PingSucceeded}
        
        }
    catch{
        
        }
        if($code)
        {
            Write-Host "$ComputerName was able to reach Google" -ForegroundColor Yello
        }
        else
        {
            Write-Host "$ComputerName was not able to reach Google" -ForegroundColor Green
        }
        }

        Remove-PSSession -Session $csession
        
        Read-Host 'Press 0 and Enter to continue'


}

16 {

    Write-Host "This menu item Test for ports listening on a Machine"

    $ComputerName = Read-Host "Enter Computer Name"

    $csession = New-PSSession -ComputerName $ComputerName -Credential $cred
    
    $version = Invoke-Command -Session $csession -ScriptBlock {$PSVersionTable.PSVersion.Major}

    if($version -lt 3)
    {
        Invoke-Command -Session $csession -ScriptBlock {netstat -abno}
    }
    else
    {

        Invoke-Command -Session $csession -ScriptBlock {Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,State | Sort-Object LocalPort -Descending|Format-Table}
    }

    Remove-PSSession -Session $csession

    Read-Host 'Press 0 and Enter to continue'

}

17 {

    Write-Host "This menu list installed programs on a Machine"

    $ComputerName = Read-Host "Enter Computer Name"

    $csession = New-PSSession -ComputerName $ComputerName -Credential $cred

    $version = Invoke-Command -Session $csession -ScriptBlock {$PSVersionTable.PSVersion.Major}

    if($version -lt 3)
    {
        Invoke-Command -Session $csession -ScriptBlock {Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate }
    }
    else
    {

        Invoke-Command -Session $csession -ScriptBlock {Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate}
    }

    Remove-PSSession -Session $csession

    Read-Host 'Press 0 and Enter to continue'

}

18 {

    Write-Host "This menu list local users on a Machine"

    $ComputerName = Read-Host "Enter Computer Name"

    $csession = New-PSSession -ComputerName $ComputerName -Credential $cred

    $version = Invoke-Command -Session $csession -ScriptBlock {$PSVersionTable.PSVersion.Major}

    if($version -lt 3)
    {
        Invoke-Command --Session $csession -ScriptBlock {net user}
    }
    else
    {
        
        Invoke-Command -Session $csession -ScriptBlock {Get-LocalUser| Select-Object Name,Enabled,PasswordExpires,PasswordLastSet,PasswordRequired,AccountExpires} -ErrorAction SilentlyContinue
    }

    Remove-PSSession -Session $csession

    Read-Host 'Press 0 and Enter to continue'

}

19{
    Write-Host "Following Menu Item will Gnerate an HTML output of Group Policy Configured on the Domain" -ForegroundColor Yellow

    Invoke-Command -ComputerName (Get-ADComputer -Filter *).Name -Credential $cred {systeminfo /FO CSV | Select-Object -Skip 1} -ErrorAction SilentlyContinue | ConvertFrom-Csv -Header $header | Out-Host

    Get-GPOReport -All -Domain $env:userdnsdomain -Server $env:COMPUTERNAME -ReportType Html -Path "C:\GPOReportsAll.html"

    Write-Host "Results are stored at C:\GPOReportsAll.html"

    Read-Host 'Press Enter to Continue'
}
20{
    $computername = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

    foreach($name in $computername)
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
    Read-Host 'Press Enter to Continue'


}
21{
    
    # Get-ADComputer -Filter * | where {!($_.DistinguishedName -like '*OU=Domain*')} This can be used to exclude DC
    $computername = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name


    foreach($name in $computername)
    {

        try {

            $psession = New-PSSession -ComputerName $name -Credential $cred -ErrorAction Stop

            $version = Invoke-Command -Session $psession -ScriptBlock {$PSVersionTable.PSVersion.Major}

            if($version -lt 3)
            {
                Invoke-Command -Session $psession -ScriptBlock {net user}
            }
            else
            {
        
                Invoke-Command -Session $psession -ScriptBlock {Get-LocalUser|Where-Object {$_.Enabled}| Select-Object Name,Enabled,PasswordExpires,PasswordLastSet,PasswordRequired,AccountExpires|Format-Table} -ErrorAction SilentlyContinue
            }
        
        }
        catch {
        
            Write-Host "Could not connect with $name"
        
        }
        finally{try{
            Remove-PSSession -Session $psession
        }
        catch{}
        }  
    } 
    Read-Host 'Press Enter to Continue'
    
}
22{
    $cname = Read-Host "Enter the name of computer system to test"

    try {
        $psession = New-PSSession -ComputerName $cname -Credential $cred -ErrorAction Stop
    
        Invoke-Command -Session $psession -ScriptBlock { param ($var) Out-File  -FilePath "$env:HOMEPATH\AVTest.txt" -InputObject $var -Encoding ASCII} -ArgumentList $avTest -ErrorAction Stop
        
    }
    catch {
        
        Write-Host "Could not connect with $name"
        
    }
    finally{try{
        Remove-PSSession -Session $psession
    }
    catch{}
    } 
    Read-Host 'Press Enter to Continue'
}
23{
    $sys32 = [System.Environment]::SystemDirectory

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
        try{
            Remove-PSSession -Session $psession
        }
        catch{}
    }
    Read-Host 'Press Enter to Continue'   
}
}

}



while ($input -ne '0')

}



Get-AD