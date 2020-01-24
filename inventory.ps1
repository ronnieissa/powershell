$Computers = @(Get-ADComputer -SearchBase "ou=IT,ou=dept-computers,dc=EXAMPLE,dc=COM" -Filter * -Properties name | Select-Object -ExpandProperty name )

# to do individual computer
#$Computers = 'workstation-01'


#foreach ($obj in $array) {write-output $obj ; Get-CimInstance -ComputerName $obj -ClassName win32_installedwin32program | Select-Object -Property name ; Write-Output "     "}
$FormatEnumerationLimit =-1

foreach ($computername in $computers) {
    
    $cimsession = New-CimSession -ComputerName $computername -ErrorAction SilentlyContinue
    $cs = Get-CimInstance -CimSession $cimsession -ClassName win32_computersystem
    $os = Get-CimInstance -CimSession $cimsession -ClassName win32_operatingsystem
    $apps = Get-CimInstance -CimSession $cimsession -ClassName win32_installedwin32program | select-object -ExpandProperty name
    $net = Get-ciminstance -CimSession $cimsession -ClassName win32_Networkadapter
    $chassis = Get-CimInstance -CimSession $cimsession -ClassName CIM_Chassis
    $netinfo = Get-CimInstance -CimSession $cimsession -ClassName win32_networkadapterconfiguration
    $datetimenow = get-date

    $csprop = @{Computername = $computername
                    Model = $cs.Model
                    Mfgr = $cs.Manufacturer
                    DNSname = $cs.DNSHostName
                    Name = $cs.Name
                    User = $cs.UserName
                    InstallDate = $os.InstallDate.ToShortDateString()
                    Domain = $cs.Domain
                    Status = $cs.Status
                    Apps = $apps
                    OSbuildnum = $os.BuildNumber
                    Lastbootup = $os.LastBootUpTime.ToShortDateString()
                    #LocalTime = $os.LocalDateTime.ToShortDateString()
                    #Serial = $os.SerialNumber
                    version = $os.Version
                    #MAC = $net.macaddress -ne $null
                    ServTag = $chassis.serialnumber
                    InvTime = @{
                        Time = $datetimenow.ToShortTimeString()
                        Date = $datetimenow.ToShortDateString()}
                    Network = @{
                        Def_Route = $netinfo.DefaultIPGateway -ne $null
                        IP = $netinfo.IPAddress -ne $null
                        DNS_Search_Order = $netinfo.DNSServerSearchOrder -ne $null
                        DHCP_Server = $netinfo.DHCPServer -ne $null
                        MACAddress = $netinfo.MACAddress -ne $null
                        
                    }
    }
    $csobj = New-Object -TypeName psobject -Property $csprop
    Write-Output $csobj | ConvertTo-Json
    #write-output $obj ; Get-CimInstance -ComputerName $obj -ClassName win32_installedwin32program | Select-Object -Property name ; Write-Output "     "
} 
