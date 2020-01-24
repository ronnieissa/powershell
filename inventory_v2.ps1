$Computers = @(Get-ADComputer -SearchBase "ou=dept-computers,dc=Example,dc=com" -Filter * -Properties name | Select-Object -ExpandProperty name )
#$computers = Get-ADComputer -Filter {name -like '*test*'} | Select-Object Name

#$computers = Get-ADComputer -Filter {name -like 'wh0*'} | Select-Object -ExpandProperty name
 
$Computers | ForEach-Object {


    Start-Job -ArgumentList $_ -name $_ -ScriptBlock {

            $computername = $args[0]
            

            try { $cimsession = New-CimSession -ComputerName $computername -ErrorAction Stop

                $cs = Get-CimInstance -CimSession $cimsession -ClassName win32_computersystem
                $os = Get-CimInstance -CimSession $cimsession -ClassName win32_operatingsystem
                $apps = Get-CimInstance -CimSession $cimsession -ClassName win32_installedwin32program | select-object -ExpandProperty name
                #$net = Get-ciminstance -CimSession $cimsession -ClassName win32_Networkadapter
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
                            
                        }
                catch { new-item -Name $("FAILED " + $computername) -Path c:\pcsnew\ }

                finally {
                            $csobj = New-Object -TypeName psobject -Property $csprop
                            $csobj | ConvertTo-Json | Out-File -FilePath "C:\pcsnew\$computername.json"
                }
            #else {  }
                }
}
