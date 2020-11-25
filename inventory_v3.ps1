$PSModuleAutoLoadingPreference="none"

Import-Module Microsoft.PowerShell.Management -Force -Verbose
Import-Module Microsoft.PowerShell.Security -force -Verbose
Import-Module Microsoft.PowerShell.Utility -force -Verbose
Import-Module ActiveDirectory -Force -Verbose
Import-Module FailoverClusters -Force -Verbose -Prefix w

Get-ChildItem -Path "$home\documents\windowspowershell\modules" -Recurse -Include *.psd1| unblock-file
Import-Module "vmware.vimautomation.core" -prefix 'v' -Force -verbose 
connect-vviserver vcenter.domain.local -force -verbose


## Create the Directory to store the inventory files
$inv_dir = "$home\desktop\VM_INV\"
if ((test-path $inv_dir)) {rm "$home\Desktop\VM_INV\FAILED*" -force}
if (!(test-path $inv_dir)) {mkdir -path "$home\Desktop\" -name "VM_INV" -force}
#$environment = ""

#############################################################
## Create Array of computer names you want to inventory
$computers = @(Get-ADComputer -Filter {name -like 'aws-server*'} | select-object -ExpandProperty name | select-string -pattern "$environment-\D\D\D\d\d")

## Get 1 specific computers
#$computers = @(get-adcomputer -server "computername" -filter {name -like 'F03-SMAXP-SQL01'} | select-object -ExpandProperty name)

## Get list of computers from file
#$computers = @(Get-Content -Path "$home\desktop\server.txt" )

#############################################################

$testarg = "HELOOOOOOOOO"
$datetimenow = Get-Date


###############################
## Run the inventory program ##
###############################
$Computers | ForEach-Object {

    Start-Job -ArgumentList $_,$testarg,$datetimenow -name $_ -ScriptBlock {
 
            $computername = $args[0]
            $testarg = $args[1]
            $datetimenow = $args[2]
            
            try {
                ## Connect - Create Sessions
                $cimsession = New-CimSession -ComputerName "$computername.domain.local" -ErrorAction Stop
                $pssession = New-PSSession -ComputerName "$computername.domain.local" -ErrorAction Stop
                
                $sccm = Get-CimInstance -CimSession $cimsession -ClassName SMS_Client -Namespace root\ccm
                $cs = Get-CimInstance -CimSession $cimsession -ClassName win32_computersystem
                $os = Get-CimInstance -CimSession $cimsession -ClassName win32_operatingsystem
                $apps = Get-CimInstance -CimSession $cimsession -ClassName win32_installedwin32program
                $chassis = Get-CimInstance -CimSession $cimsession -ClassName CIM_Chassis
                $netinfo = Get-CimInstance -CimSession $cimsession -ClassName win32_networkadapterconfiguration
                $services = Get-CimInstance -CimSession $cimsession -ClassName Win32_Service -Filter "state like 'running'"
                $features = Get-WindowsFeature | Where-Object installed | Select-Object -ExpandProperty DisplayName | Select-String -Pattern "." | Select-String -NotMatch "tool" | Select-String -NotMatch "module"
                $Disk = Get-CimInstance -CimSession $cimsession -ClassName cim_logicaldisk
                $WSFCinstalled = Get-CimInstance -CimSession $cimsession -ClassName win32_optionalfeature -Filter "name like 'failovercluster-fullserver'"
                $test_net = Invoke-Command -Session $pssession -ScriptBlock {Test-NetConnection -computername domain.local}
                $nslookup = Invoke-Command -Session $pssession -scriptblock {nslookup $env:computername}
                #$vminfo = get-vvm -name $COMPUTERNAME -debug
                
                #if ($WSFCinstalled) {Start-Job -Session $pssession -ArgumentList $computername -ScriptBlock {(Get-wCluster -name "$computername.domain.local" | Select-Object -ExcludeProperty sharedvolumesecuritydescriptor,Pscomputername,psshowcomputername)} -OutVariable WSFC}
               
                ## Create array of Computer Properties
                $csprop = @{
                                #testarg = $testarg
                                #Computername = $computername
                                TESTS =  @(
                                    if ($test_net.pingsucceeded) {'TRUE : Can Ping domain.local and returned ' + $test_net.remoteaddress}
                                    'nslookup ' + $nslookup
                                    'Logon Server = ' + $env:LOGONSERVER
                                    'SCCM Client Version = ' + $sccm.ClientVersion
                                )
                                
                                #vm_hardware = @(
                                #   'powerstate = ' + $vminfo
                                    #'PowerState = ' + $vminfo.powerstate
                                    #'HW_version = ' + $vminfo.hardwareversion
                                    #'Processors = ' + $vminfo.NumCpu
                                    #'Memory = ' + $vminfo.MemoryMB
                                    #'VM_Host = ' + $vminfo.VMHost.name
                                #)
                                Processors = $cs.NumberOfLogicalProcessors
                                Model = $cs.Model
                                Mfgr = $cs.Manufacturer
                                DNSname = $cs.DNSHostName
                                Name = $cs.Name
                                OS_InstallDate = $os.InstallDate.ToShortDateString()
                                Domain = $cs.Domain
                                OS_Status = $cs.Status
                                Apps = @(
                                    foreach ($app in $apps) {$app.vendor + '_______________'+ $app.name + '_______________' + $app.version}
                                ) | Sort-Object
                                OS_buildnum = $os.BuildNumber
                                Lastbootup = $os.LastBootUpTime.ToShortDateString()
                                #LocalTime = $os.LocalDateTime.ToShortDateString()
                                #Serial = $os.SerialNumber
                                OS_version = $os.Version
                                #ServiceTag = $chassis.serialnumber
                                Inventory_Time = @{
                                    Time = $datetimenow.ToShortTimeString()
                                    Date = $datetimenow.ToShortDateString()
                                }
                                Network = @(
                                    foreach ($adapter in $netinfo) {if ($adapter.MACAddress -ne $null) {$adapter | Select-Object -Property caption,Description,Macaddress,IPAddress,IPSubnet,DefaultIPGateway,DHCPEnabled,DHCPServer,DNSServerSearchOrder,servicename}}
                                )

                                <###>
                                Services = @(
                                    foreach ($service in $services) {$service.DisplayName +'_______________'+ $service.name  + '_______________' +  $service.startname | Sort-Object -Property $service.Name}
                                ) | Sort-Object

                                Features_Enabled = @(
                                    $features.Line
                                ) | Sort-Object
                                

                                Disk = @(
                                    $Disk | Select-Object -Property DeviceID,volumename,{$_.size /1GB}
                                )  
                                
                                WSFC = if ($WSFCinstalled.InstallState -eq 1){'TRUE : Failover Clustering is installed'} else {
                                    'FALSE : Failover Clustering is NOT installed'
                                }
                            }
            }

            catch { $inv_dir = "$home\desktop\VM_INV\" ; new-item -Name $("FAILED " + $computername) -Path "$inv_dir\" }

            finally {
                        $inv_dir = "$home\desktop\VM_INV\"
                        $csobj = New-Object -TypeName psobject -Property $csprop
                        $bar = $csobj | ConvertTo-Json | convertfrom-json #|Out-File -FilePath "$inv_dir$computername.txt"

                        # Build an ordered hashtable of the property-value pairs.
                        $sortedProps = [ordered] @{}
                        Get-Member -Type  NoteProperty -InputObject $bar | Sort-Object Name | foreach-object { $sortedProps[$_.Name] = $bar.$($_.Name) }

                        # Create a new object that receives the sorted properties.
                        $barWithSortedProperties = New-Object PSCustomObject
                        Add-Member -InputObject $barWithSortedProperties -NotePropertyMembers $sortedProps

                        $barWithSortedProperties | ConvertTo-Json | Out-File -FilePath "$inv_dir$computername.json"
            }
    }
}
#disconnect-vviserver -force -confirm:$false
