Import-Module vmware.vimautomation.core
connect-viserver vcenter-vcenter01.domain.local -force
$isopath = '[dstore01] c0898b5e-ae64-160b-33d3-e4434bafd090/SW_DVD9_Win_Svr_STD_Core_and_DataCtr_Core_2016_64Bit_English_-3_MLF_X21-30350.ISO'
$computers = @(get-adcomputer -filter {name -like 'servername*'} | select -expandproperty name | select-string -Pattern 'servername')

foreach ($computername in $computers){

    try {
        Write-Output "Test"
        if ((Get-CDDrive $computername) -ne $null) { throw }
    }

    catch {
        write-output "$computername doesn't have a CD Drive. Please log into vcenter, shutdown $computername and add the virtual CD Drive"
    }

    finally {
        Get-CDDrive $computername | Set-CDDrive -Connected $false -nomedia -confirm:$false
        Get-CDDrive $computername | Set-CDDrive -Connected $true -IsoPath $isopath -confirm:$false -verbose
        $driveletter = Invoke-AsWorkflow -PSComputerName server.domain.local -expression 'get-volume | ? {$_.drivetype -eq "CD-ROM"} | select -expandproperty driveletter'
        install-windowsfeature "net-framework-core" -source ($driveletter + ":\sources\sxs\") -computername "$computername.domain.local" -verbose -WhatIf
    }
}




    foreach ($computername in $computers) {
        Get-VM -Name $computername | Get-CDDrive | Set-CDDrive -Connected $false -nomedia -confirm:$false
    }

    foreach ($computername in $computers) {
        Get-VM -Name $computername | Get-CDDrive | Set-CDDrive -Connected $true -IsoPath $isopath -confirm:$false -verbose
        #Get-VM -name $computername | new-cddrive -verbose

    }


    $computers = @(get-adcomputer -filter {name -like 'servername*'} | select -expandproperty name)
    foreach ($computer in $computers) {start-vm -vm $computer -runasync}
}
