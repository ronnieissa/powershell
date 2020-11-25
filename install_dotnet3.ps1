Import-Module vmware.vimautomation.core
connect-viserver vcenter.domain.local -force
$isopath = '[datastorename] c0898b5e-ae64-160b-33d3-e4434bafd090/SW_DVD9_Win_Svr_STD_Core_and_DataCtr_Core_2016_64Bit_English_-3_MLF_X21-30350.ISO'
$computers = @(get-adcomputer -filter {name -like 'computername*'} | select -expandproperty name)



foreach ($computername in $computers) {
    #Get-VM -Name $computername | Get-CDDrive | Set-CDDrive -Connected $true -IsoPath $isopath -confirm:$false -verbose
    #Get-VM -name $computername | new-cddrive -verbose 
    install-windowsfeature "net-framework-core" -source "D:\sources\sxs\" -computername "$computername.domain.local" -verbose
}

foreach ($computername in $computers) {
    Get-VM -Name $computername | Get-CDDrive | Set-CDDrive -Connected $false -nomedia -confirm:$false
}

$computers = @(get-adcomputer -filter {name -like 'computername*'} | select -expandproperty name)
foreach ($computer in $computers) {start-vm -vm $computer -runasync}
