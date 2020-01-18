
###########################################################################################
# First, get a list of Computer account names and export it as stream of strings and put 
# it in a Variable called $stream
###########################################################################################

$stream = Get-ADComputer -SearchBase "ou=dept-computers,dc=example,dc=com" -filter * | Select-Object -ExpandProperty name | Out-String -stream


############################################################################################
#############  For Names Matching STORE0NN
############################################################################################

    $stream -match 'STORE[0][1-9][0-9]' | out-string -Stream | foreach-object -process {
        
        if ($_) {
          
            $displayname = $_ -replace "STORE(\d)(\d)(\d)(.*)", 'STORE $1$2$3'
            $samaccountname = $_ -replace 'store(\d)(\d)(\d)(.*)', 'STORE$2$3'
            $userprincipalname = $samaccountname + '@example.com'
            $LogonWorkstations = $displayname -replace " ", ''

            # TEST Write-Output $LogonWorkstations
            
            
            New-ADUser `
                -SamAccountName $samaccountname `
                -Name $displayname `
                -DisplayName $displayname `
                -UserPrincipalName $userprincipalname `
                -PasswordNeverExpires $false `
                -AccountPassword(ConvertTo-SecureString 'P@ssword123' -AsPlainText -Force) `
                -ChangePasswordAtLogon:$true `
                -Path 'OU=dept-users,DC=example,DC=COM' `
                -Enabled $true `
                -LogonWorkstations $LogonWorkstations `
                -Verbose `
                -ErrorAction SilentlyContinue `
                
        }
    }


############################################################################################
#############  For Names Matching STORE00N
############################################################################################

    $stream -match 'STORE[0][0][0-9]' | out-string -Stream | foreach-object -process {
        
        if ($_) {
          
            $displayname = $_ -replace "STORE(\d)(\d)(\d)(.*)", 'STORE $1$2$3'
            $samaccountname = $_ -replace 'store(\d)(\d)(\d)(.*)', 'STORE$3'
            $userprincipalname = $samaccountname + '@example.com'
            $LogonWorkstations = $displayname -replace " ", ''

            # TEST write-output $displayname
            
            New-ADUser `
                -SamAccountName $samaccountname `
                -Name $displayname `
                -DisplayName $displayname `
                -UserPrincipalName $userprincipalname `
                -PasswordNeverExpires $false `
                -AccountPassword(ConvertTo-SecureString "P@ssword123" -AsPlainText -Force) `
                -ChangePasswordAtLogon $true `
                -Path "OU=stores-users,DC=example,DC=COM" `
                -Enabled $true `
                -LogonWorkstations $LogonWorkstations `
                -Verbose `
                -ErrorAction SilentlyContinue `
               
        }
    }


############################################################################################
#############  For Names Matching STOREN00
############################################################################################

    $stream -match 'STORE[1-9][0-9][0-9]' | out-string -Stream | foreach-object -process {
        
        if ($_) {
          
            $displayname = $_ -replace "STORE(\d)(\d)(\d)(.*)", 'STORE $1$2$3'
            $samaccountname = $_ -replace 'store(\d)(\d)(\d)(.*)', 'STORE$1$2$3'
            $userprincipalname = $samaccountname + '@example.com'
            $LogonWorkstations = $displayname -replace " ", ''

            # TEST write-output $displayname
            
            New-ADUser `
                -SAMAccountName $samaccountname `
                -Name $displayname `
                -DisplayName $displayname `
                -UserPrincipalName $userprincipalname `
                -PasswordNeverExpires $false `
                -AccountPassword(ConvertTo-SecureString "P@ssword123" -AsPlainText -Force) `
                -ChangePasswordAtLogon $true `
                -Path "OU=stores-users,DC=example,DC=COM" `
                -Enabled $true `
                -LogonWorkstations $LogonWorkstations `
                -Verbose `
                -ErrorAction SilentlyContinue `
               
        }
    }
