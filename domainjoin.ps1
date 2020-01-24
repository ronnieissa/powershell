$DomainName = "EXAMPLE.COM"
$Password = 'P@ssword' | ConvertTo-SecureString -AsPlainText -Force
$username = 'sa_domainjoin'
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username,$password

Add-Computer -DomainName $DomainName -Restart:$false -Confirm:$false -Credential $credential -OUPath "OU=dept-Computers,DC=example,DC=com"
