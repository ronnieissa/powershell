<#
This script will query AD to find users whose password is expiring in 14 days, 7 days and already expired.
It will then add these users to an array.
Then for each user, it will log the Send in C:\scripts\logdb.txt, then send the user an email notifiying them that their password will expire and to reset.
#>

#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# This is our simple logging mechanism. It's just a plain text file that we continuously append the users name and date we sent the email.
$emaillog = "C:\scripts\passwddb\emaillog.txt"

## Database - Just a file database, so that we know who has been alerted so that we dont alert everyday.
$logdir = "C:\scripts\passwddb\"
#////////////////////////////////////////////////

## CLEAR DB, Remove alerts that are older than 4 days to reset the counter on how often we alert users
Get-ChildItem -Path $logdir | % {if ($_.lastwritetime -lt (get-date).adddays(-4)) {remove-item $_}}


#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# Creating an array called $users to pu the OU we are targeting, which is the top level OU "Domain Users"
$users = @(get-aduser `
            -searchbase "ou=domain users,dc=domain,dc=org" `
            -filter * `
            -Properties name,passwordlastset,passwordneverexpires,userprincipalname,passwordexpired | `
            ? {$_.passwordneverexpires -eq $false} | select-object name,passwordlastset,userprincipalname,passwordexpired)


<#\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
##<<<<<<  Run the app  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>
/////////////////////////////////////////////////#>
$users | % {

        $expireDate = $_.passwordlastset.adddays(180) ##Set the date that the password is supposed to exprie (180 days from date created)
        $daysleft = (new-timespan -Start (get-date) -end $expireDate).Days ##Calculate the days left from $expiredate and set new variable

        ## Already expired
        if ($_.passwordexpired -eq $true -and (-not(Test-Path -Path "$logdir\$($_.userprincipalname)"))) {
            Add-Content -path $emaillog -Value ($_.Name + " " + (get-date).datetime)
            New-Item -Path $logdir -Name $_.userprincipalname
            Send-MailMessage `
                -SmtpServer "domain-org.mail.protection.outlook.com" `
                -From "helpdesk@domain.org" `
                -to "rissa@domain.org" `
                -ReplyTo "helpdesk@domain.org" `
                -subject "**URGENT** - Your Password has expired!" `
                -Attachments "C:\scripts\pwreset.docx" `
                -body ("Hello " + $_.name + "," + "`r`r" + "We in IT are reaching out to let you know that your computer login password has expired on " + (($_.passwordlastset).adddays(180)).toshortdatestring() + ". Please contact helpdesk@domain.org (or reply to this email) at your earliest convenience, so we can help you reset your password." + "`r`r" + "Please note: This is a time sensitive request, if not addressed right away, you may be locked out of your account." + "`r`r" + "Thanks," + "`r" + "" + "`r" + "IT Director")
        }
        
        ## Expiring with 14 Days
        elseif ( $daysleft -le 14 -and (-not(Test-Path -Path "$logdir\$($_.userprincipalname)"))) {
            Add-Content -path $emaillog -Value ($_.Name + " " + (get-date).datetime)
            New-Item -Path $logdir -Name $_.userprincipalname
            Send-MailMessage `
                -SmtpServer "domain-org.mail.protection.outlook.com" `
                -From "helpdesk@domain.org" `
                -to "rissa@domain.org" `
                -ReplyTo "helpdesk@domain.org" `
                -subject "**URGENT** - Your Password is Expiring in $daysleft Days!" `
                -Attachments "C:\scripts\pwreset.docx" `
                -body ("Hello " + $_.name + "," + "`r`r" + "We in IT are reaching out to let you know that your computer login password is expiring on " + (($_.passwordlastset).adddays(180)).toshortdatestring() + ". We attached instructions on how to reset your password yourself, but please don't hesitate to contact helpdesk@domain.org (or reply to this email), if you are having any issues." + "`r`r" + "Please note: This is a time sensitive request, if not addressed right away, you may be locked out of your account." + "`r`r" + "Thanks," + "`r" + "" + "`r" + "IT Director")
        } 
}
