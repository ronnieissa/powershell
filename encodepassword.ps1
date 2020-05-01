function Get-PasswordHash
{
param(
[String]$VMName,
[String]$GuestUser,
[String]$GuestPassword,
[String]$Password
)
$sInvoke = @{
VM = $VMName
ScriptType = 'bash'
ScriptText = "mkpasswd -m SHA-512 $Password"
GuestUser = $GuestUser
GuestPassword = $GuestPassword
}
(Invoke-VMScript @sInvoke).ScriptOutput.Trim("`n")
}
$sHash = @{
VM = 'UbuntuWork'
GuestUser = 'root'
GuestPassword = 'VMware1!'
Password = 'VMware1!'
}
Get-PasswordHash @sHash
