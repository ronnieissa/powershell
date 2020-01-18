set-executionpolicy bypass -force
iex ((New-Object system.net.webclient).DownloadString('http://chocoinstall.example.com'))
