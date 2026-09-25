param(
    [Parameter(Mandatory=$true)][string]$Username,
    [Parameter(Mandatory=$true)][string]$Password,
    [Parameter(Mandatory=$true)][string]$To,
    [Parameter(Mandatory=$true)][string]$Subject,
    [Parameter(Mandatory=$true)][string]$BodyPath
)

$ErrorActionPreference = "Stop"

$securePass = ConvertTo-SecureString $Password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($Username, $securePass)
$body = Get-Content -Path $BodyPath -Raw -Encoding UTF8

Send-MailMessage -SmtpServer smtp.gmail.com -Port 587 -UseSsl `
    -Credential $cred `
    -From $Username -To $To -Subject $Subject `
    -Body $body -BodyAsHtml -Encoding UTF8

Write-Output "Email sent to $To"
