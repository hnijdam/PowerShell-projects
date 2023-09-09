<#PSScriptInfo
Hugo's domain-info analyzer
This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
You should have received a copy of the GNU Affero General Public License along
with this program.  If not, see <https://www.gnu.org/licenses/>.
.VERSION 1.6.1
.GUID 77300be0-8cd0-4ce8-838d-ea5a286e9119
.AUTHOR Hugo Nijdam
<# 
.SYNOPSIS
Checks a domain for interesting things.
.DESCRIPTION 
This script will check a domain's DNS and web site for anything of interest.  This includes security problems, but can also be a good discovery tool.
.INSTALLATION 
1. put a similar line in your PS $Profile: Set-Alias lookup "$env:C:\PATH\TO\FILE\lookup.ps1"
2. And install a powershell module: PS C:\> Install-Module DomainHealthChecker
.PARAMETER Domain
The domain to examine.
.PARAMETER AsPlainText
By default, this script will use formatted text.  This is great for on-screen viewing, but bad for sending this data to another process, or out of the environment.  Specify this switch to ignore all colors and return things in simple plain text.
.PARAMETER NoCoolBanner
Disable the startup banner.  You might need this for printing, or for narrow screens.
.EXAMPLE
PS C:\> .\lookup.ps1 google.com
Tests the domain Google.com for interesting things.
.EXAMPLE
PS C:\> .\lookup.ps1 yahoo.com -AsPlainText | Out-Termbin
Tests the domain Yahoo.com.  In this example, the text is sent to the terminal-capture site Termbin.
.INPUTS
The domain name to scan can be specified with the -DomainName parameter, or sent in via the pipeline.
.OUTPUTS
This cmdlet generates no output to the pipeline.  However, you can pipe the output to the screen or to a cmdlet such as Out-Printer.
.NOTES
At this time, this script only runs on Microsoft Windows, due to a dependency on DnsClient's Resolve-DnsName cmdlet.
.FUNCTIONALITY
Install this script by putting it in your local folder i.e C:\Users\[YourName]\.ps > connect the script with your Powershell profile to keep it saved by adding the following command in your profile: Set-Alias lookup "$env:C:\Users\[YourName]\.ps\lookup.ps1"
Enjoy!!
.
#>
#Requires -Version 7.1
#Requires -Module DnsClient
[CmdletBinding()]
Param(
	[Alias('DomainName')]
	[Parameter(Mandatory, ValueFromPipeline)]
	[ValidateNotNullOrEmpty()]
	[String] $Domain,
	
	[Alias('PlainText')]
	[Switch] $AsPlainText,
	
	[Switch] $NoCoolBanner
)

# I'm going to be lazy and change this variable's scope so that
# I can use it in my helper functions.
$script:AsPlainText = $AsPlainText

#region Helper functions
Function Bold {
	[OutputType('String')]
	Param(
		[Parameter(Mandatory)]
		[AllowNull()]
		[String] $Message
	)
	Return ($AsPlainText ? $Message : "`e[1m${Message}`e[22m")
}

Function Underline {
	[OutputType('String')]
	Param(
		[Parameter(Mandatory)]
		[AllowNull()]
		[String] $Message
	)
	Return ($AsPlainText ? $Message : "`e[4m${Message}`e[24m")
}

Function Invert {
	[Alias('ReverseVideo')]
	[OutputType('String')]
	Param(
		[Parameter(Mandatory)]
		[AllowNull()]
		[String] $Message
	)
	Return ($AsPlainText ? $Message : "`e[7m${Message}`e[27m")
}

Function Strikeout {
	[Alias('Strikethrough')]
	[OutputType('String')]
	Param(
		[Parameter(Mandatory)]
		[AllowNull()]
		[String] $Message
	)
	Return ($AsPlainText ? $Message : "`e[9m${Message}`e[29m")
}

Function ForegroundColor {
	[Alias('Color', 'FGColor')]
	[OutputType('String')]
	Param(
		[Parameter(Position=0)]
		[ValidateSet('Black', 'Red', 'Green', 'Yellow', 'Blue', 'Magenta', 'Cyan', 'White')]
		[ValidateNotNullOrEmpty()]
		[String] $Color,

		[Parameter(Position=1)]
		[AllowNull()]
		[String] $Message
	)
	
	If ($AsPlainText) {
		Return $Message
	}
	
	Switch ($Color) {
		'Black'   {Return "`e[30m${Message}`e[37m"}
		'Red'     {Return "`e[31m${Message}`e[37m"}
		'Green'   {Return "`e[32m${Message}`e[37m"}
		'Yellow'  {Return "`e[33m${Message}`e[37m"}
		'Blue'    {Return "`e[34m${Message}`e[37m"}
		'Magenta' {Return "`e[35m${Message}`e[37m"}
		'Cyan'    {Return "`e[36m${Message}`e[37m"}
		'White'   {Return "`e[37m${Message}"}
		default   {Return $Message}
	}
}

Function BackgroundColor {
	[Alias('Background', 'BGColor')]
	[OutputType('String')]
	Param(
		[Parameter(Position=0)]
		[ValidateSet('Black', 'Red', 'Green', 'Yellow', 'Blue', 'Magenta', 'Cyan', 'White')]
		[ValidateNotNullOrEmpty()]
		[String] $Color,

		[Parameter(Position=1)]
		[AllowNull()]
		[String] $Message
	)
	
	If ($AsPlainText) {
		Return $Message
	}
	
	Switch ($Color) {
		'Black'   {Return "`e[40m${Message}`e[40m"}
		'Red'     {Return "`e[41m${Message}`e[40m"}
		'Green'   {Return "`e[42m${Message}`e[40m"}
		'Yellow'  {Return "`e[43m${Message}`e[40m"}
		'Blue'    {Return "`e[44m${Message}`e[40m"}
		'Magenta' {Return "`e[45m${Message}`e[40m"}
		'Cyan'    {Return "`e[46m${Message}`e[40m"}
		'White'   {Return "`e[47m${Message}"}
		default   {Return $Message}
	}
}
{

}
#endregion
If (-Not $NoCoolBanner) {
	# For compatibility with old or small terminals (looking at you, Windows default),
	# don't exceed 132 characters.  Don't forget to escape any dollar signs or backticks
	# that PowerShell might try to execute.  This has to be a double-quoted string because
	# of where I decided to stick the version number.
}
Write-Host @"

###########################################################################################
  _    _                   _           _                      _         _        __         
 | |  | |                 ( )         | |                    (_)       (_)      / _|     
 | |__| |_   _  __ _  ___ |/ ___    __| | ___  _ __ ___   ___ _ _ __    _ _ __ | |_ ___  
 |  __  | | | |/ _` |/ _ \  / __|  / _` |/ _ \| '_ ` _ \ / _ \ | '_ \  | | '_ \|  _/ _ \  
 | |  | | |_| | (_| | (_) | \__ \ | (_| | (_) | | | | | |  __/ | | | | | | | | | || (_) |
 |_|  |_|\__,_|\__, |\___/  |___/  \__,_|\___/|_| |_| |_|\___|_|_| |_| |_|_| |_|_| \___/ 
                __/ |                                                                    
                |___/  VERSION 1.6.1                                                                                                                                                                                  
###########################################################################################

"@                                     


#######################################################################
### 					WEBSERVER CHECK                   ###
#######################################################################

# Website section
Write-Host -ForegroundColor Cyan (Underline "`nChecking $Domain's hostnames.")
Resolve-DnsName $Domain  -type A_AAAA -ErrorAction Ignore | Where-Object Type -in 'A', 'AAAA' | Format-Table
Try
{
Invoke-WebRequest -Method HEAD -Uri $Domain | Select-Object -Property “StatusCode”,"StatusDescription" | Format-List
}

	

catch {

		Write-Host -ForegroundColor DarkYellow "`nRINGING but no ANSWER..this website might be down, or is using some kind of reverse proxy"
	}

Write-Host -ForegroundColor Cyan (Underline "`nChecking $Domain www hostnames.")
Resolve-DnsName www.$Domain  -type A_AAAA -ErrorAction Ignore | Where-Object Type -in 'A', 'AAAA' | Format-Table




Try
{
Invoke-WebRequest -Method HEAD -Uri www.$Domain | Select-Object -Property “StatusCode”,"StatusDescription" | Format-List
}

	

catch {

		Write-Host -ForegroundColor DarkYellow "`nRINGING but no ANSWER..this website might be down, or is using some kind of reverse proxy"
	}


# Nameservers What nameservers is the domain using?
Write-Host -ForegroundColor Cyan (Underline "`n$Domain NS-records")
Resolve-DnsName -Name $Domain -Type 'NS' -Server 1.1.1.1 -ErrorAction Ignore | Format-Table
#1..100 | iip -ShowProgress -TotalCount 50 | %{ sleep -mil 20 }
# Server Reverse lookup  -Server 1.1.1.1
Try
{

    Write-Host -ForegroundColor Cyan (Underline "`nReverse lookup for servername on $Domain")
$IPAddress = (Resolve-DnsName -Name $Domain -Type A).IPAddress
$Reversenamehost = (Resolve-DnsName -Name $IPAddress).NameHost
	Resolve-DnsName ($Reversenamehost) | Select-Object -Property Name | Format-Table
}
Catch
{
	Write-Host -ForegroundColor DarkYellow -NoNewline ("`nReverse lookup is not possible for this domain, probable a reverse proxy")
}

#E-mail Section 
Write-Host -ForegroundColor Cyan (Underline "`n`nMX-records.")
Resolve-DnsName -Type 'MX' -Name $Domain -ErrorAction Ignore | Format-Table
# CAA section, does this domain has a CAA record in the DNS zone?
Write-Host -ForegroundColor Cyan (Underline "`nDNS-zone CAA-record`n")


Wsl.exe dig $Domain caa +noall +answer
# SSL specifcis
Write-Host -ForegroundColor Cyan  (Underline "`n`nSSL-Record specifics`n")
#Certificate Section
$WebsiteURLs= @("$Domain")
$WebsitePort=443
$Threshold=120

foreach ($WebsiteURL in $WebsiteURLs){
$CommonName=$WebsiteURL
Try{
    $Conn = New-Object System.Net.Sockets.TcpClient($WebsiteURL,$WebsitePort) 

    Try {
        $Stream = New-Object System.Net.Security.SslStream($Conn.GetStream())
        $Stream.AuthenticateAsClient($CommonName) 

          
       
        $Stream.Get_RemoteCertificate() | Format-List -Property Subject,Issuer,Thumbprint,NotBefore,NotAfter
       
        

       
        if ($ValidDays -lt $Threshold)
        {


        }
        else
        {
        
        }
    }
    Catch { Throw $_ }
    Finally { $Conn.close() }
    }
    Catch {
            Write-Host "`nError occurred connecting to $($WebsiteURL)" -ForegroundColor Red
            Write-Host "Status:" "Looking up the specifics of the Certificate is not possible, or this host doesn't hold any certificate" -ForegroundColor Yellow
            
}
}
#region DMARC check
Write-Host -ForegroundColor Cyan (Underline "`nSPF/DKIM/DMARC records`n")
Get-SPFRecord $Domain -ErrorAction Ignore | Format-List -Property SPFRecord,SPFAdvisory
Get-DKIMRecord $Domain -ErrorAction Ignore | Format-List -Property DkimRecord,DKIMAdvisory
Get-DMARCRecord $Domain -ErrorAction Ignore | Format-List -Property DMARCRecord,DmarcAdvisory

$question = Read-Host "`nDo you wanna use NMAP to enumerate all subdomains? [y/n]"
switch($question){
		  y{wsl.exe sudo nmap --script dns-brute $Domain -Force}
		  n{exit}
	default{write-warning "Invalid Input"}
}
#endregion
Remove-Variable * -ErrorAction SilentlyContinue; Remove-Module *; $error.Clear(); exit
