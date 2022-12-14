#>
.SYNOPSIS
Checks a domain for interesting things.
.DESCRIPTION 
This script will check a domain's DNS and web site for anything of interest.  This includes security problems, but can also be a good discovery tool.
.PARAMETER Domain
The domain to examine.
.PARAMETER AsPlainText
By default, this script will use formatted text.  This is great for on-screen viewing, but bad for sending this data to another process, or out of the environment.  Specify this switch to ignore all colors and return things in simple plain text.
.PARAMETER NoCoolBanner
Disable the startup banner.  You might need this for printing, or for narrow screens.
.EXAMPLE
PS C:\> .\DNSQuery.ps1 google.com
Tests the domain Google.com for interesting things.
.EXAMPLE
PS C:\> .\DNSQuery.ps1 yahoo.com -AsPlainText | Out-Termbin
Tests the domain Yahoo.com.  In this example, the text is sent to the terminal-capture site Termbin.
.INPUTS
The domain name to scan can be specified with the -DomainName parameter, or sent in via the pipeline.
.OUTPUTS
This cmdlet generates no output to the pipeline.  However, you can pipe the output to the screen or to a cmdlet such as Out-Printer.
.NOtes
At this time, this script only runs on Microsoft Windows, due to a dependency on DnsClient's Resolve-DnsName cmdlet.
.FUNCTIONALITY
Install this script by putting it in your local folder i.e C:\Users\[YourName]\.ps > connect the script with your Powershell profile to keep it saved by adding the following command in your profile: Set-Alias lookup "$env:C:\Users\[YourName]\.ps\lookup.ps1"
Enjoy!!
.
<#