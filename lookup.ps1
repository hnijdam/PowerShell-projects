<#PSScriptInfo
This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
You should have received a copy of the GNU Affero General Public License along
with this program.  If not, see <https://www.gnu.org/licenses/>.
#>
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
By default, this script will use formatted text.  This is great for on-screen viewing, but bad for sending this data to another process, or out of the environment. Specify this switch to ignore all colors and return things in simple plain text.
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
.NOtes
At this time, this script only runs on Microsoft Windows, due to a dependency on DnsClient's Resolve-DnsName cmdlet.
.FUNCTIONALITY
Install this script by putting it in your local folder i.e C:\Users\[Username]\.ps > connect the script with your Powershell profile to keep it saved by adding the following command in your profile: Set-Alias lookup "$env:C:\Users\[YourName]\.ps\lookup.ps1"
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


If (-Not $NoCoolBanner) {
	Write-Output @"
|----------------------------------------------------------------------------------------------|   
|     _    _                   _       _____                       _         _        __       | 
|    | |  | |                 ( )     |  __ \                     (_)       (_)      / _|      |
|    | |__| |_   _  __ _  ___ |/ ___  | |  | | ___  _ __ ___   ___ _ _ __    _ _ __ | |_ ___   |
|    |  __  | | | |/ _` |/ _ \  / __| | |  | |/ _ \| '_ ` _ \ / _ \ | '_ \  | | '_ \|  _/ _ \  |
|    | |  | | |_| | (_| | (_) | \__ \ | |__| | (_) | | | | | |  __/ | | | | | | | | | || (_) | |
|    |_|  |_|\__,_|\__, |\___/  |___/ |_____/ \___/|_| |_| |_|\___|_|_| |_| |_|_| |_|_| \___/  |
|                   __/ |                                                                      |
|                  |___/              2022 © Free of use under Gnu public license             |                                           
|                                                                                              |
 ----------------------------------------------------------------------------------------------                                                                                                                     
"@                                     
}
#######################################################################
### WEBSERVER CHECK
#######################################################################


Write-Output "`nInvestigating: $Domain...."

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



Write-Output (Underline "`nChecking the webserver of $Domain on A and AAAA hostnames.")
Resolve-DnsName -Type 'A_AAAA' -Name $Domain -ErrorAction Stop | Format-Table
Resolve-DnsName -Type 'A' -Name $Domain -ErrorAction Ignore | Format-Table
Resolve-DnsName -Type 'A_AAAA' -Name www.$Domain -ErrorAction Ignore | Format-Table
Resolve-DnsName -Type 'A' -Name www.$Domain -ErrorAction Ignore | Format-Table 
Write-Output (Underline "`nChecking the webserver's MX records.")
Resolve-DnsName -Type 'MX' -Name $Domain -ErrorAction Ignore | Format-Table 
Write-Output (Underline "`nChecking the webserver's nameservers.")
Resolve-DnsName -Type 'NS' -Name $Domain -ErrorAction Ignore | Format-Table 
Write-Output (Underline "`nChecking the webserver's TXT records.")
Resolve-DnsName -Type 'TXT' -Name $Domain -ErrorAction Ignore | Format-Table
Write-Output (Underline "`nChecking the webserver's CNAME records.`n")
Resolve-DnsName -Type 'CNAME' -Name $Domain | Format-Table

#region HTTPS/HTTP checks
Write-Output (Underline "HTTPS/HTTP checks. `n")

Write-Information -Tag 'Verbose' -Message "Resolving the IP addresses for $Domain `n"
$IPAddresses = @()
$IPAddresses += Resolve-DnsName -Type 'A_AAAA' -Name $Domain -ErrorAction Ignore | Where-Object Type -in 'A','AAAA' | Select-Object -ExpandProperty IPAddress



If ($IPAddresses) {
	Try {
		# I'm using the HEAD(er) method just to make responses smaller.
		# Some of these web pages can get pretty big.
		# The $HTTPRequest variable will be used later in the script.
		Write-Information -Tag 'Verbose' -Message "Attempting to connect to https://$Domain"
		$script:HTTPRequest = Invoke-WebRequest -Method HEAD -Uri "https://$Domain/"

		# If they have a working and valid HTTPS server, now we will test different versions of
		# SSL/TLS.  In each case, we'll "Try" to connect with a specific version, and assume that
		# a failure means that version is not supported.
		$SupportedTLSVersions = @()

		# To attempt to use SSL 2.0 and SSL 3.0, we need to manually set the security protocols.
		# It's considered good etiquette to save the user's preference, and restore it afterwards.
		$OldTLSClientSettings = [Net.ServicePointManager]::SecurityProtocol
		
		#region SSL 2.0 test
		# Note that newer versions of Windows and PowerShell don't support SSL 2.0 at all (good!).
		# Thus, we're wrapping this in two separate Try/Catch blocks.  The outer one throws if the
		# system doesn't support it.  The inner one throws if the server doesn't support it.
		Write-Information -Tag 'Verbose' -Message "Attempting to connect to https://$Domain with SSL 2.0."
		Try {
			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl2
			Try {
				# I don't know if DisableKeepAlive is required or not, so let's play it safe.
				Invoke-WebRequest -Method HEAD -Uri "https://$Domain/" -DisableKeepAlive | Out-Null
				If ($AsPlainText) {
					Write-Output '    • SSL 2.0 is supported!'
				} Else {
					$SupportedTLSVersions += (Color Red 'SSL 2.0')
					Write-Information -Tag 'Notice' -Message 'The webserver supports SSL 2.0.'
				}
			}
			Catch {
				If ($AsPlainText) {
					Write-Output '    • SSL 2.0 is not supported.'
				} Else {
					$SupportedTLSVersions += (Color Green (Strikeout 'SSL 2.0'))
					Write-Information -Tag 'Notice' -Message 'The webserver does not support SSL 2.0.'
				}
			}
		}
		Catch {
			Write-Information -Tag 'Notice' -Message 'SSL 2.0 could not be tested because the operating system does not support it.'
		}
		#endregion
		
		#region SSL 3.0 test
		# Note that newer versions of Windows and PowerShell don't support SSL 3.0 at all (good!).
		# See explanation above.
		Try {
			Write-Information -Tag 'Verbose' -Message "Attempting to connect to https://$Domain with SSL 3.0."
			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3
			Try {
				Invoke-WebRequest -Method HEAD -Uri "https://$Domain/" -DisableKeepAlive | Out-Null
				If ($AsPlainText) {
					Write-Output '    • SSL 3.0 is supported!'
				} Else {
					$SupportedTLSVersions += (Color Red 'SSL 3.0')
					Write-Information -Tag 'Notice' -Message 'The webserver supports SSL 3.0.'
				}
			}
			Catch {
				If ($AsPlainText) {
					Write-Output '    • SSL 3.0 is not supported.'
				} Else {
					$SupportedTLSVersions += (Color Green (Strikeout 'SSL 3.0'))
					Write-Information -Tag 'Notice' -Message 'The webserver does not support SSL 3.0.'
				}
			}
		}
		Catch {
			Write-Information -Tag 'Notice' -Message 'SSL 3.0 could not be tested because the operating system does not support it.'
		}
		#endregion
		
		# Restore the user's preferences, so they won't accidentally use SSL 2.0/3.0 to connect to things.
		# We won't need to use this method when testing TLS 1.0 and up, as those protocols can be tested
		# directly with the Invoke-WebRequest cmdlet.
		[Net.ServicePointManager]::SecurityProtocol = $OldTlsClientSettings
		
		#region TLS 1.0 test
		Try {
			Write-Information -Tag 'Verbose' -Message "Attempting to connect to https://$Domain with TLS 1.0."
			Invoke-WebRequest -Method HEAD -Uri "https://$Domain/" -SslProtocol Tls | Out-Null
			If ($AsPlainText) {
				Write-Output '    • TLS 1.0 is supported'
			} Else {
				$SupportedTLSVersions += (Color Yellow 'TLS 1.0')
				Write-Information -Tag 'Notice' -Message 'The webserver supports TLS 1.0.'
			}
		}
		Catch {
			If ($AsPlainText) {
				Write-Output '    • TLS 1.0 is not supported'
			} Else {
				$SupportedTLSVersions += (Color Green (Strikeout 'TLS 1.0'))
				Write-Information -Tag 'Notice' -Message 'The webserver supports TLS 1.0.'
			}
		}
		#endregion
		
		#region TLS 1.1 test
		Try {
			Write-Information -Tag 'Verbose' -Message "Attempting to connect to https://$Domain with TLS 1.1."
			Invoke-WebRequest -Method HEAD -Uri "https://$Domain/" -SslProtocol Tls11 | Out-Null
			If ($AsPlainText) {
				Write-Output '    • TLS 1.1 is supported'
			} Else {
				$SupportedTLSVersions += (Color Yellow 'TLS 1.1')
				Write-Information -Tag 'Notice' -Message 'The webserver supports TLS 1.1.'
			}
		}
		Catch {
			If ($AsPlainText) {
				Write-Output '    • TLS 1.1 is not supported'
			} Else {
				$SupportedTLSVersions += (Color Green (Strikeout 'TLS 1.1'))
				Write-Information -Tag 'Notice' -Message 'The webserver does not support TLS 1.1.'
			}
		}
		#endregion
		
		#region TLS 1.2 test	
		Try {
			Write-Information -Tag 'Verbose' -Message "Attempting to connect to https://$Domain with TLS 1.2."
			Invoke-WebRequest -Method HEAD -Uri "https://$Domain/" -SslProtocol Tls12 | Out-Null
			If ($AsPlainText) {
				Write-Output '    • TLS 1.2 is supported'
			} Else {
				$SupportedTLSVersions += (Color Green 'TLS 1.2')
				Write-Information -Tag 'Notice' -Message 'The webserver supports TLS 1.2.'
			}
		}
		Catch {
			If ($AsPlainText) {
				Write-Output '    • TLS 1.2 is not supported!'
			} Else {
				$SupportedTLSVersions += (Color Red (Strikeout 'TLS 1.2'))
				Write-Information -Tag 'Notice' -Message 'The webserver does not support TLS 1.2.'
			}
		}
		#endregion
		
		#region TLS 1.3 test
		Try {
			Write-Information -Tag 'Verbose' -Message "Attempting to connect to https://$Domain with TLS 1.3."
			Invoke-WebRequest -Method HEAD -Uri "https://$Domain/" -SslProtocol Tls13 | Out-Null
			If ($AsPlainText) {
				Write-Output '    • TLS 1.3 is supported'
			} Else {
				$SupportedTLSVersions += (Color Green 'TLS 1.3')
				Write-Information -Tag 'Notice' -Message 'The webserver supports TLS 1.3.'
			}
		}
		Catch [Security.Authentication.AuthenticationException] {		
			# This is a weird bug that I found out.  Windows 10 supports TLS 1.3 as of Version 1903, but the support
			# is not complete.  A TLS 1.3 connection is negotiated, but there are somehow no ciphers in common.
			# This behavior is fixed in Version 21H1.  Thus, we're going to Catch this specific exception.
			Write-Information -Tag 'Notice' -Message 'TLS 1.3 could not be tested because this computer does not support it.'
		}
		Catch {
			If ($AsPlainText) {
				Write-Output '    • TLS 1.3 is not supported'
			} Else {
				$SupportedTLSVersions += (Color Yellow (Strikeout 'TLS 1.3'))
				Write-Information -Tag 'Notice' -Message 'The webserver does not support TLS 1.3.'
			}
		}
		#endregion

		# When running with PlainText, output is generated incrementally.
		If (-Not $AsPlainText) {
			Write-Output "• Tested SSL/TLS versions:  $($SupportedTLSVersions -Join ', ')`n"
		}
	}

	# If the above Try block threw an exception, that would be because HTTPS did not connect.
	Catch {
		# If it happened because of a certificate error, we'll find out here.
		Try {
			Write-Information -Tag 'Verbose' -Message "Attempting to connect to https://$Domain (ignoring certificate checks)."
			$script:HTTPRequest = Invoke-WebRequest -Method HEAD -Uri "https://$Domain" -SkipCertificateCheck
			Write-Output (Color Red "• Their webserver supports HTTPS, but there's something wrong with their certificate!`n")
		}
		# If we get this far, then HTTPS is not supported at all.
		Catch {
			Write-Output (Color Red "• Their webserver does not support HTTPS!`n")
		}
	}
}
#endregion

#region HTTP test
# It's somewhat rare, but maybe the webserver is not listening on port 80 at all.
# Recent versions of Chrome and Firefox try HTTPS first, so this may not be a bad thing.
If ($IPAddresses) {
	Try {
		Write-Information -Tag 'Notice' -Message "Attempting a clear-text HTTP connection to http://$Domain"
		$iwr = Invoke-WebRequest -Method HEAD -Uri "http://$Domain/"
		If ($null -eq $script:HTTPRequest) {
			$script:HTTPRequest = $iwr
		}
	}
	Catch {
		Write-Output (Color Yellow "• Their webserver does not support non-secure HTTP.")
	}
}
#endregion




#region HTTP header check
If ($IPAddresses) {
	Write-Output '>> Looking for interesting HTTP headers:`n'
	Try {
		$headers = Select-Object -InputObject $script:HTTPRequest -ExpandProperty 'Headers'
		ForEach ($header in (Sort-Object -InputObject $headers.GetEnumerator())) {
			Switch ($header.Key) {
				'Alt-Svc' {
					$header.Value -Split ',' | ForEach-Object {
						$_ -Split ';\s*' | ForEach-Object {
							$_ -Match "(.+)=(`"?.*`"?)" | Out-Null
							$Scheme = $Matches[1]
							$URL    = $Matches[2]
							If ($Matches[2][0] -eq ':') {
								$URL = "$Domain$($Matches[2])"
							}
							
							Switch -WildCard ($Scheme) {
								'h2*' {
									Write-Output "    • This web site is also available over HTTP/2 at: $URL"
								}
								'h3*' {
									Write-Output "    • This web site is also available over HTTP/3 at: $URL"
								}
								'ma' {
									# do nothing with the max-age token.
								}
								'persist' {
									# do nothing with the persist token.
								}
								default {
									Write-Output "    • This web site is also available over $Scheme at: $URL"
								}
							}
						}
					}
				}
				'Content-Security-Policy'      {Write-Output (Color Green '    • A content security policy is set to prevent CSRF and XSS attacks.')}
				'Cross-Origin-Embedder-Policy' {Write-Output (Color Green '    • A cross-origin embedder policy is set to prevent CSRF and XSS attacks.')}
				'Cross-Origin-Opener-Policy'   {Write-Output (Color Green '    • A cross-origin opener policy is set to prevent CSRF and XSS attacks.')}
				'Cross-Origin-Resource-Policy' {Write-Output (Color Green '    • A cross-origin resource policy is set to prevent CSRF and XSS attacks.')}
				'Expect-CT' {
					If ($header.Value -NotMatch 'max-age=0') {
						Write-Output (Color Green "    • Certificate Transparency is enforced.  A certificate and HTTPS connection without CT information $(Bold 'must') fail!")
					} Else {
						Write-Output (Color Yellow '    • Certificate Transparency is being explicitly disabled by the server administrator.')
					}
				}
				'Expect-Staple' {
					If ($header.Value -NotMatch 'max-age=0') {
						Write-Output (Color Green "    • A valid and fresh OCSP response $(Bold 'must') be stapled, or the HTTPS connection $(Bold 'must') fail.")
					} Else {
						Write-Output (Color Yellow '    • OCSP stapling enforcement is being explicitly disabled by the server administrator.')
					}
				}
				'Last-Modified' {Write-Output "    • This page was last modified on $(Get-Date $header.Value)."}
				'Onion-Location' {
					[String]($header.Value) -Match "https?\:\/\/([a-z2-7]+)\.onion" | Out-Null
					If ($Matches[1].Length -eq 56) {
						Write-Output "    • This site is available as a Tor $(Color Green '(version 3)') hidden service."
					} ElseIf ($Matches[1].Length -eq 16) {
						Write-Output "    • This site is available as a Tor $(Color Yellow 'version 2') hidden service."
					} Else {
						Write-Output '    • This site is available as a Tor hidden service.'
					}
				}
				'Permissions-Policy' {Write-Output (Color Green '    • A permission policy is defined to limit browser features.')}
				'Referrer-Policy'    {Write-Output (Color Green '    • A referrer policy is defined for user privacy.')}
				'Server'             {Write-Output "    $(Invert '•') Their webserver is running $($header.Value)."}
				'X-Powered-By'       {Write-Output "    $(Invert '•') Their website is powered by $($header.Value)."}
				'X-XSS-Protection'   {Write-Output (Color Green "    • A cross-site scripting policy is set.")}
				'Strict-Transport-Security' {
					If ($header.Value -Match 'max-age=0') {
						Write-Output (Color Yellow '    • HSTS is being intentionally disabled by the server administrator.')
					} Else {
						Write-Output (Color Green "    • HSTS is in use.  All HTTP connections $(Bold 'must') be secure.")
						If ($header.Value -Match 'preload') {
							Write-Output (Color Green "    • This domain name wants to be on the HSTS preload list.  If it is, HSTS will $(Bold 'always') be enforced!")
						}
					}
				}
				default	{
					Write-Information -Tag 'Verbose' -Message "    • We found the HTTP header $(Bold $header.Key) with the value: $($header.Value)"
				}
			}
		}
	}
	Catch {
		# If a customer doesn't have a web site, this will fail.
		# That's okay.
		If ($AsPlainText) {
			Write-Output "    • Nothing interesting was found."
		}
		Else {
			# Erase the previous line.
			Write-Output "`e[1A`e[K"
		}
	}
}
#endregion

#region Ping test

Write-Output (Underline "`nChecking if the webserver is responding to PING's.`n")


If ($IPAddresses) {
	# Hide the progress bar.
	$OldProgressPreference = $global:ProgressPreference
	$global:ProgressPreference = 'SilentlyContinue'

	# A warning message is printed if a ping fails.  Redirect that to null.
	$Test = (Test-NetConnection -ComputerName $IPAddresses[0] 3> $null)
	
	If ($Test.PingSucceeded) {
		Write-Output "• $($IPAddresses[0]) of $Domain responds to pings ($($Test.PingReplyDetails.RoundTripTime) ms).`n"
	}
	Else {
		Write-Output "• $($IPAddresses[0]) of $Domain does not respond to pings.`n"
	}

	# Restore the user's progress preference.
	$global:ProgressPreference = $OldProgressPreference
}
#endregion

Write-Output (Underline "I'm curious.. Are there any ports open?`n")

#region Common port scanclear

If ($IPAddresses) {
	# The Windows version of /etc/services may be incomplete compared to the *nix version,
	# so let's add some definitions to it, for the user's benefit.
	If ($IsWindows) {
		$Services = Get-Content "${env:WinDir}\System32\drivers\etc\services"
		$Services += @'
smtps 465/tcp
smtp-submission 587/tcp
http-alt 8080/tcp
https-alt 8443/tcp
https-alt 8843/tcp
'@
	}
	Else {
		$Services = Get-Content '/etc/services'
	}

	# Since we're ending this sentence in a colon, wrap an IPv6 address in brackets.
	If ($IPAddresses[0] -Match ':') {
		Write-Output (Color yellow " >>> Scanning for common service ports on IP-Address [$($IPAddresses[0])]:`n")
	}
	Else {
		Write-Output ">>> Scanning for common service ports on IP-Address $($IPAddresses[0]):`n"
	}

	# This is the list of ports that we're going to scan.  Make sure they have
	# a matching entry in the services file or the variable above.
	$Ports = @(21, 22, 23, 25, 53, 70, 80, 110, 139, 143, 389, 443, 445, 465,
			   515, 587, 636, 666, 993, 995, 1723, 3268, 3269, 3389, 5355,
			   8080, 8443)
	
	$Ports | ForEach-Object -ThrottleLimit 25 -Parallel {
		$Port = $_
		$ServiceName = (($using:Services | Select-String "\s$Port\/tcp") -Split "\s+" | Select-Object -First 1) ?? 'unknown'
		
		Try {
			Write-Progress -Activity "Scanning TCP port $Port"
			# TODO: Figure out how to get a shorter timeout.
			# This can really get painful when testing a lot of ports.
			$null = [Net.Sockets.TcpClient]::new(${using:IPAddresses}[0], $Port)
			Write-Output "    • TCP port $Port ($ServiceName) is open."
		}
		Catch {
			Write-Information "    • TCP port $Port ($ServiceName) is closed or filtered.`n"
		}
	}

	# it's a lot of data to keep in memory.
	Remove-Variable -Name 'Services'
}
#endregion

#region Look for interesting files
# Webservers can be full of interesting things describing the site.
# Let's look for some well-known sources of information.

Write-Output (Underline "`nLooking for files of interest..`n")
If ($IPAddresses) {
	Try {
		@(
			'.well-known/host-meta',				# machine-readable web site info
			'.well-known/security.txt',				# security contact info
			'ads.txt',								# authorized digital sellers
			'have-i-been-pwned-verification.txt',	# HIBP verification data
			'humans.txt',							# a place to write fun things about the people involved
			'robots.txt',							# instructions for bots
			'README.txt',							# if they use a template, this might exist
			'sitemap.xml'							# a list of all web pages on this site
		) | `
		ForEach-Object {
			If ((Invoke-WebRequest -Uri "http://$Domain/$_" -Method HEAD -SkipHttpErrorCheck -ErrorAction Ignore).StatusCode -eq 200)
			{
				If ($_ -eq 'robots.txt') {
					Write-Output "$(Invert '•') The file http://$Domain/$_ exists.  Let's see where they don't want you to go."
					(Invoke-WebRequest -Uri "http://$Domain/robots.txt").Content -Split "[`r`n]+" | ForEach-Object {
						$Directive, $Value = $_ -Split ":\s+",2
						If ($Directive -eq 'Disallow') {
							Write-Output "    $(Invert '•') The URL $(Bold http://$Domain$Value) is disallowed.  It might be worth a peek."
						}
					}
				}
				
				# Early drafts of the security.txt specification placed this file in the root.
				# It now should live in the .well-known folder.
				ElseIf ($_ -Like '*security.txt') {
					Write-Output (Color Green '• There is a security.txt file in the well-known location:')
					
					# These files are supposed to be served only over HTTPS.
					# I'm a bit more lenient, so I can show an error.
					Try {
						$securityTxt = Invoke-WebRequest -Uri "https://$Domain/.well-known/security.txt"
					}
					Catch {
						$securityTxt = Invoke-WebRequest -Uri "http://$Domain/.well-known/security.txt"
						Write-Output (Color Red "    • This file could not be fetched over HTTPS.")
					}
					
					# Go through the file line by line.
					$securityTxt.Content -Split "[`r`n]+" `
					| Select-String -Pattern '^[A-Za-z-]+:\s+' `	# This regex matches all directive-value pairs.
					| ForEach-Object {
							$Directive, $Value = $_ -Split ":\s+",2
							Switch ($Directive) {
								'Acknowledgments' {Write-Output "    • See who's reported security issues:  $(Bold $Value)"}
								'Contact'         {Write-Output "    • Report security issues to:  $(Bold $Value)"}
								'Encryption'      {Write-Output "    • Encrypt your security reports with:  $(Bold $Value)"}
								'Hiring'          {Write-Output (Invert "    • They're hiring security professionals!  Visit: (Bold $Value)")}
								'Policy'          {Write-Output "    • A security policy is available at: $(Bold $Value)"}
								'Expires'         {
													Try {
														$expires = Get-Date $Value
														If ((Get-Date) -gt $expires) {
															Write-Output (Color Red "    • Their security.txt file is expired!")
														} Else {
															Write-Output "    • This file expires at $expires."
														}
													}
													Catch {
														Write-Output (Color Red "    • There's an expiration date, but it's not parseable.")
													}
												}
							}
					}
					
					# We can't assume that the user will have the GnuPG tools installed, so we're just going
					# to check for the existence of something that looks like a signature and call it a day.
					# Validating the signature is an exercise left to the reader.
					If ($securityTxt.Content -Match 'BEGIN PGP SIGNED MESSAGE') {
						Write-Output (Color Green "    • This file $(Underline 'appears') to have a PGP signature.")
					}
				}
				
				# For all other interesting files, just show this generic message.
				Else {
					Write-Output "$(Invert '•') The file http://$Domain/$_ exists.  There may be something interesting inside."
				}
			}
		}
	}
    Catch {
		# If a customer doesn't have a web site, this will fail.
		# That's okay.
		If ($AsPlainText) {
			Write-Output "    • Nothing interesting was found."
		}
		Else {
			# Erase the previous line.
			Write-Output "`e[1A`e[K"
		}
	}
}
#endregion
#region Look for interesting files
# Webservers can be full of interesting things describing the site.
# Let's look for some well-known sources of information.
Write-Output "`e[1A`e[K"

If ($IPAddresses) {
	Try {
		@(
			'.well-known/host-meta',				# machine-readable web site info
			'.well-known/security.txt',				# security contact info
			'ads.txt',								# authorized digital sellers
			'have-i-been-pwned-verification.txt',	# HIBP verification data
			'humans.txt',							# a place to write fun things about the people involved
			'robots.txt',							# instructions for bots
			'README.txt',							# if they use a template, this might exist
			'sitemap.xml'							# a list of all web pages on this site
		) | `
		ForEach-Object {
			If ((Invoke-WebRequest -Uri "http://$Domain/$_" -Method HEAD -SkipHttpErrorCheck -ErrorAction Ignore).StatusCode -eq 200)
			{
				If ($_ -eq 'robots.txt') {
					Write-Output "$(Invert '•') The file http://$Domain/$_ exists.  Let's see where they don't want you to go."
					(Invoke-WebRequest -Uri "http://$Domain/robots.txt").Content -Split "[`r`n]+" | ForEach-Object {
						$Directive, $Value = $_ -Split ":\s+",2
						If ($Directive -eq 'Disallow') {
							Write-Output "    $(Invert '•') The URL $(Bold http://$Domain$Value) is disallowed.  It might be worth a peek."
						}
					}
				}
				
				# Early drafts of the security.txt specification placed this file in the root.
				# It now should live in the .well-known folder.
				ElseIf ($_ -Like '*security.txt') {
					Write-Output (Color Green '• There is a security.txt file in the well-known location:')
					
					# These files are supposed to be served only over HTTPS.
					# I'm a bit more lenient, so I can show an error.
					Try {
						$securityTxt = Invoke-WebRequest -Uri "https://$Domain/.well-known/security.txt"
					}
					Catch {
						$securityTxt = Invoke-WebRequest -Uri "http://$Domain/.well-known/security.txt"
						Write-Output (Color Red "    • This file could not be fetched over HTTPS.")
					}
					
					# Go through the file line by line.
					$securityTxt.Content -Split "[`r`n]+" `
					| Select-String -Pattern '^[A-Za-z-]+:\s+' `	# This regex matches all directive-value pairs.
					| ForEach-Object {
							$Directive, $Value = $_ -Split ":\s+",2
							Switch ($Directive) {
								'Acknowledgments' {Write-Output "    • See who's reported security issues:  $(Bold $Value)"}
								'Contact'         {Write-Output "    • Report security issues to:  $(Bold $Value)"}
								'Encryption'      {Write-Output "    • Encrypt your security reports with:  $(Bold $Value)"}
								'Hiring'          {Write-Output (Invert "    • They're hiring security professionals!  Visit: (Bold $Value)")}
								'Policy'          {Write-Output "    • A security policy is available at: $(Bold $Value)"}
								'Expires'         {
													Try {
														$expires = Get-Date $Value
														If ((Get-Date) -gt $expires) {
															Write-Output (Color Red "    • Their security.txt file is expired!")
														} Else {
															Write-Output "    • This file expires at $expires."
														}
													}
													Catch {
														Write-Output (Color Red "    • There's an expiration date, but it's not parseable.")
													}
												}
							}
					}
					
					# We can't assume that the user will have the GnuPG tools installed, so we're just going
					# to check for the existence of something that looks like a signature and call it a day.
					# Validating the signature is an exercise left to the reader.
					If ($securityTxt.Content -Match 'BEGIN PGP SIGNED MESSAGE') {
						Write-Output (Color Green "    • This file $(Underline 'appears') to have a PGP signature.")
					}
				}
				
				# For all other interesting files, just show this generic message.
				Else {
					Write-Output "$(Invert '•') The file http://$Domain/$_ exists.  There may be something interesting inside."
				}
			}
		}
	}
	Catch {
		# If a customer doesn't have a web site, this will fail.  That's okay.
	}
}
#endregion


#######################################################################
### DNS CHECKS
#######################################################################
#region DNSSEC check
Write-Output (Underline "`nChecking DNS zone and records`n")


#region Where is the main DNS server?
# Manually select the first SOA record.  There is supposed to be only be one, but sometimes Resolve-DnsName hands us lemons.
$soa = (Resolve-DnsName -Name $Domain -Type 'SOA')[0]
Switch -WildCard ($soa.PrimaryServer) {
	# Feel free to add to this list!
	'*.domaincontrol.com'	{Write-Output '• The primary DNS zone is hosted by GoDaddy.'}
	'p*.domaincontrol.com'	{Write-Output '    • And they have GoDaddy Premium DNS.'}
	'*.worldnic.com'		{Write-Output '• Their primary DNS zone is hosted by Network Solutions.'}
	'*.dynect.net'			{Write-Output '• Their primary DNS zone is hosted by Oracle Dyn.'}
	'*.cloudflare.com'		{Write-Output '• Their primary DNS zone is hosted by Cloudflare.'}
	default					{Write-Output "• Their primary DNS zone is hosted by the nameserver $($soa.PrimaryServer)"}
}
#endregion

#region Date of last DNS update
# The SOA record's serial number should be in the formation YYYYMMDDNN, where N are
# arbitrary numbers.  Not all DNS servers support this (looking at you, Microsoft).
$serial = "$($soa.SerialNumber)"
Try {
	$Date = "$($serial.Substring(0,4))-$($serial.Substring(4,2))-$($serial.Substring(6,2))"
	Write-Output "• Their DNS zone was last updated on $(Get-Date -Format 'MM/dd/yyyy' -Date $Date)."
}
Catch {
	Write-Output (Color Yellow "• Their DNS zone does not use the recommended date-based serial numbering.  Their hostmaster may be dumb.")
}
#endregion

#region Check for Domain Connect API support
Resolve-DnsName -Type TXT -Name "_domainconnect.$Domain" -ErrorAction Ignore `
| Where-Object Type -eq 'TXT' `
| ForEach-Object {
	$TxtRecord = $_		# so we can catch it
	# Once most versions of PowerShell support TLS 1.3, the SslProtocol parameter value should be changed to:
	# [Microsoft.PowerShell.Commands.WebSslProtocol]::Tls12 -bor [Microsoft.PowerShell.Commands.WebSslProtocol]::Tls13
	Try {
		$Results = Invoke-RestMethod -SslProtocol Tls12 -Uri "https://$($_.Strings)/v2/$Domain/settings" -ErrorAction Stop
		If ($Results.providerName) {
			Write-Output "• The Domain Connect API is supported, and managed by $($Results.providerName)."
		}
		Else {
			Write-Output '• The Domain Connect API is supported, but the record could not be parsed.'
		}
	}
	Catch {
		Write-Output "$(Color Red '• An invalid Domain Connect API TXT record was found:  ') $($TxtRecord.Strings)"
	}
}
#endregion

#region DNS records that might indicate remote access
# You can call this section "Interesting DNS Records."
@('exchange','mail','remote','rds','vpn','webmail') | ForEach-Object -Parallel {
	Resolve-DnsName -Type 'A_AAAA' -Name "$_.${using:Domain}" -ErrorAction Ignore `
	| Where-Object Type -in 'A','AAAA' `
	| ForEach-Object {
		$ptr = (Resolve-DnsName -Type 'PTR' -Name $_.IPAddress -ErrorAction Ignore)?.NameHost ?? 'no reverse DNS record'
		Write-Output "• $($_.Name) exists and has the $($_.DataLength -eq 4 ? 'IPv4' : 'IPv6') address $($_.IPAddress) ($ptr)."
	}
}
#endregion

#region Wildcard DNS record
# Querying for a nonsensical DNS record will tell us if they have a wildcard
# DNS record in place. This is the default for Network Solutions' hosted zones.
Resolve-DnsName -Name "wildcard-dns-check-xyzzy.$Domain" -ErrorAction Ignore `
| Where-Object Type -ne 'SOA' `
| ForEach-Object {
	$ptr = (Resolve-DnsName -Type 'PTR' -Name $_.IPAddress -ErrorAction Ignore)?.NameHost ?? 'no reverse DNS record'
	Write-Output "• A wildcard DNS entry exists for *.$Domain, for the $($_.DataLength -eq 4 ? 'IPv4' : 'IPv6') address $($_.IPAddress) ($ptr)."
}
#endregion

#######################################################################
### EMAIL CHECKS
#######################################################################
Write-Output (Underline "`nChecking their email on particularities`n")

#region First MX record
$mx = Resolve-DnsName -Type 'MX' -Name $Domain | Where-Object Type -eq 'MX' | Sort-Object Preference
If ($mx) {
	$Output = @()
	Switch -WildCard ($mx.NameExchange) {
		'*.mail.protection.outlook.com' {$Output += '• They have an MX record pointing to Microsoft 365.'}
		'*aspmx.l.google.com'           {$Output += '• They have an MX record pointing to Google Workspace.'}
		'*.arsmtp.com'                  {$Output += '• They have an MX record pointing to AppRiver.'}
		#default                         {$Output += "• They have an MX record: $_"}
	}
	Get-Unique -InputObject $Output
}
Else {
	Write-Output '• There are no MX records.  They cannot receive email.'
}
#endregion

$autodiscover = Resolve-DnsName -Name "autodiscover.$Domain" -ErrorAction Ignore
$CNAME = $autodiscover | Where-Object Type -eq 'CNAME'
$IPs   = $autodiscover | Where-Object Type -in @('A','AAAA')
If ($CNAME) {
	If ($CNAME.NameHost -eq 'autodiscover.outlook.com') {
		Write-Output '• They use Exchange Online for Autodiscover.'
	}
	Else {
		Write-Output "• There is an Exchange Autodiscover server at $($($CNAME[-1]).NameHost)."
	}
}
ElseIf ($IPs) {
	$IPs | ForEach-Object {
		$ptr = (Resolve-DnsName -Type 'PTR' -Name $_.IPAddress -ErrorAction Ignore)?.NameHost ?? 'no reverse DNS record'
		Write-Output "• There is an Exchange Autodiscover server with the $($_.DataLength -eq 4 ? 'IPv4' : 'IPv6') address $($_.IPAddress) ($ptr)."
	}
}

#region Interesting TXT records

# This is so we can print an error if there's no SPF record.
$foundSPF = $false

Resolve-DnsName -Name $Domain -Type 'TXT' -ErrorAction Ignore `
| Where-Object Type -eq 'TXT' `
| ForEach-Object {
	#region SPF and Sender ID check.
	# "SPF 2.0" was Microsoft's failed Sender ID initiative.  I don't think it
	# ever got off the ground, but if someone out there is using it, we may as
	# well check it.
	If ($_.Strings -Like 'v=spf1 *' -or $_.Strings -Like 'spf2.0/*') {
		$script:foundSPF = $true
		
		Write-Output "• According to SPF, valid email from $(Bold $Domain) will come from:"
		$_.Strings -Split "\s+" | ForEach-Object {
			$TokenName, $TokenValue = $_ -Split "[=:]",2
			$TokenValue ??= $Domain # if there's no value, the base domain is used.
						
			# I'm not bothering to check for anything prefixed with ? because that's basically meaningless.
			# PTR lookups are in yellow because those are deprecated and should not be used.
			Switch -RegEx ($TokenName) {
				'redirect'    { Write-Output "    • anything listed in the SPF record for $(Bold $TokenValue)"; Continue}
				'^\+?a$'      { Write-Output "    • the IP addresses of $(Bold $TokenValue)"}
				'^\+?exists'  { Write-Output "    • anywhere, if there's a DNS A record for $(Bold $TokenValue)"}
				'^\+?include' { Write-Output "    • anything listed in $TokenValue's SPF record"}
				'^\+?ip4'     { Write-Output "    • the IPv4 $($TokenValue -Match '/' ? 'subnet' : 'address') $(Bold $TokenValue)"}
				'^\+?ip6'     { Write-Output "    • the IPv6 $($TokenValue -Match '/' ? 'subnet' : 'address') $(Bold $TokenValue)"}
				'^\+?mx'      { Write-Output "    • the named MX records"}
				'^\+?ptr'     { Write-Output    (Color Yellow "   • anything with a reverse DNS record matching $(Bold $TokenValue)") }
				'^\?a$'       { Write-Output "    • $(Bold 'maybe') the IP addresses of $(Bold $TokenValue)"}
				'^\?exists'   { Write-Output "    • $(Bold 'maybe') anywhere, if there's a DNS A record for $(Bold $TokenValue)"}
				'^\?include'  { Write-Output "    • $(Bold 'maybe') anything listed in $TokenValue's SPF record"}
				'^\?ip4'      { Write-Output "    • $(Bold 'maybe') the IPv4 $($TokenValue -Match '/' ? 'subnet' : 'address') $(Bold $TokenValue)"}
				'^\?ip6'      { Write-Output "    • $(Bold 'maybe') the IPv6 $($TokenValue -Match '/' ? 'subnet' : 'address') $(Bold $TokenValue)"}
				'^\?mx'       { Write-Output "    • $(Bold 'maybe') the named MX records for $TokenValue"}
				'^\?ptr'      { Write-Output (Color Yellow "    • anything with a reverse DNS record matching $(Bold $TokenValue)") }
				'-a$'         { Write-Output "    • $(Underline 'not') the IP addresses of $(Bold $TokenValue)"}
				'-exists'     { Write-Output "    • $(Underline 'not') if the host $(Bold $TokenValue) exists"}
				'-include'    { Write-Output "    • $(Underline 'nothing') listed in $(Bold $TokenValue)'s SPF record"}
				'-ip4'        { Write-Output "    • $(Underline 'not') the IPv4 $($TokenValue -Match '/' ? 'subnet' : 'address') $(Bold $TokenValue)"}
				'-ip6'        { Write-Output "    • $(Underline 'not') the IPv6 $($TokenValue -Match '/' ? 'subnet' : 'address') $(Bold $TokenValue)"}
				'-mx'         { Write-Output "    • $(Underline 'not') the named MX records for $TokenValue"}
				'-ptr'        { Write-Output (Color Yellow "    • $(Underline 'nothing') with a reverse DNS record matching $(Bold $TokenValue)")}
				'^\+?all'     { Write-Output (Color Red "    • anywhere!") }
				'\?all'       { Write-Output "    • and $(Bold 'Neutral No') iThey have a Neutral or No policy" }
				'~all'        { Write-Output "    • and $(Bold 'indicates')  a soft fail policy" }
				'-all'        { Write-Output (Color Green "    • They use a hardfail policy`n") }
				'exp'         {
								$Explanation = (Resolve-DnsName -Type TXT -Name $TokenValue).Strings
								Write-Output "    • Also, if a message fails SPF, the sender will see this error message:  `"$Explanation`""
						 	  }
			}
		}
	}
	#endregion
	
	ElseIf ($_.Strings -Like 'MS=ms*') {
		Write-Output '• This domain may be registered with Microsoft 365 (and they forgot to delete the TXT challenge record).'
	}
	
	ElseIf ($_.Strings -Like 'amazonses*') {
		Write-Output '• This domain is registered with Amazon Simple Email Service.'
	}
	
	ElseIf ($_.Strings -Like 'have-i-been-pwned-verification=*') {
		Write-Output '• Someone has requested domain-wide data from Have I Been Pwned.'
	}
}

If (-Not $foundSPF) {
	Write-Output (Color Red '• No valid SPF TXT record was found!')
}

#region Amazon SES check.
# Yes, we checked for this already.  It can be specified as a TXT record at the root, too.
If ($null -ne (Resolve-DnsName -Name "_amazonses.$Domain" -Type TXT -ErrorAction Ignore)) {
	Write-Output '• This domain is registered with Amazon SES.'
}
Else {
	Write-Information '• This domain may not be registered with Amazon SES.'
}
#endregion

#region Well-known DKIM records
$TxtParams = @{
	'ErrorAction' = 'Ignore'
	'Type'        = 'TXT'
}

If ((Resolve-DnsName -Name "selector1._domainkey.$Domain" @TxtParams | Where-Object Type -eq 'TXT') ?? `
    (Resolve-DnsName -Name "selector2._domainkey.$Domain" @TxtParams | Where-Object Type -eq 'TXT'))
{
	Write-Output "• One or more DKIM records exists for Exchange Online.  $(Bold 'They use Microsoft 365.')"
}

If (Resolve-DnsName -Name "autotask._domainkey.$Domain" @TxtParams | Where-Object Type -eq 'TXT') {
	Write-Output "• A DKIM selector called `"autotask`" exists.  $(Bold 'They use AutoTask.')"
}

If (Resolve-DnsName -Name "google._domainkey.$Domain" @TxtParams | Where-Object Type -eq 'TXT') {
	Write-Output "• A DKIM selector called `"google`" exists.  $(Bold 'They use Google Workspace.')"
}

If (Resolve-DnsName -Name "k1._domainkey.$Domain" @TxtParams | Where-Object Type -eq 'TXT') {
	Write-Output "• A DKIM selector called `"k1`" exists.  $(Bold 'They use MailChimp.')"
}

If (Resolve-DnsName -Name "default._domainkey.$Domain" @TxtParams | Where-Object Type -eq 'TXT') {
	Write-Output '• A DKIM selector called "default" exists.'
}
#endregion

#region DKIM-related records
$DkimPolicyRecord = Resolve-DnsName -Name "_domainkey.$Domain" @TxtParams | Where-Object Type -eq 'TXT'
Switch -WildCard (${DkimPolicyRecord}?.Strings -Split "[;\s*]") {
	'o=~' {Write-Output "• This domain asserts that $(Bold 'some') outgoing emails are signed with DomainKeys or DKIM."}
	'o=-' {Write-Output (Color Green "• This domain asserts that $(Bold 'all') outgoing emails are signed with DomainKeys or DKIM.")}
	'r=*' {Write-Output "• DomainKeys/DKIM policy violations will be sent to $($_.Substring(2))."}
	'n=*' {Write-Output "• The DomainKeys/DKIM policy has a note:  $($_.Substring(2))"}
}

# ADSP is considered historical.  Yet, we may as well check it if it's there.
$AdspRecord = Resolve-DnsName -Name "_adsp._domainkey.$Domain" @TxtParams | Where-Object Type -eq 'TXT'
Switch (${AdspRecord}?.Strings) {
	'dkim=unknown'    {Write-Output "• This domain asserts that $(Bold 'some, most, or all') outgoing emails have an DKIM author domain signature."}
	'dkim=all'        {Write-Output (Color Green "• This domain asserts that $(Bold 'all') outgoing emails have an DKIM author domain signature.")}
	'dkim=discarable' {Write-Output (Color Green "• This domain asserts that $(Bold 'all') outgoing emails have an DKIM author domain signature, $(Bold 'and') anything else can be discarded.  Power move.")}
}

#region DMARC check
$DMARC = Resolve-DnsName -Name "_dmarc.$Domain" @TxtParams | Where-Object Type -eq 'TXT'
If ($DMARC) {
	Write-Output "$(Color Green '• This domain publishes a DMARC record:')  $($DMARC.Strings)"
}
Else {
	Write-Output (Color Yellow '• This domain does not publish a DMARC record.')
}
#endregion

#######################################################################
### OTHER DEFINED SERVICES
#######################################################################
Write-Output (Underline "`nChecking for other services`n")

#region Interesting TXT records
Resolve-DnsName -Name $Domain -Type 'TXT' -ErrorAction Ignore `
  | Where-Object Type -eq 'TXT'
  | ForEach-Object {
		If ($_.Strings -Like 'google-site-verification=*') {
			Write-Output '• They use Google Webmaster Tools.'
		}
		ElseIf ($_.Strings -Like 'knowbe4-site-verification=*') {
			Write-Output '• They receive simulated phishing emails from KnowBe4.`n`n`n'
		}
}
#endregion

#region Other services
$lync = Resolve-DnsName -Name "lyncdiscover.$Domain" -ErrorAction Ignore
$CNAME = $lync | Where-Object Type -eq 'CNAME'
$IPs   = $lync | Where-Object Type -in 'A','AAAA'
If ($CNAME) {
	If ($CNAME.NameHost -eq 'webdir.online.lync.com') {
		Write-Output '• They use Microsoft Teams and/or Skype for Business Online.'
	}
	Else {
		Write-Output "• There is a Skype for Business or Lync server at $($($CNAME[-1]).NameHost)."
	}
}
ElseIf ($IPs) {
	$IPs | ForEach-Object {
		$ptr = (Resolve-DnsName -Type 'PTR' -Name $_.IPAddress -ErrorAction Ignore).NameHost ?? 'no reverse DNS record'
		Write-Output "• They have a Skype for Business/Lync server with the $($_.DataLength -eq 4 ? 'IPv4' : 'IPv6') address $($_.IPAddress) ($ptr)."
	}
}
#endregion

#region Advertised services
# This is a comma-separated values list of human-readable names,
# and the service names they correspond to.
@"
Name,Service
CalDAV,caldav
CardDAV,carddav
IMAP,imap
IMAP over TLS,imaps
IMPS SAP,imps-server
Kerberos 5 KDC,kerberos
Kerberos 5 primary KDC,kerberos-adm
Kerberos 4 KDC,kerberos-iv
Kerberos 5 primary KDC,kerberos-master
Kerberos 5 password change,kpasswd
LDAP,ldap
Matrix,matrix
Minecraft,minecraft
Mumble,mumble
POP3,pop3
POP3 over TLS,pop3s
Puppet,x-puppet
SIP,sip
SIP federation,sipfederation
SMTP submission,submission
secure TURN,turns
STUN,stun
Teamspeak,ts3
TURN,turn
Web,http
XMPP client connection,xmpp-client
XMPP server connection,xmpp-server
"@ `
| ConvertFrom-CSV `
| ForEach-Object -Parallel {
	#region Redefine functions due to ForEach Parallel running in a separate space.
	Function Bold {
		[OutputType('String')]
		Param(
			[Parameter(Mandatory)]
			[AllowNull()]
			[String] $Message
		)
		Return "`e[1m${Message}`e[22m"
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
	#endregion

	# This $_ will not be available in the nested ForEach, so we need to redefine them here.
	$Name    = $_.Name
	$Service = $_.Service
		
	# Not all of these will be valid combinations (e.g., _autodiscover._udp),
	# but this makes the code easier to write.  Anything that fails will be ignored.
	$Results  = @()
	$Results += Resolve-DnsName -Name "_$Service._tcp.${using:Domain}" -Type 'SRV' -ErrorAction Ignore
	$Results += Resolve-DnsName -Name "_$Service._udp.${using:Domain}" -Type 'SRV' -ErrorAction Ignore
	$Results += Resolve-DnsName -Name "_$Service._tls.${using:Domain}" -Type 'SRV' -ErrorAction Ignore
	
	$Results | Where-Object Type -eq 'SRV' | Sort-Object Priority,Weight | ForEach-Object {
		$_.Name -Match "_$Service._([A-Za-z]+)\..*" | Out-Null
		$Protocol = $Matches[1].ToUpper()
		
		# For some services, a hostname that's only a dot means	that the service is explicitly not available.
		If ($_.NameTarget -eq '.') {
			Write-Output "• $Name is not available for this domain."
		}
		Else {
			If ($Protocol -eq 'TLS') {
				Write-Output "• There is an encrypted $Name server at $(Bold ($_.NameTarget.ToString())) on TCP port $($_.Port)."
			}
			Else {
				Write-Output "• There is a $Name server at $(Bold ($_.NameTarget.ToString())) on $Protocol port $($_.Port)."
			}
		}
	}
}
#endregion




