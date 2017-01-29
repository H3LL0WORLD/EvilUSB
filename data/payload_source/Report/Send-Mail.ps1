Function Send-Mail
{
	Param
	(
		[Parameter(Mandatory = $true)]
		[String] $From,
		[Parameter(Mandatory = $true)]
		[String] $Password,
		[Parameter(Mandatory = $true)]
		[Object[]] $Key,
		[Parameter(Mandatory = $true)]
		[String] $To,
		[Parameter(Mandatory = $false)]
		[String] $Subject,
		[Parameter(Mandatory = $true)]
		[Object[]] $Body,
		[Parameter(Mandatory = $false)]
		[Object[]] $Attachments,
		[Parameter(Mandatory = $false)]
		[Switch] $IsBodyHtml = $false
	)

	[SecureString] $Password = $Password | ConvertTo-SecureString -Key $Key

	if ([Environment]::Version.Major -eq 2)
	{
		[String] $Password = [Management.Automation.PSCredential]::new(' ',$Password).GetNetworkCredential().Password
	}

	$Client = New-Object Net.Mail.SmtpClient('smtp.gmail.com', 587)
	$Client.Credentials = New-Object Net.NetworkCredential($From, $Password)
	$Client.EnableSsl = $true

	$From = New-Object mailaddress($From, $From.Split('@')[0])
	$MailMessage = New-Object Net.Mail.MailMessage
	$MailMessage.Sender = $From
	$MailMessage.From = $From
	$MailMessage.Body = $Body | Out-String
	if ($IsBodyHtml)
	{
		$MailMessage.IsBodyHtml = $true
	}
	if ($Subject)
	{
		$MailMessage.Subject = $Subject
	}
	foreach ($Attachment in $Attachments)
	{
		if (Test-Path $Attachment)
		{
			try
			{
				$MailMessage.Attachments.Add( (New-Object Net.Mail.Attachment $Attachment) )
			}
			catch {}
		}
	}

	try
	{
		$To = New-Object mailaddress($To, $To.Split('@')[0])
		$MailMessage.To.Add($To)
	}
	catch
	{
		$MailMessage.To.Add($From)
	}
	finally
	{
		foreach ($i in (1..3))
		{
			if (-not $EmailSent)
			{
				try
				{
					$Client.Send($MailMessage)
					$EmailSent = $true
					Write-Host "[+] Email sent successfully" -ForegroundColor Green
				}
				catch
				{
					Write-Warning "There was an error trying to send the email"
					Write-Host -ForegroundColor Red $Error[0]
					Start-Sleep -Seconds 3
				}
			}
		}
	}
}
