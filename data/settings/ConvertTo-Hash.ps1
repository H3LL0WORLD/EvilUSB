Function ConvertTo-Hash
{
	do {
		$String = Read-Host "Password" -AsSecureString
	} until ($String)
	return ConvertFrom-SecureString $String
}

$Hash = ConvertTo-Hash

try {
	Add-Type -AssemblyName System.Windows.Forms
	[Windows.Forms.Clipboard]::SetText($Hash)

	Write-Host "[+] Hash copied to clipboard"
} catch {
	Write-Host "[+] Hash: " + $Hash
} finally {
	Write-Host "[?] Press any key to continue..." -NoNewline
	[Void][Console]::ReadKey()
}