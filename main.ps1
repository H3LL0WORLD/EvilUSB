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
Function Main {
    Begin {
		# Importar configuracion
		Add-Type -AssemblyName System.Web.Extensions
		$Global:Settings = (New-Object Web.Script.Serialization.JavascriptSerializer).DeserializeObject((Get-Content .\data\settings\settings.json | Out-String))
		# Importar idiomas
		$Global:LANG = Get-Content .\data\lang\es-ES.lng
		#$Global:LANG = Get-Content .\data\lang\en-EN.lng
		# Importar funciones
		Import-Module .\lib\common\functions.ps1 -Force

		# Save original WindowSize
		$Global:WindowSize = Get-WindowSize
		# Set WindowSize
        Set-WindowSize (New-Object Management.Automation.Host.Size 120,30)

        # Save original WindowTitle
        $Global:WindowTitle = $Host.UI.RawUI.WindowTitle
        # Set WindowTitle
        $Host.UI.RawUI.WindowTitle = $LANG[0]
        # Save original BackgroundColor
        $Global:BackgroundColor = Get-BackgroundColor
        # Change BackgroundColor
        $bColor = 'Black'
        Set-BackgroundColor @{
            BackgroundColor = $bColor
            ErrorBackgroundColor = $bColor
            WarningBackgroundColor = $bColor
            DebugBackgroundColor = $bColor
            VerboseBackgroundColor = $bColor
            ProgressBackgroundColor = $bColor
        }
        # Mensaje bienvenida
        TypeWrite-Host "$($LANG[1]), " -NoNewLine -EndSleep 250;TypeWrite-Host $env:USERNAME -ForegroundColor Green -EndSleep 1000
    }

    Process {
        do {
            # Volume 2 use
            $Global:Volume = AskForVolume
        } until ($Global:Volume)
        Clear-Host
        TypeWrite-Host -Delay 0 -NoNewLine '
========================================================================================================================
                          EvilUSB: Auto-executable USB using PS & WMI | [Version]: 0.0.1-beta                   
========================================================================================================================
                       [Facebook]: https://www.facebook.com/HolaMundo.YT | [Twitter]: H3LL0WORLD                       
========================================================================================================================'
        
        # Initialize/Reset variable of payloads to write
        EvilUSB:ManagePayloads -Reset
        # Load payloads
        EvilUSB:LoadPayloads

		$Global:Aliases = @{
            '?' = New-Object PSCustomObject -Property @{
                Name = '?'
                Function = 'EvilUSB:Help'
                Description = 'Alias for Help'
            }
			'/?' = New-Object PSCustomObject -Property @{
                Name = '/?'
                Function = 'EvilUSB:Help'
                Description = 'Alias for Help'
            }
			'-?' = New-Object PSCustomObject -Property @{
                Name = '-?'
                Function = 'EvilUSB:Help'
                Description = 'Alias for Help'
            }
			'-H' = New-Object PSCustomObject -Property @{
                Name = '-H'
                Function = 'EvilUSB:Help'
                Description = 'Alias for Help'
            }
            'Add' = New-Object PSCustomObject -Property @{
                Name = 'Add'
                Function = 'EvilUSB:ManagePayloads -Write'
                Description = 'Alias for Write'
            }
			'Clean' = New-Object PSCustomObject -Property @{
                Name = 'Clean'
                Function = 'EvilUSB:Remove'
                Description = 'Alias for Remove'
            }
			'Del' = New-Object PSCustomObject -Property @{
                Name = 'Del'
                Function = 'EvilUSB:ManagePayloads -Reset'
                Description = 'Alias for Reset'
            }
            'Quit' = New-Object PSCustomObject -Property @{
                Name = 'Quit'
                Function = 'EvilUSB:Exit'
                Description = 'Alias for Exit'
            }
		}

        $Global:Opciones = @{
			'Info' = New-Object PSCustomObject -Property @{
                Name = 'Info'
                Function = 'EvilUSB:Info'
                Description = 'Muestra informacion sobre este framework'
            }
            'Help' = New-Object PSCustomObject -Property @{
                Name = 'Help'
                Function = 'EvilUSB:Help'
                Description = 'Muestra la ayuda'
            }
            'Exit' = New-Object PSCustomObject -Property @{
                Name = 'Exit'
                Function = 'EvilUSB:Exit'
                Description = 'Salir'
            }
            'Infect' = New-Object PSCustomObject -Property @{
                Name = 'Infect'
                Function = 'EvilUSB:Infect'
                Description = 'Generar archivo de infeccion'
            }
            'Remove' = New-Object PSCustomObject -Property @{
                Name = 'Remove'
                Function = 'EvilUSB:Remove'
                Description = 'Generar archivo de des-infeccion'
            }
            'Use' = New-Object PSCustomObject -Property @{
                Name = 'Use'
                Function = 'EvilUSB:UsePayload'
                Description = 'Usar un payload'
            }
            'Reset' = New-Object PSCustomObject -Property @{
                Name = 'Reset'
                Function = 'EvilUSB:ManagePayloads -Reset'
                Description = 'Resetear los payloads'
            }
            'Write' = New-Object PSCustomObject -Property @{
                Name = 'Write'
                Function = 'EvilUSB:ManagePayloads -Write'
                Description = 'Escribir los payloads a nuestro dispositivo'
            }
            'Show' = New-Object PSCustomObject -Property @{
                Name = 'Show'
                Function = 'EvilUSB:ManagePayloads -Show'
                Description = 'Muestra los payloads agregados actualmente'
            }
			'Import' = New-Object PSCustomObject -Property @{
                Name = 'Import'
                Function = '$Global:Settings = (New-Object Web.Script.Serialization.JavascriptSerializer).DeserializeObject((Get-Content .\data\settings\settings.json | Out-String));Import-Module .\lib\common\functions.ps1 -Force -Verbose;EvilUSB:LoadPayloads'
                Description = 'Importa las funciones y configuraciones.'
            }

            'Cls' = New-Object PSCustomObject -Property @{
                Name = 'Cls'
                Function = 'Clear-Host'
                Description = 'Borra la pantalla'
            }
            'CheckUpdates' = New-Object PSCustomObject -Property @{
                Name = 'CheckUpdates'
                Function = 'EvilUSB:CheckVersion'
                Description = 'Comprobar si hay una nueva version disponible.'
            }
        }

        While ($true) {
            Write-Host "($($LANG[0])) > " -NoNewLine -ForegroundColor White
            <#Write-Host 'EvilUSB' -NoNewLine -ForegroundColor Red
            Write-Host '> ' -NoNewLine
            #>
            
            $Opcion = (Read-Host).Split(' ')

            if ($Global:Opciones.Keys -eq $Opcion[0] -or $Global:Aliases.Keys -eq $Opcion[0])
			{
            	#$Global:Opciones.("$($Opcion[0])").Function			
                if (('Exit', 'Quit') -eq $Opcion) {
                    IEX $Global:Opciones.Exit.Function
                    return
                } elseif ($Opcion.Length -eq 1) {
					try
					{
						IEX $Global:Opciones.("$($Opcion[0])").Function
					}
					catch
					{
						IEX $Global:Aliases.("$($Opcion[0])").Function
					}
                } else {
					try
					{
						IEX ($Global:Opciones.("$($Opcion[0])").Function + " $(($Opcion[1 .. ($Opcion.length - 1)] | Out-String).Trim())")
					}
					catch
					{
						IEX ($Global:Aliases.("$($Opcion[0])").Function + " $(($Opcion[1 .. ($Opcion.length - 1)] | Out-String).Trim())")
					}
				}
            }
			elseif ($Opcion)
			{
				EvilUSB:Print 1 'Opcion invalida'
				EvilUSB:Print 0 'Usa "Help" para obtener ayuda'
			}
        }
    }

    End { }
}

Main
