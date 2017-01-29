$foldertocopy = "#Destination"

$rutasarchivosacopiar = @(#Paths)

if (!(Test-Path $foldertocopy))
{
	New-Item -Path $foldertocopy -ItemType Directory
}

Set-Location $foldertocopy

foreach ($ruta in $rutasarchivosacopiar)
{
	if (Test-Path $ruta.Path)
	{
		try
		{
			$extensions = $ruta.Extensions.Split(' ')
			if ($ruta.Recurse)
			{
				if ($extensions.Length -eq 1)
				{
					$archivosacopiar = Get-ChildItem -Path $ruta.Path -Filter ("*" + $ruta.Extensions) -Recurse -Force
				}
				else
				{
					$archivosacopiar = Get-ChildItem -Path $ruta.Path -Recurse -Force | ? { [Bool]($extensions -eq $_.Extension) }
				}
			}
			else
			{
				if ($extensions.Length -eq 1)
				{
					$archivosacopiar = Get-ChildItem -Path $ruta.Path -Filter ("*" + $ruta.Extensions) -Force
				}
				else
				{
					$archivosacopiar = Get-ChildItem -Path $ruta.Path -Force | ? { [Bool]($extensions -eq $_.Extension) }
				}
			}
			
			foreach ($archivo in $archivosacopiar)
			{
				if ($ruta.Path.Length -eq $archivo.FullName.Length)
				{
					$directoriodestino = Join-Path $PWD (Split-Path -Path $Archivo.FullName -Parent).Remove(0,3).Replace('\','_')
				}
				else
				{
					$directoriodestino = Join-Path $PWD (Join-Path ($Ruta.Path).Remove(0,3).Replace('\','_') (Split-Path -Path $Archivo.FullName -Parent).Remove(0,($Ruta.Path).Length))
				}
				
				if (!(Test-Path $directoriodestino))
				{
					New-Item -Path $directoriodestino -ItemType Directory
				}
				
				Copy-Item -Path $archivo.FullName -Destination $directoriodestino -Recurse -Force
			}
		}
		catch
		{
			Write-Host $Error[0].Exception -ForegroundColor Yellow
		}
	}
}