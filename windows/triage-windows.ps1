function Show-Banner {
    param(
        [string]$Text = 'm4rcmo15'
    )
    $banner = @'

                /$$   /$$                                                   /$$    /$$$$$$$ 
               | $$  | $$                                                 /$$$$   | $$____/ 
 /$$$$$$/$$$$  | $$  | $$   /$$$$$$    /$$$$$$$  /$$$$$$/$$$$    /$$$$$$ |_  $$   | $$      
| $$_  $$_  $$ | $$$$$$$$  /$$__  $$  /$$_____/ | $$_  $$_  $$  /$$__  $$  | $$   | $$$$$$$ 
| $$ \ $$ \ $$ |_____  $$ | $$  \__/ | $$       | $$ \ $$ \ $$ | $$  \ $$  | $$   |_____  $$
| $$ | $$ | $$       | $$ | $$       | $$       | $$ | $$ | $$ | $$  | $$  | $$    /$$  \ $$
| $$ | $$ | $$       | $$ | $$       |  $$$$$$$ | $$ | $$ | $$ |  $$$$$$/ /$$$$$$ |  $$$$$$/
|__/ |__/ |__/       |__/ |__/        \_______/ |__/ |__/ |__/  \______/ |______/  \______/ 
                                                                                     
                                                                                     
                                                                                     

'@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host
}
Show-Banner

# Función para verificar privilegios de administración
function Test-Privileges {
    [cmdletBinding(SupportsShouldProcess=$true)]
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    return $isAdmin
}

#Función para extraer archivos de prefetch.
#Argumentos de entrada: $Destination (Ruta de volcado de archivos *.pf)
function Save-PrefetchFile {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Destination
    )

    # 1) Privilegios
    if (-not (Test-Privileges)) {
        Write-Warning "[!] Necesitas ejecutar la consola como Administrador."
        return
    }

    # 1.b) Prefetch habilitado
    $pfEnabled = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher -ErrorAction SilentlyContinue).EnablePrefetcher
    if ($pfEnabled -eq 0) {
        Write-Warning "[!] El Prefetcher está deshabilitado (EnablePrefetcher=0). No hay archivos que copiar."
        return
    }

    # 2) Carpeta destino
    try {
        $destPath = Resolve-Path (New-Item -ItemType Directory -Path $Destination -Force -ErrorAction Stop)
    } catch {
        Write-Error "[!] No se pudo preparar '$Destination': $($_.Exception.Message)"
        return
    }

    # 3) Copia
    if ($PSCmdlet.ShouldProcess($destPath, 'Copy Prefetch files')) {

        $sw     = [Diagnostics.Stopwatch]::StartNew()
        $files  = @()

        try {
            $files = Copy-Item -Path "$Env:SystemRoot\Prefetch\*.pf" `
                               -Destination $destPath `
                               -Recurse -Force -ErrorAction Stop
        }
        catch [System.UnauthorizedAccessException] {
            Write-Error "[!] Acceso denegado a '$Env:SystemRoot\Prefetch'."
            return
        }
        catch {
            Write-Error "[!] Error inesperado: $($_.Exception.Message)"
            return
        }
        finally {
            $sw.Stop()
        }

        # 4) Salida estructurada
        [PSCustomObject]@{
            Artifact    = 'Prefetch'
            Copied      = (Get-ChildItem $destPath -Filter *.pf).Count
            Duration_ms = $sw.ElapsedMilliseconds
            Destination = $destPath.Path
        }
    }
}

function Save-EventLogs {
    <#
        Exporta logs de eventos seleccionados en formato .evtx
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Destination,
        [string[]]$LogName = @('Security','System','Application')
    )

    # 1) privilegios admin
    if (-not (Test-Privileges)) {
        Write-Warning '[!] Ejecuta como administrador para exportar Event Logs.'
        return
    }

    # 2) carpeta de destino
    try {
        $destPath = Resolve-Path (New-Item -ItemType Directory -Path $Destination -Force -ErrorAction Stop)
    } catch {
        Write-Error "[!] No se pudo preparar '$Destination': $($_.Exception.Message)"
        return
    }

    # 3) exportación
    foreach ($log in $LogName) { 
        try {
            $outFile = Join-Path $destPath \"${log}.evtx"
        } catch {
            Write-Error "[!] No se pudo crear '$outFile': $($_.Exception.Message)"
            return
        }

        if ($PSCmdlet.ShouldProcess($outFile,'Export log')) {
            try{
                wevtutil epl $log $outFile /ow:true 2>&1 | Write-Verbose
            } catch {
                Write-Error "[!] Error inesperado: $($_.Exception.Message)"
                return
            }
        }
    }
    # 4) devuelve métricas para el manifest/log 
    [PScustomObject]@{
        Artifact = 'EventLogs'
        Logs     = $LogName -join ','
        Files    = (Get-ChildItem $destPath -Filter *.evtx).Count
        Path     = $destPath.Path
    }

}


function Save-RegistryHives {
    <#
        Exporta SAM, SYSTEM y SECURITY a ficheros .hiv
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Destination
    )

    # 1) privilegios
    if (-not (Test-Privileges)) {
        Write-Warning '[!] Ejecuta como Administrador para guardar los hives.'
        return
    }

    # 2) carpeta destino
    $destPath = (Resolve-Path (New-Item -ItemType Directory -Path $Destination -Force)).Path

    # 3) tabla hives
    $hives = @{
        'HKLM\SAM'      = 'sam.hiv'
        'HKLM\SYSTEM'   = 'system.hiv'
        'HKLM\SECURITY' = 'security.hiv'
    }

    # 4) recorrido
    foreach ($key in $hives.Keys) {
        $file = Join-Path $destPath $hives[$key]

        if ($PSCmdlet.ShouldProcess($file,'Save hive')) {
            & reg.exe save $key $file /y 2>&1 | Write-Verbose
        }
    }

    # 5) métricas
    [pscustomobject]@{
        Artifact = 'RegistryHives'
        Files    = ($hives.Values) -join ','
        Path     = $destPath
    }
}

function Save-USNJournal {
    <#
        Exporta el USN Change Journal de C: a un fichero .txt
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Destination
    )

    # 1) Requisitos
    if (-not (Test-Privileges)){
        Write-Warning '[!] Ejecuta como administrador para leer el USN Journal.'
        return
    }

    if ((Get-Volume -DriveLetter C).FileSystem -ne 'NTFS') {
        Write-Warning '[!] La unidad C: no usa NTFS; No hay USN Journal que capturar'
        return
    }

    # 2) Preparar carpeta destino
    $destPath = (Resolve-Path (New-Item -ItemType Directory -Path $Destination -Force)).Path
    $outFile = Join-Path $destPath 'usn_journal_C.txt'

    # 3) Exportación
    if ($PSCmdlet.ShouldProcess($outFile,'Save USN Journal')) {
        
        $sw = [Diagnostics.StopWatch]::StartNew()
        try {
            & fsutil usn readjournal C: $null 2>&1 | Out-File -FilePath $outFile -Encoding utf8
        } catch {
            Write-Error "[!] Error al leer el USN Journal: $($_.Exception.Message)"
            return 
        } finally {
            $sw.Stop()
        }

        # 4) Objeto de Salida
        return [PScustomObject]@{
            Artifact = 'USNJournal'
            File = $outFile
            Size_MB = [math]::Round((Get-Item $outFile).Lenght / 1MB,2)
            Duration_ms = $sw.ElapsedMilliseconds
            Path = $destPath
        }
    }
}


function Save-ScheduledAndServices {
    <#
        Exporta lista completa de tareas programadas y servicios instalados.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Destination
    )

    # 1) Privilegios: no es obligatorio ser Admin, pero ciertos
    #    servicios/tareas (e.g. WinRM) muestran más datos con elevación.
    $isAdmin = Test-Privileges
    if (-not $isAdmin) {
        Write-Verbose 'Ejecutando sin privilegios elevados: algunos campos podrían aparecer vacíos.'
    }

    # 2) Crear carpeta destino
    $destPath = (Resolve-Path (New-Item -ItemType Directory -Path $Destination -Force)).Path
    $sw       = [Diagnostics.Stopwatch]::StartNew()

    # ---------- 3) Scheduled Tasks ----------
    $tasksFile = Join-Path $destPath 'scheduled_tasks.csv'

    if ($PSCmdlet.ShouldProcess($tasksFile,'Export Scheduled Tasks')) {
        Get-ScheduledTask |
          Select-Object TaskName,TaskPath,State,Author,Description,`
                        @{N='Action';E={($_.Actions).Execute}},
                        @{N='Trigger';E={($_.Triggers | Select-Object -First 1).StartBoundary}},
                        LastRunTime,NextRunTime |
          Export-Csv -NoTypeInformation -Encoding UTF8 -Path $tasksFile
    }

    # ---------- 4) Windows Services ----------
    $svcFile = Join-Path $destPath 'services.csv'

    if ($PSCmdlet.ShouldProcess($svcFile,'Export Services')) {
        Get-Service |
          Select-Object Name,DisplayName,Status,StartType,`
                        @{N='Path';E={(Get-CimInstance Win32_Service -Filter \"Name='$_'\" -ErrorAction SilentlyContinue).PathName}} |
          Export-Csv -NoTypeInformation -Encoding UTF8 -Path $svcFile
    }

    $sw.Stop()

    # 5) Salida estructurada
    [pscustomobject]@{
        Artifact    = 'TasksServices'
        TasksFile   = $tasksFile
        ServicesFile= $svcFile
        Duration_ms = $sw.ElapsedMilliseconds
        Path        = $destPath
    }
}

function Full-Run {
    # Prefetch Files
    $prefetch = Save-PrefetchFile .\output\prefetch -Verbose
    $prefetch | Format-Table -AutoSize

    # Event Logs
    $evtLogs = Save-EventLogs .\output\eventLogs -Verbose
    $evtLogs | Format-Table -Autosize

    $regHives = Save-RegistryHives .\output\regHives -Verbose
    $regHives | Format-Table -Autosize

    $usnJournal = Save-USNJournal .\output\usnJournal -Verbose
    $usnJournal | Format-Table -Autosize

    $tasksAndServices = Save-ScheduledAndServices .\output\scheduledTasksServices 
    $tasksAndServices | Format-Table -Autosize

}

Full-Run
