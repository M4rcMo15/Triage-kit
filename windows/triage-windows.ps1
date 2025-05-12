##### ───────────── Banner ─────────────
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
##### ────────── Fin Banner ────────────

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
    $isAdmin = Test-Privileges
    if (-not $isAdmin) {
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
            Copied      = $files.Count
            Duration_ms = $sw.ElapsedMilliseconds
            Destination = $destPath.Path
        }
    }
}

# Ejemplo
$result = Save-PrefetchFile .\output\prefetch -Verbose
$result

