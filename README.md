# Triage‑kit

*Forensic triage toolkit – versión **MVP Windows Prefetch***

---

## ¿Qué hace?

Actualmente la herramienta copia de forma segura todos los archivos **Prefetch (\*.pf)** de Windows a una carpeta que elijas, comprobando:

* Privilegios de administrador (imprescindible para acceder a `C:\Windows\Prefetch`).
* Que el **Prefetcher** esté habilitado.
* Manejo de errores (ruta de destino, permisos, etc.).
* Métricas devueltas (nº de archivos, duración, destino).

Cada ejecución muestra un banner ASCII **m4rcmo15** al inicio para que sepas que estás usando Triage‑kit.

---

## Requisitos rápidos

| Sistema    | Versión mínima   |
| ---------- | ---------------- |
| Windows    | 10 / Server 2016 |
| PowerShell | 7.4 LTS (pwsh)   |

> Instala PowerShell 7 con Winget:
>
> ```powershell
> winget install --id Microsoft.PowerShell --source winget
> ```

---

## Instalación

```powershell
# 1. Clona el repositorio
git clone https://github.com/M4rcMo15/triage-kit.git
cd triage-kit\windows

# 2. (Opcional) Revisa el código y firma si lo deseas

# 3. Ejecuta el script
pwsh -File .\triage-windows.ps1
```

---

## Uso básico

### 1. Cargar la función en tu sesión

```powershell
. .\triage-windows.ps1   # «dot‑source»
```

### 2. Ejecutar la recolección

```powershell
Save-PrefetchFile -Destination .\output\prefetch -Verbose
```

Parámetros útiles:

* **-Destination**  Carpeta donde se guardarán los archivos .pf.
* **-WhatIf / -Confirm**  (gracias a SupportsShouldProcess).
* **-Verbose**  Muestra archivos copiados en tiempo real.

> El comando devuelve un objeto con métricas; p.ej. `($result).Copied`.

---

## Salida esperada

```
[+] Collecting Prefetch files...
[+] Copiados 87 archivos .pf a 'C:\triage-kit\windows\output\prefetch'.

Artifact  Copied Duration_ms Destination                                
--------  ------ ----------- -----------                                
Prefetch  87     183         C:\triage-kit\windows\output\prefetch
```

---

## Preguntas frecuentes

* **¿Por qué necesito ser administrador?**  El directorio Prefetch está protegido por ACLs de sistema.
* **¿Qué pasa si copié 0 archivos?**  Puede que el servicio Prefetcher esté deshabilitado (`EnablePrefetcher=0`).

---

## Licencia

MIT. Consulta `LICENSE` para más detalles.

---

¡Contribuciones, issues y PRs son bienvenidos! Abre un issue si encuentras un bug o tienes ideas de nuevos artefactos.
