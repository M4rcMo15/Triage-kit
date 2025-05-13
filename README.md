# Triage‑kit

**Minimal Windows Forensic Triage – v0.2 (MVP)**

Captura, en un solo comando, los artefactos más útiles para un análisis rápido de incidentes en sistemas Windows.

| Artefacto                  | Qué contiene                    | Archivo de salida              |
| -------------------------- | ------------------------------- | ------------------------------ |
| Prefetch                   | Historial de ejecución reciente | `output/prefetch/*.pf`         |
| Event Logs                 | Security, System, Application   | `output/eventLogs/*.evtx`      |
| Registry Hives             | SAM, SYSTEM, SECURITY           | `output/hives/*.hiv`           |
| USN Journal                | Cambios NTFS de C:\\            | `output/usn/usn_journal_C.txt` |
| Scheduled Tasks & Services | Persistencia y autostart        | `output/tasks/*.csv`           |

---

## Instalación rápida

1. **PowerShell 7.4+**: `winget install --id Microsoft.PowerShell -e`
2. Clona o descarga el repositorio:

   ```powershell
   git clone https://github.com/M4rcMo15/triage-kit.git
   cd triage-kit\windows
   ```
3. (Opcional) Firma el script o añade la carpeta a tu política de ejecución.

> ⚠️  Debes ejecutar el script en una consola *elevada* (Administrador) para acceder a todos los artefactos.

---

## Uso básico

```powershell
# Desde PowerShell 7 elevado, en la carpeta del repositorio "windows"
./triage-windows.ps1 -Verbose
```

El script ejecuta internamente **`Full-Run`**, que llama a cada módulo y genera:

* Carpeta `output/` con subcarpetas por artefacto.
---

## Requisitos

* Windows 10 / Server 2016 o superior.
* Volumen C:\ formateado en NTFS (para USN Journal).
* Cuenta Administrador o ejecución como **SYSTEM** (PsExec) si Tamper Protection de Windows Defender bloquea la adquisición de SAM/SECURITY.

---

## Licencia

Este proyecto se publica bajo la licencia **MIT**.
