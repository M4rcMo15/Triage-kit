function Collect-Prefetch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Destination
    )
    
    Begin { New-Item -ItemType Directory -Path $Destination -ErrorAction SilentlyContinue }
    Process {
        Copy-Item -Path "$Env:SystemRoot\Prefetch\*.pf" `
                  -Destination $Destination `
                  -Recurse -Force -ErrorAction Continue
    }
}
