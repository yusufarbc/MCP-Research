$ErrorActionPreference = 'Stop'
Push-Location "$PSScriptRoot/..\paper"
try {
  Write-Host "Cleaning LaTeX build artifacts..."
  latexmk -C
}
finally {
  Pop-Location
}

