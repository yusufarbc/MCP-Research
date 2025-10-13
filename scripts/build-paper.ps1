Param(
  [switch]$Open
)
$ErrorActionPreference = 'Stop'
Push-Location "$PSScriptRoot/..\paper"
try {
  Write-Host "Building paper/main.tex with latexmk..."
  latexmk -pdf -interaction=nonstopmode -synctex=1 main.tex
  if ($LASTEXITCODE -ne 0) { throw "latexmk failed with exit code $LASTEXITCODE" }
  if ($Open) {
    $pdf = Join-Path (Get-Location) 'main.pdf'
    if (Test-Path $pdf) { Start-Process $pdf }
  }
}
finally {
  Pop-Location
}

