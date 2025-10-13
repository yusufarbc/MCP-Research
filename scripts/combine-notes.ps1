Param(
  [string[]]$Files = @(
    'notes/literatur.md',
    'notes/protokol-arastirmasi.md',
    'notes/google-arastirmasi.md',
    'notes/x-arastirmasi.md'
  ),
  [string]$OutFile = 'notes/combined.md'
)

$ErrorActionPreference = 'Stop'

function Get-TitleAndContent {
  param([string]$Path)
  $raw = Get-Content -Raw -Encoding UTF8 -Path $Path
  $lines = $raw -split "`r?`n"
  if ($lines.Length -gt 0 -and ($lines[0] -match '^#\s+(.+)$')) {
    $title = $Matches[1].Trim()
    $content = ($lines[1..($lines.Length-1)] -join "`r`n")
  } else {
    $title = [IO.Path]::GetFileNameWithoutExtension($Path).Replace('-', ' ')
    $content = $raw
  }
  return [pscustomobject]@{ Title=$title; Content=$content; File=[IO.Path]::GetFileName($Path) }
}

function Make-Anchor {
  param([string]$Title)
  $a = ($Title -replace '\s+', '-')
  $a = ($a -replace '[^A-Za-z0-9\-]', '')
  return $a.ToLower()
}

$sections = @()
foreach ($f in $Files) {
  if (Test-Path $f) { $sections += Get-TitleAndContent -Path $f }
}

if (-not $sections) { Write-Error 'No notes found to combine.' }

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('# Birlesik Notlar')
[void]$sb.AppendLine()
[void]$sb.AppendLine('Asagida, notlarin tamami tek sayfada derlenmistir. Ayrintilar icin orijinal dosyalara bakiniz.')
[void]$sb.AppendLine()
[void]$sb.AppendLine('## Icindekiler')
foreach ($s in $sections) {
  $anchor = Make-Anchor $s.Title
  [void]$sb.AppendLine("- [$($s.Title)](#$anchor)")
}
[void]$sb.AppendLine()

foreach ($s in $sections) {
  $anchor = Make-Anchor $s.Title
  [void]$sb.AppendLine("## $($s.Title)")
  [void]$sb.AppendLine()
  [void]$sb.AppendLine("Kaynak: `$($s.File)`")
  [void]$sb.AppendLine()
  [void]$sb.AppendLine(($s.Content).Trim())
  [void]$sb.AppendLine()
  [void]$sb.AppendLine('---')
  [void]$sb.AppendLine()
}

$destDir = Split-Path -Parent $OutFile
if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir | Out-Null }
$sb.ToString() | Set-Content -Encoding UTF8 -Path $OutFile
Write-Host "Generated $OutFile"
