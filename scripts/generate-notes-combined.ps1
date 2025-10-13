Param([string]$NotesDir = "notes")
$ErrorActionPreference = 'Stop'
function Get-FirstTitle($text){ $m = [regex]::Matches($text, '^#\s+(.+)$', 'Multiline') | Select-Object -First 1; if($m){ return $m.Groups[1].Value.Trim() } $null }
$files = Get-ChildItem -Path $NotesDir -Filter *.md | Where-Object { $_.Name -notin @('README.md','combined.md') -and -not $_.Name.StartsWith('_') } | Sort-Object Name
$out = New-Object System.Text.StringBuilder
[void]$out.AppendLine('# Birleşik Notlar')
[void]$out.AppendLine(); [void]$out.AppendLine('Aşağıda, notların tamamı tek sayfada derlenmiştir. Ayrıntılar için özgün dosyalara bakınız.'); [void]$out.AppendLine(); [void]$out.AppendLine('## İçindekiler')
foreach($f in $files){ $raw = Get-Content -Raw -Encoding UTF8 -Path $f.FullName; $title = Get-FirstTitle $raw; if(-not $title){ $title = [IO.Path]::GetFileNameWithoutExtension($f.Name).Replace('-', ' ') }; $anchor = ($title -replace '\s+', '-').ToLower(); [void]$out.AppendLine("- [$title](#$anchor)") }
[void]$out.AppendLine()
foreach($f in $files){ $raw = Get-Content -Raw -Encoding UTF8 -Path $f.FullName; $title = Get-FirstTitle $raw; if(-not $title){ $title = [IO.Path]::GetFileNameWithoutExtension($f.Name).Replace('-', ' ') }; [void]$out.AppendLine("## $title"); [void]$out.AppendLine(); [void]$out.AppendLine("Kaynak: `$($f.Name)`"); [void]$out.AppendLine(); $lines = $raw -split "`r?`n"; if($lines.Length -gt 0 -and $lines[0] -match '^#\s+'){ $raw = ($lines[1..($lines.Length-1)] -join "`n") }; [void]$out.AppendLine($raw.Trim()); [void]$out.AppendLine(); [void]$out.AppendLine('---'); [void]$out.AppendLine() }
$out.ToString() | Set-Content -Path (Join-Path $NotesDir 'combined.md') -Encoding UTF8
