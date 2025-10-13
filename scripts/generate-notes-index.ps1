Param(
  [string]$NotesDir = "notes"
)
$ErrorActionPreference = 'Stop'
function Get-FirstMatch($text, [string]$pattern){
  $m = [regex]::Matches($text, $pattern, 'Multiline') | Select-Object -First 1
  if($m){ return $m.Groups[1].Value.Trim() } else { return $null }
}
function Get-FirstParagraph($text){
  $lines = $text -split "`r?`n"
  $i = 0
  while($i -lt $lines.Length -and ($lines[$i] -match '^\s*$' -or $lines[$i] -match '^#')){ $i++ }
  $buf = New-Object System.Collections.Generic.List[string]
  while($i -lt $lines.Length -and $lines[$i] -notmatch '^\s*$'){
    $buf.Add($lines[$i]); $i++
  }
  ($buf -join ' ').Trim()
}
$files = Get-ChildItem -Path $NotesDir -Filter *.md | Where-Object { $_.Name -notin @('README.md','combined.md') -and -not $_.Name.StartsWith('_') } | Sort-Object Name
$items = @()
foreach($f in $files){
  $raw = Get-Content -Raw -Encoding UTF8 -Path $f.FullName
  $title = Get-FirstMatch $raw '^#\s+(.+)$'; if(-not $title){ $title = [IO.Path]::GetFileNameWithoutExtension($f.Name).Replace('-', ' ') }
  $tags  = Get-FirstMatch $raw '^\s*(Etiketler|Tags)\s*:\s*(.+)$'
  $para  = Get-FirstParagraph $raw
  if([string]::IsNullOrWhiteSpace($para)){ $para = $raw.Substring(0, [Math]::Min(160, $raw.Length)) }
  $summary = ($para -replace '\s+', ' ').Trim(); if($summary.Length -gt 160){ $summary = $summary.Substring(0,157) + '...' }
  $items += [pscustomobject]@{ FileName=$f.Name; Title=$title; Date=$f.LastWriteTime.ToString('yyyy-MM-dd'); Tags=$tags; Summary=$summary }
}
$out = New-Object System.Text.StringBuilder
[void]$out.AppendLine('# Notlar Dizini')
[void]$out.AppendLine()
[void]$out.AppendLine('Bu sayfa `scripts/generate-notes-index.ps1` ile otomatik üretilir. Birleşik özet için: `notes/combined.md`.')
[void]$out.AppendLine()
[void]$out.AppendLine('| Başlık | Tarih | Etiketler | Dosya |')
[void]$out.AppendLine('|---|---|---|---|')
foreach($it in $items){
  $link = "[${($it.Title)}](./$($it.FileName))"; $tags = if($it.Tags){ $it.Tags } else { '' }
  [void]$out.AppendLine("| $link | $($it.Date) | $tags | `$($it.FileName)` |")
  [void]$out.AppendLine()
  [void]$out.AppendLine("> $($it.Summary)")
  [void]$out.AppendLine()
}
$out.ToString() | Set-Content -Path (Join-Path $NotesDir 'README.md') -Encoding UTF8
