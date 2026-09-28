# Save this file and soc-bridge-alert-first-update.zip in the project root.
$ErrorActionPreference = 'Stop'
$project = (Get-Location).Path
$archive = Join-Path $project 'soc-bridge-alert-first-update.zip'
$python = Join-Path $project '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath (Join-Path $project 'pyproject.toml')) -or
    -not (Test-Path -LiteralPath $python) -or
    -not (Test-Path -LiteralPath $archive)) {
    throw 'Execute na pasta soc-bridge-investigator com pyproject.toml, .venv e o ZIP da atualizacao.'
}

Expand-Archive -LiteralPath $archive -DestinationPath $project -Force
& $python -m compileall -q '.\src\soc_bridge'
if ($LASTEXITCODE -ne 0) { throw 'Falha ao validar codigo Python atualizado.' }
& $python -m unittest discover -s tests -q
if ($LASTEXITCODE -ne 0) { throw 'Falha nos testes locais apos a atualizacao.' }
Write-Host 'Atualizacao instalada e testes OK. Feche Kiro e rode .\start-kiro-soc-bridge.ps1'
