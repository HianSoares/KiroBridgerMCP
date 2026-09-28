# Save in the soc-bridge-investigator folder containing pyproject.toml.
$ErrorActionPreference = 'Stop'
$path = Join-Path (Get-Location).Path 'src\soc_bridge\transports.py'
if (-not (Test-Path -LiteralPath $path) -or -not (Test-Path -LiteralPath '.\pyproject.toml')) {
    throw 'Execute este script da pasta soc-bridge-investigator que contem pyproject.toml.'
}
$source = [System.IO.File]::ReadAllText($path)
$oldError = 'result.is_error'
$newError = 'result.isError'
$oldStructured = '"structured_content"'
$newStructured = '"structuredContent"'
if (-not $source.Contains($oldError)) {
    if ($source.Contains($newError) -and $source.Contains($newStructured)) {
        Write-Host 'Correcao ja aplicada. Proximo comando: .\run-soc-bridge-live.ps1'
        exit 0
    }
    throw 'Codigo diferente do esperado. Nenhuma alteracao foi feita.'
}
if (-not $source.Contains($oldStructured)) { throw 'Codigo diferente do esperado. Nenhuma alteracao foi feita.' }
$updated = $source.Replace($oldError, $newError).Replace($oldStructured, $newStructured)
[System.IO.File]::WriteAllText($path, $updated, [System.Text.UTF8Encoding]::new($false))
Write-Host 'Correcao aplicada. Proximo comando: .\run-soc-bridge-live.ps1'
