# Save this file in the soc-bridge-investigator project root and run from there.
$ErrorActionPreference = 'Stop'
$python = Join-Path (Get-Location).Path '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python) -or -not (Test-Path -LiteralPath '.\pyproject.toml')) {
    throw 'Execute este script da pasta soc-bridge-investigator que contem pyproject.toml e .venv.'
}

$offenseId = Read-Host 'ID de um offense autorizado do QRadar (somente numeros)'
if ($offenseId -notmatch '^[1-9][0-9]*$') { throw 'ID de offense invalido.' }

function Set-TemporarySecret([string] $name, [string] $prompt) {
    $secret = Read-Host $prompt -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
    try {
        [Environment]::SetEnvironmentVariable($name, [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer), 'Process')
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

try {
    Set-TemporarySecret 'QRADAR_MCP_TOKEN' 'Token de acesso ao QRadar MCP local'
    Set-TemporarySecret 'TREND_VISION_ONE_API_KEY' 'API key do Vision One'
    $env:QRADAR_MCP_URL = 'http://127.0.0.1:5001/mcp'
    $env:TREND_VISION_ONE_REGION = 'us'

    $output = "reports\live-offense-$offenseId"
    & $python -m soc_bridge.cli investigate --offense $offenseId --output $output
    if ($LASTEXITCODE -ne 0) { throw 'Falha na investigacao. Confira as mensagens acima e os MCPs locais.' }
    Write-Host "Relatorios locais: $output.md e $output.json"
    Write-Host 'Esses arquivos contem dados reais do incidente. Nao os compartilhe ou publique.'
} finally {
    foreach ($name in 'QRADAR_MCP_TOKEN', 'TREND_VISION_ONE_API_KEY', 'QRADAR_MCP_URL', 'TREND_VISION_ONE_REGION') {
        Remove-Item -Path "Env:\$name" -ErrorAction SilentlyContinue
    }
}
