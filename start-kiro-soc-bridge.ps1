# Start from the project root. Demo mode needs neither Docker nor credentials.
param([switch] $Live)
$ErrorActionPreference = 'Stop'
$project = $PSScriptRoot
$python = Join-Path $project '.venv\Scripts\python.exe'
$configurator = Join-Path $project 'scripts\configure_kiro.py'
if (-not (Test-Path -LiteralPath (Join-Path $project 'pyproject.toml')) -or
    -not (Test-Path -LiteralPath $python) -or
    -not (Test-Path -LiteralPath $configurator)) {
    throw 'Execute apos criar .venv e instalar o projeto; confira pyproject.toml e scripts\configure_kiro.py.'
}

& $python $configurator
if ($LASTEXITCODE -ne 0) { throw 'Falha ao configurar soc-bridge-readonly no Kiro.' }
if (-not (Get-Command kiro -ErrorAction SilentlyContinue)) {
    throw 'Comando kiro nao encontrado. Abra a pasta deste projeto no Kiro IDE; a configuracao MCP ja foi criada.'
}

function Read-TemporarySecret([string] $prompt) {
    $secret = Read-Host $prompt -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

$previous = @{}
foreach ($name in 'QRADAR_MCP_TOKEN', 'TREND_VISION_ONE_API_KEY') {
    $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    if ($Live) {
        $token = Read-TemporarySecret 'Token do QRadar MCP local (Enter se single-user sem token)'
        if ($token) { $env:QRADAR_MCP_TOKEN = $token }
        $key = Read-TemporarySecret 'API key do Vision One'
        if (-not $key) { throw 'A API key do Vision One e necessaria no modo live.' }
        $env:TREND_VISION_ONE_API_KEY = $key
    }
    Push-Location $project
    try {
        Write-Host 'No Kiro, confirme soc-bridge-readonly conectado. Teste investigate_demo primeiro.'
        & kiro .
    } finally {
        Pop-Location
    }
} finally {
    foreach ($name in $previous.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
    }
}
