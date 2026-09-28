# Run from soc-bridge-investigator (the folder containing pyproject.toml).
$ErrorActionPreference = 'Stop'
$project = (Get-Location).Path
$python = Join-Path $project '.venv\Scripts\python.exe'
$configPath = Join-Path $project '.kiro\settings\mcp.json'
if (-not (Test-Path -LiteralPath (Join-Path $project 'pyproject.toml')) -or
    -not (Test-Path -LiteralPath $python)) {
    throw 'Abra PowerShell na pasta soc-bridge-investigator que contem pyproject.toml e .venv.'
}
if (-not (Get-Command kiro -ErrorAction SilentlyContinue)) {
    throw 'Comando kiro nao encontrado. Abra o Kiro e instale o comando kiro no PATH, ou use a configuracao MCP no IDE.'
}

$configDir = Split-Path -Parent $configPath
if (-not (Test-Path -LiteralPath $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
}
if (Test-Path -LiteralPath $configPath) {
    $config = [System.IO.File]::ReadAllText($configPath) | ConvertFrom-Json
} else {
    $config = [pscustomobject]@{ mcpServers = [pscustomobject]@{} }
}
if ($null -eq $config.mcpServers) {
    $config | Add-Member -NotePropertyName mcpServers -NotePropertyValue ([pscustomobject]@{}) -Force
}
if ($null -eq $config.mcpServers.'soc-bridge-readonly') {
    $config.mcpServers | Add-Member -NotePropertyName 'soc-bridge-readonly' -NotePropertyValue ([pscustomobject]@{})
}
$bridge = $config.mcpServers.'soc-bridge-readonly'
$bridge | Add-Member -NotePropertyName command -NotePropertyValue $python -Force
$bridge | Add-Member -NotePropertyName args -NotePropertyValue @('-m', 'soc_bridge.kiro_server') -Force
$bridge | Add-Member -NotePropertyName autoApprove -NotePropertyValue @('investigate_demo') -Force
$bridge | Add-Member -NotePropertyName env -NotePropertyValue ([ordered]@{
    QRADAR_MCP_URL = 'http://127.0.0.1:5001/mcp'
    QRADAR_MCP_TOKEN = '${QRADAR_MCP_TOKEN}'
    TREND_VISION_ONE_API_KEY = '${TREND_VISION_ONE_API_KEY}'
    TREND_VISION_ONE_REGION = 'us'
}) -Force
$json = $config | ConvertTo-Json -Depth 20
[System.IO.File]::WriteAllText($configPath, $json + "`n", [System.Text.UTF8Encoding]::new($false))

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
    Set-TemporarySecret 'QRADAR_MCP_TOKEN' 'Token do QRadar MCP local'
    Set-TemporarySecret 'TREND_VISION_ONE_API_KEY' 'API key do Vision One'
    Write-Host 'Iniciando Kiro neste projeto. No MCP Servers, confirme soc-bridge-readonly conectado.'
    & kiro .
} finally {
    Remove-Item Env:\QRADAR_MCP_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:\TREND_VISION_ONE_API_KEY -ErrorAction SilentlyContinue
}
