[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$AppleIPv4,

    [ValidateRange(1, 65535)]
    [int]$ControlPort = 51837,

    [ValidateRange(1, 65535)]
    [int]$WindowsUDPPort = 49152,

    [ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
    [string]$ExpectedServerID = '01234567-89ab-cdef-0123-456789abcdef'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$parsedAddress = [System.Net.IPAddress]::Parse($AppleIPv4)
if ($parsedAddress.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'AppleIPv4 must be an IPv4 address for the current Phase 3 fixture.'
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$probe = Join-Path $repositoryRoot 'out\build\windows-msvc\WinDevice\tools\control_probe\Debug\GhostMediaWinControlProbe.exe'
if (-not (Test-Path -LiteralPath $probe -PathType Leaf)) {
    throw "Windows probe is missing: $probe. Build with cmake --build --preset windows-msvc first."
}

$occupied = Get-NetUDPEndpoint -LocalPort $WindowsUDPPort -ErrorAction SilentlyContinue
if ($null -ne $occupied) {
    throw "Windows UDP port $WindowsUDPPort is already in use. Choose -WindowsUDPPort with a free port."
}

Write-Host "Ready to connect to $AppleIPv4`:$ControlPort using Windows UDP port $WindowsUDPPort."
Write-Host 'Do not probe the Mac TCP port first: the Apple Phase 3 harness accepts one connection only.'

& $probe `
    --connect $AppleIPv4 $ControlPort `
    --phase3-test `
    --udp-port $WindowsUDPPort `
    --expect-server-id $ExpectedServerID
exit $LASTEXITCODE
