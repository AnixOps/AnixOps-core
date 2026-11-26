# Smoke test of the device without the Agent on Windows: installs it with
# install-device-windows.ps1 against a stand-in for Control
# (mesh-device-mock-control.py, private CA from mesh-device-certs.sh), and
# checks that
#   - the device enrolls, runs as the service AnixOpsMeshDevice and reports;
#   - the state directory is open to SYSTEM and the administrators only,
#     with nothing inherited, and the service logs to device.log there;
#   - running the installer again keeps the enrolment;
#   - a revoked token stops the service, removes the token, is reported to
#     the service manager as a clean stop and is not restarted;
#   - -Uninstall removes the service and the program and keeps the state,
#     -Purge removes the state.
# Runs as Administrator (GitHub's Windows runners).
#
#   mesh-device-smoke-windows.ps1 -Binary EXE -Wintun DLL -Work DIR
#
# DIR\certs holds the output of mesh-device-certs.sh.

param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$Wintun,
    [Parameter(Mandatory = $true)][string]$Work
)

Set-StrictMode -Version 3
$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$installer = Join-Path $root "apps\mesh-node\install\install-device-windows.ps1"
$serviceName = "AnixOpsMeshDevice"
$state = Join-Path $env:ProgramData "AnixOps\Mesh\device"
$programDir = Join-Path $env:ProgramFiles "AnixOps\Mesh\device"
$bin = Join-Path $programDir "anixops-mesh.exe"
$mock = Join-Path $Work "mock"
$certs = Join-Path $Work "certs"

function Fail([string]$Message) {
    Write-Host "::error::$Message"
    $log = Join-Path $state "device.log"
    if (Test-Path -LiteralPath $log) { Get-Content -Tail 50 -LiteralPath $log }
    throw $Message
}

function Wait-For([string]$What, [int]$Seconds, [scriptblock]$Check) {
    for ($i = 0; $i -lt $Seconds; $i++) {
        if (& $Check) { return }
        Start-Sleep -Seconds 1
    }
    Fail "timed out waiting for $What"
}

function Count([string]$Kind) {
    $path = Join-Path $mock "$Kind.count"
    if (Test-Path -LiteralPath $path) { return [int](Get-Content -Raw -LiteralPath $path) }
    return 0
}

function Invoke-Installer([string[]]$Arguments) {
    & pwsh -NoProfile -File $installer @Arguments
    if ($LASTEXITCODE -ne 0) { Fail "the installer failed ($LASTEXITCODE)" }
}

New-Item -ItemType Directory -Force -Path $mock | Out-Null
# The workflow makes the certificates first (mesh-device-certs.sh, in Git
# Bash): `bash` from here could be another one.
if (-not (Test-Path -LiteralPath (Join-Path $certs "leaf.pem"))) { Fail "no certificates in $certs" }
$server = Start-Process -PassThru -NoNewWindow python -ArgumentList @(
    (Join-Path $root ".github\scripts\mesh-device-mock-control.py"),
    "--cert", (Join-Path $certs "leaf.pem"), "--key", (Join-Path $certs "leaf.key"), "--dir", $mock)
try {
    Wait-For "the mock Control" 20 { Test-Path -LiteralPath (Join-Path $mock "port") }
    $control = "https://localhost:" + (Get-Content -Raw -LiteralPath (Join-Path $mock "port")).Trim()
    $binarySha = (Get-FileHash -Algorithm SHA256 -LiteralPath $Binary).Hash
    $wintunSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $Wintun).Hash
    $credential = Join-Path $Work "credential"
    [IO.File]::WriteAllText($credential, "mse_ci-smoke`n")

    Write-Host "::group::Install and enroll"
    Invoke-Installer @("-BinaryFile", $Binary, "-BinarySha256", $binarySha,
        "-WintunFile", $Wintun, "-WintunSha256", $wintunSha,
        "-Control", $control, "-TokenFile", $credential,
        "-Latency", "cn=30", "-CaFile", (Join-Path $certs "ca.pem"))
    Write-Host "::endgroup::"
    if ((Count "enroll") -ne 1) { Fail "the device did not enroll" }
    if ((Get-Service -Name $serviceName).Status -ne "Running") { Fail "the service is not running" }
    if (Test-Path -LiteralPath (Join-Path $state "enroll-credential.tmp")) { Fail "the credential file was left behind" }

    # Open to SYSTEM and the administrators only, nothing inherited.
    $acl = Get-Acl -LiteralPath $state
    if (-not $acl.AreAccessRulesProtected) { Fail "the state directory inherits entries" }
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if (@("S-1-5-18", "S-1-5-32-544") -notcontains $sid) { Fail "the state directory is open to $sid" }
    }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (@("S-1-5-18", "S-1-5-32-544") -notcontains $owner) { Fail "the state directory belongs to $owner" }

    $status = (& $bin device-status --state-dir $state) -join "`n"
    if ($LASTEXITCODE -ne 0) { Fail "device-status failed" }
    Write-Host $status
    $parsed = $status | ConvertFrom-Json
    if (-not $parsed.ok -or $parsed.device.device_id -ne 5) { Fail "unexpected status" }
    if (@($parsed.mesh.networks).Count -ne 0) { Fail "unexpected networks" }
    if ($status -match "msd_|mse_") { Fail "a token in the status" }
    Wait-For "the first report" 30 { (Count "report") -ge 1 }
    Wait-For "control_state ok" 10 { ((& $bin device-status --state-dir $state) -join "") -match '"control_state":"ok"' }
    if (-not (Test-Path -LiteralPath (Join-Path $state "device.log"))) { Fail "the service wrote no device.log" }

    Write-Host "::group::Install again"
    Invoke-Installer @("-BinaryFile", $Binary, "-BinarySha256", $binarySha,
        "-WintunFile", $Wintun, "-WintunSha256", $wintunSha)
    Write-Host "::endgroup::"
    if ((Count "enroll") -ne 1) { Fail "an enrolled device enrolled again" }
    if ((Get-Service -Name $serviceName).Status -ne "Running") { Fail "the service is not running after the second install" }

    Write-Host "::group::Revoked token"
    New-Item -ItemType File -Path (Join-Path $mock "revoke") | Out-Null
    # Started without waiting: it stops again at once.
    Stop-Service -Name $serviceName -Force
    & sc.exe start $serviceName | Out-Null
    Wait-For "the token to go" 20 { -not (Test-Path -LiteralPath (Join-Path $state "token")) }
    Wait-For "the service to stop" 20 { (Get-Service -Name $serviceName).Status -eq "Stopped" }
    # Longer than the restart delay of the recovery actions.
    Start-Sleep -Seconds 15
    if ((Get-Service -Name $serviceName).Status -ne "Stopped") { Fail "the service was started again without a token" }
    $query = (& sc.exe query $serviceName) -join "`n"
    Write-Host $query
    if ($query -notmatch "WIN32_EXIT_CODE\s+:\s+0\s") { Fail "the refused token was not reported as a clean stop" }
    & $bin device-status --state-dir $state | Out-Null
    if ($LASTEXITCODE -ne 1) { Fail "device-status answered with the service stopped" }
    Write-Host "::endgroup::"

    Write-Host "::group::Uninstall"
    Invoke-Installer @("-Uninstall")
    if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { Fail "the service is still there" }
    if (Test-Path -LiteralPath $programDir) { Fail "the program is still there" }
    if (-not (Test-Path -LiteralPath (Join-Path $state "device.json"))) { Fail "the device identity was not kept" }
    Invoke-Installer @("-Uninstall", "-Purge")
    if (Test-Path -LiteralPath $state) { Fail "-Purge kept the state directory" }
    Write-Host "::endgroup::"
    Write-Host "Windows device smoke test passed"
}
finally {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    & pwsh -NoProfile -File $installer -Uninstall -Purge *> $null
}
