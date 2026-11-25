# One-command installer of the intranet mesh node for Windows.
#
#   install-windows.ps1 -BinaryUrl URL -BinarySha256 HEX
#                       [-ProfileUrl URL -ProfileSha256 HEX]
#                       [-Config FILE] [-Address CIDR] [-AllowUnencrypted]
#                       [-AcceptConfirmations] [-DryRun]
#   install-windows.ps1 -Uninstall
#
# Run as Administrator. The panel generates the command with the exact URLs
# and SHA-256 values, so every download is checked before it runs. The
# node runs as the Windows service AnixOpsMesh. With a takeover profile the
# script imports the existing installation and only takes it over when this
# build can run the node; if our service fails to start, the takeover is
# rolled back. See docs/deploy/mesh-node.md.

[CmdletBinding()]
param(
    [string]$BinaryUrl = "",
    [string]$BinarySha256 = "",
    [string]$ProfileUrl = "",
    [string]$ProfileSha256 = "",
    [string]$Config = "",
    [string]$Address = "",
    [switch]$AllowUnencrypted,
    [switch]$AcceptConfirmations,
    [switch]$DryRun,
    [switch]$Uninstall
)

Set-StrictMode -Version 3
$ErrorActionPreference = "Stop"

$ServiceName = "AnixOpsMesh"
$ProgramDir = Join-Path $env:ProgramFiles "AnixOps\Mesh"
$Bin = Join-Path $ProgramDir "anixops-mesh.exe"
$DataDir = Join-Path $env:ProgramData "AnixOps\Mesh"
$State = Join-Path $DataDir "state"
$ConfigPath = Join-Path $DataDir "mesh.json"
$ProfilePath = Join-Path $DataDir "takeover-profile.json"

function Fail([string]$Message) {
    Write-Error "anixops-mesh: $Message" -ErrorAction Continue
    exit 1
}

function Say([string]$Message) {
    Write-Host "anixops-mesh: $Message"
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "run as Administrator"
}

# Owned by the administrators and open to them and the system only: the
# configuration holds the network secret and the state holds what a
# rollback starts. Any user may create folders in ProgramData, so one that
# already exists must not be a link and must belong to the administrators,
# the system or the installer service; its access list is then replaced,
# not added to, with inheritance off. The program checks the same before
# it reads or writes its state.
$TrustedOwners = @("S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
function Protect-Directory([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "$Path is a link or junction; remove it and run again" }
        if (-not $item.PSIsContainer) { Fail "$Path is not a directory" }
        $owner = (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($TrustedOwners -notcontains $owner) { Fail "$Path belongs to $owner, not to the administrators or the system; remove it and run again" }
    } else {
        # Fails if someone creates it in between.
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
    $admins = New-Object Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $system = New-Object Security.Principal.SecurityIdentifier("S-1-5-18")
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($admins)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($system, $admins)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Stop-Ours {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $ServiceName | Out-Null
    }
}

function Invoke-Rollback {
    if ((Test-Path $Bin) -and (Test-Path (Join-Path $State "takeover\takeover.json"))) {
        Say "restoring the programs that were taken over"
        & $Bin rollback --state-dir (Join-Path $State "takeover") --report (Join-Path $State "rollback-report.json") | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail "rollback incomplete; see $State\rollback-report.json" }
    }
}

if ($Uninstall) {
    Stop-Ours
    Invoke-Rollback
    Say "removed the service; configuration kept in $DataDir"
    exit 0
}

if (-not $BinaryUrl -or -not $BinarySha256) { Fail "-BinaryUrl and -BinarySha256 are required" }
if ($ProfileUrl -and -not $ProfileSha256) { Fail "-ProfileSha256 is required with -ProfileUrl" }

$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -ne "AMD64" -and $arch -ne "ARM64") { Fail "unsupported architecture $arch" }

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Get-Download([string]$Url, [string]$Path, [string]$Sha256, [string]$What) {
    if (-not $Url.StartsWith("https://")) { Fail "only https downloads are allowed" }
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Path
    $actual = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256.ToLowerInvariant()) { Fail "checksum mismatch for $What" }
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("anixops-mesh-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    Say "downloading the program"
    $download = Join-Path $work "anixops-mesh.exe"
    Get-Download $BinaryUrl $download $BinarySha256 "the program"
    $capabilities = & $download capabilities
    if ($LASTEXITCODE -ne 0) { Fail "the downloaded program does not run here" }
    $canRun = ($capabilities -join "`n") -match '"run"'

    Protect-Directory (Split-Path -Parent $DataDir)
    Protect-Directory $DataDir
    Protect-Directory $State

    $imported = ""
    if ($ProfileUrl) {
        Say "downloading the takeover profile"
        $profileDownload = Join-Path $work "profile.json"
        Get-Download $ProfileUrl $profileDownload $ProfileSha256 "the takeover profile"
        $importDir = Join-Path $work "imported"
        $importReport = Join-Path $work "import-report.json"
        $importArgs = @("import", "--profile", $profileDownload, "--out-dir", $importDir, "--report", $importReport)
        if ($Address) { $importArgs += @("--address", $Address) }
        if ($AllowUnencrypted) { $importArgs += "--allow-unencrypted" }
        & $download @importArgs | Out-Null
        $status = $LASTEXITCODE
        Copy-Item -Force $importReport (Join-Path $State "import-report.json")
        switch ($status) {
            0 { }
            3 { Say "no existing installation found" }
            5 {
                if (-not $AcceptConfirmations) {
                    Fail "the import needs confirmation; review $State\import-report.json, then rerun with -AcceptConfirmations"
                }
            }
            6 { Fail "this machine cannot be migrated automatically; see $State\import-report.json" }
            default { Fail "the import failed ($status); see $State\import-report.json" }
        }
        if ($status -ne 3) {
            $files = @(Get-ChildItem -Path $importDir -Filter "*.json" -File)
            if ($files.Count -ne 1) { Fail "found $($files.Count) networks on this machine; one node per network is not supported yet" }
            $imported = $files[0].FullName
        }
    }

    if ($Config -and $imported) { Fail "-Config and an imported configuration are both present; give one" }
    $sourceConfig = if ($Config) { $Config } else { $imported }
    if (-not $sourceConfig -and -not (Test-Path $ConfigPath)) { Fail "no configuration: pass -Config or a takeover profile" }

    # The takeover's own checks, before anything is installed: a process it
    # could not put back on rollback refuses the takeover.
    if ($ProfileUrl -and $canRun) {
        $check = Join-Path $work "takeover-check.json"
        & $download takeover --profile $profileDownload --state-dir (Join-Path $State "takeover") --dry-run --report $check | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Copy-Item -Force $check (Join-Path $State "takeover-check.json")
            Fail "the takeover would be refused; see $State\takeover-check.json"
        }
    }

    if ($DryRun) {
        Say "dry run: checks passed; nothing was changed"
        if ($ProfileUrl) {
            & $download takeover --profile $profileDownload --state-dir (Join-Path $State "takeover") --dry-run
        }
        exit 0
    }

    New-Item -ItemType Directory -Force -Path $ProgramDir | Out-Null
    Copy-Item -Force $download $Bin
    if ($ProfileUrl) { Copy-Item -Force $profileDownload $ProfilePath }
    if ($sourceConfig) { Copy-Item -Force $sourceConfig $ConfigPath }

    if (-not $canRun) {
        Say "installed the program and the configuration; this build cannot run the node yet, so nothing was taken over or started"
        exit 0
    }

    Stop-Ours
    $command = "`"$Bin`" run --config `"$ConfigPath`""
    New-Service -Name $ServiceName -DisplayName "AnixOps Mesh" -BinaryPathName $command -StartupType Automatic | Out-Null
    # Restarted after a failure, five seconds apart.
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null

    if ($ProfileUrl) {
        Say "taking over the existing installation"
        & $Bin takeover --profile $ProfilePath --state-dir (Join-Path $State "takeover") --report (Join-Path $State "takeover-report.json") | Out-Null
        $status = $LASTEXITCODE
        if ($status -ne 0) {
            Stop-Ours
            if ($status -eq 7) {
                Fail "takeover failed and could not be fully undone; see $State\takeover-report.json, then run: & '$Bin' rollback --state-dir '$State\takeover'"
            }
            Fail "takeover failed or was refused; nothing it changed is left changed; see $State\takeover-report.json"
        }
    }

    $started = $true
    try { Start-Service -Name $ServiceName } catch { $started = $false }
    Start-Sleep -Seconds 5
    if ((Get-Service -Name $ServiceName).Status -ne "Running") { $started = $false }

    if (-not $started) {
        Say "the node did not start; restoring the previous state"
        Stop-Ours
        if ($ProfileUrl) { Invoke-Rollback }
        Fail "installation failed; see the AnixOpsMesh service in the event log"
    }
    Say "installed and running"
}
finally {
    Remove-Item -Recurse -Force -Path $work -ErrorAction SilentlyContinue
}
