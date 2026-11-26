# Installer of the mesh device without the Agent for Windows
# (docs/deploy/mesh-device.md).
#
#   install-device-windows.ps1 (-BinaryUrl URL | -BinaryFile FILE) -BinarySha256 HEX
#                              (-WintunUrl URL | -WintunFile FILE) -WintunSha256 HEX
#                              -Control URL [-TokenFile FILE]
#                              [-Latency CODE=MS,...] [-CaFile FILE]
#   install-device-windows.ps1 -Uninstall [-Purge]
#
# Places the program and wintun.dll, enrolls the device with the one-time
# credential and starts it as the Windows service AnixOpsMeshDevice
# (LocalSystem). The credential is read from -TokenFile, or asked for on
# the console; it never goes on a command line. A device already enrolled
# (its state directory holds a token) is not enrolled again: the program is
# replaced and the service restarted. -Uninstall stops and deletes the
# service and removes the program, and keeps the state directory (the
# device identity) unless -Purge is given. Run as Administrator.

[CmdletBinding()]
param(
    [string]$BinaryUrl = "",
    [string]$BinaryFile = "",
    [string]$BinarySha256 = "",
    [string]$WintunUrl = "",
    [string]$WintunFile = "",
    [string]$WintunSha256 = "",
    [string]$Control = "",
    [string]$TokenFile = "",
    [string[]]$Latency = @(),
    [string]$CaFile = "",
    [switch]$Uninstall,
    [switch]$Purge
)

Set-StrictMode -Version 3
$ErrorActionPreference = "Stop"

$ServiceName = "AnixOpsMeshDevice"
$ProgramDir = Join-Path $env:ProgramFiles "AnixOps\Mesh\device"
$Bin = Join-Path $ProgramDir "anixops-mesh.exe"
$DataDir = Join-Path $env:ProgramData "AnixOps\Mesh"
$State = Join-Path $DataDir "device"
$CaPath = Join-Path $DataDir "device-control-ca.pem"

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
# state holds the device token, the network secrets and keys. Any user may
# create folders in ProgramData, so one that already exists must not be a
# link and must belong to the administrators, the system or the installer
# service; its access list is then replaced, not added to, with
# inheritance off. The program checks the same before it reads or writes
# its state (the same rules as install-windows.ps1).
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
        # The service manager deletes it once every handle is closed.
        for ($i = 0; $i -lt 20 -and $null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue); $i++) {
            Start-Sleep -Milliseconds 500
        }
    }
}

if ($Uninstall) {
    Stop-Ours
    if (Test-Path -LiteralPath $ProgramDir) { Remove-Item -Recurse -Force -LiteralPath $ProgramDir }
    if ($Purge) {
        if (Test-Path -LiteralPath $State) { Remove-Item -Recurse -Force -LiteralPath $State }
        if (Test-Path -LiteralPath $CaPath) { Remove-Item -Force -LiteralPath $CaPath }
        Say "removed the service, the program and the device state; revoke the device in the panel"
    } else {
        Say "removed the service and the program; the device identity is kept in $State (-Purge removes it)"
    }
    exit 0
}

if (-not $BinarySha256 -or (-not $BinaryUrl -and -not $BinaryFile)) { Fail "-BinaryUrl or -BinaryFile, and -BinarySha256, are required" }
if ($BinaryUrl -and $BinaryFile) { Fail "give -BinaryUrl or -BinaryFile, not both" }
if (-not $WintunSha256 -or (-not $WintunUrl -and -not $WintunFile)) { Fail "-WintunUrl or -WintunFile, and -WintunSha256, are required: the networks need wintun.dll" }
if ($WintunUrl -and $WintunFile) { Fail "give -WintunUrl or -WintunFile, not both" }
foreach ($entry in $Latency) {
    if ($entry -notmatch '^[A-Za-z0-9.-]+=[0-9.]+$') { Fail "-Latency takes CODE=MS" }
}

$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -ne "AMD64" -and $arch -ne "ARM64") { Fail "unsupported architecture $arch" }

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Get-Checked([string]$Url, [string]$File, [string]$Path, [string]$Sha256, [string]$What) {
    if ($Url) {
        if (-not $Url.StartsWith("https://")) { Fail "only https downloads are allowed" }
        Say "downloading $What"
        Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Path
    } else {
        Copy-Item -LiteralPath $File -Destination $Path
    }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256.ToLowerInvariant()) { Fail "checksum mismatch for $What" }
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("anixops-mesh-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    # The program runs from a folder of its own with wintun.dll beside it:
    # it loads the library from its own folder only.
    $stage = Join-Path $work "program"
    New-Item -ItemType Directory -Path $stage | Out-Null
    $download = Join-Path $stage "anixops-mesh.exe"
    Get-Checked $BinaryUrl $BinaryFile $download $BinarySha256 "the program"
    $wintun = Join-Path $stage "wintun.dll"
    Get-Checked $WintunUrl $WintunFile $wintun $WintunSha256 "wintun.dll"
    # The library must be built for this machine.
    $bytes = [IO.File]::ReadAllBytes($wintun)
    $machine = [BitConverter]::ToUInt16($bytes, [BitConverter]::ToInt32($bytes, 0x3C) + 4)
    $wanted = if ($arch -eq "ARM64") { 0xAA64 } else { 0x8664 }
    if ($machine -ne $wanted) { Fail "wintun.dll is not built for $arch" }

    $capabilities = (& $download capabilities) -join "`n"
    if ($LASTEXITCODE -ne 0) { Fail "the program does not run here" }
    foreach ($command in @("enroll", "device", "device-status")) {
        if ($capabilities -notmatch ('"' + $command + '"')) { Fail "this build has no $command command" }
    }

    Protect-Directory (Split-Path -Parent $DataDir)
    Protect-Directory $DataDir
    Protect-Directory $State

    $enrolled = (Test-Path -LiteralPath (Join-Path $State "token")) -and (Test-Path -LiteralPath (Join-Path $State "device.json"))
    if (-not $enrolled) {
        if (-not $Control) { Fail "-Control is required to enroll" }
        # The credential goes to a file in the protected state directory
        # and is removed right after the enrolment.
        $credential = Join-Path $State "enroll-credential.tmp"
        if ($TokenFile) {
            Copy-Item -Force -LiteralPath $TokenFile -Destination $credential
        } else {
            $secure = Read-Host -AsSecureString "One-time credential"
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            try {
                [IO.File]::WriteAllText($credential, [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr))
            } finally {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
        $enrollArgs = @("enroll", "--control", $Control, "--token-file", $credential, "--state-dir", $State)
        foreach ($entry in $Latency) { $enrollArgs += @("--latency", $entry) }
        if ($CaFile) {
            # Kept beside the state: the device trusts only this file from now on.
            Copy-Item -Force -LiteralPath $CaFile -Destination $CaPath
            $enrollArgs += @("--ca-file", $CaPath)
        }
        Say "enrolling the device"
        try {
            & $download @enrollArgs | Out-Null
            $status = $LASTEXITCODE
        } finally {
            Remove-Item -Force -LiteralPath $credential -ErrorAction SilentlyContinue
        }
        switch ($status) {
            0 { }
            8 { Fail "the panel refused the credential; ask the administrator for a new one" }
            9 { Fail "the panel could not be reached or answered wrongly; run again within 10 minutes with the same credential" }
            default { Fail "enrolment failed ($status)" }
        }
    } else {
        Say "the device is already enrolled; replacing the program"
    }

    Stop-Ours
    New-Item -ItemType Directory -Force -Path $ProgramDir | Out-Null
    Copy-Item -Force $download $Bin
    Copy-Item -Force $wintun (Join-Path $ProgramDir "wintun.dll")

    $command = "`"$Bin`" device --state-dir `"$State`""
    New-Service -Name $ServiceName -DisplayName "AnixOps Mesh Device" -BinaryPathName $command -StartupType Automatic | Out-Null
    # Restarted after a failure, five seconds apart. The program reports a
    # refused token (exit code 8) as a clean stop, so it is not restarted
    # until the device is enrolled again.
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-Ours; Fail "setting the recovery actions failed ($LASTEXITCODE)" }
    & sc.exe failureflag $ServiceName 1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-Ours; Fail "setting the failure flag failed ($LASTEXITCODE)" }

    try { Start-Service -Name $ServiceName } catch { }
    # The service answers on its status pipe once it runs.
    $answered = $false
    for ($i = 0; $i -lt 10; $i++) {
        & $Bin device-status --state-dir $State | Out-Null
        if ($LASTEXITCODE -eq 0) { $answered = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $answered) {
        Stop-Ours
        Fail "the device did not start; see $State\device.log (the enrolment is kept; run again to retry)"
    }
    Say "installed and running"
}
finally {
    Remove-Item -Recurse -Force -Path $work -ErrorAction SilentlyContinue
}
