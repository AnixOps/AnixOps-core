# Downloads the Wintun prebuilt package, checks its pinned SHA-256 and copies
# the wintun.dll of one architecture (unmodified, as its license requires)
# plus the license to the destination directory. Same package and checksum
# as the client (anixops-net .github/scripts/fetch-wintun.ps1). Prints the
# DLL path.
param(
  [Parameter(Mandatory = $true)][string]$Destination,
  [ValidateSet("amd64", "arm64")][string]$Arch = "amd64"
)
$ErrorActionPreference = "Stop"
$version = "0.14.1"
$expectedSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$work = Join-Path ([System.IO.Path]::GetTempPath()) "wintun-$version-$([guid]::NewGuid())"
New-Item -ItemType Directory -Force -Path $work | Out-Null
$zip = Join-Path $work "wintun.zip"
Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-$version.zip" -OutFile $zip -UseBasicParsing
$actual = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLowerInvariant()
if ($actual -ne $expectedSha256) {
  throw "wintun-$version.zip SHA-256 mismatch: expected $expectedSha256, got $actual"
}
Expand-Archive -Path $zip -DestinationPath $work -Force
New-Item -ItemType Directory -Force -Path $Destination | Out-Null
$dll = Join-Path $Destination "wintun.dll"
Copy-Item -Path (Join-Path $work "wintun\bin\$Arch\wintun.dll") -Destination $dll -Force
Copy-Item -Path (Join-Path $work "wintun\LICENSE.txt") -Destination (Join-Path $Destination "wintun-LICENSE.txt") -Force
if ((Get-Item $dll).Length -le 0) {
  throw "wintun.dll is empty"
}
# The PE machine type must match the architecture asked for.
$bytes = [System.IO.File]::ReadAllBytes($dll)
$pe = [BitConverter]::ToInt32($bytes, 0x3C)
$machine = [BitConverter]::ToUInt16($bytes, $pe + 4)
$expected = @{ amd64 = 0x8664; arm64 = 0xAA64 }[$Arch]
if ($machine -ne $expected) {
  throw ("wintun.dll is for machine 0x{0:X4}, not {1}" -f $machine, $Arch)
}
(Resolve-Path $dll).Path
