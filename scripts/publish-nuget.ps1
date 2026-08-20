# -----------------------------------------------------------------------------
# QualityGuard — publish NuGet packages
# Copyright (c) 2026 Passaro Francesco Paolo - Digitalsolutions.it
#
# Packs and optionally pushes the four QualityGuard packages in dependency
# order, so consumers can restore them over NuGet:
#   1. QualityGuard.Core            0.9.0
#   2. QualityGuard.Sources.Sarif   0.9.0
#   3. QualityGuard.Cli             0.9.0
#   4. QualityGuard.Mcp             0.9.0
#
# When -Push is given, each package is first checked against the feed (flat-container
# API) and skipped — pack included — if that exact id+version already exists, so
# re-running the script after a partial publish just moves on. Without -Push it's a
# pack-only rehearsal (no existence check, no push).
#
# The MCP package packs its project references as package dependencies, so it
# declares QualityGuard.Core / .Sources.Sarif / .Cli at the same version and
# becomes standalone once those three are on the feed.
#
# Usage:
#   .\scripts\publish-nuget.ps1                         # pack only, into .\artifacts
#   .\scripts\publish-nuget.ps1 -Push -ApiKey <key>     # pack + push to nuget.org
#   .\scripts\publish-nuget.ps1 -Push -ApiKey <key> -Source https://api.nuget.org/v3/index.json
#
# The -Push flag requires -ApiKey (or $env:NUGET_API_KEY). Without it the script
# only packs, so a publish run can be rehearsed before anything leaves the machine.
# -----------------------------------------------------------------------------
param(
    [switch]$Push,
    [string]$ApiKey = $env:NUGET_API_KEY,
    [string]$Source = "https://api.nuget.org/v3/index.json",
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$outDir   = Join-Path $repoRoot "artifacts"
$config   = "Release"

$targets = @(
    @{ Name = "QualityGuard.Core";            Csproj = Join-Path $repoRoot "src\QualityGuard.Core\QualityGuard.Core.csproj" },
    @{ Name = "QualityGuard.Sources.Sarif";   Csproj = Join-Path $repoRoot "src\QualityGuard.Sources.Sarif\QualityGuard.Sources.Sarif.csproj" },
    @{ Name = "QualityGuard.Cli";             Csproj = Join-Path $repoRoot "src\QualityGuard.Cli\QualityGuard.Cli.csproj" },
    @{ Name = "QualityGuard.Mcp";             Csproj = Join-Path $repoRoot "src\QualityGuard.MCP\QualityGuard.MCP.csproj" }
)

if ($Push -and [string]::IsNullOrWhiteSpace($ApiKey)) {
    throw "-Push requires -ApiKey (or the NUGET_API_KEY environment variable)."
}

New-Item -ItemType Directory -Path $outDir -Force | Out-Null
Write-Host "Publishing version $Version into: $outDir" -ForegroundColor Cyan

# Resolves the flat-container nupkg URL for a source + id + version. Prefers the
# PackageBaseAddress/3.0.0 resource advertised in the source's service index
# (e.g. https://api.nuget.org/v3-flatcontainer/... for nuget.org); falls back to
# guessing "<base>/flatcontainer/..." when the index cannot be read.
function Resolve-FlatContainerUrl([string]$source, [string]$id, [string]$version) {
    $lower = $id.ToLowerInvariant()
    $v = $version.ToLowerInvariant()
    try {
        $doc = Invoke-RestMethod -Uri $source -TimeoutSec 15 -ErrorAction Stop
        $res = @($doc.resources | Where-Object { $_.'@type' -like 'PackageBaseAddress*' } | Select-Object -First 1)
        if ($res -and $res[0].'@id') {
            return ("{0}/{1}/{2}/{1}.{2}.nupkg" -f $res[0].'@id'.TrimEnd('/'), $lower, $v)
        }
    }
    catch {
        Write-Warning "Cannot read service index at '$source' ($($_.Exception.Message)); guessing the flat-container URL."
    }
    $base = $source.TrimEnd('/') -replace 'index\.json$', ''
    return "$base/flatcontainer/$lower/$v/$lower.$v.nupkg"
}

# Returns $true when the exact id+version already exists on the source feed.
# Uses a raw HttpWebRequest with a 1-byte Range so no full package is downloaded
# and no interactive credential prompt can block CI. A 200/206 means present,
# a 404/410 means absent; anything else is treated as "unknown" (returns $false)
# so the pack/push is still attempted rather than silently skipped.
function Test-PackageOnSource([string]$source, [string]$id, [string]$version) {
    $url = Resolve-FlatContainerUrl $source $id $version
    try {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Method = "GET"
        $req.AddRange(0, 0)
        $req.Timeout = 30000
        $resp = $req.GetResponse()
        try {
            $status = [int]$resp.StatusCode
        }
        finally {
            $resp.Close()
        }
        if ($status -eq 200 -or $status -eq 206) { return $true }
        if ($status -eq 404 -or $status -eq 410) { return $false }
        Write-Warning "Unexpected status $status for '$id $version' on $source; proceeding."
    }
    catch [System.Net.WebException] {
        $status = $null
        if ($_.Exception.Response) {
            try { $status = [int]$_.Exception.Response.StatusCode } finally { $_.Exception.Response.Close() }
        }
        if ($status -eq 404 -or $status -eq 410) { return $false }
        Write-Warning "Cannot check '$id $version' on $source ($($_.Exception.Message)); proceeding."
    }
    catch {
        Write-Warning "Cannot check '$id $version' on $source ($($_.Exception.Message)); proceeding."
    }
    return $false
}

foreach ($t in $targets) {
    if (-not (Test-Path $t.Csproj)) {
        throw "Project not found: $($t.Csproj)"
    }

    if ($Push -and (Test-PackageOnSource $Source $t.Name $Version)) {
        Write-Host "`n=== Skipping $($t.Name) $Version ===" -ForegroundColor Yellow
        Write-Host "Already on $Source" -ForegroundColor Yellow
        continue
    }

    Write-Host "`n=== Packing $($t.Name) $Version ===" -ForegroundColor Cyan
    # The version comes from the project metadata (src\Directory.Build.props); the -Version
    # parameter is only used for the existence check and the nupkg name, so the two must match.
    # The MCP project restores the QualityGuard packages from NuGet; the local artifacts folder
    # is added as an extra restore source, so a fresh `-Push` run can pack it with the versions
    # produced by the very same run, before they reach the feed.
    dotnet pack $t.Csproj -c $config --nologo -p:Version=$Version "-p:RestoreAdditionalProjectSources=$outDir" -o $outDir
    if ($LASTEXITCODE -ne 0) { throw "dotnet pack failed for $($t.Name)." }

    $nupkg = Get-ChildItem $outDir -Filter "$($t.Name).$Version.nupkg" | Select-Object -First 1
    if (-not $nupkg) {
        throw "Expected nupkg not produced: $($t.Name).$Version.nupkg (version mismatch?)."
    }

    Write-Host "Packed: $($nupkg.FullName)" -ForegroundColor Green

    if ($Push) {
        Write-Host "Pushing $($nupkg.Name) to $Source ..."
        dotnet nuget push $nupkg.FullName --api-key $ApiKey --source $Source
        if ($LASTEXITCODE -ne 0) { throw "dotnet nuget push failed for $($t.Name)." }
        Write-Host "Pushed: $($t.Name) $Version" -ForegroundColor Green
    }
}

Write-Host "`nDone. Artifacts: $outDir" -ForegroundColor Green
if (-not $Push) {
    Write-Host "Pack-only run (no push). Add -Push -ApiKey <key> to upload to NuGet." -ForegroundColor Yellow
}